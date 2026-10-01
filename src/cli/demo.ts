/**
 * The end-to-end demo: a treasury agent proposing payments under a governed policy.
 *
 * The same five proposals run twice - once against a plaintext policy, once against the same
 * policy sealed behind an MXE - and each run writes what an operator would publish:
 *
 *   plaintext/  receipts.json + policy.json   anyone can replay every decision
 *   sealed/     receipts.json + trust.json    anyone can verify; nobody learns the limits
 *
 * Offline (the default) every allowed transfer is signed against a placeholder blockhash and
 * never broadcast, so nothing can land. With --devnet the plaintext run broadcasts for real
 * and each confirmed transfer is then checked against the chain.
 *
 * The sealed run uses the in-process stub MXE, which runs the same circuit model the Arcium
 * circuit implements but is not confidential. It is labelled as such in the output.
 */

import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { generateKeypair, hashReceiptBody, type Keypair } from "../receipt/sign.ts";
import { verifyChain } from "../receipt/verify.ts";
import { verifySealedChain } from "../receipt/verify-sealed.ts";
import { createPlaintextPolicyProvider, createSealedPolicyProvider, sealedCommitment, type PolicyProvider } from "../policy/sealed.ts";
import { createStubMxe } from "../mxe/stub.ts";
import { createSolanaAdapter } from "../solana/adapter.ts";
import { createExecutor, verifyExecution } from "../solana/executor.ts";
import { solanaAddress } from "../solana/keys.ts";
import type { RpcClient } from "../solana/rpc.ts";
import { NATIVE_SOL_MINT, SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID, type SolanaTransfer } from "../solana/types.ts";
import type { AgentState, Policy, Verdict } from "../policy/types.ts";
import type { SignedReceipt } from "../receipt/types.ts";
import { writeJsonFile } from "./files.ts";

const VENDOR_A = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const VENDOR_B = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const STRANGER = "GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW";
/** Never a real recent blockhash, so an offline transaction can never land. */
const OFFLINE_BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";
const CIRCUIT_ID = "genkai.policy.v1";

export const DEMO_POLICY: Policy = {
  policyId: "desk-alpha-treasury",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  counterpartyAllowlist: [VENDOR_A, VENDOR_B],
  allowedClusters: ["devnet"],
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  allowedMints: [NATIVE_SOL_MINT],
  maxAmountPerMint: { [NATIVE_SOL_MINT]: 50_000_000n },
  maxAmountPerWindow: 100_000_000n,
  maxCallsPerWindow: 10,
  escalateAboveAmount: 20_000_000n,
};

const PROPOSALS: readonly { readonly intent: string; readonly to: string; readonly lamports: bigint }[] = [
  { intent: "Pay vendor A invoice #1042", to: VENDOR_A, lamports: 10_000_000n },
  { intent: "Refund an unknown address", to: STRANGER, lamports: 5_000_000n },
  { intent: "Prepay vendor B for the quarter", to: VENDOR_B, lamports: 30_000_000n },
  { intent: "Sweep reserves to vendor A", to: VENDOR_A, lamports: 200_000_000n },
  { intent: "Pay vendor B invoice #77", to: VENDOR_B, lamports: 15_000_000n },
];

export interface DemoOptions {
  readonly out: string;
  readonly vault?: Keypair;
  readonly rpc?: RpcClient;
  readonly log?: (line: string) => void;
}

interface Step {
  readonly verdict: Verdict;
  readonly receipt: SignedReceipt;
  readonly note: string;
}

const sol = (lamports: bigint): string => {
  const whole = lamports / 1_000_000_000n;
  const frac = (lamports % 1_000_000_000n).toString().padStart(9, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
};

const afterAllow = (s: AgentState, amount: bigint): AgentState => ({
  ...s,
  spentInWindow: s.spentInWindow + amount,
  callsInWindow: s.callsInWindow + 1,
});

async function runOffline(provider: PolicyProvider, vault: Keypair, agentId: string): Promise<readonly Step[]> {
  const adapter = createSolanaAdapter({ agentId, keys: vault, provider });
  const from = solanaAddress(vault.publicKey);
  const start = Date.now();
  let state: AgentState = { spentInWindow: 0n, windowStartedAt: start, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
  let previous: string | null = null;
  const steps: Step[] = [];

  for (const [i, p] of PROPOSALS.entries()) {
    const transfer: SolanaTransfer = { kind: "sol", programId: SYSTEM_PROGRAM_ID, cluster: "devnet", from, to: p.to, decimals: 9, amount: p.lamports, requestedAt: start + i };
    const { decision, receipt } = await adapter.submit({ transfer, state, decidedAt: start + i, recentBlockhash: OFFLINE_BLOCKHASH, previousReceiptHash: previous, modelReasoning: p.intent });
    steps.push({ verdict: decision.verdict, receipt, note: decision.verdict === "allow" ? "signed, not broadcast" : "" });
    if (decision.verdict === "allow") state = afterAllow(state, p.lamports);
    previous = hashReceiptBody(receipt.body);
  }
  return steps;
}

async function runDevnet(provider: PolicyProvider, vault: Keypair, rpc: RpcClient, log: (l: string) => void): Promise<readonly Step[]> {
  const adapter = createSolanaAdapter({ agentId: "desk-bot", keys: vault, provider });
  const executor = createExecutor({ adapter, rpc, fees: { computeUnitLimit: 20_000, computeUnitPrice: 1_000n } });
  const from = solanaAddress(vault.publicKey);
  let state: AgentState = { spentInWindow: 0n, windowStartedAt: Date.now(), callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
  let previous: string | null = null;
  const steps: Step[] = [];

  for (const p of PROPOSALS) {
    const transfer: SolanaTransfer = { kind: "sol", programId: SYSTEM_PROGRAM_ID, cluster: "devnet", from, to: p.to, decimals: 9, amount: p.lamports, requestedAt: Date.now() };
    const { submission, execution } = await executor.execute({ transfer, state, previousReceiptHash: previous, modelReasoning: p.intent });
    let note = execution ? `${execution.status} ${execution.signature}` : "";
    if (execution && (execution.status === "confirmed" || execution.status === "finalized")) {
      state = afterAllow(state, p.lamports);
      const onChain = await verifyExecution(submission.receipt, rpc);
      note += onChain.executed ? " (verified on chain)" : ` (chain check failed: ${onChain.failure})`;
    }
    if (execution) log(`  ${p.intent}: ${note}`);
    steps.push({ verdict: submission.decision.verdict, receipt: submission.receipt, note });
    previous = hashReceiptBody(submission.receipt.body);
  }
  return steps;
}

export async function runDemo(options: DemoOptions): Promise<{ readonly plaintextValid: boolean; readonly sealedValid: boolean }> {
  const log = options.log ?? ((line: string) => process.stdout.write(`${line}\n`));
  const vault = options.vault ?? generateKeypair();
  const address = solanaAddress(vault.publicKey);

  // Plaintext: the policy is published alongside the receipts.
  const plainProvider = createPlaintextPolicyProvider(DEMO_POLICY);
  if (options.rpc) log(`Broadcasting allowed transfers to devnet from ${address}`);
  const plain = options.rpc
    ? await runDevnet(plainProvider, vault, options.rpc, log)
    : await runOffline(plainProvider, vault, "desk-bot");

  // Sealed: only the commitment, circuit id and cluster key are published.
  const salt = randomBytes(32).toString("hex");
  const mxe = createStubMxe({ policy: DEMO_POLICY, salt, circuitId: CIRCUIT_ID, keys: generateKeypair() });
  const sealedProvider = createSealedPolicyProvider({ commitment: sealedCommitment(DEMO_POLICY, salt), circuitId: CIRCUIT_ID, clusterPublicKey: mxe.clusterPublicKey, mxe });
  const trust = { commitment: sealedProvider.commitment, circuitId: CIRCUIT_ID, clusterPublicKey: mxe.clusterPublicKey };
  const sealed = await runOffline(sealedProvider, vault, "desk-bot-sealed");

  const plainReceipts = plain.map((s) => s.receipt);
  const sealedReceipts = sealed.map((s) => s.receipt);
  writeJsonFile(join(options.out, "plaintext", "policy.json"), DEMO_POLICY);
  writeJsonFile(join(options.out, "plaintext", "receipts.json"), plainReceipts);
  writeJsonFile(join(options.out, "sealed", "trust.json"), trust);
  writeJsonFile(join(options.out, "sealed", "receipts.json"), sealedReceipts);

  const plainCheck = verifyChain(plainReceipts, () => DEMO_POLICY);
  const sealedCheck = verifySealedChain(sealedReceipts, trust);

  log(`\nGENKAI demo (${options.rpc ? "devnet" : "offline"}) - vault ${address}\n`);
  log(`  #  ${"proposal".padEnd(34)}${"SOL".padEnd(8)}${"plaintext".padEnd(11)}sealed`);
  PROPOSALS.forEach((p, i) => {
    log(`  ${i + 1}  ${p.intent.padEnd(34)}${sol(p.lamports).padEnd(8)}${(plain[i]?.verdict ?? "-").padEnd(11)}${sealed[i]?.verdict ?? "-"}`);
  });
  log(`\nPlaintext chain: ${plainCheck.valid ? "valid" : "INVALID"} - every decision replayed against the published policy`);
  log(`Sealed chain:    ${sealedCheck.valid ? "valid" : "INVALID"} - attested under the pinned cluster key; the policy was never published`);
  log("Sealed run uses the in-process stub MXE (same circuit model, not confidential). See arcium/ for the Arcis circuit.");
  log(`\nWrote ${options.out}`);
  return { plaintextValid: plainCheck.valid, sealedValid: sealedCheck.valid };
}
