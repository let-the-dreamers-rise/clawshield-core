/**
 * The signing boundary.
 *
 * The guarantee under test: there is no path from a proposed transfer to a signature that does
 * not pass through the engine. Not "the adapter checks the policy first" - that is a claim
 * about discipline. The keypair lives in a closure and no exported function accepts it, so
 * calling code cannot sign even if it wants to.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { generateKeypair, hashPolicy, hashReceiptBody } from "../src/receipt/sign.ts";
import { verifyChain, verifyReceipt } from "../src/receipt/verify.ts";
import { RULESET_VERSION } from "../src/policy/engine.ts";
import { createPlaintextPolicyProvider, createSealedPolicyProvider, sealedCommitment } from "../src/policy/sealed.ts";
import { createStubMxe } from "../src/mxe/stub.ts";
import { createSolanaAdapter } from "../src/solana/adapter.ts";
import { solanaAddress } from "../src/solana/keys.ts";
import { SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID, USDC_MAINNET_MINT, type SolanaTransfer } from "../src/solana/types.ts";
import type { AgentState, Policy } from "../src/policy/types.ts";

const AT = Date.UTC(2026, 6, 31, 12, 0, 0);
// The adapter signs for exactly one account: the vault whose key it holds.
const VAULT_KEYS = generateKeypair();
const VAULT = solanaAddress(VAULT_KEYS.publicKey);
const BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";
const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const SALT = "1f9c4a2e6b8d0357f1a9c4e2b6d80357f1a9c4e2b6d80357f1a9c4e2b6d80357";
const CIRCUIT = "genkai.policy.v1";

const policy: Policy = {
  policyId: "solana-treasury-v1",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  allowedClusters: ["mainnet-beta"],
  allowedPrograms: [TOKEN_PROGRAM_ID],
  allowedMints: [USDC_MAINNET_MINT],
  maxAmountPerMint: { [USDC_MAINNET_MINT]: 100_000_000n },
  maxAmountPerAction: 100_000_000n,
  escalateAboveAmount: 50_000_000n,
};

const state: AgentState = {
  spentInWindow: 0n,
  windowStartedAt: AT,
  callsInWindow: 0,
  drawdownFromPeak: 0n,
  revoked: false,
};

const transfer = (over: Partial<SolanaTransfer> = {}): SolanaTransfer => ({
  kind: "spl",
  programId: TOKEN_PROGRAM_ID,
  cluster: "mainnet-beta",
  from: VAULT,
  to: VENDOR,
  mint: USDC_MAINNET_MINT,
  decimals: 6,
  amount: 10_000_000n,
  requestedAt: AT,
  ...over,
});

const plainAdapter = () =>
  createSolanaAdapter({
    agentId: "agent-1",
    keys: VAULT_KEYS,
    provider: createPlaintextPolicyProvider(policy),
  });

test("an allowed transfer is signed and produces a verifiable receipt", async () => {
  const adapter = plainAdapter();
  const result = await adapter.submit({ transfer: transfer(), state, decidedAt: AT, recentBlockhash: BLOCKHASH });

  assert.equal(result.decision.verdict, "allow");
  assert.ok(result.signedTransaction, "an allowed transfer must be signed");
  assert.equal(result.receipt.body.policyHash, hashPolicy(policy));
  assert.equal(result.receipt.body.rulesetVersion, RULESET_VERSION);

  const verified = verifyReceipt(result.receipt, policy);
  assert.equal(verified.valid, true, verified.detail.join("; "));
});

test("a denied transfer is never signed", async () => {
  const adapter = plainAdapter();
  const result = await adapter.submit({
    transfer: transfer({ programId: SYSTEM_PROGRAM_ID }),
    state,
    decidedAt: AT,
    recentBlockhash: BLOCKHASH,
  });

  assert.equal(result.decision.verdict, "deny");
  assert.equal(result.signedTransaction, undefined);
  // The denial still produces a receipt. A refusal that leaves no evidence is not a control.
  assert.equal(verifyReceipt(result.receipt, policy).valid, true);
  assert.equal(result.receipt.body.outcome?.executed, false);
});

test("an escalated transfer is not signed while awaiting a human", async () => {
  const adapter = plainAdapter();
  const result = await adapter.submit({
    transfer: transfer({ amount: 60_000_000n }),
    state,
    decidedAt: AT,
    recentBlockhash: BLOCKHASH,
  });

  assert.equal(result.decision.verdict, "escalate");
  assert.equal(result.signedTransaction, undefined, "escalate is not a soft allow");
});

test("the keypair is unreachable from outside the adapter", async () => {
  const keys = generateKeypair();
  const adapter = createSolanaAdapter({
    agentId: "agent-1",
    keys,
    provider: createPlaintextPolicyProvider(policy),
  });

  // The only surface is submit() and the public key. There is no sign(), no key accessor and
  // no configuration object left hanging off the instance.
  assert.deepEqual(Object.keys(adapter).sort(), ["publicKey", "submit"]);
  const probe = adapter as unknown as Record<string, unknown>;
  assert.equal(probe["keys"], undefined);
  assert.equal(probe["sign"], undefined);
  assert.equal(probe["privateKey"], undefined);
  assert.equal(Object.isFrozen(adapter), true);

  // Nor can the key be reached by serialising the adapter and reading it back.
  assert.doesNotMatch(JSON.stringify(adapter), /PRIVATE KEY|privateKey/);
});

test("an agent cannot obtain a signature without a verdict", async () => {
  // The module exports a factory and types. It exports nothing that signs a transfer, so
  // there is no bypass to call - the absence is the guarantee.
  const module = await import("../src/solana/adapter.ts");
  assert.deepEqual(Object.keys(module), ["createSolanaAdapter"]);
});

test("receipts chain across submissions", async () => {
  const adapter = plainAdapter();
  const first = await adapter.submit({
    transfer: transfer({ amount: 1_000_000n }),
    state,
    decidedAt: AT,
    recentBlockhash: BLOCKHASH,
  });

  const second = await adapter.submit({
    transfer: transfer({ amount: 2_000_000n }),
    state: { ...state, spentInWindow: 1_000_000n, callsInWindow: 1 },
    decidedAt: AT,
    recentBlockhash: BLOCKHASH,
    previousReceiptHash: hashReceiptBody(first.receipt.body),
  });

  const policyFor = (hash: string) => (hash === hashPolicy(policy) ? policy : undefined);
  const chain = verifyChain([first.receipt, second.receipt], policyFor);
  assert.equal(chain.valid, true, chain.detail.join("; "));
});

test("the same adapter code path works under seal", async () => {
  const mxe = createStubMxe({ policy, salt: SALT, circuitId: CIRCUIT, keys: generateKeypair() });
  const adapter = createSolanaAdapter({
    agentId: "agent-1",
    keys: VAULT_KEYS,
    provider: createSealedPolicyProvider({
      commitment: sealedCommitment(policy, SALT),
      circuitId: CIRCUIT,
      clusterPublicKey: mxe.clusterPublicKey,
      mxe,
    }),
  });

  const allowed = await adapter.submit({ transfer: transfer(), state, decidedAt: AT, recentBlockhash: BLOCKHASH });
  assert.equal(allowed.decision.verdict, "allow");
  assert.ok(allowed.signedTransaction);
  assert.ok(allowed.receipt.body.attestation, "a sealed receipt must carry its attestation");

  const denied = await adapter.submit({
    transfer: transfer({ mint: SYSTEM_PROGRAM_ID }),
    state,
    decidedAt: AT,
    recentBlockhash: BLOCKHASH,
  });
  assert.equal(denied.decision.verdict, "deny");
  assert.equal(denied.signedTransaction, undefined);
});

test("a sealed receipt cannot be replay-verified, and says so rather than failing quietly", async () => {
  // This is the trade, asserted rather than described. The receipt binds a salted commitment,
  // so the plaintext verifier cannot match it against the policy even when handed the policy.
  // A verifier must fall back to checking the attestation.
  const mxe = createStubMxe({ policy, salt: SALT, circuitId: CIRCUIT, keys: generateKeypair() });
  const adapter = createSolanaAdapter({
    agentId: "agent-1",
    keys: VAULT_KEYS,
    provider: createSealedPolicyProvider({
      commitment: sealedCommitment(policy, SALT),
      circuitId: CIRCUIT,
      clusterPublicKey: mxe.clusterPublicKey,
      mxe,
    }),
  });

  const result = await adapter.submit({ transfer: transfer(), state, decidedAt: AT, recentBlockhash: BLOCKHASH });
  const verified = verifyReceipt(result.receipt, policy);
  assert.equal(verified.valid, false);
  assert.ok(verified.failures.includes("policy_hash_mismatch"));
  assert.notEqual(result.receipt.body.policyHash, hashPolicy(policy));
});

test("a signature commits to the exact transfer, not merely to the verdict", async () => {
  const adapter = plainAdapter();
  const base = { state, decidedAt: AT, recentBlockhash: BLOCKHASH };
  const a = await adapter.submit({ ...base, transfer: transfer({ amount: 1_000_000n }) });
  const b = await adapter.submit({ ...base, transfer: transfer({ amount: 2_000_000n }) });

  assert.notEqual(a.signedTransaction, b.signedTransaction);
  // Two allowed transfers to different destinations must not share a signature either.
  const c = await adapter.submit({ ...base, transfer: transfer({ amount: 1_000_000n, to: SYSTEM_PROGRAM_ID }) });
  assert.notEqual(a.signedTransaction, c.signedTransaction);
});
