/**
 * Third-party verification of sealed receipts.
 *
 * A plaintext receipt is verified by replay. A sealed one cannot be, because the verifier is
 * not allowed to see the policy. What it can check instead, holding only public values pinned
 * out of band (the policy commitment, the circuit id and the cluster key):
 *
 *   - the operator signed this receipt
 *   - it binds the pinned commitment
 *   - the pinned circuit, under the pinned cluster key, attested this verdict for this exact
 *     request and state
 *   - the receipt discloses nothing beyond what the attestation covers
 *   - the chain and any bound transaction hold, exactly as in plaintext mode
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { generateKeypair, hashReceiptBody, signReceipt } from "../src/receipt/sign.ts";
import { verifySealedChain, verifySealedReceipt, type SealedTrust } from "../src/receipt/verify-sealed.ts";
import { SealedPolicyError, createSealedPolicyProvider, sealedCommitment, type Disclosure } from "../src/policy/sealed.ts";
import { createStubMxe } from "../src/mxe/stub.ts";
import { createSolanaAdapter } from "../src/solana/adapter.ts";
import { solanaAddress } from "../src/solana/keys.ts";
import { SOLANA_TRANSFER_TOOL, TOKEN_PROGRAM_ID, USDC_MAINNET_MINT, type SolanaTransfer } from "../src/solana/types.ts";
import type { AgentState, Policy } from "../src/policy/types.ts";
import type { MxeClient } from "../src/mxe/types.ts";

const AT = Date.UTC(2026, 8, 1, 12, 0, 0);
const SALT = "9c1d3f5a7b9e0c2d4f6a8b0c1e3d5f7a9b0c2e4d6f8a0b1c3e5d7f9a1b2c3d4e";
const CIRCUIT = "genkai.policy.v1";
const BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";
const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const VAULT_KEYS = generateKeypair();
const VAULT = solanaAddress(VAULT_KEYS.publicKey);
const CLUSTER_KEYS = generateKeypair();

const policy: Policy = {
  policyId: "desk-alpha",
  version: 3,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  allowedClusters: ["devnet"],
  allowedPrograms: [TOKEN_PROGRAM_ID],
  allowedMints: [USDC_MAINNET_MINT],
  maxAmountPerMint: { [USDC_MAINNET_MINT]: 50_000_000_000n },
  maxAmountPerAction: 50_000_000_000n,
  escalateAboveAmount: 25_000_000_000n,
};
const state: AgentState = { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
const transfer = (amount: bigint): SolanaTransfer => ({
  kind: "spl",
  programId: TOKEN_PROGRAM_ID,
  cluster: "devnet",
  from: VAULT,
  to: VENDOR,
  mint: USDC_MAINNET_MINT,
  decimals: 6,
  amount,
  requestedAt: AT,
});

function setup(disclosure: Disclosure = "rules", mxeOverride?: (m: MxeClient) => MxeClient) {
  const mxe = createStubMxe({ policy, salt: SALT, circuitId: CIRCUIT, keys: CLUSTER_KEYS });
  const provider = createSealedPolicyProvider({
    commitment: sealedCommitment(policy, SALT),
    circuitId: CIRCUIT,
    clusterPublicKey: mxe.clusterPublicKey,
    mxe: mxeOverride ? mxeOverride(mxe) : mxe,
    disclosure,
  });
  const adapter = createSolanaAdapter({ agentId: "desk-bot", keys: VAULT_KEYS, provider });
  const trust: SealedTrust = { commitment: provider.commitment, circuitId: CIRCUIT, clusterPublicKey: mxe.clusterPublicKey };
  const submit = (amount: bigint, previousReceiptHash: string | null = null) =>
    adapter.submit({ transfer: transfer(amount), state, decidedAt: AT, recentBlockhash: BLOCKHASH, previousReceiptHash });
  return { trust, submit, mxe };
}

const withKey = <T extends object>(obj: T, key: string, value: unknown): T => ({ ...obj, [key]: value });

test("a sealed receipt verifies against pinned public values alone", async () => {
  const { trust, submit } = setup();
  for (const amount of [1_000_000n, 30_000_000_000n, 90_000_000_000n]) {
    const { receipt } = await submit(amount);
    const result = verifySealedReceipt(receipt, trust);
    assert.equal(result.valid, true, `${amount}: ${result.detail.join("; ")}`);
  }
});

test("an operator who flips the verdict and re-signs is caught by the attestation", async () => {
  const { trust, submit } = setup();
  const { receipt } = await submit(90_000_000_000n);
  assert.equal(receipt.body.decision.verdict, "deny");

  const forged = signReceipt(
    { ...receipt.body, decision: { ...receipt.body.decision, verdict: "allow" } },
    VAULT_KEYS,
  );
  const result = verifySealedReceipt(forged, trust);
  assert.equal(result.valid, false);
  assert.ok(result.failures.includes("attestation_invalid"));
});

test("an attestation lifted from a different decision is caught", async () => {
  const { trust, submit } = setup();
  const small = await submit(1_000_000n);
  const large = await submit(90_000_000_000n);
  const forged = signReceipt({ ...large.receipt.body, attestation: small.receipt.body.attestation }, VAULT_KEYS);
  assert.ok(verifySealedReceipt(forged, trust).failures.includes("attestation_invalid"));
});

test("a sealed receipt with no attestation is refused", async () => {
  const { trust, submit } = setup();
  const { receipt } = await submit(1_000_000n);
  const stripped = signReceipt(withKey(receipt.body, "attestation", undefined), VAULT_KEYS);
  assert.ok(verifySealedReceipt(stripped, trust).failures.includes("attestation_missing"));
});

test("pins are enforced: commitment, circuit and cluster key", async () => {
  const { trust, submit } = setup();
  const { receipt } = await submit(1_000_000n);
  const otherKey = generateKeypair().publicKey.export({ type: "spki", format: "der" }).toString("base64");

  assert.ok(verifySealedReceipt(receipt, { ...trust, commitment: "ab".repeat(32) }).failures.includes("commitment_mismatch"));
  assert.ok(verifySealedReceipt(receipt, { ...trust, circuitId: "other.v1" }).failures.includes("attestation_invalid"));
  assert.ok(verifySealedReceipt(receipt, { ...trust, clusterPublicKey: otherKey }).failures.includes("attestation_invalid"));
});

test("a receipt that leaks reason text is flagged even though its signatures hold", async () => {
  // The attestation covers rule ids, not reason strings. An operator who writes the plaintext
  // reason back in ("exceeds per-action cap 50000000000") has disclosed the limit, and the
  // verifier says so rather than passing a receipt that hands out the strategy.
  const { trust, submit } = setup();
  const { receipt } = await submit(90_000_000_000n);
  const leaky = signReceipt(
    {
      ...receipt.body,
      decision: {
        ...receipt.body.decision,
        reasons: receipt.body.decision.reasons.map((r) => ({ ...r, reason: "Amount exceeds per-action cap 50000000000" })),
      },
    },
    VAULT_KEYS,
  );
  const result = verifySealedReceipt(leaky, trust);
  assert.equal(result.valid, false);
  assert.ok(result.failures.includes("disclosure_leak"));
});

test("a bound transaction is checked under seal exactly as in plaintext mode", async () => {
  const { trust, submit } = setup();
  const { receipt } = await submit(1_000_000n);
  assert.ok(receipt.body.transaction);
  const forged = signReceipt(
    { ...receipt.body, transaction: { ...receipt.body.transaction, recentBlockhash: VENDOR } },
    VAULT_KEYS,
  );
  assert.ok(verifySealedReceipt(forged, trust).failures.includes("transaction_mismatch"));
});

test("sealed receipts chain, and a deleted link is caught", async () => {
  const { trust, submit } = setup();
  const first = await submit(1_000_000n);
  const second = await submit(2_000_000n, hashReceiptBody(first.receipt.body));

  assert.equal(verifySealedChain([first.receipt, second.receipt], trust).valid, true);
  const gapped = verifySealedChain([second.receipt], trust);
  assert.equal(gapped.valid, false);
  assert.ok(gapped.failures.includes("chain_broken"));
});

test("verdict-only mode discloses not even which kind of rule bound", async () => {
  const { trust, submit } = setup("verdict");
  const denied = await submit(90_000_000_000n);
  const escalated = await submit(30_000_000_000n);
  const allowed = await submit(1_000_000n);

  assert.equal(denied.decision.verdict, "deny");
  assert.equal(escalated.decision.verdict, "escalate");
  assert.equal(allowed.decision.verdict, "allow");
  for (const r of [denied, escalated, allowed]) {
    assert.deepEqual(r.decision.reasons, []);
    assert.equal(r.receipt.body.attestation?.disclosure, "verdict");
    const result = verifySealedReceipt(r.receipt, trust);
    assert.equal(result.valid, true, result.detail.join("; "));
  }
  assert.doesNotMatch(JSON.stringify(denied.receipt.body.decision), /amount_exceeds|mint_cap|per_action/);
});

test("a verdict-only attestation cannot be passed off as a rules-mode one", async () => {
  const { trust, submit } = setup("verdict");
  const { receipt } = await submit(90_000_000_000n);
  const attestation = receipt.body.attestation;
  assert.ok(attestation);
  const relabelled = signReceipt(
    {
      ...receipt.body,
      attestation: withKey(attestation, "disclosure", undefined),
      decision: { ...receipt.body.decision, reasons: [{ rule: "revoked", verdict: "deny", reason: "withheld: sealed policy" }] },
    },
    VAULT_KEYS,
  );
  assert.ok(verifySealedReceipt(relabelled, trust).failures.includes("attestation_invalid"));
});

test("an MXE that discloses rule ids when asked for the verdict only is refused", async () => {
  const { submit } = setup("verdict", (mxe) => ({
    ...mxe,
    evaluate: (input) => mxe.evaluate({ ...input, disclosure: "rules" }),
  }));
  await assert.rejects(
    () => submit(90_000_000_000n),
    (err: unknown) => err instanceof SealedPolicyError && err.code === "disclosure_violation",
  );
});
