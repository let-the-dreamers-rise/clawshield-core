/**
 * The confidential-policy seam.
 *
 * The property under test is not "the MXE returns an answer". It is that a sealed provider
 * refuses every input it cannot cryptographically account for, and that its output leaks
 * nothing about the limits it enforced.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { evaluate } from "../src/policy/engine.ts";
import { hashPolicy, generateKeypair } from "../src/receipt/sign.ts";
import type { ActionRequest, AgentState, Policy } from "../src/policy/types.ts";
import {
  SEALED_REASON,
  SealedPolicyError,
  createPlaintextPolicyProvider,
  createSealedPolicyProvider,
  sealedCommitment,
} from "../src/policy/sealed.ts";
import { createStubMxe } from "../src/mxe/stub.ts";
import { SOLANA_TRANSFER_TOOL, TOKEN_PROGRAM_ID, USDC_MAINNET_MINT, toActionRequest } from "../src/solana/types.ts";

const AT = Date.UTC(2026, 6, 31, 12, 0, 0);
const VAULT = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const SALT = "1f9c4a2e6b8d0357f1a9c4e2b6d80357f1a9c4e2b6d80357f1a9c4e2b6d80357";
const CIRCUIT = "genkai.policy.v1";

const policy: Policy = {
  policyId: "desk-alpha",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  allowedClusters: ["mainnet-beta"],
  allowedPrograms: [TOKEN_PROGRAM_ID],
  allowedMints: [USDC_MAINNET_MINT],
  maxAmountPerMint: { [USDC_MAINNET_MINT]: 50_000_000_000n },
  maxAmountPerAction: 50_000_000_000n,
  escalateAboveAmount: 25_000_000_000n,
};

const state: AgentState = {
  spentInWindow: 0n,
  windowStartedAt: AT,
  callsInWindow: 0,
  drawdownFromPeak: 0n,
  revoked: false,
};

const req = (amount: bigint): ActionRequest =>
  toActionRequest(
    {
      kind: "spl",
      programId: TOKEN_PROGRAM_ID,
      cluster: "mainnet-beta",
      from: VAULT,
      to: VENDOR,
      mint: USDC_MAINNET_MINT,
      decimals: 6,
      amount,
      requestedAt: AT,
    },
    "agent-1",
  );

function sealedSetup(over: { salt?: string; circuitId?: string } = {}) {
  const clusterKeys = generateKeypair();
  const salt = over.salt ?? SALT;
  const circuitId = over.circuitId ?? CIRCUIT;
  const mxe = createStubMxe({ policy, salt, circuitId, keys: clusterKeys });
  const provider = createSealedPolicyProvider({
    commitment: sealedCommitment(policy, salt),
    circuitId,
    clusterPublicKey: mxe.clusterPublicKey,
    mxe,
  });
  return { provider, mxe, clusterKeys, salt, circuitId };
}

test("the plaintext provider is exactly today's behaviour", async () => {
  const provider = createPlaintextPolicyProvider(policy);
  const result = await provider.decide(req(1_000_000n), state, AT);

  assert.equal(provider.mode, "plaintext");
  assert.equal(provider.commitment, hashPolicy(policy));
  assert.deepEqual(result.decision, evaluate(policy, req(1_000_000n), state, AT));
  assert.deepEqual(provider.disclose(), policy);
  assert.equal(result.attestation, undefined);
});

test("a sealed commitment must be salted, or the policy is brute-forceable", () => {
  // Risk limits are low-entropy: round numbers, a handful of known mints. An unsalted hash of
  // the policy is a commitment an adversary can simply guess their way through. So the sealed
  // commitment must not equal hashPolicy, and must change with the salt.
  const other = "0000000000000000000000000000000000000000000000000000000000000001";
  assert.notEqual(sealedCommitment(policy, SALT), hashPolicy(policy));
  assert.notEqual(sealedCommitment(policy, SALT), sealedCommitment(policy, other));
  assert.equal(sealedCommitment(policy, SALT), sealedCommitment(policy, SALT));
});

test("a sealed provider reaches the same verdict as a plaintext one", async () => {
  const { provider } = sealedSetup();

  for (const amount of [1_000_000n, 30_000_000_000n, 90_000_000_000n]) {
    const sealedResult = await provider.decide(req(amount), state, AT);
    const plain = evaluate(policy, req(amount), state, AT);
    assert.equal(sealedResult.decision.verdict, plain.verdict, `amount ${amount}`);
    assert.deepEqual(
      sealedResult.decision.reasons.map((r) => r.rule),
      plain.reasons.map((r) => r.rule),
      `amount ${amount}`,
    );
  }
});

test("a sealed decision reveals no limits", async () => {
  const { provider } = sealedSetup();
  // 90 SOL-scale units is over the hard cap. The plaintext reason string would read
  // "Amount 90000000000 exceeds per-action cap 50000000000" and hand the reader the limit.
  const plain = evaluate(policy, req(90_000_000_000n), state, AT);
  assert.match(plain.reasons[0]?.reason ?? "", /50000000000/);

  const result = await provider.decide(req(90_000_000_000n), state, AT);
  assert.equal(result.decision.verdict, "deny");
  for (const reason of result.decision.reasons) {
    assert.equal(reason.reason, SEALED_REASON);
  }
  const serialised = JSON.stringify(result.decision, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
  assert.doesNotMatch(serialised, /50000000000|25000000000/, "a policy threshold leaked into the decision");
});

test("a sealed provider never discloses the policy", async () => {
  const { provider } = sealedSetup();
  assert.equal(provider.mode, "sealed");
  assert.equal(provider.disclose(), undefined);
});

test("a commitment that does not match is rejected", async () => {
  // The operator points the provider at one policy and the MXE evaluates another.
  const { mxe } = sealedSetup();
  const wrong = createSealedPolicyProvider({
    commitment: sealedCommitment({ ...policy, maxAmountPerAction: 1n }, SALT),
    circuitId: CIRCUIT,
    clusterPublicKey: mxe.clusterPublicKey,
    mxe,
  });

  await assert.rejects(
    () => wrong.decide(req(1_000_000n), state, AT),
    (err: unknown) => err instanceof SealedPolicyError && err.code === "commitment_mismatch",
  );
});

test("an attestation from the wrong circuit is rejected", async () => {
  const { mxe } = sealedSetup({ circuitId: "attacker.circuit.v1" });
  const provider = createSealedPolicyProvider({
    commitment: sealedCommitment(policy, SALT),
    circuitId: CIRCUIT,
    clusterPublicKey: mxe.clusterPublicKey,
    mxe,
  });

  await assert.rejects(
    () => provider.decide(req(1_000_000n), state, AT),
    (err: unknown) => err instanceof SealedPolicyError && err.code === "circuit_mismatch",
  );
});

test("an attestation signed by the wrong key is rejected", async () => {
  const { mxe } = sealedSetup();
  const impostor = generateKeypair();
  const provider = createSealedPolicyProvider({
    commitment: sealedCommitment(policy, SALT),
    circuitId: CIRCUIT,
    clusterPublicKey: impostor.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    mxe,
  });

  await assert.rejects(
    () => provider.decide(req(1_000_000n), state, AT),
    (err: unknown) => err instanceof SealedPolicyError && err.code === "bad_attestation",
  );
});

test("a verdict swapped after the MXE returned it is rejected", async () => {
  // The attestation covers the verdict, so an operator sitting between the MXE and the
  // receipt writer cannot flip deny to allow.
  const { mxe, provider } = sealedSetup();
  const tampered = {
    ...mxe,
    evaluate: async (input: Parameters<typeof mxe.evaluate>[0]) => {
      const out = await mxe.evaluate(input);
      return { ...out, verdict: "allow" as const, ruleIds: ["all_checks_passed"] };
    },
  };
  const viaTampered = createSealedPolicyProvider({
    commitment: provider.commitment,
    circuitId: CIRCUIT,
    clusterPublicKey: mxe.clusterPublicKey,
    mxe: tampered,
  });

  await assert.rejects(
    () => viaTampered.decide(req(90_000_000_000n), state, AT),
    (err: unknown) => err instanceof SealedPolicyError && err.code === "bad_attestation",
  );
});

test("escalation still never masks a denial under seal", async () => {
  const { provider } = sealedSetup();
  // Over the escalation threshold and over the hard cap.
  const result = await provider.decide(req(90_000_000_000n), state, AT);
  assert.equal(result.decision.verdict, "deny");
});
