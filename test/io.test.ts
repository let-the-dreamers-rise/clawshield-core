/**
 * Receipts and policies on the wire.
 *
 * A verifier reads receipts from strangers, so parsing is a security boundary: every field is
 * checked for type and shape, unknown keys are refused rather than dropped, and bigints survive
 * the round trip exactly. A parser that quietly coerced "100" into 100n, or dropped a field the
 * signature covers, would make verification answer a question nobody asked.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { fromJson, toJson } from "../src/io/json.ts";
import { canonicalise } from "../src/receipt/canonical.ts";
import { SchemaError, parsePolicy, parseSealedTrust, parseSignedReceipt } from "../src/io/schema.ts";
import { generateKeypair } from "../src/receipt/sign.ts";
import { verifyReceipt } from "../src/receipt/verify.ts";
import { createPlaintextPolicyProvider } from "../src/policy/sealed.ts";
import { createSolanaAdapter } from "../src/solana/adapter.ts";
import { solanaAddress } from "../src/solana/keys.ts";
import { NATIVE_SOL_MINT, SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID } from "../src/solana/types.ts";
import type { Policy } from "../src/policy/types.ts";

const AT = Date.UTC(2026, 8, 2, 10, 0, 0);
const KEYS = generateKeypair();
const VAULT = solanaAddress(KEYS.publicKey);
const policy: Policy = {
  policyId: "ops",
  version: 2,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  allowedClusters: ["devnet"],
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  allowedMints: [NATIVE_SOL_MINT],
  maxAmountPerMint: { [NATIVE_SOL_MINT]: 2_000_000_000n },
  escalateAboveAmount: 1_000_000_000n,
  allowedHoursUtc: [0, 1440],
};

async function sampleReceipt() {
  const adapter = createSolanaAdapter({ agentId: "bot", keys: KEYS, provider: createPlaintextPolicyProvider(policy) });
  const { receipt } = await adapter.submit({
    transfer: {
      kind: "sol",
      programId: SYSTEM_PROGRAM_ID,
      cluster: "devnet",
      from: VAULT,
      to: "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE",
      decimals: 9,
      amount: 5_000n,
      requestedAt: AT,
    },
    state: { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false },
    decidedAt: AT,
    recentBlockhash: "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N",
    fees: { computeUnitPrice: 10n },
  });
  return receipt;
}

test("bigints survive the round trip and stay distinct from strings", () => {
  const value = { a: 1n, b: "1", c: [2n, { d: (1n << 70n) + 3n }] };
  const back = fromJson(toJson(value)) as typeof value;
  assert.deepEqual(back, value);
  assert.equal(typeof back.b, "string");
});

test("a bigint tag must be exactly a decimal integer", () => {
  for (const bad of ['{"$bigint":"1.5"}', '{"$bigint":"0x10"}', '{"$bigint":""}', '{"$bigint":"1","x":1}', '{"$bigint":1}']) {
    assert.throws(() => fromJson(bad), SyntaxError, bad);
  }
  assert.equal(fromJson('{"$bigint":"-42"}'), -42n);
});

test("a receipt round-trips through JSON and still verifies", async () => {
  const receipt = await sampleReceipt();
  const parsed = parseSignedReceipt(fromJson(toJson(receipt as never)));
  // Compared by canonical bytes: the parser drops undefined-valued keys, as canonical form does.
  assert.equal(canonicalise(parsed as never), canonicalise(receipt as never));
  assert.equal(verifyReceipt(parsed, policy).valid, true);
});

test("an object that impersonates a bigint tag is refused, so one signature cannot mean two values", () => {
  // Canonical form writes 5n as {"$bigint":"5"}. If a params object could carry that literal
  // shape, the bigint and the object would canonicalise to identical bytes.
  assert.throws(() => canonicalise({ params: { $bigint: "5" } } as never), TypeError);
  assert.throws(() => toJson({ x: { $bigint: "5" } } as never), TypeError);
});

test("a policy round-trips through JSON", () => {
  assert.deepEqual(parsePolicy(fromJson(toJson(policy as never))), policy);
});

test("malformed receipts are refused with the path of the problem", async () => {
  const good = JSON.parse(toJson((await sampleReceipt()) as never)) as Record<string, any>;
  const cases: [string, (r: Record<string, any>) => void][] = [
    ["body.request.amount", (r) => (r.body.request.amount = "5000")],
    ["body.decision.verdict", (r) => (r.body.decision.verdict = "maybe")],
    ["body.injected", (r) => (r.body.injected = true)],
    ["algorithm", (r) => (r.algorithm = "rsa")],
    ["body.previousReceiptHash", (r) => delete r.body.previousReceiptHash],
    ["body.state.callsInWindow", (r) => (r.body.state.callsInWindow = -1)],
    ["body.transaction.computeUnitPrice", (r) => (r.body.transaction.computeUnitPrice = 10)],
  ];
  for (const [path, mutate] of cases) {
    const copy = JSON.parse(JSON.stringify(good)) as Record<string, any>;
    mutate(copy);
    assert.throws(
      () => parseSignedReceipt(fromJson(JSON.stringify(copy))),
      (err: unknown) => err instanceof SchemaError && err.path === path,
      path,
    );
  }
});

test("malformed policies are refused", () => {
  for (const bad of [
    { ...policy, allowedTools: "all" },
    { ...policy, maxAmountPerMint: { [NATIVE_SOL_MINT]: 5 } },
    { ...policy, allowedHoursUtc: [1, 2, 3] },
    { ...policy, version: "2" },
    { ...policy, surprise: 1 },
  ]) {
    assert.throws(() => parsePolicy(fromJson(toJson(bad as never))), SchemaError);
  }
});

test("sealed trust needs all three pins", () => {
  const trust = { commitment: "ab".repeat(32), circuitId: "genkai.policy.v1", clusterPublicKey: "MCowBQYDK2VwAyEA" };
  assert.deepEqual(parseSealedTrust(trust), trust);
  assert.throws(() => parseSealedTrust({ ...trust, commitment: "xyz" }), SchemaError);
  assert.throws(() => parseSealedTrust({ circuitId: "c", clusterPublicKey: "k" }), SchemaError);
});
