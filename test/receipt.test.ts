import { strict as assert } from "node:assert";
import { test } from "node:test";
import { evaluate } from "../src/policy/engine.ts";
import { generateKeypair, hashPolicy, hashReceiptBody, signReceipt } from "../src/receipt/sign.ts";
import { verifyChain, verifyReceipt } from "../src/receipt/verify.ts";
import { canonicalise } from "../src/receipt/canonical.ts";
import type { ActionRequest, AgentState, Policy } from "../src/policy/types.ts";
import type { ReceiptBody } from "../src/receipt/types.ts";

const AT = Date.UTC(2026, 6, 31, 12, 0, 0);

const policy: Policy = {
  policyId: "treasury-v1",
  version: 1,
  allowedTools: ["transfer_usdc"],
  counterpartyAllowlist: ["0xVendorA"],
  maxAmountPerAction: 100_000_000n,
  maxAmountPerWindow: 500_000_000n,
  maxCallsPerWindow: 10,
  escalateAboveAmount: 50_000_000n,
};

const freshState: AgentState = {
  spentInWindow: 0n,
  windowStartedAt: AT,
  callsInWindow: 0,
  drawdownFromPeak: 0n,
  revoked: false,
};

const request = (over: Partial<ActionRequest> = {}): ActionRequest => ({
  agentId: "agent-1",
  tool: "transfer_usdc",
  counterparty: "0xVendorA",
  amount: 10_000_000n,
  asset: "USDC",
  chainId: 8453,
  requestedAt: AT,
  params: {},
  ...over,
});

function makeReceipt(req: ActionRequest, state: AgentState, previous: string | null = null): ReceiptBody {
  const decision = evaluate(policy, req, state, AT);
  return {
    receiptId: `r-${req.amount ?? 0}-${previous ?? "root"}`,
    schemaVersion: 1,
    policyHash: hashPolicy(policy),
    request: req,
    state,
    decision,
    previousReceiptHash: previous,
  };
}

test("canonicalisation is order-independent and bigint-safe", () => {
  assert.equal(canonicalise({ b: 1, a: 2 }), canonicalise({ a: 2, b: 1 }));
  // A bigint and its decimal string must never produce identical bytes.
  assert.notEqual(canonicalise({ v: 1n }), canonicalise({ v: "1" }));
  assert.equal(canonicalise({ a: undefined, b: 1 }), canonicalise({ b: 1 }));
});

test("a well-formed receipt verifies", () => {
  const keys = generateKeypair();
  const signed = signReceipt(makeReceipt(request(), freshState), keys);
  const result = verifyReceipt(signed, policy);
  assert.equal(result.valid, true, result.detail.join("; "));
});

test("tampering with the recorded verdict is caught", () => {
  const keys = generateKeypair();
  const body = makeReceipt(request({ amount: 200_000_000n }), freshState);
  assert.equal(body.decision.verdict, "deny");

  // Operator rewrites the verdict to "allow" and re-signs with their own key.
  const forged = signReceipt(
    { ...body, decision: { ...body.decision, verdict: "allow" } },
    keys,
  );

  const result = verifyReceipt(forged, policy);
  assert.equal(result.valid, false);
  assert.ok(result.failures.includes("decision_not_reproducible"));
});

test("swapping the policy after the fact is caught", () => {
  // The core adversarial case. The operator enforced a strict policy, then presents a
  // permissive one to an auditor to justify an action that policy would not have allowed.
  const keys = generateKeypair();
  const signed = signReceipt(makeReceipt(request(), freshState), keys);

  const permissive: Policy = { ...policy, maxAmountPerAction: 10_000_000_000n, version: 2 };
  const result = verifyReceipt(signed, permissive);

  assert.equal(result.valid, false);
  assert.ok(result.failures.includes("policy_hash_mismatch"));
});

test("editing the body after signing breaks the signature", () => {
  const keys = generateKeypair();
  const signed = signReceipt(makeReceipt(request(), freshState), keys);
  const mutated = {
    ...signed,
    body: { ...signed.body, request: { ...signed.body.request, amount: 99_000_000n } },
  };

  const result = verifyReceipt(mutated, policy);
  assert.equal(result.valid, false);
  assert.ok(result.failures.includes("bad_signature"));
});

test("a receipt chain verifies and detects a deleted link", () => {
  const keys = generateKeypair();

  const first = makeReceipt(request({ amount: 1_000_000n }), freshState, null);
  const signedFirst = signReceipt(first, keys);

  const secondState: AgentState = { ...freshState, spentInWindow: 1_000_000n, callsInWindow: 1 };
  const second = makeReceipt(request({ amount: 2_000_000n }), secondState, hashReceiptBody(first));
  const signedSecond = signReceipt(second, keys);

  const policyFor = (hash: string) => (hash === hashPolicy(policy) ? policy : undefined);

  const intact = verifyChain([signedFirst, signedSecond], policyFor);
  assert.equal(intact.valid, true, intact.detail.join("; "));

  // Removing the first receipt must break the chain rather than pass silently.
  const gapped = verifyChain([signedSecond], policyFor);
  assert.equal(gapped.valid, false);
  assert.ok(gapped.failures.includes("chain_broken"));
});

test("escalation never masks a denial", () => {
  // Above the escalation threshold AND above the hard cap. Must deny, not ask a human.
  const decision = evaluate(policy, request({ amount: 400_000_000n }), freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "amount_exceeds_per_action"));
});

test("revocation overrides everything", () => {
  const decision = evaluate(policy, request({ amount: 1n }), { ...freshState, revoked: true }, AT);
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.reasons[0]?.rule, "revoked");
});

test("unknown tools are denied by default", () => {
  const decision = evaluate(policy, request({ tool: "drain_wallet" }), freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "tool_not_allowed"));
});
