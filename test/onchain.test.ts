/**
 * Checking a sealed receipt against the decision the Arcium cluster recorded on chain.
 *
 * The GENKAI program writes a DecisionRecord only from a callback whose output the cluster
 * signed (verify_output), alongside the exact request fields the circuit evaluated, pointing at
 * a PolicyRecord that fixes the policy commitment. A verifier with nothing but RPC access can
 * therefore confirm a receipt's verdict came from the cluster, for that request, against that
 * policy - without the Arcium SDK and without the policy.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { generateKeypair, signReceipt } from "../src/receipt/sign.ts";
import { evaluate } from "../src/policy/engine.ts";
import { encodeRequest } from "../src/mxe/encoding.ts";
import { SEALED_REASON, sealedCommitment } from "../src/policy/sealed.ts";
import {
  DECISION_RECORD_SIZE,
  decisionRecordAddress,
  decodeDecisionRecord,
  decodePolicyRecord,
  encodeRequestFields,
  policyRecordAddress,
  verifyOnChainDecision,
} from "../src/mxe/onchain.ts";
import { DEMO_POLICY } from "../src/cli/demo.ts";
import { SYSTEM_PROGRAM_ID, toActionRequest } from "../src/solana/types.ts";
import type { AgentState } from "../src/policy/types.ts";
import type { ReceiptBody } from "../src/receipt/types.ts";
import type { MxeAttestation } from "../src/mxe/types.ts";
import { PROGRAM, decisionRecordBytes, fakeChain, policyIdBytes, policyRecordBytes, type FakeAccount } from "./helpers/chain.ts";

const AUTHORITY = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj";
const SALT = "ab".repeat(32);
const AT = Date.UTC(2026, 9, 1, 12, 0, 0);
const OFFSET = 4242n;

const state: AgentState = { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
const request = (lamports: bigint) =>
  toActionRequest(
    { kind: "sol", programId: SYSTEM_PROGRAM_ID, cluster: "devnet", from: AUTHORITY, to: "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE", decimals: 9, amount: lamports, requestedAt: AT },
    "desk-bot",
  );

const POLICY = policyRecordAddress(PROGRAM, AUTHORITY, policyIdBytes(DEMO_POLICY.policyId));
const DECISION = decisionRecordAddress(PROGRAM, POLICY, OFFSET);
const commitment = sealedCommitment(DEMO_POLICY, SALT);

const policyAccount = (c = commitment, status = 1): FakeAccount => ({
  data: policyRecordBytes({ authority: AUTHORITY, policyId: DEMO_POLICY.policyId, commitment: c, status }),
});

const decisionAccount = (lamports: bigint, over: Partial<Parameters<typeof decisionRecordBytes>[0]> = {}): FakeAccount => ({
  data: decisionRecordBytes({ policy: POLICY, offset: OFFSET, sealedPolicy: DEMO_POLICY, request: request(lamports), state, ...over }),
});

function sealedReceipt(lamports: bigint, opts: { verdictOnly?: boolean } = {}) {
  const decision = evaluate(DEMO_POLICY, request(lamports), state, AT);
  const attestation: MxeAttestation = {
    kind: "onchain",
    circuitId: "genkai.policy.v2",
    programId: PROGRAM,
    policy: POLICY,
    decision: DECISION,
    computationOffset: OFFSET,
    queueSignature: "1".repeat(64),
    disclosure: opts.verdictOnly ? "verdict" : undefined,
  };
  const body: ReceiptBody = {
    receiptId: "r1",
    schemaVersion: 1,
    policyHash: commitment,
    request: request(lamports),
    state,
    decision: {
      ...decision,
      reasons: opts.verdictOnly ? [] : decision.reasons.map((r) => ({ ...r, reason: SEALED_REASON })),
      policyId: "genkai.policy.v2",
      policyVersion: 0,
    },
    attestation,
    previousReceiptHash: null,
  };
  return signReceipt(body, generateKeypair());
}

const check = (receipt: ReturnType<typeof sealedReceipt>, accounts: Record<string, FakeAccount>, pin: { policy?: string; computationOffset?: bigint } = {}) =>
  verifyOnChainDecision(receipt, { rpc: fakeChain(accounts).rpc, programId: PROGRAM, decision: DECISION, ...pin });

test("a decision record decodes to exactly the layout the program declares", () => {
  const bytes = decisionAccount(10_000_000n).data;
  assert.equal(bytes.length, DECISION_RECORD_SIZE);
  const d = decodeDecisionRecord(bytes);
  assert.equal(d.policy, POLICY);
  assert.equal(d.computationOffset, OFFSET);
  assert.equal(d.status, 1);
  assert.equal(d.verdict, 0);
  assert.equal(d.discloseRules, true);
  assert.deepEqual(d.requestFields, encodeRequestFields(encodeRequest(request(10_000_000n), state)));
  assert.equal(decodeDecisionRecord(decisionAccount(10_000_000n, { discloseRules: false }).data).discloseRules, false);
  assert.throws(() => decodeDecisionRecord(policyAccount().data), /discriminator/);
});

test("a policy record exposes its commitment and status, never its plaintext", () => {
  const p = decodePolicyRecord(policyAccount().data);
  assert.equal(p.authority, AUTHORITY);
  assert.equal(p.commitment, commitment);
  assert.equal(p.status, "active");
  assert.equal(p.stagedCount, 87);
});

test("a sealed receipt matching the on-chain decision verifies", async () => {
  for (const lamports of [10_000_000n, 30_000_000n, 200_000_000n]) {
    const result = await check(sealedReceipt(lamports), { [POLICY]: policyAccount(), [DECISION]: decisionAccount(lamports) }, { policy: POLICY, computationOffset: OFFSET });
    assert.equal(result.valid, true, `${lamports}: ${result.detail.join("; ")}`);
    assert.equal(result.decidedSlot, 105n);
  }
});

test("a verdict-only receipt verifies against a record whose mask was withheld by the circuit", async () => {
  const accounts = { [POLICY]: policyAccount(), [DECISION]: decisionAccount(200_000_000n, { discloseRules: false }) };
  const result = await check(sealedReceipt(200_000_000n, { verdictOnly: true }), accounts);
  assert.equal(result.valid, true, result.detail.join("; "));
});

test("every way the chain and the receipt can disagree is caught", async () => {
  const ok = policyAccount();
  const cases: [string, Record<string, FakeAccount>, string, { lamports?: bigint; verdictOnly?: boolean; pin?: { policy?: string; computationOffset?: bigint } }?][] = [
    ["verdict differs", { [POLICY]: ok, [DECISION]: decisionAccount(10_000_000n, { verdict: 1, mask: 1 }) }, "verdict_mismatch"],
    ["rule mask differs", { [POLICY]: ok, [DECISION]: decisionAccount(200_000_000n, { mask: 1 << 14 }) }, "verdict_mismatch", { lamports: 200_000_000n }],
    ["different request evaluated", { [POLICY]: ok, [DECISION]: decisionAccount(10_000_000n, { fieldsFor: request(11_000_000n) }) }, "request_mismatch"],
    ["still pending", { [POLICY]: ok, [DECISION]: decisionAccount(10_000_000n, { status: 0 }) }, "not_decided"],
    ["another policy's commitment", { [POLICY]: policyAccount("cd".repeat(32)), [DECISION]: decisionAccount(10_000_000n) }, "commitment_mismatch"],
    ["account forged by another program", { [POLICY]: ok, [DECISION]: { ...decisionAccount(10_000_000n), owner: SYSTEM_PROGRAM_ID } }, "wrong_owner"],
    ["no such decision", { [POLICY]: ok }, "not_found"],
    // A copycat registers its own PolicyRecord under the same public commitment, with a
    // permissive policy behind it. Only pinning the record's address catches that.
    ["decided against an unpinned policy record", { [POLICY]: ok, [DECISION]: decisionAccount(10_000_000n) }, "policy_mismatch", { pin: { policy: "GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW" } }],
    ["a different computation", { [POLICY]: ok, [DECISION]: decisionAccount(10_000_000n) }, "computation_mismatch", { pin: { computationOffset: OFFSET + 1n } }],
    ["rules claimed, circuit withheld them", { [POLICY]: ok, [DECISION]: decisionAccount(200_000_000n, { discloseRules: false }) }, "disclosure_mismatch", { lamports: 200_000_000n }],
    ["verdict only claimed, circuit disclosed rules", { [POLICY]: ok, [DECISION]: decisionAccount(200_000_000n) }, "disclosure_mismatch", { lamports: 200_000_000n, verdictOnly: true }],
  ];
  for (const [label, accounts, failure, opts = {}] of cases) {
    const result = await check(sealedReceipt(opts.lamports ?? 10_000_000n, { verdictOnly: opts.verdictOnly }), accounts, opts.pin);
    assert.equal(result.valid, false, label);
    assert.ok(result.failures.includes(failure as never), `${label}: ${result.failures.join(",")}`);
  }
});

test("addresses derive from the program's seeds", () => {
  const id = policyIdBytes(DEMO_POLICY.policyId);
  assert.notEqual(policyRecordAddress(PROGRAM, AUTHORITY, id), policyRecordAddress(PROGRAM, "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE", id));
  assert.notEqual(decisionRecordAddress(PROGRAM, POLICY, 1n), decisionRecordAddress(PROGRAM, POLICY, 2n));
});
