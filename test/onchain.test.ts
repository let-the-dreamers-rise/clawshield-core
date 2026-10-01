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
import { createHash } from "node:crypto";
import { test } from "node:test";
import { generateKeypair, signReceipt } from "../src/receipt/sign.ts";
import { evaluate } from "../src/policy/engine.ts";
import { encodePolicy, encodeRequest } from "../src/mxe/encoding.ts";
import { evaluateCircuit } from "../src/mxe/circuit.ts";
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
import { decodePubkey } from "../src/solana/base58.ts";
import type { AccountInfo, RpcClient } from "../src/solana/rpc.ts";
import { DEMO_POLICY } from "../src/cli/demo.ts";
import { SYSTEM_PROGRAM_ID, toActionRequest } from "../src/solana/types.ts";
import type { AgentState } from "../src/policy/types.ts";
import type { ReceiptBody } from "../src/receipt/types.ts";

const PROGRAM = "AwiVMGyi8P9mN6ig5FA74CTS6sncc7bbh8CNAxKXUERk";
const AUTHORITY = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj";
const SALT = "ab".repeat(32);
const AT = Date.UTC(2026, 9, 1, 12, 0, 0);
const OFFSET = 4242n;

const disc = (name: string) => createHash("sha256").update(`account:${name}`).digest().subarray(0, 8);
const u64 = (x: bigint) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(x);
  return b;
};

const state: AgentState = { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
const request = (lamports: bigint) =>
  toActionRequest(
    { kind: "sol", programId: SYSTEM_PROGRAM_ID, cluster: "devnet", from: AUTHORITY, to: "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE", decimals: 9, amount: lamports, requestedAt: AT },
    "desk-bot",
  );

const policyId = Buffer.alloc(32);
Buffer.from(DEMO_POLICY.policyId).copy(policyId);
const POLICY = policyRecordAddress(PROGRAM, AUTHORITY, policyId);
const DECISION = decisionRecordAddress(PROGRAM, POLICY, OFFSET);

function policyRecordBytes(commitment: string, status = 1): Uint8Array {
  return Buffer.concat([
    disc("PolicyRecord"),
    decodePubkey(AUTHORITY),
    policyId,
    Buffer.from(commitment, "hex"),
    Buffer.alloc(32, 7),
    Buffer.alloc(16, 1),
    Buffer.from([status, 254, 87]),
    Buffer.alloc(5),
    Buffer.alloc(87 * 32, 9),
  ]);
}

function decisionRecordBytes(lamports: bigint, over: { verdict?: number; mask?: number; status?: number; fieldsFor?: bigint } = {}): Uint8Array {
  const out = evaluateCircuit(encodePolicy(DEMO_POLICY), encodeRequest(request(lamports), state));
  return Buffer.concat([
    disc("DecisionRecord"),
    decodePubkey(POLICY),
    u64(OFFSET),
    encodeRequestFields(encodeRequest(request(over.fieldsFor ?? lamports), state)),
    Buffer.from([over.status ?? 1, over.verdict ?? out.verdict]),
    Buffer.from(Uint32Array.of(over.mask ?? out.mask).buffer),
    u64(100n),
    u64(105n),
    Buffer.from([255]),
  ]);
}

function sealedReceipt(lamports: bigint, commitment = sealedCommitment(DEMO_POLICY, SALT)) {
  const decision = evaluate(DEMO_POLICY, request(lamports), state, AT);
  const body: ReceiptBody = {
    receiptId: "r1",
    schemaVersion: 1,
    policyHash: commitment,
    request: request(lamports),
    state,
    decision: { ...decision, reasons: decision.reasons.map((r) => ({ ...r, reason: SEALED_REASON })), policyId: "genkai.policy.v1", policyVersion: 0 },
    previousReceiptHash: null,
  };
  return signReceipt(body, generateKeypair());
}

function fakeRpc(accounts: Record<string, { data: Uint8Array; owner?: string }>): RpcClient {
  const none = async () => {
    throw new Error("not used");
  };
  return {
    getLatestBlockhash: none,
    getBlockHeight: none,
    sendTransaction: none,
    getSignatureStatuses: none,
    getTransaction: none,
    getAccountInfo: async (address: string): Promise<AccountInfo | null> => {
      const a = accounts[address];
      return a ? { owner: a.owner ?? PROGRAM, lamports: 1n, data: a.data, executable: false } : null;
    },
  };
}

const commitment = sealedCommitment(DEMO_POLICY, SALT);

test("a decision record decodes to exactly the layout the program declares", () => {
  const bytes = decisionRecordBytes(10_000_000n);
  assert.equal(bytes.length, DECISION_RECORD_SIZE);
  const d = decodeDecisionRecord(bytes);
  assert.equal(d.policy, POLICY);
  assert.equal(d.computationOffset, OFFSET);
  assert.equal(d.status, 1);
  assert.equal(d.verdict, 0);
  assert.deepEqual(d.requestFields, encodeRequestFields(encodeRequest(request(10_000_000n), state)));
  assert.throws(() => decodeDecisionRecord(policyRecordBytes(commitment)), /discriminator/);
});

test("a policy record exposes its commitment and status, never its plaintext", () => {
  const p = decodePolicyRecord(policyRecordBytes(commitment));
  assert.equal(p.authority, AUTHORITY);
  assert.equal(p.commitment, commitment);
  assert.equal(p.status, "active");
  assert.equal(p.stagedCount, 87);
});

test("a sealed receipt matching the on-chain decision verifies", async () => {
  for (const lamports of [10_000_000n, 30_000_000n, 200_000_000n]) {
    const rpc = fakeRpc({ [POLICY]: { data: policyRecordBytes(commitment) }, [DECISION]: { data: decisionRecordBytes(lamports) } });
    const result = await verifyOnChainDecision(sealedReceipt(lamports), { rpc, programId: PROGRAM, decision: DECISION });
    assert.equal(result.valid, true, `${lamports}: ${result.detail.join("; ")}`);
  }
});

test("every way the chain and the receipt can disagree is caught", async () => {
  const cases: [string, Record<string, { data: Uint8Array; owner?: string }>, string, ReturnType<typeof sealedReceipt>?][] = [
    ["verdict differs", { [POLICY]: { data: policyRecordBytes(commitment) }, [DECISION]: { data: decisionRecordBytes(10_000_000n, { verdict: 1, mask: 1 }) } }, "verdict_mismatch"],
    ["rule mask differs", { [POLICY]: { data: policyRecordBytes(commitment) }, [DECISION]: { data: decisionRecordBytes(200_000_000n, { mask: 1 << 14 }) } }, "verdict_mismatch"],
    ["different request evaluated", { [POLICY]: { data: policyRecordBytes(commitment) }, [DECISION]: { data: decisionRecordBytes(10_000_000n, { fieldsFor: 11_000_000n }) } }, "request_mismatch"],
    ["still pending", { [POLICY]: { data: policyRecordBytes(commitment) }, [DECISION]: { data: decisionRecordBytes(10_000_000n, { status: 0 }) } }, "not_decided"],
    ["another policy's commitment", { [POLICY]: { data: policyRecordBytes("cd".repeat(32)) }, [DECISION]: { data: decisionRecordBytes(10_000_000n) } }, "commitment_mismatch"],
    ["account forged by another program", { [POLICY]: { data: policyRecordBytes(commitment) }, [DECISION]: { data: decisionRecordBytes(10_000_000n), owner: SYSTEM_PROGRAM_ID } }, "wrong_owner"],
    ["no such decision", { [POLICY]: { data: policyRecordBytes(commitment) } }, "not_found"],
  ];
  for (const [label, accounts, failure] of cases) {
    const result = await verifyOnChainDecision(sealedReceipt(label === "rule mask differs" ? 200_000_000n : 10_000_000n), {
      rpc: fakeRpc(accounts),
      programId: PROGRAM,
      decision: DECISION,
    });
    assert.equal(result.valid, false, label);
    assert.ok(result.failures.includes(failure as never), `${label}: ${result.failures.join(",")}`);
  }
});

test("addresses derive from the program's seeds", () => {
  assert.notEqual(policyRecordAddress(PROGRAM, AUTHORITY, policyId), policyRecordAddress(PROGRAM, "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE", policyId));
  assert.notEqual(decisionRecordAddress(PROGRAM, POLICY, 1n), decisionRecordAddress(PROGRAM, POLICY, 2n));
});
