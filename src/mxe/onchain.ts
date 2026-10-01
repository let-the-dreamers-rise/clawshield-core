/**
 * Reading GENKAI's on-chain records, with no Arcium SDK and no policy.
 *
 * The program in arcium/genkai writes a DecisionRecord only from a callback whose output the
 * MPC cluster signed, and only verify_output's success lets the callback run. The record holds
 * the request fields the circuit evaluated and points at a PolicyRecord whose commitment is
 * immutable once active. So a verifier with RPC access alone can confirm that a sealed receipt's
 * verdict is the cluster's verdict, for that request, against that committed policy.
 *
 * Layouts here mirror programs/genkai/src/lib.rs. Anchor accounts begin with an 8-byte
 * discriminator, the first 8 bytes of sha256("account:<Name>"), which is checked so an account
 * of another type can never be read as one of these.
 */

import { createHash } from "node:crypto";
import { decodePubkey, encodeBase58 } from "../solana/base58.ts";
import { findProgramAddress } from "../solana/pda.ts";
import type { RpcClient } from "../solana/rpc.ts";
import type { SignedReceipt } from "../receipt/types.ts";
import { encodeRequest, type EncodedRequest } from "./encoding.ts";
import { ruleIdsOf, VERDICT_CODE } from "./circuit.ts";

/** 5 x u128, 4 x u64, 1 x u16, 1 x u8, 6 x bool. */
export const REQUEST_FIELDS_SIZE = 121;
export const DECISION_RECORD_SIZE = 8 + 32 + 8 + REQUEST_FIELDS_SIZE + 1 + 1 + 4 + 8 + 8 + 1;
const POLICY_FIELDS = 87;
export const POLICY_RECORD_SIZE = 8 + 32 + 32 + 32 + 32 + 16 + 3 + 5 + POLICY_FIELDS * 32;

const POLICY_STATUS = ["staging", "active", "revoked"] as const;
export type PolicyStatus = (typeof POLICY_STATUS)[number];

const discriminator = (name: string): Buffer => createHash("sha256").update(`account:${name}`).digest().subarray(0, 8);

function checkDiscriminator(data: Uint8Array, name: string, size: number): Buffer {
  const buf = Buffer.from(data);
  if (buf.length < size) throw new Error(`${name} account is ${buf.length} bytes, expected ${size}`);
  if (!buf.subarray(0, 8).equals(discriminator(name))) throw new Error(`Account discriminator is not ${name}`);
  return buf;
}

const le = (value: bigint, bytes: number): Buffer => {
  const out = Buffer.alloc(bytes);
  let v = value;
  for (let i = 0; i < bytes; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};

const readLe = (buf: Buffer, offset: number, bytes: number): bigint => {
  let v = 0n;
  for (let i = bytes - 1; i >= 0; i--) v = (v << 8n) | BigInt(buf[offset + i] ?? 0);
  return v;
};

const flag = (b: boolean): Buffer => Buffer.from([b ? 1 : 0]);

/** Borsh encoding of the program's RequestFields struct, in declaration order. */
export function encodeRequestFields(r: EncodedRequest): Uint8Array {
  const out = Buffer.concat([
    le(r.toolId, 16),
    flag(r.hasCounterparty),
    le(r.counterpartyId, 16),
    flag(r.hasAmount),
    flag(r.amountNegative),
    le(r.amountMagnitude, 8),
    flag(r.isSolana),
    flag(r.solanaValid),
    le(r.clusterId, 16),
    le(r.programId, 16),
    le(r.mintId, 16),
    le(BigInt(r.minuteOfDay), 2),
    Buffer.from([r.dayOfWeek]),
    flag(r.revoked),
    le(r.spentInWindow, 8),
    le(r.callsInWindow, 8),
    le(r.drawdownFromPeak, 8),
  ]);
  if (out.length !== REQUEST_FIELDS_SIZE) throw new Error("RequestFields layout drifted");
  return new Uint8Array(out);
}

export interface DecisionRecordView {
  readonly policy: string;
  readonly computationOffset: bigint;
  readonly requestFields: Uint8Array;
  readonly status: number;
  readonly verdict: number;
  readonly mask: number;
  readonly requestedSlot: bigint;
  readonly decidedSlot: bigint;
}

export function decodeDecisionRecord(data: Uint8Array): DecisionRecordView {
  const b = checkDiscriminator(data, "DecisionRecord", DECISION_RECORD_SIZE);
  let o = 8;
  const policy = encodeBase58(b.subarray(o, (o += 32)));
  const computationOffset = readLe(b, o, 8);
  o += 8;
  const requestFields = new Uint8Array(b.subarray(o, (o += REQUEST_FIELDS_SIZE)));
  const status = b[o++] ?? 0;
  const verdict = b[o++] ?? 0;
  const mask = b.readUInt32LE(o);
  o += 4;
  const requestedSlot = readLe(b, o, 8);
  const decidedSlot = readLe(b, o + 8, 8);
  return { policy, computationOffset, requestFields, status, verdict, mask, requestedSlot, decidedSlot };
}

export interface PolicyRecordView {
  readonly authority: string;
  readonly policyId: Uint8Array;
  readonly commitment: string;
  readonly status: PolicyStatus | "unknown";
  readonly stagedCount: number;
}

export function decodePolicyRecord(data: Uint8Array): PolicyRecordView {
  const b = checkDiscriminator(data, "PolicyRecord", POLICY_RECORD_SIZE);
  const status = b[152] ?? 255;
  return {
    authority: encodeBase58(b.subarray(8, 40)),
    policyId: new Uint8Array(b.subarray(40, 72)),
    commitment: b.subarray(72, 104).toString("hex"),
    status: POLICY_STATUS[status] ?? "unknown",
    stagedCount: b[154] ?? 0,
  };
}

export function policyRecordAddress(programId: string, authority: string, policyId: Uint8Array): string {
  if (policyId.length !== 32) throw new RangeError("A policy id is 32 bytes");
  return findProgramAddress([Buffer.from("policy"), decodePubkey(authority), policyId], programId).address;
}

export function decisionRecordAddress(programId: string, policy: string, computationOffset: bigint): string {
  return findProgramAddress([Buffer.from("decision"), decodePubkey(policy), le(computationOffset, 8)], programId).address;
}

export type OnChainFailure =
  | "not_found"
  | "wrong_owner"
  | "malformed"
  | "not_decided"
  | "commitment_mismatch"
  | "request_mismatch"
  | "verdict_mismatch";

export interface OnChainCheck {
  readonly valid: boolean;
  readonly failures: readonly OnChainFailure[];
  readonly detail: readonly string[];
  readonly decidedSlot?: bigint;
}

export interface OnChainCheckOptions {
  readonly rpc: RpcClient;
  /** The GENKAI program id, pinned by the verifier, never read from the receipt. */
  readonly programId: string;
  readonly decision: string;
}

async function load(rpc: RpcClient, address: string, programId: string) {
  const account = await rpc.getAccountInfo(address);
  if (!account) return { failure: ["not_found", `No account at ${address}`] as const };
  if (account.owner !== programId) return { failure: ["wrong_owner", `${address} is owned by ${account.owner}, not ${programId}`] as const };
  return { data: account.data };
}

/**
 * Confirm a sealed receipt against the decision the cluster recorded on chain. Pair with
 * verifySealedReceipt, which checks the operator's signature, chain and bound transaction.
 */
export async function verifyOnChainDecision(receipt: SignedReceipt, options: OnChainCheckOptions): Promise<OnChainCheck> {
  const fail = (failure: OnChainFailure, detail: string): OnChainCheck => ({ valid: false, failures: [failure], detail: [detail] });

  const decisionAccount = await load(options.rpc, options.decision, options.programId);
  if (decisionAccount.failure) return fail(decisionAccount.failure[0], decisionAccount.failure[1]);
  let decision: DecisionRecordView;
  try {
    decision = decodeDecisionRecord(decisionAccount.data);
  } catch (err) {
    return fail("malformed", (err as Error).message);
  }
  if (decision.status !== 1) return fail("not_decided", "The cluster has not recorded a verdict for this decision");

  const policyAccount = await load(options.rpc, decision.policy, options.programId);
  if (policyAccount.failure) return fail(policyAccount.failure[0], policyAccount.failure[1]);
  let policy: PolicyRecordView;
  try {
    policy = decodePolicyRecord(policyAccount.data);
  } catch (err) {
    return fail("malformed", (err as Error).message);
  }

  const findings: [OnChainFailure, string][] = [];
  const body = receipt.body;
  if (policy.commitment !== body.policyHash) {
    findings.push(["commitment_mismatch", `On-chain policy commits to ${policy.commitment}; the receipt binds ${body.policyHash}`]);
  }

  let expectedFields: Uint8Array | undefined;
  try {
    expectedFields = encodeRequestFields(encodeRequest(body.request, body.state));
  } catch (err) {
    findings.push(["request_mismatch", `The receipt's request cannot be encoded: ${(err as Error).message}`]);
  }
  if (expectedFields && !Buffer.from(expectedFields).equals(Buffer.from(decision.requestFields))) {
    findings.push(["request_mismatch", "The cluster evaluated different request fields than the receipt records"]);
  }

  const verdictCode = VERDICT_CODE[body.decision.verdict];
  const onChainRules = ruleIdsOf({ verdict: decision.verdict as 0 | 1 | 2, mask: decision.mask });
  const receiptRules = body.decision.reasons.map((r) => r.rule);
  // Verdict-only receipts carry no rule ids; there is nothing to compare beyond the verdict.
  const rulesAgree = receiptRules.length === 0 || receiptRules.join(",") === onChainRules.join(",");
  if (decision.verdict !== verdictCode || !rulesAgree) {
    findings.push(["verdict_mismatch", `On chain: verdict ${decision.verdict} [${onChainRules.join(", ")}]; receipt: ${body.decision.verdict} [${receiptRules.join(", ")}]`]);
  }

  return {
    valid: findings.length === 0,
    failures: findings.map(([f]) => f),
    detail: findings.map(([, d]) => d),
    decidedSlot: decision.decidedSlot,
  };
}
