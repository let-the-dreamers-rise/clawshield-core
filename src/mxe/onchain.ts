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
import type { ActionRequest, AgentState, Verdict } from "../policy/types.ts";
import { encodeRequest, type EncodedRequest } from "./encoding.ts";
import { ruleIdsOf, VERDICT_CODE } from "./circuit.ts";
import type { Disclosure } from "./types.ts";

/** 5 x u128, 4 x u64, 1 x u16, 1 x u8, 6 x bool. */
export const REQUEST_FIELDS_SIZE = 121;
/** discriminator, policy, offset, request, status, verdict, mask, two slots, bump, disclose_rules. */
export const DECISION_RECORD_SIZE = 8 + 32 + 8 + REQUEST_FIELDS_SIZE + 1 + 1 + 4 + 8 + 8 + 1 + 1;
const POLICY_FIELDS = 87;
export const POLICY_RECORD_SIZE = 8 + 32 + 32 + 32 + 32 + 16 + 3 + 5 + POLICY_FIELDS * 32;

const POLICY_STATUS = ["staging", "active", "revoked"] as const;

const VERDICT_NAMES: Readonly<Record<number, Verdict>> = {
  [VERDICT_CODE.allow]: "allow",
  [VERDICT_CODE.deny]: "deny",
  [VERDICT_CODE.escalate]: "escalate",
};
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

/**
 * The inverse of encodeRequestFields: what the cluster was asked to evaluate, as recorded on
 * chain. Lets an auditor read a DecisionRecord without the receipt that produced it.
 */
export function decodeRequestFields(bytes: Uint8Array): EncodedRequest {
  if (bytes.length !== REQUEST_FIELDS_SIZE) throw new RangeError(`RequestFields is ${REQUEST_FIELDS_SIZE} bytes, got ${bytes.length}`);
  const b = Buffer.from(bytes);
  let o = 0;
  const n = (size: number): bigint => {
    const v = readLe(b, o, size);
    o += size;
    return v;
  };
  const f = (): boolean => b[o++] === 1;
  return {
    toolId: n(16),
    hasCounterparty: f(),
    counterpartyId: n(16),
    hasAmount: f(),
    amountNegative: f(),
    amountMagnitude: n(8),
    isSolana: f(),
    solanaValid: f(),
    clusterId: n(16),
    programId: n(16),
    mintId: n(16),
    minuteOfDay: Number(n(2)),
    dayOfWeek: Number(n(1)),
    revoked: f(),
    spentInWindow: n(8),
    callsInWindow: n(8),
    drawdownFromPeak: n(8),
  };
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
  /** false: the circuit was asked for the verdict alone and revealed a zero mask. */
  readonly discloseRules: boolean;
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
  const discloseRules = b[o + 17] === 1;
  return { policy, computationOffset, requestFields, status, verdict, mask, requestedSlot, decidedSlot, discloseRules };
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
  | "verdict_mismatch"
  | "policy_mismatch"
  | "computation_mismatch"
  | "disclosure_mismatch";

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
  /**
   * The PolicyRecord the decision must have been made against. Pin it whenever possible: the
   * commitment is public, so anyone can register a PolicyRecord carrying the same commitment
   * over a permissive policy, and only the record's address tells the two apart.
   */
  readonly policy?: string;
  /** The computation the decision must belong to, when the caller knows it. */
  readonly computationOffset?: bigint;
}

/** What a receipt (or an MXE answer) claims the cluster decided. */
export interface DecisionClaim {
  readonly commitment: string;
  readonly request: ActionRequest;
  readonly state: AgentState;
  readonly verdict: Verdict;
  readonly ruleIds: readonly string[];
  readonly disclosure: Disclosure;
}

export function claimOfReceipt(receipt: SignedReceipt): DecisionClaim {
  const body = receipt.body;
  return {
    commitment: body.policyHash,
    request: body.request,
    state: body.state,
    verdict: body.decision.verdict,
    ruleIds: body.decision.reasons.map((r) => r.rule),
    disclosure: body.attestation?.disclosure === "verdict" ? "verdict" : "rules",
  };
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
export function verifyOnChainDecision(receipt: SignedReceipt, options: OnChainCheckOptions): Promise<OnChainCheck> {
  return checkOnChainDecision(claimOfReceipt(receipt), options);
}

function disclosureFinding(claim: DecisionClaim, decision: DecisionRecordView): [OnChainFailure, string] | null {
  const verdictOnly = claim.disclosure === "verdict";
  if (verdictOnly === decision.discloseRules) {
    return ["disclosure_mismatch", `The cluster was asked to ${decision.discloseRules ? "disclose" : "withhold"} rules; the claim is ${claim.disclosure} mode`];
  }
  if (verdictOnly && (decision.mask !== 0 || claim.ruleIds.length > 0)) {
    return ["disclosure_mismatch", "A verdict-only decision carries rule identifiers"];
  }
  return null;
}

/** The same check as verifyOnChainDecision, for a claim that is not yet a signed receipt. */
export async function checkOnChainDecision(claim: DecisionClaim, options: OnChainCheckOptions): Promise<OnChainCheck> {
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
  if (options.policy !== undefined && decision.policy !== options.policy) {
    findings.push(["policy_mismatch", `Decided against policy record ${decision.policy}, pinned ${options.policy}`]);
  }
  if (options.computationOffset !== undefined && decision.computationOffset !== options.computationOffset) {
    findings.push(["computation_mismatch", `Record belongs to computation ${decision.computationOffset}, expected ${options.computationOffset}`]);
  }
  if (policy.commitment !== claim.commitment) {
    findings.push(["commitment_mismatch", `On-chain policy commits to ${policy.commitment}; the receipt binds ${claim.commitment}`]);
  }

  let expectedFields: Uint8Array | undefined;
  try {
    expectedFields = encodeRequestFields(encodeRequest(claim.request, claim.state));
  } catch (err) {
    findings.push(["request_mismatch", `The receipt's request cannot be encoded: ${(err as Error).message}`]);
  }
  if (expectedFields && !Buffer.from(expectedFields).equals(Buffer.from(decision.requestFields))) {
    findings.push(["request_mismatch", "The cluster evaluated different request fields than the receipt records"]);
  }

  const disclosure = disclosureFinding(claim, decision);
  if (disclosure) findings.push(disclosure);

  const verdictCode = VERDICT_CODE[claim.verdict];
  // Under verdict-only disclosure the mask is zero by construction and only the verdict is
  // compared; disclosureFinding has already required the claim to carry no rule ids.
  const onChainRules = decision.discloseRules ? ruleIdsOf({ verdict: decision.verdict as 0 | 1 | 2, mask: decision.mask }) : [];
  const rulesAgree = !decision.discloseRules || claim.ruleIds.join(",") === onChainRules.join(",");
  if (decision.verdict !== verdictCode || !rulesAgree) {
    const recorded = VERDICT_NAMES[decision.verdict] ?? `unknown verdict code ${decision.verdict}`;
    findings.push(["verdict_mismatch", `The cluster recorded ${recorded} [${onChainRules.join(", ")}]; the claim is ${claim.verdict} [${claim.ruleIds.join(", ")}]`]);
  }

  return {
    valid: findings.length === 0,
    failures: findings.map(([f]) => f),
    detail: findings.map(([, d]) => d),
    decidedSlot: decision.decidedSlot,
  };
}
