/**
 * Fixed-width encoding of a policy and a request for the MPC circuit.
 *
 * An Arcis circuit evaluates over integers in fixed-size structures. It cannot take a string,
 * a map or a list whose length varies, and its control flow cannot depend on secret data. So
 * before a policy is sealed it is translated into this form:
 *
 *   identifiers  -> 128-bit truncated SHA-256 under a domain tag (tools, mints, programs...)
 *   lists        -> fixed-capacity arrays plus an encrypted element count
 *   optional     -> an explicit presence flag, because "absent" and "zero" mean different things
 *   amounts      -> u64 range, checked here so the circuit never overflows
 *
 * The capacities are part of the confidentiality story, not just a limit. Every sealed policy
 * encrypts to the same number of field elements whatever it says, so ciphertext length reveals
 * nothing about how many mints or counterparties are allowlisted.
 *
 * Anything the circuit cannot represent is refused HERE, when the policy is sealed. Refusing
 * at decision time instead would turn an unsealable policy into an outage.
 *
 * Collision note: two identifiers that share a 128-bit truncated hash would be confused, which
 * in an allowlist means a non-listed value could pass. Finding such a pair costs about 2^64
 * hash evaluations against a chosen target set; that is the security margin, stated.
 */

import { createHash } from "node:crypto";
import type { ActionRequest, AgentState, Policy } from "../policy/types.ts";
import { isSolanaRequest, mintOf, readSolanaParams } from "../solana/types.ts";

export const CAPACITY = Object.freeze({
  tools: 8,
  counterparties: 16,
  clusters: 4,
  programs: 8,
  mints: 8,
  mintCaps: 8,
});

const U64_LIMIT = 1n << 64n;
const U32_LIMIT = 2 ** 32;
const MINUTES_PER_DAY = 1440;
const ID_DOMAIN = "genkai/id/v1\u0000";

export class EncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncodingError";
  }
}

/** A 128-bit identifier for a string, under a domain tag so it cannot collide with other uses. */
export function idOf(value: string): bigint {
  const digest = createHash("sha256").update(ID_DOMAIN + value, "utf8").digest();
  return BigInt(`0x${digest.subarray(0, 16).toString("hex")}`);
}

export interface EncodedList {
  readonly present: boolean;
  readonly count: number;
  /** Always exactly the capacity long; slots at or beyond count are zero and ignored. */
  readonly items: readonly bigint[];
}

export interface EncodedOptional {
  readonly present: boolean;
  readonly value: bigint;
}

export interface EncodedPolicy {
  readonly tools: EncodedList;
  readonly counterparties: EncodedList;
  readonly clusters: EncodedList;
  readonly programs: EncodedList;
  readonly mints: EncodedList;
  readonly mintCapKeys: EncodedList;
  readonly mintCapValues: readonly bigint[];
  readonly maxPerAction: EncodedOptional;
  readonly maxPerWindow: EncodedOptional;
  readonly maxCalls: EncodedOptional;
  readonly drawdownHalt: EncodedOptional;
  readonly escalateAbove: EncodedOptional;
  readonly hours: { readonly present: boolean; readonly start: number; readonly end: number };
  readonly days: { readonly present: boolean; readonly mask: number };
}

export interface EncodedRequest {
  readonly toolId: bigint;
  readonly hasCounterparty: boolean;
  readonly counterpartyId: bigint;
  readonly hasAmount: boolean;
  readonly amountNegative: boolean;
  readonly amountMagnitude: bigint;
  readonly isSolana: boolean;
  readonly solanaValid: boolean;
  readonly clusterId: bigint;
  readonly programId: bigint;
  readonly mintId: bigint;
  readonly minuteOfDay: number;
  readonly dayOfWeek: number;
  readonly revoked: boolean;
  readonly spentInWindow: bigint;
  readonly callsInWindow: bigint;
  readonly drawdownFromPeak: bigint;
}

function list(name: string, values: readonly string[] | undefined, capacity: number): EncodedList {
  const xs = values ?? [];
  if (xs.length > capacity) {
    throw new EncodingError(`${name} lists ${xs.length} entries; the circuit holds at most ${capacity}`);
  }
  const items = [...xs.map(idOf), ...new Array<bigint>(capacity - xs.length).fill(0n)];
  return { present: values !== undefined, count: xs.length, items };
}

function u64(name: string, value: bigint): bigint {
  if (value < 0n || value >= U64_LIMIT) {
    throw new EncodingError(`${name} ${value} is outside the circuit's u64 range`);
  }
  return value;
}

function optional(name: string, value: bigint | undefined): EncodedOptional {
  return value === undefined ? { present: false, value: 0n } : { present: true, value: u64(name, value) };
}

function encodeCalls(value: number | undefined): EncodedOptional {
  if (value === undefined) return { present: false, value: 0n };
  if (!Number.isInteger(value) || value < 0 || value >= U32_LIMIT) {
    throw new EncodingError(`maxCallsPerWindow ${value} must be a non-negative integer below 2^32`);
  }
  return { present: true, value: BigInt(value) };
}

function encodeHours(hours: readonly [number, number] | undefined): EncodedPolicy["hours"] {
  if (hours === undefined) return { present: false, start: 0, end: 0 };
  const [start, end] = hours;
  for (const m of [start, end]) {
    if (!Number.isInteger(m) || m < 0 || m > MINUTES_PER_DAY) {
      throw new EncodingError(`allowedHoursUtc bound ${m} must be an integer minute in [0, ${MINUTES_PER_DAY}]`);
    }
  }
  return { present: true, start, end };
}

/**
 * Days outside 0..6 can never equal a real UTC day, so the engine never matches them. Leaving
 * them out of the mask reproduces that exactly rather than rejecting a harmless policy.
 */
function encodeDays(days: readonly number[] | undefined): EncodedPolicy["days"] {
  if (days === undefined) return { present: false, mask: 0 };
  const mask = days.filter((d) => Number.isInteger(d) && d >= 0 && d <= 6).reduce((m, d) => m | (1 << d), 0);
  return { present: true, mask };
}

export function encodePolicy(policy: Policy): EncodedPolicy {
  const capEntries = Object.entries(policy.maxAmountPerMint ?? {});
  const mintCapKeys = list(
    "maxAmountPerMint",
    policy.maxAmountPerMint === undefined ? undefined : capEntries.map(([mint]) => mint),
    CAPACITY.mintCaps,
  );
  const capValues = capEntries.map(([mint, cap]) => u64(`maxAmountPerMint[${mint}]`, cap));

  return {
    tools: list("allowedTools", policy.allowedTools, CAPACITY.tools),
    counterparties: list("counterpartyAllowlist", policy.counterpartyAllowlist, CAPACITY.counterparties),
    clusters: list("allowedClusters", policy.allowedClusters, CAPACITY.clusters),
    programs: list("allowedPrograms", policy.allowedPrograms, CAPACITY.programs),
    mints: list("allowedMints", policy.allowedMints, CAPACITY.mints),
    mintCapKeys,
    mintCapValues: [...capValues, ...new Array<bigint>(CAPACITY.mintCaps - capValues.length).fill(0n)],
    maxPerAction: optional("maxAmountPerAction", policy.maxAmountPerAction),
    maxPerWindow: optional("maxAmountPerWindow", policy.maxAmountPerWindow),
    maxCalls: encodeCalls(policy.maxCallsPerWindow),
    drawdownHalt: optional("drawdownHaltThreshold", policy.drawdownHaltThreshold),
    escalateAbove: optional("escalateAboveAmount", policy.escalateAboveAmount),
    hours: encodeHours(policy.allowedHoursUtc),
    days: encodeDays(policy.allowedDaysUtc),
  };
}

function encodeAmount(amount: bigint | undefined): Pick<EncodedRequest, "hasAmount" | "amountNegative" | "amountMagnitude"> {
  if (amount === undefined) return { hasAmount: false, amountNegative: false, amountMagnitude: 0n };
  const negative = amount < 0n;
  return { hasAmount: true, amountNegative: negative, amountMagnitude: u64("amount", negative ? -amount : amount) };
}

export function encodeRequest(request: ActionRequest, state: AgentState): EncodedRequest {
  const at = new Date(request.requestedAt);
  if (!Number.isFinite(at.getTime())) {
    throw new EncodingError(`requestedAt ${request.requestedAt} is not a valid instant`);
  }
  if (!Number.isSafeInteger(state.callsInWindow) || state.callsInWindow < 0) {
    throw new EncodingError(`callsInWindow ${state.callsInWindow} must be a non-negative integer`);
  }

  const params = readSolanaParams(request);
  return {
    toolId: idOf(request.tool),
    hasCounterparty: request.counterparty !== undefined,
    counterpartyId: request.counterparty === undefined ? 0n : idOf(request.counterparty),
    ...encodeAmount(request.amount),
    isSolana: isSolanaRequest(request),
    solanaValid: params !== null,
    clusterId: params === null ? 0n : idOf(params.cluster),
    programId: params === null ? 0n : idOf(params.programId),
    mintId: idOf(mintOf(request)),
    minuteOfDay: at.getUTCHours() * 60 + at.getUTCMinutes(),
    dayOfWeek: at.getUTCDay(),
    revoked: state.revoked,
    spentInWindow: u64("spentInWindow", state.spentInWindow),
    callsInWindow: BigInt(state.callsInWindow),
    drawdownFromPeak: u64("drawdownFromPeak", state.drawdownFromPeak),
  };
}

const b = (x: boolean): bigint => (x ? 1n : 0n);
const listFields = (l: EncodedList): bigint[] => [b(l.present), BigInt(l.count), ...l.items];
const optFields = (o: EncodedOptional): bigint[] => [b(o.present), o.value];

/**
 * The exact field-element order the circuit's SealedPolicy struct declares. Changing this order
 * is a wire-format change and requires a new circuit id.
 */
export function flattenPolicy(p: EncodedPolicy): readonly bigint[] {
  return [
    ...listFields(p.tools),
    ...listFields(p.counterparties),
    ...listFields(p.clusters),
    ...listFields(p.programs),
    ...listFields(p.mints),
    ...listFields(p.mintCapKeys),
    ...p.mintCapValues,
    ...optFields(p.maxPerAction),
    ...optFields(p.maxPerWindow),
    ...optFields(p.maxCalls),
    ...optFields(p.drawdownHalt),
    ...optFields(p.escalateAbove),
    b(p.hours.present),
    BigInt(p.hours.start),
    BigInt(p.hours.end),
    b(p.days.present),
    BigInt(p.days.mask),
  ];
}

/** The circuit's PublicRequest struct, in declaration order. */
export function flattenRequest(r: EncodedRequest): readonly bigint[] {
  return [
    r.toolId,
    b(r.hasCounterparty),
    r.counterpartyId,
    b(r.hasAmount),
    b(r.amountNegative),
    r.amountMagnitude,
    b(r.isSolana),
    b(r.solanaValid),
    r.clusterId,
    r.programId,
    r.mintId,
    BigInt(r.minuteOfDay),
    BigInt(r.dayOfWeek),
    b(r.revoked),
    r.spentInWindow,
    r.callsInWindow,
    r.drawdownFromPeak,
  ];
}

const listWidth = (capacity: number) => 2 + capacity;

export const POLICY_FIELD_COUNT =
  listWidth(CAPACITY.tools) +
  listWidth(CAPACITY.counterparties) +
  listWidth(CAPACITY.clusters) +
  listWidth(CAPACITY.programs) +
  listWidth(CAPACITY.mints) +
  listWidth(CAPACITY.mintCaps) +
  CAPACITY.mintCaps +
  5 * 2 +
  3 +
  2;

export const REQUEST_FIELD_COUNT = 17;
