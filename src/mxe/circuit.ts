/**
 * The policy circuit, as a TypeScript model.
 *
 * This is the reference for arcium/genkai/encrypted-ixs/src/lib.rs and is written the way an
 * MPC circuit has to be written: every rule is evaluated on every call, there is no early
 * return, and no branch depends on a policy value. Branching on a secret inside MPC either
 * fails to compile or leaks the secret through which path ran; computing everything and
 * combining with masks does neither.
 *
 * The output is two small integers - a verdict code and a bitmask of fired rules - which is
 * all the cluster reveals. The rule ids are recovered from the mask outside the circuit.
 *
 * test/circuit.test.ts holds this model to the engine across thousands of random cases. The
 * Rust circuit holds to this model line for line. Together that is the argument that a sealed
 * decision is the decision the plaintext engine would have reached.
 */

import type { Verdict } from "../policy/types.ts";
import type { EncodedList, EncodedPolicy, EncodedRequest } from "./encoding.ts";

/** Bit i of the mask is RULE_ORDER[i]. Same order as the engine, which is part of the wire format. */
export const RULE_ORDER = Object.freeze([
  "revoked",
  "tool_not_allowed",
  "solana_params_malformed",
  "counterparty_missing",
  "counterparty_not_allowed",
  "cluster_not_allowed",
  "program_not_allowed",
  "mint_not_allowed",
  "amount_not_positive",
  "drawdown_halt",
  "rate_limited",
  "amount_exceeds_per_action",
  "mint_cap_missing",
  "mint_cap_exceeded",
  "amount_exceeds_window",
  "day_not_allowed",
  "outside_time_window",
  "human_approval_required",
] as const);

const ESCALATION_BIT = RULE_ORDER.indexOf("human_approval_required");
const DENY_MASK = (1 << ESCALATION_BIT) - 1;

export const VERDICT_CODE = Object.freeze({ allow: 0, deny: 1, escalate: 2 } as const);

export interface CircuitOutput {
  readonly verdict: 0 | 1 | 2;
  readonly mask: number;
}

/** Membership over the full capacity, so the work done never depends on the list length. */
function member(list: EncodedList, x: bigint): boolean {
  let found = false;
  for (let i = 0; i < list.items.length; i++) {
    found = found || (i < list.count && list.items[i] === x);
  }
  return found;
}

/** amount <= cap for a signed amount against an unsigned cap. */
const amountAtMost = (r: EncodedRequest, cap: bigint): boolean => r.amountNegative || r.amountMagnitude <= cap;

/** spent + amount <= cap, without ever forming a negative number. */
const windowAtMost = (r: EncodedRequest, cap: bigint): boolean =>
  r.amountNegative ? r.spentInWindow <= cap + r.amountMagnitude : r.spentInWindow + r.amountMagnitude <= cap;

function mintCap(p: EncodedPolicy, mintId: bigint): { found: boolean; cap: bigint } {
  let found = false;
  let cap = 0n;
  for (let i = 0; i < p.mintCapKeys.items.length; i++) {
    const hit = i < p.mintCapKeys.count && p.mintCapKeys.items[i] === mintId;
    found = found || hit;
    cap = hit ? (p.mintCapValues[i] ?? 0n) : cap;
  }
  return { found, cap };
}

export function evaluateCircuit(p: EncodedPolicy, r: EncodedRequest): CircuitOutput {
  const valid = r.solanaValid;
  const cap = mintCap(p, r.mintId);
  const nonPositive = !r.hasAmount || r.amountNegative || r.amountMagnitude === 0n;
  const capGate = valid && p.mintCapKeys.present && r.hasAmount;
  const dayFails = p.days.present && ((p.days.mask >> r.dayOfWeek) & 1) === 0;
  const inHours = r.minuteOfDay >= p.hours.start && r.minuteOfDay < p.hours.end;

  const fired: readonly boolean[] = [
    r.revoked,
    !member(p.tools, r.toolId),
    r.isSolana && !valid,
    p.counterparties.present && !r.hasCounterparty,
    p.counterparties.present && r.hasCounterparty && !member(p.counterparties, r.counterpartyId),
    valid && (!p.clusters.present || !member(p.clusters, r.clusterId)),
    valid && (!p.programs.present || !member(p.programs, r.programId)),
    valid && (!p.mints.present || !member(p.mints, r.mintId)),
    valid && nonPositive,
    p.drawdownHalt.present && r.drawdownFromPeak >= p.drawdownHalt.value,
    p.maxCalls.present && r.callsInWindow >= p.maxCalls.value,
    p.maxPerAction.present && r.hasAmount && !amountAtMost(r, p.maxPerAction.value),
    capGate && !cap.found,
    capGate && cap.found && !amountAtMost(r, cap.cap),
    p.maxPerWindow.present && r.hasAmount && !windowAtMost(r, p.maxPerWindow.value),
    dayFails,
    p.hours.present && !inHours && !dayFails,
    false,
  ];

  const denyMask = fired.reduce((m, hit, i) => (hit ? m | (1 << i) : m), 0) & DENY_MASK;
  const escalates =
    denyMask === 0 &&
    p.escalateAbove.present &&
    r.hasAmount &&
    !r.amountNegative &&
    r.amountMagnitude >= p.escalateAbove.value;

  return {
    verdict: denyMask !== 0 ? VERDICT_CODE.deny : escalates ? VERDICT_CODE.escalate : VERDICT_CODE.allow,
    mask: denyMask | (escalates ? 1 << ESCALATION_BIT : 0),
  };
}

export function verdictOf(out: CircuitOutput): Verdict {
  return out.verdict === VERDICT_CODE.deny ? "deny" : out.verdict === VERDICT_CODE.escalate ? "escalate" : "allow";
}

/** The rule ids the engine would report, recovered from the revealed mask. */
export function ruleIdsOf(out: CircuitOutput): readonly string[] {
  if (out.verdict === VERDICT_CODE.allow) return ["all_checks_passed"];
  return RULE_ORDER.filter((_, i) => (out.mask >> i) & 1);
}
