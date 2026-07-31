/**
 * Individual rule evaluators.
 *
 * Each returns a RuleResult or null when the rule does not apply. Every function is pure:
 * same inputs, same output, no clock reads, no IO. That is what makes a decision replayable
 * by a verifier who does not trust us.
 */

import type { ActionRequest, AgentState, Policy, RuleResult } from "./types.ts";

const deny = (rule: string, reason: string): RuleResult => ({ rule, verdict: "deny", reason });
const escalate = (rule: string, reason: string): RuleResult => ({ rule, verdict: "escalate", reason });

export function checkRevoked(_p: Policy, _r: ActionRequest, s: AgentState): RuleResult | null {
  return s.revoked ? deny("revoked", "Agent authority has been revoked") : null;
}

export function checkToolAllowed(p: Policy, r: ActionRequest): RuleResult | null {
  if (p.allowedTools.includes(r.tool)) return null;
  return deny("tool_not_allowed", `Tool "${r.tool}" is not in the allowlist`);
}

export function checkCounterparty(p: Policy, r: ActionRequest): RuleResult | null {
  if (!p.counterpartyAllowlist) return null;
  if (r.counterparty === undefined) {
    return deny("counterparty_missing", "Policy requires an allowlisted counterparty but none was supplied");
  }
  if (p.counterpartyAllowlist.includes(r.counterparty)) return null;
  return deny("counterparty_not_allowed", `Counterparty ${r.counterparty} is not allowlisted`);
}

export function checkAmountPerAction(p: Policy, r: ActionRequest): RuleResult | null {
  if (p.maxAmountPerAction === undefined || r.amount === undefined) return null;
  if (r.amount <= p.maxAmountPerAction) return null;
  return deny("amount_exceeds_per_action", `Amount ${r.amount} exceeds per-action cap ${p.maxAmountPerAction}`);
}

export function checkWindowSpend(p: Policy, r: ActionRequest, s: AgentState): RuleResult | null {
  if (p.maxAmountPerWindow === undefined || r.amount === undefined) return null;
  const projected = s.spentInWindow + r.amount;
  if (projected <= p.maxAmountPerWindow) return null;
  return deny(
    "amount_exceeds_window",
    `Projected window spend ${projected} exceeds cap ${p.maxAmountPerWindow}`,
  );
}

export function checkRateLimit(p: Policy, _r: ActionRequest, s: AgentState): RuleResult | null {
  if (p.maxCallsPerWindow === undefined) return null;
  if (s.callsInWindow < p.maxCallsPerWindow) return null;
  return deny("rate_limited", `Window call count ${s.callsInWindow} has reached limit ${p.maxCallsPerWindow}`);
}

export function checkDrawdown(p: Policy, _r: ActionRequest, s: AgentState): RuleResult | null {
  if (p.drawdownHaltThreshold === undefined) return null;
  if (s.drawdownFromPeak < p.drawdownHaltThreshold) return null;
  return deny(
    "drawdown_halt",
    `Drawdown ${s.drawdownFromPeak} has reached halt threshold ${p.drawdownHaltThreshold}`,
  );
}

export function checkTimeWindow(p: Policy, r: ActionRequest): RuleResult | null {
  const d = new Date(r.requestedAt);
  if (p.allowedDaysUtc && !p.allowedDaysUtc.includes(d.getUTCDay())) {
    return deny("day_not_allowed", `UTC day ${d.getUTCDay()} is outside the permitted days`);
  }
  if (!p.allowedHoursUtc) return null;
  const [start, end] = p.allowedHoursUtc;
  const minutes = d.getUTCHours() * 60 + d.getUTCMinutes();
  if (minutes >= start && minutes < end) return null;
  return deny("outside_time_window", `Minute ${minutes} UTC is outside permitted window [${start}, ${end})`);
}

/** Evaluated last: only reached when nothing denied, so escalation never masks a denial. */
export function checkEscalation(p: Policy, r: ActionRequest): RuleResult | null {
  if (p.escalateAboveAmount === undefined || r.amount === undefined) return null;
  if (r.amount < p.escalateAboveAmount) return null;
  return escalate(
    "human_approval_required",
    `Amount ${r.amount} is at or above the escalation threshold ${p.escalateAboveAmount}`,
  );
}
