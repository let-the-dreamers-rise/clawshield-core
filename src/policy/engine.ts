/**
 * The policy engine.
 *
 * The single most important property of this file: the engine is deterministic and the model
 * is not consulted. An LLM may propose an action and may supply reasoning that gets recorded,
 * but it can never widen what is permitted. Every rule can only narrow.
 *
 * Ordering is deliberate. Denials are evaluated before escalation so a large, disallowed
 * action is denied rather than sent to a human for approval it should never receive.
 */

import type { ActionRequest, AgentState, Decision, Policy, RuleResult } from "./types.ts";
import {
  checkAmountPerAction,
  checkCounterparty,
  checkDrawdown,
  checkEscalation,
  checkRateLimit,
  checkRevoked,
  checkTimeWindow,
  checkToolAllowed,
  checkWindowSpend,
} from "./rules.ts";
import {
  checkClusterAllowed,
  checkMintAllowed,
  checkMintSpendCap,
  checkProgramAllowed,
  checkSolanaParams,
  checkTransferAmount,
} from "../solana/rules.ts";

type Rule = (p: Policy, r: ActionRequest, s: AgentState) => RuleResult | null;

/**
 * Version of this rule set.
 *
 * A receipt records which ruleset produced it, because replay is only meaningful against the
 * same rules. Adding a rule cannot change the verdict for a policy that does not configure it
 * - every rule above returns null when its policy fields are absent - but it can change the
 * recorded list of firing rules, and verifyReceipt compares that list exactly. Binding the
 * version lets a verifier say "I cannot replay this" instead of "this receipt is forged".
 */
export const RULESET_VERSION = 1;

/**
 * Denying rules run first, in order of severity. Escalation runs only if none denied.
 *
 * The Solana rules sit with the other allowlists rather than at the end: they answer "may this
 * agent touch this program and mint at all", which is a more fundamental question than "is
 * this amount too large". The per-mint cap sits with the other numeric caps for the same
 * reason. Order is part of the recorded output, so it is part of the wire format.
 */
const DENY_RULES: readonly Rule[] = [
  checkRevoked,
  checkToolAllowed,
  checkSolanaParams,
  checkCounterparty,
  checkClusterAllowed,
  checkProgramAllowed,
  checkMintAllowed,
  checkTransferAmount,
  checkDrawdown,
  checkRateLimit,
  checkAmountPerAction,
  checkMintSpendCap,
  checkWindowSpend,
  checkTimeWindow,
];

const ESCALATE_RULES: readonly Rule[] = [checkEscalation];

/**
 * Evaluate a request against a policy and observed state.
 *
 * `decidedAt` is passed in rather than read from the clock so a verifier can replay the exact
 * decision later and reach byte-identical output.
 */
export function evaluate(
  policy: Policy,
  request: ActionRequest,
  state: AgentState,
  decidedAt: number,
): Decision {
  const denials = DENY_RULES.map((rule) => rule(policy, request, state)).filter(
    (x): x is RuleResult => x !== null,
  );

  if (denials.length > 0) {
    return {
      verdict: "deny",
      reasons: denials,
      policyId: policy.policyId,
      policyVersion: policy.version,
      decidedAt,
    };
  }

  const escalations = ESCALATE_RULES.map((rule) => rule(policy, request, state)).filter(
    (x): x is RuleResult => x !== null,
  );

  if (escalations.length > 0) {
    return {
      verdict: "escalate",
      reasons: escalations,
      policyId: policy.policyId,
      policyVersion: policy.version,
      decidedAt,
    };
  }

  return {
    verdict: "allow",
    reasons: [{ rule: "all_checks_passed", verdict: "allow", reason: "No rule objected" }],
    policyId: policy.policyId,
    policyVersion: policy.version,
    decidedAt,
  };
}
