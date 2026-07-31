/**
 * Solana rule evaluators.
 *
 * Same purity contract as src/policy/rules.ts: same inputs, same output, no clock, no IO.
 * These are wired into the engine's deny list, so any deviation from purity would silently
 * break replay-based verification for every Solana receipt.
 *
 * One deliberate asymmetry with the core rules, called out because it looks like an
 * inconsistency and is not:
 *
 *   checkCounterparty in src/policy/rules.ts treats an absent allowlist as "rule does not
 *   apply" and permits any counterparty. The Solana allowlists here treat an absent allowlist
 *   as DENY. A policy written before Solana existed must not be readable as authorisation to
 *   move funds on Solana. Deny by default is the stated invariant, and a chain the policy
 *   author never contemplated is exactly the case it exists for.
 */

import type { ActionRequest, AgentState, Policy, RuleResult } from "../policy/types.ts";
import { isSolanaRequest, mintOf, readSolanaParams } from "./types.ts";

const deny = (rule: string, reason: string): RuleResult => ({ rule, verdict: "deny", reason });

/**
 * Every rule takes the full (policy, request, state) triple even where it ignores state, so
 * the whole set is uniformly assignable to the engine's Rule type and can be iterated over in
 * tests without special-casing arities.
 */
type SolanaRule = (p: Policy, r: ActionRequest, s: AgentState) => RuleResult | null;

/**
 * A request claiming to be Solana whose params do not parse is denied outright.
 *
 * Without this, forging `{ chain: "solana" }` with a broken body would make readSolanaParams
 * return null in every other rule, each of which would then decline to fire, and the request
 * would fall through the Solana rule set entirely.
 */
export const checkSolanaParams: SolanaRule = (_p, r) => {
  if (!isSolanaRequest(r)) return null;
  if (readSolanaParams(r) !== null) return null;
  return deny("solana_params_malformed", "Request declares chain solana but its parameters do not parse");
};

export const checkClusterAllowed: SolanaRule = (p, r) => {
  const params = readSolanaParams(r);
  if (params === null) return null;
  // Absent means deny. A devnet policy must never be readable as mainnet authorisation.
  if (!p.allowedClusters) {
    return deny("cluster_not_allowed", "Policy names no permitted Solana clusters");
  }
  if (p.allowedClusters.includes(params.cluster)) return null;
  return deny("cluster_not_allowed", `Cluster ${params.cluster} is not allowlisted`);
};

export const checkProgramAllowed: SolanaRule = (p, r) => {
  const params = readSolanaParams(r);
  if (params === null) return null;
  if (!p.allowedPrograms) {
    return deny("program_not_allowed", "Policy names no permitted Solana programs");
  }
  if (p.allowedPrograms.includes(params.programId)) return null;
  return deny("program_not_allowed", `Program ${params.programId} is not allowlisted`);
};

export const checkMintAllowed: SolanaRule = (p, r) => {
  if (readSolanaParams(r) === null) return null;
  if (!p.allowedMints) {
    return deny("mint_not_allowed", "Policy names no permitted Solana mints");
  }
  const mint = mintOf(r);
  if (p.allowedMints.includes(mint)) return null;
  return deny("mint_not_allowed", `Mint ${mint} is not allowlisted`);
};

/**
 * Per-mint spend cap.
 *
 * A cap table that is present but silent about a mint denies rather than defaulting to
 * unlimited. Adding a mint to the allowlist and forgetting to give it a cap is the single
 * most likely operator mistake here, and the failure mode has to be a refusal, not an
 * uncapped transfer.
 */
export const checkMintSpendCap: SolanaRule = (p, r) => {
  if (readSolanaParams(r) === null) return null;
  if (p.maxAmountPerMint === undefined || r.amount === undefined) return null;

  const mint = mintOf(r);
  const cap = p.maxAmountPerMint[mint];
  if (cap === undefined) {
    return deny("mint_cap_missing", `No per-mint cap is configured for ${mint}`);
  }
  if (r.amount <= cap) return null;
  return deny("mint_cap_exceeded", `Amount ${r.amount} exceeds the cap for ${mint}`);
};

/**
 * The amount must be strictly positive.
 *
 * This is not defensive boilerplate. Window spend is computed as `spentInWindow + amount`, and
 * bigint permits negatives, so a negative amount would pass every cap comparison AND increase
 * the agent's remaining headroom. A zero-amount transfer is rejected too: it burns a rate-limit
 * slot and produces a receipt asserting a movement of nothing.
 */
export const checkTransferAmount: SolanaRule = (_p, r) => {
  if (readSolanaParams(r) === null) return null;
  if (r.amount === undefined) {
    return deny("amount_not_positive", "A Solana transfer must carry an amount");
  }
  if (r.amount > 0n) return null;
  return deny("amount_not_positive", `Amount ${r.amount} is not strictly positive`);
};
