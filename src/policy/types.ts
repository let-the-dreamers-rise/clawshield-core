/**
 * Policy types.
 *
 * Design principle: a policy is data, not code. It serialises deterministically so it can be
 * hashed, and that hash is bound into every receipt. A verifier can therefore prove which
 * policy was in force at the moment a decision was taken.
 */

export type Verdict = "allow" | "deny" | "escalate";

/** An action an agent wants to execute. Amounts are integer minor units - never floats. */
export interface ActionRequest {
  readonly agentId: string;
  readonly tool: string;
  readonly counterparty?: string;
  readonly amount?: bigint;
  readonly asset?: string;
  readonly chainId?: number;
  readonly requestedAt: number;
  readonly params: Readonly<Record<string, unknown>>;
}

/** Observed state the engine reasons over. Supplied by the ledger, never by the agent. */
export interface AgentState {
  readonly spentInWindow: bigint;
  readonly windowStartedAt: number;
  readonly callsInWindow: number;
  readonly drawdownFromPeak: bigint;
  readonly revoked: boolean;
}

export interface Policy {
  readonly policyId: string;
  readonly version: number;
  /** Tools the agent may call. Empty means none - deny by default, never allow by default. */
  readonly allowedTools: readonly string[];
  readonly counterpartyAllowlist?: readonly string[];
  readonly maxAmountPerAction?: bigint;
  readonly maxAmountPerWindow?: bigint;
  readonly windowSeconds?: number;
  readonly maxCallsPerWindow?: number;
  /** Cumulative loss from peak that halts trading outright. */
  readonly drawdownHaltThreshold?: bigint;
  /** At or above this amount a human must approve. Escalate, do not deny. */
  readonly escalateAboveAmount?: bigint;
  /** Minutes past midnight UTC, inclusive start, exclusive end. */
  readonly allowedHoursUtc?: readonly [number, number];
  readonly allowedDaysUtc?: readonly number[];

  /*
   * Solana-specific constraints.
   *
   * These are optional, and canonicalise() drops undefined-valued keys, so a policy that does
   * not set them hashes byte-identically to how it hashed before these fields existed. Every
   * receipt already issued stays verifiable. That property is why these live here rather than
   * in a separate SolanaPolicy type that would have had to be hashed alongside.
   *
   * Unlike counterpartyAllowlist above, absent means DENY for all of these. See the note at
   * the top of src/solana/rules.ts.
   */

  /** Cluster names, for example "mainnet-beta". Kept as strings so this type stays chain-agnostic. */
  readonly allowedClusters?: readonly string[];
  readonly allowedPrograms?: readonly string[];
  readonly allowedMints?: readonly string[];
  /** Per-mint spend cap in that mint's minor units. A mint absent from the table is denied. */
  readonly maxAmountPerMint?: Readonly<Record<string, bigint>>;
}

export interface RuleResult {
  readonly rule: string;
  readonly verdict: Verdict;
  readonly reason: string;
}

export interface Decision {
  readonly verdict: Verdict;
  readonly reasons: readonly RuleResult[];
  readonly policyId: string;
  readonly policyVersion: number;
  readonly decidedAt: number;
}
