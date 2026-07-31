/**
 * Receipt types.
 *
 * A receipt is the artifact that separates this from an audit log. A log is a claim by the
 * operator. A receipt binds, under signature:
 *
 *   - the hash of the exact policy in force at decision time
 *   - the exact request that was evaluated
 *   - the observed state the engine reasoned over
 *   - the verdict and the rules that produced it
 *   - the resulting transaction, if the action executed
 *
 * A third party holding only the public key and the receipt can confirm the operator did not
 * silently swap the policy after the fact.
 */

import type { ActionRequest, AgentState, Decision } from "../policy/types.ts";

export interface ExecutionOutcome {
  readonly executed: boolean;
  readonly txHash?: string;
  readonly chainId?: number;
  readonly balanceBefore?: bigint;
  readonly balanceAfter?: bigint;
  readonly error?: string;
}

export interface ReceiptBody {
  readonly receiptId: string;
  readonly schemaVersion: 1;
  /** SHA-256 over the canonical form of the policy. */
  readonly policyHash: string;
  readonly request: ActionRequest;
  readonly state: AgentState;
  readonly decision: Decision;
  /** Optional model reasoning. Recorded for accountability, never trusted for enforcement. */
  readonly modelReasoning?: string;
  readonly outcome?: ExecutionOutcome;
  /** Hash of the previous receipt for this agent, forming a tamper-evident chain. */
  readonly previousReceiptHash: string | null;
}

export interface SignedReceipt {
  readonly body: ReceiptBody;
  /** Ed25519 signature over the canonical bytes of `body`, base64. */
  readonly signature: string;
  /** SPKI DER public key, base64. */
  readonly publicKey: string;
  readonly algorithm: "ed25519";
}

export type VerificationFailure =
  | "bad_signature"
  | "policy_hash_mismatch"
  | "decision_not_reproducible"
  | "chain_broken";

export interface VerificationResult {
  readonly valid: boolean;
  readonly failures: readonly VerificationFailure[];
  readonly detail: readonly string[];
}
