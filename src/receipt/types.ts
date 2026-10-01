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
import type { MxeAttestation } from "../mxe/types.ts";

export interface ExecutionOutcome {
  readonly executed: boolean;
  readonly txHash?: string;
  readonly chainId?: number;
  readonly balanceBefore?: bigint;
  readonly balanceAfter?: bigint;
  readonly error?: string;
}

/**
 * The transaction an allow verdict authorised, bound into the receipt.
 *
 * Everything needed to rebuild the signed message from the evaluated request is here, so a
 * verifier never has to trust that the signature covers what the operator says it covers.
 */
export interface AuthorisedTransaction {
  /** Base58 fee-payer signature: the transaction id on chain. */
  readonly signature: string;
  /** SHA-256 of the signed message bytes, hex. */
  readonly messageSha256: string;
  readonly recentBlockhash: string;
  readonly computeUnitLimit?: number;
  readonly computeUnitPrice?: bigint;
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
  /**
   * Version of the rule set that produced this decision.
   *
   * Optional, and canonicalise() drops undefined keys, so adding it did not change the hash of
   * any receipt issued before it existed. Replay is only meaningful against the same rules:
   * with this bound, a verifier running a different rule set can say "I cannot replay this"
   * instead of the far more damaging "this receipt is forged".
   */
  readonly rulesetVersion?: number;
  /**
   * Present only for decisions taken under seal. The verifier cannot replay a policy it is not
   * allowed to see, so it checks this instead. See src/policy/sealed.ts.
   */
  readonly attestation?: MxeAttestation;
  /**
   * Present only when the verdict was allow and a transaction was signed. Optional, so every
   * receipt issued before it existed hashes and verifies exactly as it did.
   */
  readonly transaction?: AuthorisedTransaction;
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
  | "chain_broken"
  | "transaction_mismatch";

export interface VerificationResult {
  readonly valid: boolean;
  readonly failures: readonly VerificationFailure[];
  readonly detail: readonly string[];
}
