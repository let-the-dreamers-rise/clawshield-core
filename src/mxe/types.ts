/**
 * The MXE boundary.
 *
 * GENKAI evaluates policy on ciphertext inside an Arcium MXE on Solana. The limits are never
 * decrypted - not by the agent, not by the operator, not by the verifier. This file defines
 * the shape of that call and nothing else, so the interface can be got right before the
 * circuit exists.
 *
 * What crosses this boundary, and what deliberately does not:
 *
 *   in   commitment to the sealed policy, the request, the observed state, decidedAt
 *   out  a verdict, opaque rule identifiers, and an attestation over all of it
 *   never  the policy itself, in either direction
 *
 * The input is exactly the input to evaluate(), minus the policy. That is not a coincidence:
 * it is the constraint that keeps a sealed decision comparable to a plaintext one.
 */

import type { ActionRequest, AgentState, Verdict } from "../policy/types.ts";

/**
 * How much a sealed decision reveals beyond its verdict.
 *
 *   rules    the verdict and the ids of the rules that fired ("mint_cap_exceeded")
 *   verdict  the verdict alone. Not even the kind of constraint that bound is disclosed.
 *
 * A rule id is a smaller leak than a threshold, but it is a leak: a run of
 * "amount_exceeds_window" denials tells an observer the desk is near its daily limit.
 */
export type Disclosure = "rules" | "verdict";

export interface MxeEvaluationInput {
  readonly policyCommitment: string;
  readonly request: ActionRequest;
  readonly state: AgentState;
  /** Passed in, never read from a clock, for the same reason the engine does it. */
  readonly decidedAt: number;
  /** Defaults to "rules". Bound into the attestation, so it cannot be relabelled afterwards. */
  readonly disclosure?: Disclosure;
}

/**
 * An attestation that a named circuit, running under a known cluster key, produced this
 * verdict for this input against this policy commitment.
 *
 * This is what replaces replay. A plaintext verifier re-runs the engine and needs to trust
 * nobody. A sealed verifier cannot re-run anything, because it does not have the policy, so
 * it checks a signature from the cluster instead. That substitution is the central trade of
 * the whole design and it is stated here rather than buried.
 */
export interface MxeAttestation {
  readonly circuitId: string;
  /** SPKI DER public key of the MPC cluster, base64. */
  readonly clusterPublicKey: string;
  /** Ed25519 signature over the canonical attested payload, base64. */
  readonly signature: string;
  /** Present only in verdict-only mode; absent means rules mode, so older attestations verify. */
  readonly disclosure?: "verdict";
}

export interface MxeEvaluationOutput {
  /** Echoed back so the caller can confirm which policy was actually evaluated. */
  readonly policyCommitment: string;
  readonly verdict: Verdict;
  /**
   * Identifiers of the rules that fired, in engine order.
   *
   * Identifiers only - no interpolated amounts. A plaintext reason string reads "Amount
   * 90000000000 exceeds per-action cap 50000000000" and hands the reader the limit. A rule id
   * still discloses which KIND of constraint bound, which is a smaller but real leak; see the
   * roadmap note in the README about a verdict-only mode.
   */
  readonly ruleIds: readonly string[];
  readonly attestation: MxeAttestation;
}

export interface MxeClient {
  readonly circuitId: string;
  readonly clusterPublicKey: string;
  evaluate(input: MxeEvaluationInput): Promise<MxeEvaluationOutput>;
}

/** The exact payload an attestation signs. Canonicalised, so both sides agree byte for byte. */
export interface AttestedPayload {
  readonly circuitId: string;
  readonly policyCommitment: string;
  readonly request: ActionRequest;
  readonly state: AgentState;
  readonly decidedAt: number;
  readonly verdict: Verdict;
  readonly ruleIds: readonly string[];
  readonly disclosure?: "verdict";
}

export function attestedPayload(
  input: MxeEvaluationInput,
  circuitId: string,
  verdict: Verdict,
  ruleIds: readonly string[],
): AttestedPayload {
  return {
    circuitId,
    policyCommitment: input.policyCommitment,
    request: input.request,
    state: input.state,
    decidedAt: input.decidedAt,
    verdict,
    ruleIds,
    disclosure: input.disclosure === "verdict" ? "verdict" : undefined,
  };
}
