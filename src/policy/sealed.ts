/**
 * The seam between an enforceable policy and a confidential one.
 *
 * Why this exists
 * ---------------
 * Every agent guardrail available today publishes the policy in order to enforce it. For a
 * fund or a trading desk the risk parameters ARE the strategy: "max 50k per day through these
 * programs" leaks position sizing to anyone who reads the config, the audit log, or a receipt.
 * ClawShield's own receipts have this property by construction, because verification works by
 * handing the verifier the policy and replaying it.
 *
 * GENKAI keeps the policy encrypted end to end and evaluates it on ciphertext inside an
 * Arcium MXE. This file is the boundary that makes both modes interchangeable to callers.
 *
 * The trade, stated plainly
 * -------------------------
 * Plaintext mode gives independent verification: a verifier holding the policy re-runs the
 * engine and needs to trust nobody. That is the strongest property in the system and it is
 * incompatible with confidentiality - you cannot replay a computation over inputs you are not
 * allowed to see.
 *
 * Sealed mode therefore substitutes an attestation for a replay. The verifier checks that a
 * named circuit, under a known MPC cluster key, asserted this verdict for this request against
 * a policy matching this commitment. The trust assumption moves from "nobody" to "the Arcium
 * cluster and the published circuit". That is a genuine weakening and it is the price of the
 * limits staying secret. It is worth paying only because the alternative on offer today is an
 * audit log, which asks you to trust the operator alone.
 *
 * The interface makes the difference impossible to miss rather than papering over it:
 * disclose() returns the policy in plaintext mode and undefined in sealed mode, so any code
 * path that needs the plaintext policy fails loudly instead of silently degrading.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { evaluate } from "./engine.ts";
import { canonicalBytes, type Canonicalisable } from "../receipt/canonical.ts";
import { hashPolicy } from "../receipt/sign.ts";
import type { ActionRequest, AgentState, Decision, Policy, RuleResult } from "./types.ts";
import { attestedPayload, type MxeAttestation, type MxeClient } from "../mxe/types.ts";

/**
 * The reason string on every rule of a sealed decision.
 *
 * A plaintext reason reads "Amount 90000000000 exceeds per-action cap 50000000000" and hands
 * the reader the limit. Under seal there is no reason text at all, only the rule id.
 */
export const SEALED_REASON = "withheld: sealed policy";

export type SealedErrorCode =
  | "commitment_mismatch"
  | "circuit_mismatch"
  | "bad_attestation";

export class SealedPolicyError extends Error {
  readonly code: SealedErrorCode;

  constructor(code: SealedErrorCode, message: string) {
    super(message);
    this.name = "SealedPolicyError";
    this.code = code;
  }
}

export interface ProviderDecision {
  readonly decision: Decision;
  /** Bound into the receipt as policyHash. A hash in plaintext mode, a commitment when sealed. */
  readonly commitment: string;
  /** Present only under seal. Replaces the verifier's ability to replay. */
  readonly attestation?: MxeAttestation;
}

export interface PolicyProvider {
  readonly mode: "plaintext" | "sealed";
  readonly commitment: string;
  /**
   * Async in both modes. An MXE call is a network round trip, and a synchronous plaintext
   * signature would have let callers build code paths that cannot survive the switch to
   * sealed. Paying that cost in plaintext mode keeps the two genuinely interchangeable.
   */
  decide(request: ActionRequest, state: AgentState, decidedAt: number): Promise<ProviderDecision>;
  /** The policy, or undefined when sealed. Callers must handle undefined; that is the point. */
  disclose(): Policy | undefined;
}

/**
 * Commitment to a sealed policy.
 *
 * NOT hashPolicy(). A bare hash of the policy is a commitment an adversary can brute-force:
 * risk limits are round numbers, the mint and program sets are drawn from a small public
 * universe, and the whole search space of plausible treasury policies is small enough to
 * enumerate. Guessing until the hash matches recovers exactly what the design set out to hide.
 *
 * So the commitment is salted with a high-entropy secret held alongside the encrypted policy.
 * The salt is never published; a verifier checks the commitment by equality against the value
 * bound into the receipt, never by recomputing it.
 */
export function sealedCommitment(policy: Policy, salt: string): string {
  const bytes = canonicalBytes({ policy, salt } as unknown as Canonicalisable);
  return createHash("sha256").update(bytes).digest("hex");
}

/** Today's behaviour, behind the new interface. Nothing about enforcement changes. */
export function createPlaintextPolicyProvider(policy: Policy): PolicyProvider {
  return Object.freeze({
    mode: "plaintext" as const,
    commitment: hashPolicy(policy),
    decide: async (request: ActionRequest, state: AgentState, decidedAt: number) =>
      Object.freeze({
        decision: evaluate(policy, request, state, decidedAt),
        commitment: hashPolicy(policy),
      }),
    disclose: () => policy,
  });
}

export interface SealedProviderConfig {
  /** The commitment this provider will accept, and only this one. */
  readonly commitment: string;
  readonly circuitId: string;
  /** SPKI DER, base64. Pinned by the operator out of band. */
  readonly clusterPublicKey: string;
  readonly mxe: MxeClient;
}

export function createSealedPolicyProvider(config: SealedProviderConfig): PolicyProvider {
  async function decide(
    request: ActionRequest,
    state: AgentState,
    decidedAt: number,
  ): Promise<ProviderDecision> {
    const output = await config.mxe.evaluate({
      policyCommitment: config.commitment,
      request,
      state,
      decidedAt,
    });

    // 1. The MXE evaluated the policy we think it did. Checked before the signature, because
    //    a validly signed answer about the wrong policy is still the wrong answer.
    if (output.policyCommitment !== config.commitment) {
      throw new SealedPolicyError(
        "commitment_mismatch",
        "The MXE answered for a different policy commitment than the one configured",
      );
    }

    // 2. The answer came from the circuit we pinned, not some other circuit the cluster runs.
    if (output.attestation.circuitId !== config.circuitId) {
      throw new SealedPolicyError(
        "circuit_mismatch",
        `Attestation names circuit ${output.attestation.circuitId}, expected ${config.circuitId}`,
      );
    }

    // 3. The attestation verifies under the pinned cluster key, over a payload that includes
    //    the verdict and the firing rules. This is what stops an operator sitting between the
    //    MXE and the receipt writer from flipping deny to allow.
    const payload = attestedPayload(
      { policyCommitment: output.policyCommitment, request, state, decidedAt },
      output.attestation.circuitId,
      output.verdict,
      output.ruleIds,
    );
    if (!verifyAttestation(payload, output.attestation, config.clusterPublicKey)) {
      throw new SealedPolicyError(
        "bad_attestation",
        "The MXE attestation does not verify under the pinned cluster key",
      );
    }

    const reasons: readonly RuleResult[] = output.ruleIds.map((rule) => ({
      rule,
      verdict: output.verdict,
      reason: SEALED_REASON,
    }));

    return Object.freeze({
      decision: {
        verdict: output.verdict,
        reasons,
        // The policy id and version are metadata the operator chooses to publish. They name
        // which sealed policy is in force without revealing what it says.
        policyId: config.circuitId,
        policyVersion: 0,
        decidedAt,
      },
      commitment: config.commitment,
      attestation: output.attestation,
    });
  }

  return Object.freeze({
    mode: "sealed" as const,
    commitment: config.commitment,
    decide,
    // Sealed means sealed. Returning the policy here would defeat the entire design, so there
    // is no configuration under which this returns anything else.
    disclose: () => undefined,
  });
}

/**
 * Verify an MXE attestation. Exported because a third party needs it: it is the sealed-mode
 * substitute for re-running the engine.
 */
export function verifyAttestation(
  payload: Canonicalisable,
  attestation: MxeAttestation,
  clusterPublicKey: string,
): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.from(clusterPublicKey, "base64"),
      format: "der",
      type: "spki",
    });
    return cryptoVerify(
      null,
      canonicalBytes(payload),
      key,
      Buffer.from(attestation.signature, "base64"),
    );
  } catch {
    return false;
  }
}
