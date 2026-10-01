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
import {
  attestedPayload,
  isOnChainAttestation,
  type Disclosure,
  type MxeAttestation,
  type MxeClient,
  type MxeEvaluationOutput,
} from "../mxe/types.ts";
import { checkOnChainDecision } from "../mxe/onchain.ts";
import type { RpcClient } from "../solana/rpc.ts";

export type { Disclosure } from "../mxe/types.ts";

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
  | "disclosure_violation"
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

/**
 * What the provider checks an MXE answer against, pinned by the operator out of band.
 *
 *   clusterPublicKey  an MXE that signs attestations offline (the in-process stub)
 *   onChain           the live Arcium path: the answer must be the DecisionRecord the GENKAI
 *                     program wrote, against this exact PolicyRecord, read back over RPC
 */
export type AttestationAnchor =
  | { readonly clusterPublicKey: string; readonly onChain?: undefined }
  | { readonly onChain: OnChainAnchor; readonly clusterPublicKey?: undefined };

export interface OnChainAnchor {
  readonly rpc: RpcClient;
  readonly programId: string;
  readonly policy: string;
}

export type SealedProviderConfig = {
  /** The commitment this provider will accept, and only this one. */
  readonly commitment: string;
  readonly circuitId: string;
  readonly mxe: MxeClient;
  /** Defaults to "rules". See Disclosure in src/mxe/types.ts. */
  readonly disclosure?: Disclosure;
} & AttestationAnchor;

export function createSealedPolicyProvider(config: SealedProviderConfig): PolicyProvider {
  const disclosure: Disclosure = config.disclosure ?? "rules";

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
      disclosure,
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

    // 3. The MXE disclosed no more than it was asked to. Checked explicitly so an over-sharing
    //    MXE is named as such, rather than surfacing as an opaque signature failure.
    if (disclosure === "verdict" && (output.ruleIds.length > 0 || output.attestation.disclosure !== "verdict")) {
      throw new SealedPolicyError(
        "disclosure_violation",
        "Verdict-only disclosure was requested but the MXE disclosed rule identifiers",
      );
    }

    // 4. The attestation verifies under the pinned anchor, over the verdict, the firing rules
    //    and the disclosure mode. This is what stops an operator sitting between the MXE and
    //    the receipt writer from flipping deny to allow.
    const problem = await attestationProblem(config, output, { request, state, decidedAt, disclosure });
    if (problem !== null) throw new SealedPolicyError("bad_attestation", problem);

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

interface Asked {
  readonly request: ActionRequest;
  readonly state: AgentState;
  readonly decidedAt: number;
  readonly disclosure: Disclosure;
}

async function attestationProblem(config: SealedProviderConfig, output: MxeEvaluationOutput, asked: Asked): Promise<string | null> {
  const attestation = output.attestation;
  if (config.onChain !== undefined) {
    if (!isOnChainAttestation(attestation)) return "Expected an on-chain attestation from the live MXE";
    if (attestation.programId !== config.onChain.programId || attestation.policy !== config.onChain.policy) {
      return "The attestation points at a program or policy record other than the pinned ones";
    }
    const check = await checkOnChainDecision(
      { commitment: config.commitment, ...asked, verdict: output.verdict, ruleIds: output.ruleIds },
      { rpc: config.onChain.rpc, programId: config.onChain.programId, policy: config.onChain.policy, decision: attestation.decision, computationOffset: attestation.computationOffset },
    );
    return check.valid ? null : `The on-chain decision does not support this answer: ${check.detail.join("; ")}`;
  }

  const payload = attestedPayload(
    { policyCommitment: output.policyCommitment, ...asked },
    attestation.circuitId,
    output.verdict,
    output.ruleIds,
  );
  return verifyAttestation(payload as unknown as Canonicalisable, attestation, config.clusterPublicKey)
    ? null
    : "The MXE attestation does not verify under the pinned cluster key";
}

/**
 * Verify a signed MXE attestation. Exported because a third party needs it: it is the
 * sealed-mode substitute for re-running the engine. An on-chain attestation carries no
 * signature to check here and never verifies; see verifySealedReceiptOnChain.
 */
export function verifyAttestation(
  payload: Canonicalisable,
  attestation: MxeAttestation,
  clusterPublicKey: string,
): boolean {
  if (isOnChainAttestation(attestation)) return false;
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
