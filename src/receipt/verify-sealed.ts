/**
 * Third-party verification of a receipt issued under a sealed policy.
 *
 * The plaintext verifier replays the engine. This one cannot: replay needs the policy, and the
 * whole point of sealing is that the verifier never sees it. It substitutes the MXE attestation
 * for the replay, which moves the trust assumption from "nobody" to "the Arcium cluster and the
 * published circuit". Everything else - the operator's signature, the chain, the bound
 * transaction - is checked exactly as in plaintext mode.
 *
 * The verifier needs three public values, pinned out of band rather than read from the receipt
 * it is checking:
 *
 *   commitment        the salted commitment to the sealed policy the operator registered
 *   circuitId         the circuit the operator claims evaluates it
 *   clusterPublicKey  the key the MPC cluster attests under
 *
 * Reading any of them from the receipt itself would let a forger supply their own.
 */

import { hashReceiptBody } from "./sign.ts";
import { checkReceiptSignature } from "./verify-signature.ts";
import { checkBoundTransaction } from "./verify-transaction.ts";
import { SEALED_REASON, verifyAttestation } from "../policy/sealed.ts";
import { attestedPayload } from "../mxe/types.ts";
import type { Canonicalisable } from "./canonical.ts";
import type { ReceiptBody, SignedReceipt, VerificationFailure, VerificationResult } from "./types.ts";

export interface SealedTrust {
  readonly commitment: string;
  readonly circuitId: string;
  readonly clusterPublicKey: string;
}

export interface SealedVerifyOptions {
  readonly expectedPreviousHash?: string | null;
}

type Finding = readonly [VerificationFailure, string];

function checkAttestation(body: ReceiptBody, trust: SealedTrust): Finding | null {
  const attestation = body.attestation;
  if (!attestation) return ["attestation_missing", "A sealed receipt must carry its MXE attestation"];
  if (attestation.circuitId !== trust.circuitId) {
    return ["attestation_invalid", `Attestation names circuit ${attestation.circuitId}, pinned ${trust.circuitId}`];
  }
  if (attestation.clusterPublicKey !== trust.clusterPublicKey) {
    return ["attestation_invalid", "Attestation names a cluster key other than the pinned one"];
  }

  const payload = attestedPayload(
    {
      policyCommitment: body.policyHash,
      request: body.request,
      state: body.state,
      decidedAt: body.decision.decidedAt,
      disclosure: attestation.disclosure === "verdict" ? "verdict" : "rules",
    },
    attestation.circuitId,
    body.decision.verdict,
    body.decision.reasons.map((r) => r.rule),
  );
  if (!verifyAttestation(payload as unknown as Canonicalisable, attestation, trust.clusterPublicKey)) {
    return ["attestation_invalid", "The attestation does not cover this verdict, request and state under the pinned key"];
  }
  return null;
}

/**
 * The attestation covers rule ids, not reason text. Any reason that is not the fixed sealed
 * placeholder is information the cluster never vouched for, and it is exactly where a
 * threshold would leak ("exceeds per-action cap 50000000000").
 */
function checkDisclosure(body: ReceiptBody): Finding | null {
  const leaked = body.decision.reasons.filter(
    (r) => r.reason !== SEALED_REASON || r.verdict !== body.decision.verdict,
  );
  if (leaked.length > 0) {
    return ["disclosure_leak", `${leaked.length} reason(s) carry text or verdicts the attestation does not cover`];
  }
  return null;
}

export function verifySealedReceipt(
  receipt: SignedReceipt,
  trust: SealedTrust,
  options: SealedVerifyOptions = {},
): VerificationResult {
  const body = receipt.body;
  const signatureProblem = checkReceiptSignature(receipt);
  const findings: readonly (Finding | null)[] = [
    signatureProblem === null ? null : ["bad_signature", signatureProblem],
    body.policyHash === trust.commitment
      ? null
      : ["commitment_mismatch", `Receipt binds ${body.policyHash}, pinned commitment is ${trust.commitment}`],
    checkAttestation(body, trust),
    checkDisclosure(body),
    options.expectedPreviousHash === undefined || body.previousReceiptHash === options.expectedPreviousHash
      ? null
      : ["chain_broken", `Receipt points at previous ${body.previousReceiptHash} but ${options.expectedPreviousHash} was expected`],
    ((problem) => (problem === null ? null : (["transaction_mismatch", problem] as const)))(checkBoundTransaction(body)),
  ];

  const present = findings.filter((f): f is Finding => f !== null);
  return {
    valid: present.length === 0,
    failures: present.map(([failure]) => failure),
    detail: present.map(([, text]) => text),
  };
}

/** Verify an ordered run of sealed receipts for one agent, including chain linkage. */
export function verifySealedChain(receipts: readonly SignedReceipt[], trust: SealedTrust): VerificationResult {
  const results = receipts.map((receipt, index) => {
    const previous = index === 0 ? null : hashReceiptBody((receipts[index - 1] as SignedReceipt).body);
    return { index, result: verifySealedReceipt(receipt, trust, { expectedPreviousHash: previous }) };
  });
  const failures = results.flatMap(({ result }) => result.failures);
  return {
    valid: failures.length === 0,
    failures,
    detail: results.flatMap(({ index, result }) => result.detail.map((d) => `Receipt ${index}: ${d}`)),
  };
}
