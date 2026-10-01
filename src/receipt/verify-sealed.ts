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
 *
 * A receipt from the live Arcium MXE carries an on-chain attestation instead of a signature.
 * Its trust anchor pins the GENKAI program and the PolicyRecord rather than a cluster key, and
 * the evidence is the DecisionRecord the program wrote, so it can only be checked with RPC
 * access: verifySealedReceiptOnChain. The offline verifier checks everything else about such a
 * receipt and then reports attestation_unchecked - it never calls one valid.
 */

import { hashReceiptBody } from "./sign.ts";
import { checkReceiptSignature } from "./verify-signature.ts";
import { checkBoundTransaction } from "./verify-transaction.ts";
import { SEALED_REASON, verifyAttestation } from "../policy/sealed.ts";
import { attestedPayload, isOnChainAttestation } from "../mxe/types.ts";
import { checkOnChainDecision, claimOfReceipt } from "../mxe/onchain.ts";
import type { RpcClient } from "../solana/rpc.ts";
import type { Canonicalisable } from "./canonical.ts";
import type { ReceiptBody, SignedReceipt, VerificationFailure, VerificationResult } from "./types.ts";

export interface SignedTrust {
  readonly commitment: string;
  readonly circuitId: string;
  readonly clusterPublicKey: string;
}

/** For receipts from the live MXE. Both addresses are pinned: see OnChainCheckOptions.policy. */
export interface OnChainTrust {
  readonly commitment: string;
  readonly circuitId: string;
  readonly programId: string;
  readonly policy: string;
}

export type SealedTrust = SignedTrust | OnChainTrust;

export function isOnChainTrust(trust: SealedTrust): trust is OnChainTrust {
  return "programId" in trust;
}

export interface SealedVerifyOptions {
  readonly expectedPreviousHash?: string | null;
}

type Finding = readonly [VerificationFailure, string];

function checkOnChainPointer(body: ReceiptBody, trust: SealedTrust): Finding | null {
  const attestation = body.attestation;
  if (!attestation || !isOnChainAttestation(attestation)) return null;
  if (!isOnChainTrust(trust)) return ["attestation_invalid", "An on-chain attestation needs a trust anchor that pins the program and policy record"];
  if (attestation.programId !== trust.programId) {
    return ["attestation_invalid", `Attestation names program ${attestation.programId}, pinned ${trust.programId}`];
  }
  if (attestation.policy !== trust.policy) {
    return ["attestation_invalid", `Attestation names policy record ${attestation.policy}, pinned ${trust.policy}`];
  }
  return ["attestation_unchecked", `The evidence is the decision record at ${attestation.decision}; verify with RPC access`];
}

function checkAttestation(body: ReceiptBody, trust: SealedTrust): Finding | null {
  const attestation = body.attestation;
  if (!attestation) return ["attestation_missing", "A sealed receipt must carry its MXE attestation"];
  if (attestation.circuitId !== trust.circuitId) {
    return ["attestation_invalid", `Attestation names circuit ${attestation.circuitId}, pinned ${trust.circuitId}`];
  }
  if (isOnChainAttestation(attestation)) return checkOnChainPointer(body, trust);
  if (isOnChainTrust(trust)) {
    return ["attestation_invalid", "The trust anchor pins an on-chain deployment but the receipt carries a signed attestation"];
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

function sealedFindings(receipt: SignedReceipt, trust: SealedTrust, options: SealedVerifyOptions): readonly Finding[] {
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

  return findings.filter((f): f is Finding => f !== null);
}

const resultOf = (findings: readonly Finding[]): VerificationResult => ({
  valid: findings.length === 0,
  failures: findings.map(([failure]) => failure),
  detail: findings.map(([, text]) => text),
});

export function verifySealedReceipt(
  receipt: SignedReceipt,
  trust: SealedTrust,
  options: SealedVerifyOptions = {},
): VerificationResult {
  return resultOf(sealedFindings(receipt, trust, options));
}

export interface OnChainVerifyOptions extends SealedVerifyOptions {
  readonly rpc: RpcClient;
}

/**
 * Verify a sealed receipt whose attestation is on chain: everything verifySealedReceipt checks,
 * plus the DecisionRecord itself - written by the pinned program, against the pinned policy
 * record, for this computation, this request, this verdict and this disclosure mode.
 */
export async function verifySealedReceiptOnChain(
  receipt: SignedReceipt,
  trust: OnChainTrust,
  options: OnChainVerifyOptions,
): Promise<VerificationResult> {
  const offline = sealedFindings(receipt, trust, options);
  const attestation = receipt.body.attestation;
  // attestation_unchecked is reported only for a well-formed pointer at the pinned deployment.
  // Without it the pointer is wrong or absent, and there is no record worth fetching.
  if (!offline.some(([f]) => f === "attestation_unchecked") || !attestation || !isOnChainAttestation(attestation)) {
    return resultOf(offline);
  }
  const pending = offline.filter(([failure]) => failure !== "attestation_unchecked");
  const check = await checkOnChainDecision(claimOfReceipt(receipt), {
    rpc: options.rpc,
    programId: trust.programId,
    policy: trust.policy,
    decision: attestation.decision,
    computationOffset: attestation.computationOffset,
  });
  const onChain: Finding[] = check.detail.map((d, i) => ["attestation_invalid", `On chain (${check.failures[i]}): ${d}`]);
  return resultOf([...pending, ...onChain]);
}

interface Indexed {
  readonly index: number;
  readonly result: VerificationResult;
}

const chainResult = (results: readonly Indexed[]): VerificationResult => {
  const failures = results.flatMap(({ result }) => result.failures);
  return {
    valid: failures.length === 0,
    failures,
    detail: results.flatMap(({ index, result }) => result.detail.map((d) => `Receipt ${index}: ${d}`)),
  };
};

const previousOf = (receipts: readonly SignedReceipt[], index: number): string | null =>
  index === 0 ? null : hashReceiptBody((receipts[index - 1] as SignedReceipt).body);

/** Verify an ordered run of sealed receipts for one agent, including chain linkage. */
export function verifySealedChain(receipts: readonly SignedReceipt[], trust: SealedTrust): VerificationResult {
  return chainResult(
    receipts.map((receipt, index) => ({ index, result: verifySealedReceipt(receipt, trust, { expectedPreviousHash: previousOf(receipts, index) }) })),
  );
}

/** verifySealedChain for on-chain attestations. Records are read one receipt at a time. */
export async function verifySealedChainOnChain(
  receipts: readonly SignedReceipt[],
  trust: OnChainTrust,
  rpc: RpcClient,
): Promise<VerificationResult> {
  const results: Indexed[] = [];
  for (const [index, receipt] of receipts.entries()) {
    results.push({ index, result: await verifySealedReceiptOnChain(receipt, trust, { rpc, expectedPreviousHash: previousOf(receipts, index) }) });
  }
  return chainResult(results);
}
