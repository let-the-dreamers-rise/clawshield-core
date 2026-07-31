/**
 * Third-party verification.
 *
 * This is the file that makes the whole system worth building. It takes a receipt and the
 * claimed policy, and answers one question:
 *
 *   Did this operator actually enforce the policy they say they enforced?
 *
 * It needs no database access, no API key, and no trust in the operator. Four independent
 * checks, all of which must pass:
 *
 *   1. the signature is valid over the canonical body
 *   2. the policy hash in the receipt matches the policy supplied
 *   3. replaying the engine on the recorded request and state reproduces the recorded verdict
 *   4. the receipt chains correctly to its predecessor
 *
 * Check 3 is the one competitors cannot offer. Anyone can sign a log. Only a deterministic
 * engine can prove the log describes what the code actually did.
 */

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalBytes, type Canonicalisable } from "./canonical.ts";
import { evaluate } from "../policy/engine.ts";
import { hashPolicy, hashReceiptBody } from "./sign.ts";
import type { Policy } from "../policy/types.ts";
import type { SignedReceipt, VerificationFailure, VerificationResult } from "./types.ts";

export interface VerifyOptions {
  /** Hash of the previous receipt for this agent, or null if this is the first. */
  readonly expectedPreviousHash?: string | null;
}

export function verifyReceipt(
  receipt: SignedReceipt,
  policy: Policy,
  options: VerifyOptions = {},
): VerificationResult {
  const failures: VerificationFailure[] = [];
  const detail: string[] = [];

  // 1. Signature over the canonical body.
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(receipt.publicKey, "base64"),
      format: "der",
      type: "spki",
    });
    const message = canonicalBytes(receipt.body as unknown as Canonicalisable);
    const ok = cryptoVerify(null, message, publicKey, Buffer.from(receipt.signature, "base64"));
    if (!ok) {
      failures.push("bad_signature");
      detail.push("Ed25519 signature does not verify over the canonical receipt body");
    }
  } catch (err) {
    failures.push("bad_signature");
    detail.push(`Signature check threw: ${err instanceof Error ? err.message : String(err)}`);
  }

  // 2. The policy supplied is the policy that was in force.
  const actualPolicyHash = hashPolicy(policy);
  if (actualPolicyHash !== receipt.body.policyHash) {
    failures.push("policy_hash_mismatch");
    detail.push(
      `Receipt binds policy ${receipt.body.policyHash} but the supplied policy hashes to ${actualPolicyHash}`,
    );
  }

  // 3. Replay. The engine is deterministic, so the verdict must reproduce exactly.
  const replayed = evaluate(
    policy,
    receipt.body.request,
    receipt.body.state,
    receipt.body.decision.decidedAt,
  );
  if (replayed.verdict !== receipt.body.decision.verdict) {
    failures.push("decision_not_reproducible");
    detail.push(
      `Replay produced "${replayed.verdict}" but the receipt records "${receipt.body.decision.verdict}"`,
    );
  } else {
    const replayedRules = replayed.reasons.map((r) => r.rule).join(",");
    const recordedRules = receipt.body.decision.reasons.map((r) => r.rule).join(",");
    if (replayedRules !== recordedRules) {
      failures.push("decision_not_reproducible");
      detail.push(`Verdict matched but firing rules differ: replay [${replayedRules}] vs receipt [${recordedRules}]`);
    }
  }

  // 4. Chain integrity.
  if (options.expectedPreviousHash !== undefined) {
    if (receipt.body.previousReceiptHash !== options.expectedPreviousHash) {
      failures.push("chain_broken");
      detail.push(
        `Receipt points at previous ${receipt.body.previousReceiptHash} but ${options.expectedPreviousHash} was expected`,
      );
    }
  }

  return { valid: failures.length === 0, failures, detail };
}

/** Verify an ordered run of receipts for one agent, including chain linkage. */
export function verifyChain(
  receipts: readonly SignedReceipt[],
  policyFor: (policyHash: string) => Policy | undefined,
): VerificationResult {
  const failures: VerificationFailure[] = [];
  const detail: string[] = [];
  let expectedPrevious: string | null = null;

  for (const [index, receipt] of receipts.entries()) {
    const policy = policyFor(receipt.body.policyHash);
    if (!policy) {
      failures.push("policy_hash_mismatch");
      detail.push(`Receipt ${index}: no policy known for hash ${receipt.body.policyHash}`);
      continue;
    }

    const result = verifyReceipt(receipt, policy, { expectedPreviousHash: expectedPrevious });
    if (!result.valid) {
      failures.push(...result.failures);
      detail.push(...result.detail.map((d) => `Receipt ${index}: ${d}`));
    }
    expectedPrevious = hashReceiptBody(receipt.body);
  }

  return { valid: failures.length === 0, failures, detail };
}
