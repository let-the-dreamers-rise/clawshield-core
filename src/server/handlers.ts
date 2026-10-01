/**
 * Request handlers for the hosted verifier, free of any HTTP plumbing.
 *
 * Each takes the parsed JSON body and returns verification data, or throws a SchemaError
 * describing what was wrong with the request. A caller supplies exactly one of:
 *
 *   policy  the plaintext policy, for replay-based verification
 *   trust   the pinned commitment, circuit and cluster key, for a sealed receipt
 *
 * Supplying both is refused rather than guessed at: the two modes have different trust
 * assumptions, and the caller should know which one they are relying on.
 */

import { hashPolicy } from "../receipt/sign.ts";
import { verifyChain, verifyReceipt } from "../receipt/verify.ts";
import { verifySealedChain, verifySealedReceipt, type SealedTrust } from "../receipt/verify-sealed.ts";
import { SchemaError, parsePolicy, parseSealedTrust, parseSignedReceipt } from "../io/schema.ts";
import { array, opt, record, hex64 } from "../io/validate.ts";
import type { Policy } from "../policy/types.ts";
import type { VerificationResult } from "../receipt/types.ts";

export const MAX_CHAIN_LENGTH = 1_000;

export interface VerificationData extends VerificationResult {
  readonly mode: "plaintext" | "sealed";
}

type Anchor = { readonly mode: "plaintext"; readonly policy: Policy } | { readonly mode: "sealed"; readonly trust: SealedTrust };

function anchorOf(o: Readonly<Record<string, unknown>>): Anchor {
  const hasPolicy = o["policy"] !== undefined;
  const hasTrust = o["trust"] !== undefined;
  if (hasPolicy === hasTrust) {
    throw new SchemaError("", "supply exactly one of policy (plaintext) or trust (sealed)");
  }
  return hasPolicy
    ? { mode: "plaintext", policy: parsePolicy(o["policy"], "policy") }
    : { mode: "sealed", trust: parseSealedTrust(o["trust"], "trust") };
}

export function handleVerifyReceipt(body: unknown): VerificationData {
  const o = record(body, "", ["receipt"], ["policy", "trust", "expectedPreviousHash"]);
  const receipt = parseSignedReceipt(o["receipt"], "receipt");
  const anchor = anchorOf(o);
  const expectedPreviousHash =
    o["expectedPreviousHash"] === null ? null : opt(o, "expectedPreviousHash", "", hex64);

  const result =
    anchor.mode === "plaintext"
      ? verifyReceipt(receipt, anchor.policy, { expectedPreviousHash })
      : verifySealedReceipt(receipt, anchor.trust, { expectedPreviousHash });
  return { mode: anchor.mode, ...result };
}

export function handleVerifyChain(body: unknown): VerificationData {
  const o = record(body, "", ["receipts"], ["policy", "trust"]);
  const receipts = array(o["receipts"], "receipts", parseSignedReceipt, MAX_CHAIN_LENGTH);
  const anchor = anchorOf(o);

  if (anchor.mode === "plaintext") {
    const expected = hashPolicy(anchor.policy);
    const result = verifyChain(receipts, (hash) => (hash === expected ? anchor.policy : undefined));
    return { mode: "plaintext", ...result };
  }
  return { mode: "sealed", ...verifySealedChain(receipts, anchor.trust) };
}
