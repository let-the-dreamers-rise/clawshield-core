/**
 * The operator's signature over a receipt body.
 *
 * Shared by the plaintext and sealed verifiers: whatever else differs between the two modes,
 * both start from "the holder of this key asserted exactly these bytes".
 */

import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalBytes, type Canonicalisable } from "./canonical.ts";
import type { SignedReceipt } from "./types.ts";

/** Returns a description of the problem, or null when the signature holds. */
export function checkReceiptSignature(receipt: SignedReceipt): string | null {
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(receipt.publicKey, "base64"),
      format: "der",
      type: "spki",
    });
    const message = canonicalBytes(receipt.body as unknown as Canonicalisable);
    const ok = cryptoVerify(null, message, publicKey, Buffer.from(receipt.signature, "base64"));
    return ok ? null : "Ed25519 signature does not verify over the canonical receipt body";
  } catch (err) {
    return `Signature check threw: ${err instanceof Error ? err.message : String(err)}`;
  }
}
