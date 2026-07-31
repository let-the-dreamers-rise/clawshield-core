/**
 * Receipt hashing and signing.
 *
 * Ed25519 via node:crypto - no third-party crypto dependency, because a supply-chain
 * compromise in a signing library would invalidate every receipt ever issued.
 */

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { canonicalBytes, canonicalise, type Canonicalisable } from "./canonical.ts";
import type { Policy } from "../policy/types.ts";
import type { ReceiptBody, SignedReceipt } from "./types.ts";

export interface Keypair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

export function generateKeypair(): Keypair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey };
}

export function keypairFromPkcs8(pkcs8Pem: string): Keypair {
  const privateKey = createPrivateKey(pkcs8Pem);
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Hash of the canonical policy. This is what gets bound into the receipt. */
export function hashPolicy(policy: Policy): string {
  return sha256Hex(canonicalBytes(policy as unknown as Canonicalisable));
}

export function hashReceiptBody(body: ReceiptBody): string {
  return sha256Hex(canonicalBytes(body as unknown as Canonicalisable));
}

export function signReceipt(body: ReceiptBody, keys: Keypair): SignedReceipt {
  const message = canonicalBytes(body as unknown as Canonicalisable);
  const signature = sign(null, message, keys.privateKey);

  return {
    body,
    signature: signature.toString("base64"),
    publicKey: keys.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    algorithm: "ed25519",
  };
}

/** Exposed for debugging: the exact string that gets signed. */
export function signedPayload(body: ReceiptBody): string {
  return canonicalise(body as unknown as Canonicalisable);
}
