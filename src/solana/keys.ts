/**
 * Conversions between node:crypto Ed25519 keys and Solana's representations.
 *
 * A Solana keypair file is 64 bytes: the 32-byte seed followed by the 32-byte public key. The
 * public half is redundant, which makes it a consistency check worth enforcing: a file whose
 * halves disagree is corrupted or forged, and signing with it would authorise transfers from an
 * account the operator never named.
 */

import { createPrivateKey, createPublicKey, type KeyObject } from "node:crypto";
import { encodeBase58 } from "./base58.ts";
import type { Keypair } from "../receipt/sign.ts";

/** RFC 8410 PKCS#8 prefix for an Ed25519 private key; the 32-byte seed follows it. */
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function publicKeyBytes(publicKey: KeyObject): Uint8Array {
  const jwk = publicKey.export({ format: "jwk" });
  if (jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new TypeError("Expected an Ed25519 public key");
  }
  return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}

/** The base58 address of an Ed25519 public key. */
export function solanaAddress(publicKey: KeyObject): string {
  return encodeBase58(publicKeyBytes(publicKey));
}

export function keypairFromSeed(seed: Uint8Array): Keypair {
  if (seed.length !== 32) {
    throw new RangeError(`An Ed25519 seed is 32 bytes, got ${seed.length}`);
  }
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

/**
 * The 64-byte solana-keygen form of a keypair: seed then public key. Secret material - callers
 * write it to a file with restrictive permissions and never log it.
 */
export function solanaSecretKey(keys: Keypair): Uint8Array {
  const jwk = keys.privateKey.export({ format: "jwk" });
  if (typeof jwk.d !== "string") throw new TypeError("Expected an Ed25519 private key");
  return Uint8Array.from([...Buffer.from(jwk.d, "base64url"), ...publicKeyBytes(keys.publicKey)]);
}

/** Load the 64-byte secret key format used by solana-keygen. */
export function keypairFromSolanaSecretKey(secret: Uint8Array): Keypair {
  if (secret.length !== 64) {
    throw new RangeError(`A Solana secret key is 64 bytes, got ${secret.length}`);
  }
  const keys = keypairFromSeed(secret.subarray(0, 32));
  const derived = publicKeyBytes(keys.publicKey);
  const claimed = secret.subarray(32);
  if (!Buffer.from(derived).equals(Buffer.from(claimed))) {
    throw new Error("The public half of the secret key does not match the key derived from its seed");
  }
  return keys;
}
