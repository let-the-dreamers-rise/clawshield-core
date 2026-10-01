/**
 * API keys for the gateway.
 *
 * A key is `gk_<keyId>_<secret>`: a 12-hex-character public id that names the key in logs,
 * listings and revocations, and 32 random bytes of secret. Only SHA-256 of the secret is stored.
 * A slow password hash buys nothing here: the secret has 256 bits of entropy, so there is no
 * dictionary to make expensive, and a fast hash keeps authentication cheap enough to sit on
 * every request.
 *
 * Lookup is by id, then the secret's hash is compared in constant time, so response timing
 * says nothing about how much of a guessed secret was right.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export type Role = "admin" | "agent";

export interface ApiKey {
  readonly keyId: string;
  readonly secret: string;
  /** The whole credential, shown to its holder once and never stored. */
  readonly token: string;
}

export interface Principal {
  readonly keyId: string;
  readonly role: Role;
  /** Set for agent keys: the one agent this key may act as. */
  readonly agentId?: string;
}

const TOKEN = /^gk_([0-9a-f]{12})_([A-Za-z0-9_-]{43})$/;

export function generateApiKey(): ApiKey {
  const keyId = randomBytes(6).toString("hex");
  const secret = randomBytes(32).toString("base64url");
  return { keyId, secret, token: `gk_${keyId}_${secret}` };
}

export function parseApiKey(token: string): { readonly keyId: string; readonly secret: string } | null {
  const m = TOKEN.exec(token);
  return m ? { keyId: m[1] as string, secret: m[2] as string } : null;
}

export function hashSecret(secret: string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(secret, "utf8").digest());
}

export function secretMatches(secret: string, storedHash: Uint8Array): boolean {
  const candidate = hashSecret(secret);
  return candidate.length === storedHash.length && timingSafeEqual(candidate, storedHash);
}

/** The token from an Authorization header, or null. The scheme name is case-insensitive. */
export function bearerToken(header: string | undefined): string | null {
  if (header === undefined) return null;
  const m = /^Bearer (\S+)$/i.exec(header);
  return m ? (m[1] as string) : null;
}
