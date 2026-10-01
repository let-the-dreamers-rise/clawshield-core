/**
 * Turn an Authorization header into a principal, or nothing.
 *
 * Every failure - no header, a malformed token, an unknown key id, a wrong secret, a revoked
 * key - returns undefined, and the caller answers all of them with the same 401. Telling a
 * client which part was wrong would tell an attacker which part to keep guessing.
 */

import { bearerToken, parseApiKey, secretMatches, type Principal } from "./auth.ts";
import type { GatewayStore } from "./store.ts";

export type { Principal } from "./auth.ts";

export function authenticate(store: GatewayStore, header: string | undefined, now: number): Principal | undefined {
  const token = bearerToken(header);
  const parsed = token === null ? null : parseApiKey(token);
  if (!parsed) return undefined;
  const key = store.findKey(parsed.keyId);
  if (!key || key.revokedAt !== undefined || !secretMatches(parsed.secret, key.hash)) return undefined;
  store.touchKey(key.keyId, now);
  return key.agentId === undefined ? { keyId: key.keyId, role: key.role } : { keyId: key.keyId, role: key.role, agentId: key.agentId };
}
