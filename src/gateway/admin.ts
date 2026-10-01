/**
 * Operator actions that sit outside the HTTP API: creating the first admin key. Every gateway
 * starts with no keys at all, and the first admin key can only be minted by someone with the
 * database file - that is, the operator - via `genkai gateway-admin create-admin-key`.
 */

import { generateApiKey, hashSecret, type ApiKey } from "./auth.ts";
import type { GatewayStore } from "./store.ts";

export function issueAdminKey(store: GatewayStore, opts: { readonly label: string; readonly now: number }): ApiKey {
  const key = generateApiKey();
  store.insertKey({ keyId: key.keyId, hash: hashSecret(key.secret), role: "admin", label: opts.label, now: opts.now });
  store.audit({ at: opts.now, actor: "operator", action: "key.create", subject: key.keyId, detail: { role: "admin", label: opts.label } });
  return key;
}

export function issueAgentKey(store: GatewayStore, opts: { readonly agentId: string; readonly label: string; readonly actor: string; readonly now: number }): ApiKey {
  const key = generateApiKey();
  store.insertKey({ keyId: key.keyId, hash: hashSecret(key.secret), role: "agent", agentId: opts.agentId, label: opts.label, now: opts.now });
  store.audit({ at: opts.now, actor: opts.actor, action: "key.create", subject: key.keyId, detail: { role: "agent", agentId: opts.agentId, label: opts.label } });
  return key;
}
