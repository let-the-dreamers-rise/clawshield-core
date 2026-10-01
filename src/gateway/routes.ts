/**
 * The gateway's routes: path, method, who may call it, and what it does. Access is declared
 * beside each handler so the authorisation rule for any endpoint can be read in one place:
 *
 *   public    anyone
 *   receipts  anyone when receipts are public, otherwise any valid key
 *   agent     an agent key; the agent acted for is always the key's own
 *   self      an admin key, or the agent key of the agent named in the path
 *   admin     an admin key
 */

import { HttpError } from "../server/http.ts";
import { handleVerifyChain, handleVerifyReceipt } from "../server/handlers.ts";
import { issueAgentKey } from "./admin.ts";
import type { Principal } from "./auth.ts";
import { QueueFullError } from "./mutex.ts";
import { agentId, parseCreateAgent, parseCreateKey, parseDecisionRequest, parseDrawdown, parsePage } from "./requests.ts";
import { NotFoundError } from "./service.ts";
import { ConflictError, type StoredReceipt } from "./store.ts";
import type { GatewayServerConfig } from "./server.ts";

export type Access = "public" | "receipts" | "agent" | "self" | "admin";

export interface RouteContext {
  readonly config: GatewayServerConfig;
  readonly principal?: Principal;
  readonly params: Readonly<Record<string, string>>;
  readonly query: URLSearchParams;
  readonly body: unknown;
  readonly now: number;
}

export interface RouteResult {
  readonly status?: number;
  readonly data: unknown;
  readonly meta?: { readonly total: number; readonly limit: number; readonly next: string | null };
}

export interface RouteDef {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly path: string;
  readonly access: Access;
  readonly body?: boolean;
  readonly handle: (ctx: RouteContext) => RouteResult | Promise<RouteResult>;
}

const ok = (data: unknown, status = 200): RouteResult => ({ status, data });

/** Domain failures become the HTTP status a client can act on. */
function mapped<T>(fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    throw toHttp(err);
  }
}

function toHttp(err: unknown): unknown {
  if (err instanceof NotFoundError) return new HttpError(404, err.message);
  if (err instanceof ConflictError) return new HttpError(409, err.message);
  if (err instanceof QueueFullError) return new HttpError(429, err.message, { "retry-after": "5" });
  return err;
}

function requireSelf(ctx: RouteContext, agent: string): void {
  const p = ctx.principal;
  if (p?.role === "admin" || (p?.role === "agent" && p.agentId === agent)) return;
  throw new HttpError(403, "This key may not read another agent's data");
}

function existingAgent(ctx: RouteContext): string {
  const id = agentId(ctx.params["id"], "id");
  if (!ctx.config.store.getAgent(id)) throw new HttpError(404, `No agent ${id}`);
  return id;
}

const actor = (ctx: RouteContext): string => `key:${ctx.principal?.keyId ?? "anonymous"}`;

const publicReceipt = (r: StoredReceipt) => r.receipt;

export const ROUTES = {
  health: { method: "GET", path: "/healthz", access: "public", handle: () => ok({ status: "ok" }) },

  ready: {
    method: "GET",
    path: "/readyz",
    access: "public",
    handle: (ctx) => {
      const database = ctx.config.store.ping() ? "ok" : "down";
      if (database !== "ok") throw new HttpError(503, "Database unavailable");
      return ok({ database, rpc: ctx.config.rpc ? "configured" : "offline", execution: ctx.config.service.execution });
    },
  },

  trust: {
    method: "GET",
    path: "/v1/trust",
    access: "public",
    handle: (ctx) =>
      ok({
        ...ctx.config.trust,
        vault: ctx.config.service.vaultAddress,
        cluster: ctx.config.service.cluster,
        operatorPublicKey: ctx.config.service.operatorPublicKey,
        execution: ctx.config.service.execution,
      }),
  },

  verifyReceipt: { method: "POST", path: "/v1/receipts/verify", access: "public", body: true, handle: async (ctx) => ok(await handleVerifyReceipt(ctx.body, { rpc: ctx.config.rpc })) },
  verifyChain: { method: "POST", path: "/v1/chains/verify", access: "public", body: true, handle: async (ctx) => ok(await handleVerifyChain(ctx.body, { rpc: ctx.config.rpc })) },

  getReceipt: {
    method: "GET",
    path: "/v1/receipts/:id",
    access: "receipts",
    handle: (ctx) => {
      const stored = ctx.config.store.getReceipt(ctx.params["id"] ?? "");
      if (!stored) throw new HttpError(404, "No such receipt");
      return ok(publicReceipt(stored));
    },
  },

  receiptTransaction: {
    method: "GET",
    path: "/v1/receipts/:id/transaction",
    access: "self",
    handle: (ctx) => {
      const stored = ctx.config.store.getReceipt(ctx.params["id"] ?? "");
      if (!stored) throw new HttpError(404, "No such receipt");
      requireSelf(ctx, stored.agentId);
      if (stored.signedTransaction === undefined) throw new HttpError(404, "This decision produced no transaction");
      return ok({ signedTransaction: stored.signedTransaction, submittedSignature: stored.submittedSignature ?? null });
    },
  },

  listReceipts: {
    method: "GET",
    path: "/v1/agents/:id/receipts",
    access: "receipts",
    handle: (ctx) => {
      const id = existingAgent(ctx);
      const page = parsePage(ctx.query);
      const result = ctx.config.store.listReceipts(id, { afterSeq: page.after, limit: page.limit });
      const last = result.items.at(-1)?.seq;
      const next = last !== undefined && last < result.total ? String(last) : null;
      return { data: result.items.map(publicReceipt), meta: { total: result.total, limit: page.limit, next } };
    },
  },

  decide: {
    method: "POST",
    path: "/v1/decisions",
    access: "agent",
    body: true,
    handle: async (ctx) => {
      const request = parseDecisionRequest(ctx.body);
      try {
        return ok(await ctx.config.service.decide(ctx.principal?.agentId as string, request.transfer, request.modelReasoning));
      } catch (err) {
        throw toHttp(err);
      }
    },
  },

  createAgent: {
    method: "POST",
    path: "/v1/agents",
    access: "admin",
    body: true,
    handle: (ctx) => {
      const input = parseCreateAgent(ctx.body);
      const agent = mapped(() => ctx.config.store.createAgent({ ...input, now: ctx.now }));
      ctx.config.store.audit({ at: ctx.now, actor: actor(ctx), action: "agent.create", subject: agent.id, detail: { label: agent.label } });
      return ok(agent, 201);
    },
  },

  listAgents: { method: "GET", path: "/v1/agents", access: "admin", handle: (ctx) => ok(ctx.config.store.listAgents()) },

  getAgent: {
    method: "GET",
    path: "/v1/agents/:id",
    access: "self",
    handle: (ctx) => {
      const id = agentId(ctx.params["id"], "id");
      requireSelf(ctx, id);
      return ok(mapped(() => ctx.config.service.status(id)));
    },
  },

  createKey: {
    method: "POST",
    path: "/v1/agents/:id/keys",
    access: "admin",
    body: true,
    handle: (ctx) => {
      const id = existingAgent(ctx);
      const { label } = parseCreateKey(ctx.body);
      const key = issueAgentKey(ctx.config.store, { agentId: id, label, actor: actor(ctx), now: ctx.now });
      // The only time the secret is ever shown.
      return ok({ keyId: key.keyId, token: key.token, role: "agent", agentId: id, label }, 201);
    },
  },

  listKeys: { method: "GET", path: "/v1/agents/:id/keys", access: "admin", handle: (ctx) => ok(ctx.config.store.listKeys(existingAgent(ctx))) },

  revokeKey: {
    method: "DELETE",
    path: "/v1/keys/:keyId",
    access: "admin",
    handle: (ctx) => {
      const keyId = ctx.params["keyId"] ?? "";
      if (!ctx.config.store.revokeKey(keyId, ctx.now)) throw new HttpError(404, "No active key with that id");
      ctx.config.store.audit({ at: ctx.now, actor: actor(ctx), action: "key.revoke", subject: keyId });
      return ok({ keyId, revoked: true });
    },
  },

  revokeAgent: {
    method: "POST",
    path: "/v1/agents/:id/revoke",
    access: "admin",
    handle: (ctx) => {
      const id = existingAgent(ctx);
      ctx.config.store.audit({ at: ctx.now, actor: actor(ctx), action: "agent.revoke", subject: id });
      return ok(ctx.config.store.setRevoked(id, true));
    },
  },

  reinstateAgent: {
    method: "POST",
    path: "/v1/agents/:id/reinstate",
    access: "admin",
    handle: (ctx) => {
      const id = existingAgent(ctx);
      ctx.config.store.audit({ at: ctx.now, actor: actor(ctx), action: "agent.reinstate", subject: id });
      return ok(ctx.config.store.setRevoked(id, false));
    },
  },

  setDrawdown: {
    method: "PUT",
    path: "/v1/agents/:id/drawdown",
    access: "admin",
    body: true,
    handle: (ctx) => {
      const id = existingAgent(ctx);
      const drawdown = parseDrawdown(ctx.body);
      ctx.config.store.setDrawdown(id, drawdown);
      ctx.config.store.audit({ at: ctx.now, actor: actor(ctx), action: "agent.drawdown", subject: id, detail: { drawdownFromPeak: drawdown } });
      return ok(mapped(() => ctx.config.service.status(id)));
    },
  },

  audit: {
    method: "GET",
    path: "/v1/audit",
    access: "admin",
    handle: (ctx) => {
      const page = parsePage(ctx.query, 500);
      const result = ctx.config.store.listAudit({ afterId: page.after, limit: page.limit });
      const last = result.items.at(-1)?.id;
      return { data: result.items, meta: { total: result.total, limit: page.limit, next: last !== undefined && result.items.length === page.limit ? String(last) : null } };
    },
  },
} as const satisfies Record<string, RouteDef>;

export type RouteName = keyof typeof ROUTES;

interface Compiled {
  readonly name: RouteName;
  readonly method: string;
  readonly pattern: RegExp;
  readonly keys: readonly string[];
}

const COMPILED: readonly Compiled[] = (Object.entries(ROUTES) as [RouteName, RouteDef][]).map(([name, def]) => {
  const keys: string[] = [];
  const source = def.path.replace(/:([A-Za-z]+)/g, (_, key: string) => {
    keys.push(key);
    return "([^/]{1,128})";
  });
  return { name, method: def.method, pattern: new RegExp(`^${source}$`), keys };
});

export type RouteMatch =
  | { readonly kind: "ok"; readonly route: Compiled; readonly params: Readonly<Record<string, string>> }
  | { readonly kind: "method"; readonly allowed: readonly string[] }
  | { readonly kind: "not_found" };

export function matchRoute(method: string, path: string): RouteMatch {
  const hits = COMPILED.map((route) => ({ route, m: route.pattern.exec(path) })).filter((h) => h.m !== null);
  if (hits.length === 0) return { kind: "not_found" };
  const hit = hits.find((h) => h.route.method === method);
  if (!hit || !hit.m) return { kind: "method", allowed: [...new Set(hits.map((h) => h.route.method))] };
  const m = hit.m;
  const params = Object.fromEntries(hit.route.keys.map((k, i) => [k, decodeURIComponent(m[i + 1] ?? "")]));
  return { kind: "ok", route: hit.route, params };
}
