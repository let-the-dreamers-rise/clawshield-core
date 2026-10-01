/**
 * The gateway's HTTP API.
 *
 *   public   GET  /healthz /readyz /v1/trust
 *            GET  /v1/receipts/:id  /v1/agents/:id/receipts      (when receipts are public)
 *            POST /v1/receipts/verify /v1/chains/verify
 *   agent    POST /v1/decisions
 *            GET  /v1/agents/:self   /v1/receipts/:id/transaction (own receipts only)
 *   admin    POST /v1/agents   GET /v1/agents   GET /v1/agents/:id
 *            POST /v1/agents/:id/keys   GET /v1/agents/:id/keys   DELETE /v1/keys/:keyId
 *            POST /v1/agents/:id/revoke /reinstate   PUT /v1/agents/:id/drawdown
 *            GET  /v1/audit
 *
 * Authentication is an API key in `Authorization: Bearer gk_...`. An admin key administers; an
 * agent key decides for its own agent and reads its own private data, nothing more. An admin
 * cannot take decisions: who acted is always an agent identity, so the receipt chain and the
 * audit trail never have to guess.
 *
 * Every response is { success, data, error, meta? } and carries an X-Request-Id. Each request is
 * logged as one JSON line with that id, route, status, latency and key id. Never the credential,
 * never the body.
 */

import { randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createRateLimiter, type RateLimitConfig } from "../server/rate-limit.ts";
import { HttpError, clientOf, readJsonBody, send, sendError, type Meta } from "../server/http.ts";
import type { RpcClient } from "../solana/rpc.ts";
import type { Policy } from "../policy/types.ts";
import type { GatewayStore } from "./store.ts";
import type { GatewayService } from "./service.ts";
import { authenticate, type Principal } from "./authenticate.ts";
import { ROUTES, matchRoute, type RouteContext, type RouteDef, type RouteResult } from "./routes.ts";

export interface TrustInfo {
  readonly mode: "plaintext" | "sealed";
  readonly commitment: string;
  /** Published in plaintext mode: anyone may replay every decision against it. */
  readonly policyDocument?: Policy;
  readonly circuitId?: string;
  readonly programId?: string;
  readonly policy?: string;
  readonly clusterPublicKey?: string;
}

export interface GatewayServerConfig {
  readonly store: GatewayStore;
  readonly service: GatewayService;
  readonly trust: TrustInfo;
  /** Receipts are designed to be published. Set false to require a key to read them. */
  readonly publicReceipts: boolean;
  readonly trustProxy?: boolean;
  readonly rpc?: RpcClient;
  readonly maxBodyBytes?: number;
  /** Per client address, every route. */
  readonly rateLimit?: RateLimitConfig;
  /** Per API key, decisions only. */
  readonly decisionRateLimit?: RateLimitConfig;
  readonly operatorPublicKey?: string;
  readonly now?: () => number;
  readonly log?: (line: string) => void;
}

export function createGatewayHandler(config: GatewayServerConfig): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const now = config.now ?? (() => Date.now());
  const log = config.log ?? ((line: string) => process.stdout.write(`${line}\n`));
  const limit = config.maxBodyBytes ?? 64 * 1024;
  const perClient = createRateLimiter(config.rateLimit ?? { capacity: 120, refillPerSecond: 2 });
  const perKey = createRateLimiter(config.decisionRateLimit ?? { capacity: 30, refillPerSecond: 0.5 });

  return async (req, res) => {
    const started = Date.now();
    const requestId = randomBytes(8).toString("hex");
    // Returned on every response, so a client holding a failure can name the log line behind it.
    res.setHeader("x-request-id", requestId);
    const url = new URL(req.url ?? "/", "http://gateway.invalid");
    let principal: Principal | undefined;
    let route = "unmatched";
    try {
      const rate = perClient.take(clientOf(req, config.trustProxy ?? false));
      if (!rate.allowed) throw new HttpError(429, "Rate limit exceeded", { "retry-after": String(rate.retryAfterSeconds) });

      const match = matchRoute(req.method ?? "GET", url.pathname);
      if (match.kind === "not_found") throw new HttpError(404, "Not found");
      if (match.kind === "method") throw new HttpError(405, `Use ${match.allowed.join(", ")}`, { allow: match.allowed.join(", ") });
      route = match.route.name;

      principal = authenticate(config.store, req.headers.authorization, now());
      const def: RouteDef = ROUTES[match.route.name];
      const needsKey = def.access === "agent" || def.access === "self" || def.access === "admin" || (def.access === "receipts" && !config.publicReceipts);
      if (needsKey && !principal) throw new HttpError(401, "Missing or invalid API key", { "www-authenticate": "Bearer" });
      if (def.access === "admin" && principal?.role !== "admin") throw new HttpError(403, "Admin key required");
      if (def.access === "agent" && principal?.role !== "agent") throw new HttpError(403, "Agent key required");
      if (match.route.name === "decide" && principal) {
        const r = perKey.take(principal.keyId);
        if (!r.allowed) throw new HttpError(429, "Decision rate limit exceeded for this key", { "retry-after": String(r.retryAfterSeconds) });
      }

      const body = def.body ? await readJsonBody(req, limit) : undefined;
      const ctx: RouteContext = { config, principal, params: match.params, query: url.searchParams, body, now: now() };
      const result: RouteResult = await def.handle(ctx);
      send(res, result.status ?? 200, { success: true, data: result.data, error: null, ...(result.meta ? { meta: result.meta as Meta } : {}) });
    } catch (err) {
      if (!sendError(res, err)) {
        log(JSON.stringify({ level: "error", id: requestId, route, error: err instanceof Error ? err.message : String(err) }));
      }
    } finally {
      log(JSON.stringify({ level: "info", id: requestId, method: req.method, path: url.pathname, route, status: res.statusCode, ms: Date.now() - started, key: principal?.keyId ?? null }));
    }
  };
}

export function createGatewayServer(config: GatewayServerConfig): Server {
  const handle = createGatewayHandler(config);
  const server = createServer((req, res) => void handle(req, res));
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  return server;
}
