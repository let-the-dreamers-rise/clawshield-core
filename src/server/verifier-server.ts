/**
 * The hosted verifier: an unauthenticated public HTTP endpoint, built like one.
 *
 *   GET  /                     browser verifier page
 *   GET  /healthz              liveness
 *   POST /v1/receipts/verify   { receipt, policy | trust, expectedPreviousHash? }
 *   POST /v1/chains/verify     { receipts, policy | trust }
 *
 * Every response uses one envelope: { success, data, error }. Request bodies are bounded and
 * must be JSON. Clients are rate limited per address. Errors in the request are 400s that name
 * the offending field; anything unexpected is a 500 with no detail, logged server side only.
 * There are no credentials and no state, so permissive CORS is safe and lets any page verify.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createRateLimiter, type RateLimitConfig } from "./rate-limit.ts";
import { BASE_HEADERS as SHARED_HEADERS, HttpError, clientOf, readJsonBody, send, sendError } from "./http.ts";
import { handleVerifyChain, handleVerifyReceipt, type HandlerContext } from "./handlers.ts";
import type { RpcClient } from "../solana/rpc.ts";
import { PAGE_CSP, PAGE_HTML } from "./page.ts";

export interface VerifierServerConfig {
  readonly maxBodyBytes?: number;
  readonly rateLimit?: RateLimitConfig;
  /** Read the client address from X-Forwarded-For. Only behind a proxy you control. */
  readonly trustProxy?: boolean;
  readonly log?: (line: string) => void;
  /** Enables checking on-chain attestations against the cluster's DecisionRecords. */
  readonly rpc?: RpcClient;
}

/** No credentials and no state, so any origin may call it. */
const CORS = { "access-control-allow-origin": "*" } as const;
const BASE_HEADERS = { ...SHARED_HEADERS, ...CORS } as const;

const ROUTES: Readonly<Record<string, { readonly method: "GET" | "POST"; readonly handle?: (body: unknown, ctx: HandlerContext) => Promise<unknown> }>> = {
  "/": { method: "GET" },
  "/healthz": { method: "GET" },
  "/v1/receipts/verify": { method: "POST", handle: handleVerifyReceipt },
  "/v1/chains/verify": { method: "POST", handle: handleVerifyChain },
};

/**
 * The request handler on its own, so it can run under node:http here or as a serverless
 * function (see deploy/vercel), with identical behaviour.
 */
export function createVerifierHandler(config: VerifierServerConfig = {}): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const limit = config.maxBodyBytes ?? 1024 * 1024;
  const limiter = createRateLimiter(config.rateLimit ?? { capacity: 60, refillPerSecond: 1 });
  const log = config.log ?? ((line: string) => process.stderr.write(`${line}\n`));

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const rate = limiter.take(clientOf(req, config.trustProxy ?? false));
    if (!rate.allowed) {
      send(res, 429, { success: false, data: null, error: "Rate limit exceeded" }, { ...CORS, "retry-after": String(rate.retryAfterSeconds) });
      return;
    }

    const path = new URL(req.url ?? "/", "http://verifier.invalid").pathname;
    const route = ROUTES[path];
    if (!route) throw new HttpError(404, "Not found");
    if (req.method === "OPTIONS") {
      res.writeHead(204, { ...BASE_HEADERS, "access-control-allow-methods": `${route.method}, OPTIONS`, "access-control-allow-headers": "content-type", "access-control-max-age": "600" });
      res.end();
      return;
    }
    if (req.method !== route.method) {
      send(res, 405, { success: false, data: null, error: `Use ${route.method}` }, { ...CORS, allow: route.method });
      return;
    }

    if (path === "/") {
      res.writeHead(200, { ...BASE_HEADERS, "content-type": "text/html; charset=utf-8", "content-security-policy": PAGE_CSP, "x-frame-options": "DENY" });
      res.end(PAGE_HTML);
      return;
    }
    if (path === "/healthz") {
      send(res, 200, { success: true, data: { status: "ok", onChain: config.rpc !== undefined }, error: null }, CORS);
      return;
    }

    const body = await readJsonBody(req, limit);
    const data = route.handle ? await route.handle(body, { rpc: config.rpc }) : null;
    send(res, 200, { success: true, data, error: null }, CORS);
  }

  return async (req, res) => {
    try {
      await route(req, res);
    } catch (err) {
      if (!sendError(res, err, CORS)) {
        log(`verifier: unexpected error on ${req.method} ${req.url}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  };
}

export function createVerifierServer(config: VerifierServerConfig = {}): Server {
  const handle = createVerifierHandler(config);
  const server = createServer((req, res) => void handle(req, res));
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  return server;
}
