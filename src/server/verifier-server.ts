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
import { fromJson, toJson } from "../io/json.ts";
import { SchemaError } from "../io/validate.ts";
import { createRateLimiter, type RateLimitConfig } from "./rate-limit.ts";
import { handleVerifyChain, handleVerifyReceipt } from "./handlers.ts";
import { PAGE_CSP, PAGE_HTML } from "./page.ts";

export interface VerifierServerConfig {
  readonly maxBodyBytes?: number;
  readonly rateLimit?: RateLimitConfig;
  /** Read the client address from X-Forwarded-For. Only behind a proxy you control. */
  readonly trustProxy?: boolean;
  readonly log?: (line: string) => void;
}

class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const BASE_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
  "access-control-allow-origin": "*",
} as const;

const ROUTES: Readonly<Record<string, { readonly method: "GET" | "POST"; readonly handle?: (body: unknown) => unknown }>> = {
  "/": { method: "GET" },
  "/healthz": { method: "GET" },
  "/v1/receipts/verify": { method: "POST", handle: handleVerifyReceipt },
  "/v1/chains/verify": { method: "POST", handle: handleVerifyChain },
};

function send(res: ServerResponse, status: number, payload: { success: boolean; data: unknown; error: string | null }, extra: Record<string, string> = {}) {
  const body = toJson(payload as never);
  res.writeHead(status, { ...BASE_HEADERS, "content-type": "application/json; charset=utf-8", ...extra });
  res.end(body);
}

/**
 * Read a bounded body. An oversized body is drained without being stored, so the client gets a
 * clean 413 instead of a reset connection, but only up to a hard cap: past that the socket is
 * destroyed rather than letting a client make the server read without limit.
 */
async function readBody(req: IncomingMessage, limit: number): Promise<string> {
  const drainCap = limit * 4;
  if (Number(req.headers["content-length"] ?? 0) > drainCap) {
    req.destroy();
    throw new HttpError(413, `Body exceeds ${limit} bytes`);
  }

  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > drainCap) {
      req.destroy();
      break;
    }
    if (size <= limit) chunks.push(chunk as Buffer);
  }
  if (size > limit) throw new HttpError(413, `Body exceeds ${limit} bytes`);
  return Buffer.concat(chunks).toString("utf8");
}

function clientOf(req: IncomingMessage, trustProxy: boolean): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (trustProxy && typeof forwarded === "string") return forwarded.split(",")[0]?.trim() || "unknown";
  return req.socket.remoteAddress ?? "unknown";
}

export function createVerifierServer(config: VerifierServerConfig = {}): Server {
  const limit = config.maxBodyBytes ?? 1024 * 1024;
  const limiter = createRateLimiter(config.rateLimit ?? { capacity: 60, refillPerSecond: 1 });
  const log = config.log ?? ((line: string) => process.stderr.write(`${line}\n`));

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const rate = limiter.take(clientOf(req, config.trustProxy ?? false));
    if (!rate.allowed) {
      send(res, 429, { success: false, data: null, error: "Rate limit exceeded" }, { "retry-after": String(rate.retryAfterSeconds) });
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
      send(res, 405, { success: false, data: null, error: `Use ${route.method}` }, { allow: route.method });
      return;
    }

    if (path === "/") {
      res.writeHead(200, { ...BASE_HEADERS, "content-type": "text/html; charset=utf-8", "content-security-policy": PAGE_CSP, "x-frame-options": "DENY" });
      res.end(PAGE_HTML);
      return;
    }
    if (path === "/healthz") {
      send(res, 200, { success: true, data: { status: "ok" }, error: null });
      return;
    }

    if (!/^application\/json\b/i.test(req.headers["content-type"] ?? "")) {
      throw new HttpError(415, "Content-Type must be application/json");
    }
    const text = await readBody(req, limit);
    let body: unknown;
    try {
      body = fromJson(text);
    } catch {
      throw new HttpError(400, "Body is not valid JSON");
    }
    send(res, 200, { success: true, data: route.handle?.(body) ?? null, error: null });
  }

  const server = createServer((req, res) => {
    route(req, res).catch((err: unknown) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (err instanceof HttpError) {
        // A client that sent too much is not read to the end; the connection closes after this.
        const extra: Record<string, string> = err.status === 413 ? { connection: "close" } : {};
        send(res, err.status, { success: false, data: null, error: err.message }, extra);
      } else if (err instanceof SchemaError) {
        send(res, 400, { success: false, data: null, error: err.message });
      } else {
        log(`verifier: unexpected error on ${req.method} ${req.url}: ${err instanceof Error ? err.message : String(err)}`);
        send(res, 500, { success: false, data: null, error: "Internal error" });
      }
    });
  });

  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  return server;
}
