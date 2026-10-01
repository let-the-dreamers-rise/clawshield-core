/**
 * HTTP plumbing shared by the public verifier and the gateway: one response envelope, bounded
 * bodies, client addressing and error mapping. Kept in one place so both servers fail the same
 * way: a client mistake is a 4xx that names the problem; anything unexpected is a 500 with no
 * detail, logged server side only.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { fromJson, toJson } from "../io/json.ts";
import { SchemaError } from "../io/validate.ts";

export class HttpError extends Error {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;

  constructor(status: number, message: string, headers: Readonly<Record<string, string>> = {}) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.headers = headers;
  }
}

export const BASE_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
} as const;

export interface Meta {
  readonly total?: number;
  readonly limit?: number;
  readonly next?: string | null;
}

export interface Envelope {
  readonly success: boolean;
  readonly data: unknown;
  readonly error: string | null;
  readonly meta?: Meta;
}

export function send(res: ServerResponse, status: number, payload: Envelope, extra: Readonly<Record<string, string>> = {}): void {
  const body = toJson(payload as never);
  res.writeHead(status, { ...BASE_HEADERS, "content-type": "application/json; charset=utf-8", ...extra });
  res.end(body);
}

/**
 * Read a bounded body. An oversized body is drained without being stored, so the client gets a
 * clean 413 instead of a reset connection, but only up to a hard cap: past that the socket is
 * destroyed rather than letting a client make the server read without limit.
 */
export async function readBody(req: IncomingMessage, limit: number): Promise<string> {
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

/** A JSON body: content type enforced, size bounded, bigint tags decoded strictly. */
export async function readJsonBody(req: IncomingMessage, limit: number): Promise<unknown> {
  if (!/^application\/json\b/i.test(req.headers["content-type"] ?? "")) {
    throw new HttpError(415, "Content-Type must be application/json");
  }
  const text = await readBody(req, limit);
  try {
    return fromJson(text);
  } catch {
    throw new HttpError(400, "Body is not valid JSON");
  }
}

export function clientOf(req: IncomingMessage, trustProxy: boolean): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (trustProxy && typeof forwarded === "string") return forwarded.split(",")[0]?.trim() || "unknown";
  return req.socket.remoteAddress ?? "unknown";
}

/** Map a thrown error to a response. Returns true when the error was a client mistake. */
export function sendError(res: ServerResponse, err: unknown, extra: Readonly<Record<string, string>> = {}): boolean {
  if (res.headersSent) {
    res.destroy();
    return true;
  }
  if (err instanceof HttpError) {
    // A client that sent too much is not read to the end; the connection closes after this.
    const close: Record<string, string> = err.status === 413 ? { connection: "close" } : {};
    send(res, err.status, { success: false, data: null, error: err.message }, { ...extra, ...err.headers, ...close });
    return true;
  }
  if (err instanceof SchemaError) {
    send(res, 400, { success: false, data: null, error: err.message }, extra);
    return true;
  }
  send(res, 500, { success: false, data: null, error: "Internal error" }, extra);
  return false;
}
