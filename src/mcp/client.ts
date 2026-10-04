/**
 * The gateway's HTTP API as the MCP server uses it: one agent key, three calls.
 *
 * A call is retried when the failure says nothing about the request itself: no answer, an
 * unreadable answer, 409 (the ledger moved on), 429, or a 5xx. A decision is retried under the
 * same Idempotency-Key, so when the first attempt was recorded after all, the retry gets that
 * decision back and nothing is paid twice.
 */

import { fromJson, toJson } from "../io/json.ts";

export class GatewayError extends Error {
  /** The HTTP status, when the gateway answered at all. */
  readonly status: number | undefined;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "GatewayError";
    this.status = status;
  }
}

/** POST /v1/decisions, with the amount in minor units as a decimal string. */
export interface DecisionInput {
  readonly transfer: {
    readonly kind: "sol" | "spl";
    readonly to: string;
    readonly amount: string;
    readonly decimals: number;
    readonly mint?: string;
  };
  readonly modelReasoning?: string;
}

export interface GatewayClientConfig {
  readonly url: string;
  readonly agentKey: string;
  readonly fetch?: typeof fetch;
  /** Per attempt. A sealed decision waits on the MPC cluster: 5 to 38 seconds on devnet. */
  readonly timeoutMs?: number;
  readonly retries?: number;
  readonly sleep?: (ms: number) => Promise<void>;
}

const RETRYABLE = new Set([409, 429, 500, 502, 503, 504]);
const MAX_RETRY_AFTER_MS = 30_000;

type Attempt =
  | { readonly ok: true; readonly data: unknown }
  | { readonly ok: false; readonly error: GatewayError; readonly retryable: boolean; readonly waitMs?: number };

interface Envelope {
  readonly success: boolean;
  readonly data: unknown;
  readonly error: string | null;
}

function describe(err: unknown): string {
  if (!(err instanceof Error)) return String(err);
  if (err.name === "TimeoutError") return "timed out";
  const cause = err.cause instanceof Error ? `: ${err.cause.message}` : "";
  return `${err.message}${cause}`;
}

/** The gateway always answers with its envelope; anything else is a proxy's page or a cut body. */
async function readEnvelope(response: Response): Promise<Envelope | undefined> {
  let parsed: unknown;
  try {
    parsed = fromJson(await response.text());
  } catch {
    return undefined;
  }
  const ok = typeof parsed === "object" && parsed !== null && typeof (parsed as Envelope).success === "boolean";
  return ok ? (parsed as Envelope) : undefined;
}

function retryAfter(response: Response): { readonly waitMs?: number } {
  const raw = response.headers.get("retry-after")?.trim();
  if (raw === undefined || !/^[0-9]{1,6}$/.test(raw)) return {};
  return { waitMs: Math.min(Number(raw) * 1000, MAX_RETRY_AFTER_MS) };
}

export type GatewayClient = ReturnType<typeof createGatewayClient>;

export function createGatewayClient(config: GatewayClientConfig) {
  const base = config.url.replace(/\/+$/, "");
  const fetchFn = config.fetch ?? fetch;
  const timeoutMs = config.timeoutMs ?? 120_000;
  const retries = config.retries ?? 2;
  const sleep = config.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));

  async function once(method: string, path: string, headers: Record<string, string>, body: string | undefined): Promise<Attempt> {
    let response: Response;
    try {
      // A redirect is refused rather than followed: it would turn the POST into a GET, and the
      // key belongs to this gateway only.
      response = await fetchFn(`${base}${path}`, { method, headers, body, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      return { ok: false, retryable: true, error: new GatewayError(`The gateway did not answer: ${describe(err)}`) };
    }
    const envelope = await readEnvelope(response);
    if (response.ok && envelope?.success === true) return { ok: true, data: envelope.data };
    const message = envelope?.error ?? `The gateway answered HTTP ${response.status} without a GENKAI response`;
    return {
      ok: false,
      retryable: envelope === undefined || RETRYABLE.has(response.status),
      error: new GatewayError(message, response.status),
      ...retryAfter(response),
    };
  }

  async function request(method: "GET" | "POST", path: string, payload?: unknown, extra: Readonly<Record<string, string>> = {}): Promise<unknown> {
    const body = payload === undefined ? undefined : toJson(payload as never);
    const headers = {
      authorization: `Bearer ${config.agentKey}`,
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...extra,
    };
    for (let attempt = 0; ; attempt += 1) {
      const result = await once(method, path, headers, body);
      if (result.ok) return result.data;
      if (!result.retryable || attempt >= retries) throw result.error;
      await sleep(result.waitMs ?? 1000 * 2 ** attempt);
    }
  }

  return Object.freeze({
    /** Ask for a decision. Every attempt carries the same key, so the transfer is decided once. */
    decide: (input: DecisionInput, idempotencyKey: string) => request("POST", "/v1/decisions", input, { "idempotency-key": idempotencyKey }),
    agent: (id: string) => request("GET", `/v1/agents/${encodeURIComponent(id)}`),
    receipt: (id: string) => request("GET", `/v1/receipts/${encodeURIComponent(id)}`),
  });
}
