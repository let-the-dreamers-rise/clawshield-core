/**
 * Parsers for what clients send the gateway. Closed objects only: a field the gateway does not
 * know is refused, never ignored. That matters most for decisions, where an agent might try to
 * slip in `from`, `state` or `requestedAt`; none of those are the agent's to supply.
 */

import { decodePubkey } from "../solana/base58.ts";
import { SchemaError, at, int, oneOf, opt, record, str, type Obj } from "../io/validate.ts";
import type { TransferInput } from "./service.ts";

const AGENT_ID = /^[a-z0-9][a-z0-9-]{2,63}$/;
const AMOUNT = /^[0-9]{1,20}$/;
const U64_MAX = (1n << 64n) - 1n;

export function agentId(v: unknown, path: string): string {
  const s = str(v, path, { max: 64 });
  if (!AGENT_ID.test(s)) throw new SchemaError(path, "3-64 characters: lowercase letters, digits and hyphens, starting with a letter or digit");
  return s;
}

const label = (v: unknown, path: string): string => str(v, path, { max: 128 });

function address(v: unknown, path: string): string {
  const s = str(v, path, { nonEmpty: true, max: 44 });
  try {
    decodePubkey(s);
  } catch {
    throw new SchemaError(path, "expected a base58 Solana address");
  }
  return s;
}

/** Integer minor units as a decimal string (or a bigint). Never a float, never negative. */
export function amount(v: unknown, path: string): bigint {
  const value = typeof v === "bigint" ? v : typeof v === "string" && AMOUNT.test(v) ? BigInt(v) : undefined;
  if (value === undefined || value < 0n || value > U64_MAX) throw new SchemaError(path, "expected a whole number of minor units as a decimal string");
  return value;
}

export function parseCreateAgent(v: unknown): { readonly id: string; readonly label: string } {
  const o = record(v, "", ["id", "label"]);
  return { id: agentId(o["id"], "id"), label: label(o["label"], "label") };
}

export function parseCreateKey(v: unknown): { readonly label: string } {
  const o = record(v ?? {}, "", [], ["label"]);
  return { label: o["label"] === undefined ? "" : label(o["label"], "label") };
}

export function parseDrawdown(v: unknown): bigint {
  const o = record(v, "", ["drawdownFromPeak"]);
  return amount(o["drawdownFromPeak"], "drawdownFromPeak");
}

function parseTransfer(v: unknown, path: string): TransferInput {
  const o: Obj = record(v, path, ["kind", "to", "amount", "decimals"], ["mint", "programId"]);
  const kind = oneOf(o["kind"], at(path, "kind"), ["sol", "spl"] as const);
  const mint = opt(o, "mint", path, address);
  if (kind === "spl" && mint === undefined) throw new SchemaError(at(path, "mint"), "required for an SPL transfer");
  return {
    kind,
    to: address(o["to"], at(path, "to")),
    amount: amount(o["amount"], at(path, "amount")),
    decimals: int(o["decimals"], at(path, "decimals"), 0),
    ...(mint === undefined ? {} : { mint }),
    ...(o["programId"] === undefined ? {} : { programId: address(o["programId"], at(path, "programId")) }),
  };
}

export function parseDecisionRequest(v: unknown): { readonly transfer: TransferInput; readonly modelReasoning?: string } {
  const o = record(v, "", ["transfer"], ["modelReasoning"]);
  const transfer = parseTransfer(o["transfer"], "transfer");
  if (transfer.decimals > 18) throw new SchemaError("transfer.decimals", "at most 18");
  const modelReasoning = opt(o, "modelReasoning", "", (x, p) => str(x, p, { max: 8 * 1024 }));
  return modelReasoning === undefined ? { transfer } : { transfer, modelReasoning };
}

const IDEMPOTENCY_KEY = /^[\x21-\x7e][\x20-\x7e]{0,254}$/;

/**
 * The Idempotency-Key header: 1 to 255 printable ASCII characters, sent bare (as Stripe and
 * most clients do) or as the quoted string of the IETF draft. Absent means no deduplication.
 */
export function parseIdempotencyKey(v: string | readonly string[] | undefined): string | undefined {
  if (v === undefined) return undefined;
  const raw = typeof v === "string" ? v : "";
  const key = /^"(.*)"$/.exec(raw)?.[1] ?? raw;
  if (!IDEMPOTENCY_KEY.test(key)) throw new SchemaError("Idempotency-Key", "expected 1 to 255 printable ASCII characters");
  return key;
}

/** `?after=<n>&limit=<n>`, bounded so one request cannot ask for the whole table. */
export function parsePage(params: URLSearchParams, maxLimit = 100): { readonly after: number; readonly limit: number } {
  const n = (key: string, fallback: number, max: number): number => {
    const raw = params.get(key);
    if (raw === null) return fallback;
    if (!/^[0-9]{1,9}$/.test(raw)) throw new SchemaError(key, "expected a non-negative integer");
    return Math.min(Number(raw), max);
  };
  return { after: n("after", 0, Number.MAX_SAFE_INTEGER), limit: Math.max(1, n("limit", 50, maxLimit)) };
}
