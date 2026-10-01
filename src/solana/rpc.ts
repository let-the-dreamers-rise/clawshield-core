/**
 * A minimal Solana JSON-RPC client.
 *
 * Every response comes from a server the operator does not control, so nothing is believed
 * until it has been validated: blockhashes must decode to 32 bytes, signatures to 64, numbers
 * must be numbers. A malformed response is an error, never a default.
 *
 * Retries cover transport failures only (network errors, timeouts, 429 and 5xx). A JSON-RPC
 * error is the server's answer, and retrying it would only hide it. Retrying sendTransaction
 * is safe because a transaction is identified by its signature: the cluster will not execute
 * the same signed bytes twice.
 */

import { decodeBase58, decodePubkey, encodeBase58 } from "./base58.ts";

export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal },
) => Promise<Response>;

export type RpcErrorCode = "transport" | "rpc" | "invalid_response" | "config";

export class RpcError extends Error {
  readonly code: RpcErrorCode;
  readonly rpcCode?: number;

  constructor(code: RpcErrorCode, message: string, rpcCode?: number) {
    super(message);
    this.name = "RpcError";
    this.code = code;
    this.rpcCode = rpcCode;
  }
}

export type Commitment = "processed" | "confirmed" | "finalized";

export interface Blockhash {
  readonly blockhash: string;
  readonly lastValidBlockHeight: number;
}

export interface SignatureStatus {
  readonly slot: number;
  readonly err: unknown;
  readonly confirmationStatus: Commitment | null;
}

export interface OnChainTransaction {
  readonly slot: number;
  readonly wire: Uint8Array;
  readonly err: unknown;
}

export interface AccountInfo {
  readonly owner: string;
  readonly lamports: bigint;
  readonly data: Uint8Array;
  readonly executable: boolean;
}

export interface RpcClient {
  getLatestBlockhash(commitment?: Commitment): Promise<Blockhash>;
  getBlockHeight(commitment?: Commitment): Promise<number>;
  sendTransaction(wireBase64: string): Promise<string>;
  getSignatureStatuses(signatures: readonly string[]): Promise<readonly (SignatureStatus | null)[]>;
  getTransaction(signature: string): Promise<OnChainTransaction | null>;
  getAccountInfo(address: string): Promise<AccountInfo | null>;
}

export interface RpcConfig {
  readonly endpoint: string;
  readonly fetch?: FetchLike;
  readonly timeoutMs?: number;
  readonly retries?: number;
  readonly backoffMs?: number;
  readonly sleep?: (ms: number) => Promise<void>;
}

type Json = Record<string, unknown>;

const isRecord = (v: unknown): v is Json => typeof v === "object" && v !== null && !Array.isArray(v);
const invalid = (what: string): RpcError => new RpcError("invalid_response", `Malformed RPC response: ${what}`);

function int(v: unknown, what: string): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw invalid(what);
  return v;
}

function pubkey(v: unknown, what: string): string {
  try {
    if (typeof v !== "string") throw invalid(what);
    decodePubkey(v);
    return v;
  } catch {
    throw invalid(what);
  }
}

function signature(v: unknown): string {
  try {
    if (typeof v === "string" && decodeBase58(v).length === 64) return v;
  } catch {
    // fall through to the uniform error
  }
  throw invalid("signature");
}

function base64Data(v: unknown, what: string): Uint8Array {
  if (!Array.isArray(v) || typeof v[0] !== "string" || v[1] !== "base64") throw invalid(what);
  return new Uint8Array(Buffer.from(v[0], "base64"));
}

function commitmentOf(v: unknown): Commitment | null {
  if (v === null || v === undefined) return null;
  if (v === "processed" || v === "confirmed" || v === "finalized") return v;
  throw invalid("confirmationStatus");
}

export function createRpcClient(config: RpcConfig): RpcClient {
  let url: URL;
  try {
    url = new URL(config.endpoint);
  } catch {
    throw new RpcError("config", `Not a URL: ${config.endpoint}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RpcError("config", `RPC endpoint must be http(s), got ${url.protocol}`);
  }

  const doFetch: FetchLike = config.fetch ?? ((u, init) => fetch(u, init));
  const timeoutMs = config.timeoutMs ?? 15_000;
  const retries = config.retries ?? 3;
  const backoffMs = config.backoffMs ?? 250;
  const sleep = config.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  let nextId = 1;

  async function attempt(body: string): Promise<{ retryable: boolean; json?: unknown; error?: string }> {
    try {
      const res = await doFetch(url.toString(), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status === 429 || res.status >= 500) return { retryable: true, error: `HTTP ${res.status}` };
      if (res.status !== 200) return { retryable: false, error: `HTTP ${res.status}` };
      return { retryable: false, json: await res.json() };
    } catch (err) {
      return { retryable: true, error: err instanceof Error ? err.message : String(err) };
    }
  }

  async function call(method: string, params: readonly unknown[]): Promise<unknown> {
    const id = nextId++;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });

    let last = "no attempt made";
    for (let n = 0; n <= retries; n++) {
      if (n > 0) await sleep(backoffMs * 2 ** (n - 1));
      const result = await attempt(body);
      if (result.json === undefined) {
        last = result.error ?? last;
        if (result.retryable) continue;
        break;
      }
      const json = result.json;
      if (!isRecord(json) || json["id"] !== id) throw invalid(`${method} envelope`);
      const error = json["error"];
      if (isRecord(error)) {
        const code = typeof error["code"] === "number" ? error["code"] : undefined;
        throw new RpcError("rpc", `${method}: ${String(error["message"] ?? "unknown error")}`, code);
      }
      if (!("result" in json)) throw invalid(`${method} has neither result nor error`);
      return json["result"];
    }
    throw new RpcError("transport", `${method} failed after ${retries + 1} attempt(s): ${last}`);
  }

  const valueOf = (result: unknown, what: string): unknown => {
    if (!isRecord(result) || !("value" in result)) throw invalid(what);
    return result["value"];
  };

  return Object.freeze({
    async getLatestBlockhash(commitment: Commitment = "confirmed") {
      const value = valueOf(await call("getLatestBlockhash", [{ commitment }]), "getLatestBlockhash");
      if (!isRecord(value)) throw invalid("getLatestBlockhash value");
      return {
        blockhash: pubkey(value["blockhash"], "blockhash"),
        lastValidBlockHeight: int(value["lastValidBlockHeight"], "lastValidBlockHeight"),
      };
    },

    async getBlockHeight(commitment: Commitment = "confirmed") {
      return int(await call("getBlockHeight", [{ commitment }]), "getBlockHeight");
    },

    async sendTransaction(wireBase64: string) {
      const result = await call("sendTransaction", [
        wireBase64,
        { encoding: "base64", skipPreflight: false, preflightCommitment: "confirmed", maxRetries: 0 },
      ]);
      return signature(result);
    },

    async getSignatureStatuses(signatures: readonly string[]) {
      const value = valueOf(
        await call("getSignatureStatuses", [signatures, { searchTransactionHistory: true }]),
        "getSignatureStatuses",
      );
      if (!Array.isArray(value) || value.length !== signatures.length) throw invalid("getSignatureStatuses value");
      return value.map((s): SignatureStatus | null => {
        if (s === null) return null;
        if (!isRecord(s)) throw invalid("signature status");
        return { slot: int(s["slot"], "slot"), err: s["err"] ?? null, confirmationStatus: commitmentOf(s["confirmationStatus"]) };
      });
    },

    async getTransaction(sig: string) {
      const result = await call("getTransaction", [
        sig,
        { encoding: "base64", commitment: "confirmed", maxSupportedTransactionVersion: 0 },
      ]);
      if (result === null) return null;
      if (!isRecord(result)) throw invalid("getTransaction");
      const meta = isRecord(result["meta"]) ? result["meta"] : {};
      return {
        slot: int(result["slot"], "slot"),
        wire: base64Data(result["transaction"], "transaction"),
        err: meta["err"] ?? null,
      };
    },

    async getAccountInfo(address: string) {
      const value = valueOf(await call("getAccountInfo", [address, { encoding: "base64" }]), "getAccountInfo");
      if (value === null) return null;
      if (!isRecord(value)) throw invalid("getAccountInfo value");
      return {
        owner: pubkey(value["owner"], "owner"),
        lamports: BigInt(int(value["lamports"], "lamports")),
        data: base64Data(value["data"], "data"),
        executable: value["executable"] === true,
      };
    },
  });
}

/** The transaction id of a wire transaction: its first signature, base58. */
export function signatureOfWire(wire: Uint8Array): string {
  if (wire[0] !== 1 || wire.length < 65) throw new RpcError("invalid_response", "Not a single-signer transaction");
  return encodeBase58(wire.subarray(1, 65));
}
