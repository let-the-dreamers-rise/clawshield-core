/**
 * The real devnet run, offline: the committed example receipts and a snapshot of the accounts
 * they point at (test/fixtures/devnet-accounts.json), served through a fake fetch so the
 * browser verifier's own RPC client is exercised end to end.
 */

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { FetchLike } from "../../src/solana/rpc.ts";

export const ROOT = resolve(import.meta.dirname, "..", "..");
export const DEVNET_RPC = "https://api.devnet.solana.com";

const text = (path: string): string => readFileSync(join(ROOT, path), "utf8");

export const SEALED_RECEIPTS = text("examples/devnet/sealed-receipts.json");
export const GATEWAY_RECEIPTS = text("examples/devnet/gateway/receipts.json");
export const TRUST = text("examples/devnet/trust.json");
export const PLAINTEXT_RECEIPTS = text("examples/devnet/plaintext-receipts.json");
export const POLICY = text("examples/devnet/policy.json");
export const MANIFEST = JSON.parse(text("arcium/genkai/deployments/devnet.json")) as Readonly<Record<string, unknown>>;

export interface FixtureAccount {
  readonly owner: string;
  readonly lamports: number;
  readonly executable: boolean;
  /** base64 */
  readonly data: string;
}

const FIXTURE = JSON.parse(text("test/fixtures/devnet-accounts.json")) as {
  readonly accounts: Readonly<Record<string, FixtureAccount>>;
  readonly landed: Readonly<Record<string, number>>;
};
export const ACCOUNTS = FIXTURE.accounts;
/** The transactions the snapshot found finalized on chain: signature to slot. */
export const LANDED = FIXTURE.landed;

export interface FixtureOptions {
  readonly accounts?: Readonly<Record<string, FixtureAccount>>;
  /** Signatures to report as landed, with their slot. Everything else is unknown to the chain. */
  readonly landed?: Readonly<Record<string, number>>;
  /** Every JSON-RPC method called, in order. */
  readonly calls?: string[];
}

const json = (body: unknown): Response => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

/** A Solana JSON-RPC endpoint over the snapshot: getAccountInfo and getSignatureStatuses. */
export function devnetFetch(options: FixtureOptions = {}): FetchLike {
  const accounts = options.accounts ?? ACCOUNTS;
  return async (_url, init) => {
    const call = JSON.parse(init.body) as { readonly id: number; readonly method: string; readonly params: readonly unknown[] };
    options.calls?.push(call.method);
    if (call.method === "getAccountInfo") {
      const account = accounts[String(call.params[0])];
      const value = account === undefined ? null : { ...account, data: [account.data, "base64"], rentEpoch: 0 };
      return json({ jsonrpc: "2.0", id: call.id, result: { context: { slot: 1 }, value } });
    }
    if (call.method === "getSignatureStatuses") {
      const statuses = (call.params[0] as readonly string[]).map((s) => {
        const slot = options.landed?.[s];
        return slot === undefined ? null : { slot, err: null, confirmationStatus: "finalized", confirmations: null };
      });
      return json({ jsonrpc: "2.0", id: call.id, result: { context: { slot: 1 }, value: statuses } });
    }
    return json({ jsonrpc: "2.0", id: call.id, error: { code: -32601, message: "Method not found" } });
  };
}
