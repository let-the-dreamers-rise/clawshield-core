/**
 * Solana devnet as the page sees it, answered from the committed snapshot
 * (test/fixtures/devnet-accounts.json) so every run checks the same chain state. The page reads
 * accounts and signature statuses and nothing else; any other method is an error, so a page
 * that started depending on more of the chain would fail here first.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page, Route } from "@playwright/test";

interface Snapshot {
  readonly accounts: Readonly<Record<string, { readonly owner: string; readonly lamports: number; readonly executable: boolean; readonly data: string }>>;
  readonly landed: Readonly<Record<string, number>>;
}

const SNAPSHOT = JSON.parse(readFileSync(join(import.meta.dirname, "..", "fixtures", "devnet-accounts.json"), "utf8")) as Snapshot;

/** Transactions the snapshot found finalized: signature to slot. */
export const LANDED = SNAPSHOT.landed;

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};

interface Call {
  readonly id: number;
  readonly method: string;
  readonly params: readonly unknown[];
}

function answer(call: Call): unknown {
  const context = { slot: 1 };
  if (call.method === "getAccountInfo") {
    const account = SNAPSHOT.accounts[String(call.params[0])];
    const value = account === undefined ? null : { ...account, data: [account.data, "base64"], rentEpoch: 0 };
    return { jsonrpc: "2.0", id: call.id, result: { context, value } };
  }
  if (call.method === "getSignatureStatuses") {
    const value = (call.params[0] as readonly string[]).map((signature) => {
      const slot = SNAPSHOT.landed[signature];
      return slot === undefined ? null : { slot, err: null, confirmationStatus: "finalized", confirmations: null };
    });
    return { jsonrpc: "2.0", id: call.id, result: { context, value } };
  }
  return { jsonrpc: "2.0", id: call.id, error: { code: -32601, message: `Method not found: ${call.method}` } };
}

async function respond(route: Route, down: boolean, calls: string[]): Promise<void> {
  const request = route.request();
  if (request.method() === "OPTIONS") return route.fulfill({ status: 204, headers: CORS });
  if (down) return route.fulfill({ status: 503, headers: CORS, body: "Service Unavailable" });
  const call = JSON.parse(request.postData() ?? "{}") as Call;
  calls.push(call.method);
  return route.fulfill({ status: 200, headers: { ...CORS, "content-type": "application/json" }, body: JSON.stringify(answer(call)) });
}

/**
 * Answer the page's devnet RPC from the snapshot, or, with `down`, fail every call the way an
 * overloaded endpoint does. Returns the JSON-RPC methods called, in order.
 */
export async function answerDevnet(page: Page, options: { readonly down?: boolean } = {}): Promise<readonly string[]> {
  const calls: string[] = [];
  await page.route((url) => url.hostname === "api.devnet.solana.com", (route) => respond(route, options.down ?? false, calls));
  return calls;
}
