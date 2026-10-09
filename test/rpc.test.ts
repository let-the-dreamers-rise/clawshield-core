/**
 * The JSON-RPC client.
 *
 * Everything this client returns came from a server the operator does not control, so every
 * response is validated before it is believed. Retries are limited to transport failures:
 * a JSON-RPC error is an answer, not an outage, and retrying it only hides it.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { createRpcClient, RpcError, withAccountMemo, type FetchLike, type RpcClient } from "../src/solana/rpc.ts";

const BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";
const SIG = "4iNuB2HPT5ERfgA87NU5W4u32WGqcEkVJF7ZqVj99jYv1TZtvG6De8FpdE3urkw6ERvhwrRMT18he4yv3yLCbULA";

interface Call {
  readonly method: string;
  readonly params: unknown;
}

function fakeFetch(responses: readonly (object | number | Error)[]): { fetch: FetchLike; calls: Call[] } {
  const calls: Call[] = [];
  let i = 0;
  const fetch: FetchLike = async (_url, init) => {
    const body = JSON.parse(String(init.body)) as { method: string; params: unknown; id: number };
    calls.push({ method: body.method, params: body.params });
    const next = responses[Math.min(i++, responses.length - 1)];
    if (next instanceof Error) throw next;
    if (typeof next === "number") return new Response("busy", { status: next });
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, ...next }), { status: 200 });
  };
  return { fetch, calls };
}

const client = (fetch: FetchLike) =>
  createRpcClient({ endpoint: "https://rpc.invalid", fetch, retries: 2, sleep: async () => {} });

test("getLatestBlockhash returns a validated blockhash and expiry height", async () => {
  const { fetch, calls } = fakeFetch([
    { result: { context: { slot: 1 }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: 300 } } },
  ]);
  const result = await client(fetch).getLatestBlockhash();
  assert.deepEqual(result, { blockhash: BLOCKHASH, lastValidBlockHeight: 300 });
  assert.equal(calls[0]?.method, "getLatestBlockhash");
});

test("a response that does not have the expected shape is refused", async () => {
  for (const value of [{ blockhash: "0OIl", lastValidBlockHeight: 1 }, { blockhash: BLOCKHASH }, null]) {
    const { fetch } = fakeFetch([{ result: { context: { slot: 1 }, value } }]);
    await assert.rejects(() => client(fetch).getLatestBlockhash(), RpcError);
  }
});

test("transport failures are retried, then reported", async () => {
  const ok = { result: { context: { slot: 1 }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: 9 } } };
  const recovered = fakeFetch([429, new Error("socket hang up"), ok]);
  assert.equal((await client(recovered.fetch).getLatestBlockhash()).lastValidBlockHeight, 9);
  assert.equal(recovered.calls.length, 3);

  const down = fakeFetch([503]);
  await assert.rejects(
    () => client(down.fetch).getLatestBlockhash(),
    (err: unknown) => err instanceof RpcError && err.code === "transport",
  );
  assert.equal(down.calls.length, 3, "one attempt plus two retries");
});

test("a rate limit's Retry-After is honoured up to a cap; without one the backoff doubles", async () => {
  const ok = { result: { context: { slot: 1 }, value: { blockhash: BLOCKHASH, lastValidBlockHeight: 9 } } };
  const waitsFor = async (retryAfter: string | undefined): Promise<number[]> => {
    const waits: number[] = [];
    let n = 0;
    const fetch: FetchLike = async (_url, init) => {
      const { id } = JSON.parse(init.body) as { id: number };
      if (n++ < 2) return new Response("slow down", { status: 429, headers: retryAfter === undefined ? {} : { "retry-after": retryAfter } });
      return new Response(JSON.stringify({ jsonrpc: "2.0", id, ...ok }), { status: 200 });
    };
    const rpc = createRpcClient({ endpoint: "https://rpc.invalid", fetch, retries: 3, backoffMs: 100, sleep: async (ms) => void waits.push(ms) });
    assert.equal((await rpc.getLatestBlockhash()).lastValidBlockHeight, 9);
    return waits;
  };
  assert.deepEqual(await waitsFor("3"), [3_000, 3_000]);
  assert.deepEqual(await waitsFor("3600"), [10_000, 10_000], "a server cannot stall the caller for an hour");
  assert.deepEqual(await waitsFor(undefined), [100, 200]);
  assert.deepEqual(await waitsFor("soon"), [100, 200], "an unreadable header falls back to the backoff");
});

test("withAccountMemo reads each account once, shares a read in flight, and forgets a failed one", async () => {
  const reads: string[] = [];
  let flaky = true;
  const base: RpcClient = {
    getLatestBlockhash: async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 1 }),
    getBlockHeight: async () => 42,
    sendTransaction: async () => SIG,
    getSignatureStatuses: async (signatures) => signatures.map(() => null),
    getTransaction: async () => null,
    getAccountInfo: async (address) => {
      reads.push(address);
      if (address === "flaky" && flaky) {
        flaky = false;
        throw new RpcError("transport", "getAccountInfo failed after 3 attempt(s): HTTP 429");
      }
      return address === "missing" ? null : { owner: address, lamports: 1n, data: new Uint8Array(), executable: false };
    },
  };
  const rpc = withAccountMemo(base);

  const [first, second] = await Promise.all([rpc.getAccountInfo("policy"), rpc.getAccountInfo("policy")]);
  assert.equal(first, second);
  await rpc.getAccountInfo("policy");
  assert.equal(await rpc.getAccountInfo("missing"), null);
  await rpc.getAccountInfo("missing");
  await assert.rejects(rpc.getAccountInfo("flaky"), RpcError);
  assert.equal((await rpc.getAccountInfo("flaky"))?.owner, "flaky", "a failed read is tried again");
  assert.deepEqual(reads, ["policy", "missing", "flaky", "flaky"]);

  assert.equal(await rpc.getBlockHeight(), 42, "everything else passes straight through");
  await withAccountMemo(base).getAccountInfo("policy");
  assert.equal(reads.filter((r) => r === "policy").length, 2, "a new memo reads afresh");
});

test("a JSON-RPC error is surfaced and not retried", async () => {
  const { fetch, calls } = fakeFetch([{ error: { code: -32002, message: "Transaction simulation failed" } }]);
  await assert.rejects(
    () => client(fetch).sendTransaction("AQ=="),
    (err: unknown) => err instanceof RpcError && err.code === "rpc" && err.rpcCode === -32002 && /simulation/.test(err.message),
  );
  assert.equal(calls.length, 1);
});

test("sendTransaction sends base64 with preflight and returns the signature", async () => {
  const { fetch, calls } = fakeFetch([{ result: SIG }]);
  assert.equal(await client(fetch).sendTransaction("AQID"), SIG);
  const params = calls[0]?.params as [string, Record<string, unknown>];
  assert.equal(params[0], "AQID");
  assert.equal(params[1]["encoding"], "base64");
  assert.equal(params[1]["skipPreflight"], false);
});

test("signature statuses are parsed, including unknown signatures", async () => {
  const { fetch } = fakeFetch([
    { result: { context: { slot: 5 }, value: [{ slot: 4, confirmations: 0, err: null, confirmationStatus: "confirmed" }, null] } },
  ]);
  const statuses = await client(fetch).getSignatureStatuses([SIG, SIG]);
  assert.deepEqual(statuses, [{ slot: 4, err: null, confirmationStatus: "confirmed" }, null]);
});

test("getTransaction returns the raw wire bytes for independent checking", async () => {
  const { fetch } = fakeFetch([{ result: { slot: 77, transaction: ["AQID", "base64"], meta: { err: null } } }]);
  const tx = await client(fetch).getTransaction(SIG);
  assert.ok(tx);
  assert.equal(tx.slot, 77);
  assert.deepEqual([...tx.wire], [1, 2, 3]);
  assert.equal(tx.err, null);

  const missing = fakeFetch([{ result: null }]);
  assert.equal(await client(missing.fetch).getTransaction(SIG), null);
});

test("an endpoint that is not http(s) is refused at construction", () => {
  assert.throws(() => createRpcClient({ endpoint: "file:///etc/passwd" }), RpcError);
});
