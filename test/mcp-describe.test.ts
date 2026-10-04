/**
 * What request_transfer tells a model when the gateway broadcasts: a payment sent, a payment
 * signed but not delivered, and an allow that produced no transaction. Each one calls for a
 * different next step, and the wrong one costs money: a model told to start over after a failed
 * send could pay twice.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { generateKeypair } from "../src/receipt/sign.ts";
import { createPlaintextPolicyProvider } from "../src/policy/sealed.ts";
import { NATIVE_SOL_MINT, SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID, type SolanaCluster } from "../src/solana/types.ts";
import { openDatabase } from "../src/gateway/db.ts";
import { createStore } from "../src/gateway/store.ts";
import { createGatewayService } from "../src/gateway/service.ts";
import { decisionResult, readDecided } from "../src/mcp/describe.ts";
import type { Policy } from "../src/policy/types.ts";
import type { RpcClient } from "../src/solana/rpc.ts";

const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";

const policy: Policy = {
  policyId: "describe",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  counterpartyAllowlist: [VENDOR],
  allowedClusters: ["devnet", "mainnet-beta", "localnet"],
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  allowedMints: [NATIVE_SOL_MINT],
  maxAmountPerMint: { [NATIVE_SOL_MINT]: 1_000_000_000n },
};

const healthy = {
  getLatestBlockhash: async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 9 }),
  sendTransaction: async () => "5".repeat(88),
};

/** A broadcasting gateway's decision for 0.015 SOL, described as the tool describes it. */
async function described(cluster: SolanaCluster, rpc: Partial<RpcClient>) {
  const db = openDatabase(":memory:");
  const store = createStore(db);
  store.createAgent({ id: "bot", label: "bot", now: 0 });
  const service = createGatewayService({
    store,
    provider: createPlaintextPolicyProvider(policy),
    vault: generateKeypair(),
    cluster,
    execution: "broadcast",
    rpc: rpc as RpcClient,
    windowSeconds: 3600,
  });
  try {
    const decided = readDecided(await service.decide("bot", { kind: "sol", to: VENDOR, amount: 15_000_000n, decimals: 9 }, { idempotencyKey: "inv-7" }));
    const result = decisionResult(decided, { requestId: "inv-7", what: "0.015 SOL", to: VENDOR });
    return { result, data: result.structured as Record<string, any>, signature: decided.receipt.body.transaction?.signature ?? "", receiptId: decided.receipt.body.receiptId };
  } finally {
    db.close();
  }
}

test("a payment the gateway sent says so, with its transaction and where to see it", async () => {
  const { result, data, signature, receiptId } = await described("devnet", healthy);
  const link = `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
  assert.equal(result.text, `ALLOWED. 0.015 SOL to ${VENDOR} was signed and sent as transaction ${signature} (${link}). Receipt ${receiptId}.`);
  assert.deepEqual(data["transaction"], { signature, submitted: true });
  assert.equal(data["explorer"], link);
  assert.equal(data["signedTransaction"], undefined, "a sent transaction is not handed out again");

  const mainnet = await described("mainnet-beta", healthy);
  assert.equal(mainnet.data["explorer"], `https://explorer.solana.com/tx/${mainnet.signature}`, "a mainnet link names no cluster");
  const local = await described("localnet", healthy);
  assert.equal(local.data["explorer"], undefined, "no public explorer shows a local cluster");
  assert.doesNotMatch(local.result.text, /https:/);
});

test("a payment signed but not delivered is retried under the same request_id, never started over", async () => {
  const { result, data } = await described("devnet", { ...healthy, sendTransaction: async () => Promise.reject(new Error("node is behind")) });
  assert.match(result.text, /^ALLOWED and signed, but sending it failed: node is behind\. Call request_transfer again with the same request_id/);
  assert.match(result.text, /instead of starting a new payment/);
  assert.equal(data["transaction"].submitted, false);
  assert.equal(data["transaction"].error, "node is behind");
  assert.ok(data["signedTransaction"], "the signed transaction is there for whoever can deliver it");
  assert.equal(data["explorer"], undefined, "nothing to show on an explorer yet");
});

test("an allow that produced no transaction says nothing was paid", async () => {
  const { result, data } = await described("devnet", { ...healthy, getLatestBlockhash: async () => Promise.reject(new Error("HTTP 503")) });
  assert.match(result.text, /^ALLOWED, but no transaction could be built: No recent blockhash: HTTP 503\. Nothing was paid\./);
  assert.match(result.text, /new request_id/);
  assert.equal(data["transaction"], null);
});

test("an answer that is not a decision is refused, not described", () => {
  assert.throws(() => readDecided(null), /not a decision/);
  assert.throws(() => readDecided({ seq: "1" }), /sequence number/);
  assert.throws(() => readDecided({ seq: 1, receipt: { body: {} } }), /receipt/);
});
