/**
 * The decision service under pressure: concurrent proposals, delivery to the chain, and the
 * bounds that keep one agent from parking unlimited work on the gateway.
 *
 * The concurrency test is the important one. A sealed decision is a network round trip, so
 * proposals from one agent overlap in time. Without serialisation each would read the same
 * spend and all would be allowed; the window cap would be spent several times over.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { generateKeypair } from "../src/receipt/sign.ts";
import { verifyChain } from "../src/receipt/verify.ts";
import { createPlaintextPolicyProvider, type PolicyProvider } from "../src/policy/sealed.ts";
import { NATIVE_SOL_MINT, SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID } from "../src/solana/types.ts";
import { solanaAddress, solanaSecretKey } from "../src/solana/keys.ts";
import { openDatabase } from "../src/gateway/db.ts";
import { createStore } from "../src/gateway/store.ts";
import { createGatewayService } from "../src/gateway/service.ts";
import { createKeyedMutex, QueueFullError } from "../src/gateway/mutex.ts";
import { ConfigError, parseGatewayEnv } from "../src/gateway/config.ts";
import { startGateway } from "../src/gateway/boot.ts";
import type { Policy } from "../src/policy/types.ts";
import type { RpcClient } from "../src/solana/rpc.ts";

const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const T0 = Date.UTC(2026, 9, 2, 9, 0, 0);
const policy: Policy = {
  policyId: "race",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  counterpartyAllowlist: [VENDOR],
  allowedClusters: ["devnet"],
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  allowedMints: [NATIVE_SOL_MINT],
  maxAmountPerMint: { [NATIVE_SOL_MINT]: 10_000_000n },
  maxAmountPerWindow: 25_000_000n,
  windowSeconds: 3600,
};

/** A provider that takes a while to answer, as a sealed one does, so calls overlap. */
function slow(provider: PolicyProvider, ms: number): PolicyProvider {
  return { ...provider, decide: async (...args) => {
    await new Promise((r) => setTimeout(r, ms));
    return provider.decide(...args);
  } };
}

function setup(over: { rpc?: RpcClient; execution?: "sign" | "broadcast"; maxQueued?: number; provider?: PolicyProvider } = {}) {
  const db = openDatabase(":memory:");
  const store = createStore(db);
  store.createAgent({ id: "bot", label: "bot", now: T0 });
  const service = createGatewayService({
    store,
    provider: over.provider ?? slow(createPlaintextPolicyProvider(policy), 15),
    vault: generateKeypair(),
    cluster: "devnet",
    windowSeconds: 3600,
    execution: over.execution ?? "sign",
    ...(over.rpc ? { rpc: over.rpc } : {}),
    ...(over.maxQueued ? { maxQueuedPerAgent: over.maxQueued } : {}),
    now: () => T0,
  });
  return { db, store, service };
}

const pay = (lamports: bigint) => ({ kind: "sol" as const, to: VENDOR, amount: lamports, decimals: 9 });

test("overlapping proposals cannot spend a window twice", async () => {
  const { db, store, service } = setup();
  // Ten proposals of 10M against a 25M window, all in flight at once. At most two can fit.
  const results = await Promise.all(Array.from({ length: 10 }, () => service.decide("bot", pay(10_000_000n))));
  const allowed = results.filter((r) => r.decision.verdict === "allow").length;
  assert.equal(allowed, 2);

  const ledger = store.getLedger("bot");
  assert.equal(ledger?.state.spentInWindow, 20_000_000n);
  assert.equal(ledger?.state.callsInWindow, 10);
  assert.deepEqual(results.map((r) => r.seq).sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

  const chain = store.listReceipts("bot", { afterSeq: 0, limit: 100 }).items.map((r) => r.receipt);
  const check = verifyChain(chain, () => policy);
  assert.equal(check.valid, true, check.detail.join("; "));
  db.close();
});

test("broadcast mode records the decision first, then delivers it", async () => {
  const sent: string[] = [];
  let fail = false;
  const rpc = {
    getLatestBlockhash: async () => ({ blockhash: "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N", lastValidBlockHeight: 9 }),
    sendTransaction: async (wire: string) => {
      if (fail) throw new Error("node is behind");
      sent.push(wire);
      return "5".repeat(88);
    },
  } as unknown as RpcClient;
  const { db, store, service } = setup({ rpc, execution: "broadcast" });

  const ok = await service.decide("bot", pay(1_000n));
  assert.equal(ok.submittedSignature, "5".repeat(88));
  assert.equal(sent[0], ok.signedTransaction);
  assert.equal(store.getReceipt(ok.receipt.body.receiptId)?.submittedSignature, "5".repeat(88));

  fail = true;
  const undelivered = await service.decide("bot", pay(1_000n));
  assert.equal(undelivered.decision.verdict, "allow");
  assert.match(undelivered.submitError ?? "", /node is behind/);
  assert.ok(store.getReceipt(undelivered.receipt.body.receiptId), "a failed delivery still leaves the decision recorded");

  // A denial is never sent anywhere.
  const before = sent.length;
  fail = false;
  assert.equal((await service.decide("bot", { ...pay(1_000n), to: solanaAddress(generateKeypair().publicKey) })).decision.verdict, "deny");
  assert.equal(sent.length, before);
  assert.throws(() => createGatewayService({ store, provider: createPlaintextPolicyProvider(policy), vault: generateKeypair(), cluster: "devnet", execution: "broadcast" }), /RPC/);
  db.close();
});

test("the blockhash is fetched after the verdict, and an allow that could not be signed spends nothing", async () => {
  // A sealed verdict can take longer than a blockhash stays valid, so the gateway must not
  // fetch one before asking.
  const order: string[] = [];
  let rpcDown = false;
  const plaintext = slow(createPlaintextPolicyProvider(policy), 15);
  const provider: PolicyProvider = { ...plaintext, decide: async (...args) => {
    const decided = await plaintext.decide(...args);
    order.push("decided");
    return decided;
  } };
  const rpc = {
    getLatestBlockhash: async () => {
      order.push("blockhash");
      if (rpcDown) throw new Error("getLatestBlockhash failed after 4 attempt(s): HTTP 503");
      return { blockhash: "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N", lastValidBlockHeight: 9 };
    },
    sendTransaction: async () => "5".repeat(88),
  } as unknown as RpcClient;
  const { db, store, service } = setup({ rpc, execution: "broadcast", provider });

  assert.equal((await service.decide("bot", pay(1_000n))).submittedSignature, "5".repeat(88));
  assert.deepEqual(order, ["decided", "blockhash"]);

  // A refusal signs nothing, so it never asks for a blockhash.
  order.length = 0;
  assert.equal((await service.decide("bot", { ...pay(1_000n), to: solanaAddress(generateKeypair().publicKey) })).decision.verdict, "deny");
  assert.deepEqual(order, ["decided"]);

  // By the time the fetch fails the verdict exists (under seal it is already on chain), so it
  // is recorded with the reason. Nothing was signed: nothing is sent and the window is not charged.
  rpcDown = true;
  const unsigned = await service.decide("bot", pay(1_000n));
  assert.equal(unsigned.decision.verdict, "allow");
  assert.equal(unsigned.signedTransaction, undefined);
  assert.equal(unsigned.submittedSignature, undefined);
  assert.match(unsigned.receipt.body.outcome?.error ?? "", /^No recent blockhash: getLatestBlockhash failed/);
  assert.ok(store.getReceipt(unsigned.receipt.body.receiptId));
  const ledger = store.getLedger("bot");
  assert.equal(ledger?.state.spentInWindow, 1_000n, "only the signed allow is charged");
  assert.equal(ledger?.state.callsInWindow, 3, "every decision is a call");

  const chain = store.listReceipts("bot", { afterSeq: 0, limit: 10 }).items.map((r) => r.receipt);
  const check = verifyChain(chain, () => policy);
  assert.equal(check.valid, true, check.detail.join("; "));
  db.close();
});

test("an agent cannot queue unbounded work, and an unknown agent is refused", async () => {
  const mutex = createKeyedMutex(2);
  let release: () => void = () => {};
  const held = mutex.run("a", () => new Promise<void>((r) => (release = r)));
  const queued = mutex.run("a", async () => {});
  await assert.rejects(mutex.run("a", async () => {}), QueueFullError);
  // Other keys are unaffected.
  await mutex.run("b", async () => {});
  release();
  await held;
  await queued;
  assert.equal(mutex.size(), 0);

  const { db, service } = setup();
  await assert.rejects(service.decide("ghost", pay(1n)), /No agent ghost/);
  db.close();
});

test("sealed mode refuses an authority key that is not the deployment's", async () => {
  const dir = mkdtempSync(join(tmpdir(), "genkai-sealed-"));
  const write = (name: string, value: unknown) => {
    const path = join(dir, name);
    writeFileSync(path, JSON.stringify(value));
    return path;
  };
  const authority = generateKeypair();
  const deployment = write("devnet.json", {
    cluster: "devnet",
    rpc: "https://api.devnet.solana.com",
    programId: "AwiVMGyi8P9mN6ig5FA74CTS6sncc7bbh8CNAxKXUERk",
    clusterOffset: 456,
    circuitId: "genkai.policy.v2",
    policy: "4GAuWFqwJLhEqLAguJV3cdrwYWHc3yKP4QnYVkwWQRKL",
    policyId: "desk-alpha-treasury",
    commitment: "d5987b971868601cf6845a3b9b3a95fad90c056a306e3addc45d43b540890df1",
    authority: solanaAddress(authority.publicKey),
  });
  const vault = write("vault.json", [...solanaSecretKey(generateKeypair())]);
  const wrongAuthority = write("wrong.json", [...solanaSecretKey(generateKeypair())]);
  const env = { GENKAI_VAULT_KEY_FILE: vault, GENKAI_DEPLOYMENT_FILE: deployment, GENKAI_RPC_URL: "http://127.0.0.1:1", GENKAI_DB_PATH: join(dir, "g.db"), PORT: "0" };

  await assert.rejects(startGateway(parseGatewayEnv({ ...env, GENKAI_AUTHORITY_KEY_FILE: wrongAuthority }), () => {}), (err: unknown) => err instanceof ConfigError && /policy authority/.test(err.message));

  const gw = await startGateway(parseGatewayEnv({ ...env, GENKAI_AUTHORITY_KEY: JSON.stringify([...solanaSecretKey(authority)]) }), () => {});
  try {
    const trust = (await (await fetch(`${gw.url}/v1/trust`)).json()) as { data: { mode: string; programId: string; policy: string } };
    assert.equal(trust.data.mode, "sealed");
    assert.equal(trust.data.policy, "4GAuWFqwJLhEqLAguJV3cdrwYWHc3yKP4QnYVkwWQRKL");
  } finally {
    await gw.close();
  }
});
