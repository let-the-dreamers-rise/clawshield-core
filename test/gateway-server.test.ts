/**
 * The gateway end to end over real HTTP.
 *
 * The gateway is where an operator's agents meet the policy: it holds the vault key, keeps each
 * agent's spend window and receipt chain in its database, and answers only to API keys. These
 * tests drive it the way an operator and an agent would, and then check what it published with
 * the same verifier a third party uses.
 */

import { strict as assert } from "node:assert";
import { after, before, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { generateKeypair } from "../src/receipt/sign.ts";
import { verifyChain } from "../src/receipt/verify.ts";
import { createPlaintextPolicyProvider } from "../src/policy/sealed.ts";
import { solanaAddress } from "../src/solana/keys.ts";
import { NATIVE_SOL_MINT, SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID } from "../src/solana/types.ts";
import { fromJson, toJson } from "../src/io/json.ts";
import { parseSignedReceipt } from "../src/io/schema.ts";
import { openDatabase } from "../src/gateway/db.ts";
import { createStore } from "../src/gateway/store.ts";
import { createGatewayService } from "../src/gateway/service.ts";
import { createGatewayServer } from "../src/gateway/server.ts";
import { issueAdminKey } from "../src/gateway/admin.ts";
import type { Policy } from "../src/policy/types.ts";

const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const STRANGER = "GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW";
const T0 = Date.UTC(2026, 9, 2, 9, 0, 0);

const policy: Policy = {
  policyId: "gateway-test",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  counterpartyAllowlist: [VENDOR],
  allowedClusters: ["devnet"],
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  allowedMints: [NATIVE_SOL_MINT],
  maxAmountPerMint: { [NATIVE_SOL_MINT]: 50_000_000n },
  maxAmountPerWindow: 60_000_000n,
  windowSeconds: 3600,
  maxCallsPerWindow: 50,
  escalateAboveAmount: 40_000_000n,
};

const VAULT = generateKeypair();
let clock = T0;
let server: Server;
let base = "";
let admin = "";
const logs: string[] = [];
const db = openDatabase(":memory:");
const store = createStore(db);

async function call(method: string, path: string, opts: { token?: string; body?: unknown } = {}) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: {
      ...(opts.body === undefined ? {} : { "content-type": "application/json" }),
      ...(opts.token === undefined ? {} : { authorization: `Bearer ${opts.token}` }),
    },
    body: opts.body === undefined ? undefined : toJson(opts.body as never),
  });
  const json = fromJson(await res.text()) as { success: boolean; data: any; error: string | null; meta?: any };
  return { status: res.status, ...json };
}

const pay = (token: string, lamports: string, to = VENDOR) =>
  call("POST", "/v1/decisions", { token, body: { transfer: { kind: "sol", to, amount: lamports, decimals: 9 }, modelReasoning: "invoice" } });

before(async () => {
  const service = createGatewayService({
    store,
    provider: createPlaintextPolicyProvider(policy),
    vault: VAULT,
    cluster: "devnet",
    windowSeconds: policy.windowSeconds,
    execution: "sign",
    now: () => clock,
  });
  server = createGatewayServer({
    store,
    service,
    trust: { mode: "plaintext", commitment: "00".repeat(32), policyDocument: policy },
    publicReceipts: true,
    now: () => clock,
    log: (l) => logs.push(l),
    rateLimit: { capacity: 1_000, refillPerSecond: 100 },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  admin = issueAdminKey(store, { label: "ops", now: T0 }).token;
});

after(() => {
  server.close();
  db.close();
});

test("liveness, readiness and the published trust anchor need no key", async () => {
  assert.equal((await call("GET", "/healthz")).status, 200);
  const ready = await call("GET", "/readyz");
  assert.equal(ready.data.database, "ok");
  const trust = await call("GET", "/v1/trust");
  assert.equal(trust.data.mode, "plaintext");
  assert.equal(trust.data.vault, solanaAddress(VAULT.publicKey));
  assert.ok(trust.data.operatorPublicKey.length > 40);
});

test("administration needs an admin key, and an agent key is not one", async () => {
  assert.equal((await call("POST", "/v1/agents", { body: { id: "desk-bot", label: "Desk" } })).status, 401);
  assert.equal((await call("POST", "/v1/agents", { token: "gk_000000000000_" + "A".repeat(43), body: { id: "desk-bot", label: "Desk" } })).status, 401);

  const created = await call("POST", "/v1/agents", { token: admin, body: { id: "desk-bot", label: "Desk" } });
  assert.equal(created.status, 201);
  assert.equal((await call("POST", "/v1/agents", { token: admin, body: { id: "desk-bot", label: "Again" } })).status, 409);
  assert.equal((await call("POST", "/v1/agents", { token: admin, body: { id: "Bad Id!", label: "x" } })).status, 400);

  const key = await call("POST", "/v1/agents/desk-bot/keys", { token: admin, body: { label: "prod" } });
  assert.equal(key.status, 201);
  assert.match(key.data.token, /^gk_/);
  const agentToken: string = key.data.token;
  assert.equal((await call("POST", "/v1/agents", { token: agentToken, body: { id: "other", label: "x" } })).status, 403);
  assert.equal((await call("GET", "/v1/audit", { token: agentToken })).status, 403);

  const listed = await call("GET", "/v1/agents/desk-bot/keys", { token: admin });
  assert.equal(listed.data.length, 1);
  // The secret is base64url and may itself contain "_", so take all 43 characters, not a split.
  const secret = /^gk_[0-9a-f]{12}_([A-Za-z0-9_-]{43})$/.exec(key.data.token)?.[1] ?? "";
  assert.equal(secret.length, 43);
  assert.equal(JSON.stringify(listed.data).includes(secret), false, "a listing never shows a secret");
});

test("an agent's decisions are enforced against a ledger it cannot write", async () => {
  const agentToken: string = (await call("POST", "/v1/agents/desk-bot/keys", { token: admin, body: { label: "bot" } })).data.token;

  const allowed = await pay(agentToken, "10000000");
  assert.equal(allowed.status, 200);
  assert.equal(allowed.data.decision.verdict, "allow");
  assert.ok(allowed.data.signedTransaction, "an allow comes back signed for the agent to broadcast");
  assert.equal(allowed.data.receipt.body.request.params.from, solanaAddress(VAULT.publicKey), "the gateway, not the agent, names the vault");

  assert.equal((await pay(agentToken, "5000", STRANGER)).data.decision.verdict, "deny");
  assert.equal((await pay(agentToken, "45000000")).data.decision.verdict, "escalate");
  // 10M spent of a 60M window: 55M more would exceed it.
  assert.equal((await pay(agentToken, "39000000")).data.decision.verdict, "allow");
  const over = await pay(agentToken, "20000000");
  assert.equal(over.data.decision.verdict, "deny");
  assert.ok(over.data.decision.reasons.some((r: { rule: string }) => r.rule === "amount_exceeds_window"));

  const state = await call("GET", "/v1/agents/desk-bot", { token: agentToken });
  assert.equal(state.data.state.spentInWindow, 49_000_000n);
  assert.equal(state.data.state.callsInWindow, 5, "every decision counts as a call");

  // An hour later the window has rolled, and the same payment is allowed.
  clock = T0 + 3_600_000;
  assert.equal((await pay(agentToken, "20000000")).data.decision.verdict, "allow");

  // Malformed requests are refused before any decision is taken or recorded.
  for (const body of [
    { transfer: { kind: "sol", to: VENDOR, amount: "1.5", decimals: 9 } },
    { transfer: { kind: "sol", to: VENDOR, amount: "-1", decimals: 9 } },
    { transfer: { kind: "sol", to: "not-an-address", amount: "1", decimals: 9 } },
    { transfer: { kind: "sol", to: VENDOR, amount: "1", decimals: 9, from: STRANGER } },
    { transfer: { kind: "sol", to: VENDOR, amount: "1", decimals: 9 }, state: { spentInWindow: "0" } },
  ]) {
    assert.equal((await call("POST", "/v1/decisions", { token: agentToken, body })).status, 400, JSON.stringify(body));
  }
  assert.equal((await call("GET", "/v1/agents/desk-bot", { token: agentToken })).data.state.callsInWindow, 1);
});

test("the published chain verifies with the third-party verifier", async () => {
  const page = await call("GET", "/v1/agents/desk-bot/receipts?limit=100");
  assert.equal(page.status, 200);
  assert.equal(page.meta.total, 6);
  const receipts = page.data.map((r: unknown) => parseSignedReceipt(r));
  const result = verifyChain(receipts, () => policy);
  assert.equal(result.valid, true, result.detail.join("; "));

  const one = await call("GET", `/v1/receipts/${receipts[0].body.receiptId}`);
  assert.equal(one.status, 200);
  assert.equal("signedTransaction" in one.data, false, "the public never gets a broadcastable transaction");
  assert.equal((await call("GET", "/v1/receipts/nope")).status, 404);

  const second = await call("GET", `/v1/agents/desk-bot/receipts?limit=2&after=2`);
  assert.deepEqual(second.data.map((r: any) => r.body.receiptId), receipts.slice(2, 4).map((r: any) => r.body.receiptId));
  assert.equal(second.meta.next, "4");

  const verified = await call("POST", "/v1/chains/verify", { body: { receipts: page.data, policy } });
  assert.equal(verified.data.valid, true);
});

test("the kill switch and key revocation take effect on the next request", async () => {
  const created = await call("POST", "/v1/agents/desk-bot/keys", { token: admin, body: { label: "temp" } });
  const token: string = created.data.token;

  assert.equal((await call("POST", "/v1/agents/desk-bot/revoke", { token: admin })).status, 200);
  const denied = await pay(token, "1000");
  assert.equal(denied.data.decision.verdict, "deny");
  assert.ok(denied.data.decision.reasons.some((r: { rule: string }) => r.rule === "revoked"));
  await call("POST", "/v1/agents/desk-bot/reinstate", { token: admin });
  assert.equal((await pay(token, "1000")).data.decision.verdict, "allow");

  assert.equal((await call("DELETE", `/v1/keys/${created.data.keyId}`, { token: admin })).status, 200);
  assert.equal((await pay(token, "1000")).status, 401);
  assert.equal((await call("DELETE", `/v1/keys/${created.data.keyId}`, { token: admin })).status, 404);

  const audit = await call("GET", "/v1/audit?limit=100", { token: admin });
  const actions = audit.data.map((e: { action: string }) => e.action);
  for (const a of ["agent.create", "key.create", "agent.revoke", "agent.reinstate", "key.revoke", "decision"]) {
    assert.ok(actions.includes(a), `audit records ${a}`);
  }
  assert.equal(JSON.stringify(audit.data).includes("gk_"), false, "the audit trail never holds a credential");
});

test("one agent cannot read another agent's private data", async () => {
  await call("POST", "/v1/agents", { token: admin, body: { id: "other-bot", label: "Other" } });
  const other: string = (await call("POST", "/v1/agents/other-bot/keys", { token: admin, body: { label: "o" } })).data.token;
  assert.equal((await call("GET", "/v1/agents/desk-bot", { token: other })).status, 403);
  const firstId = (await call("GET", "/v1/agents/desk-bot/receipts?limit=1")).data[0].body.receiptId;
  assert.equal((await call("GET", `/v1/receipts/${firstId}/transaction`, { token: other })).status, 403);
  assert.equal((await call("GET", `/v1/receipts/${firstId}/transaction`, { token: admin })).status, 200);
});

test("a malformed escape in a path is a client error, never a server error", async () => {
  for (const path of ["/v1/receipts/%E0%A4%A", "/v1/agents/%ZZ/receipts", "/v1/receipts/%/transaction"]) {
    const res = await call("GET", path, { token: admin });
    assert.equal(res.status, 404, path);
    assert.equal(res.success, false);
  }
});

test("an Idempotency-Key makes a retried decision safe over HTTP", async () => {
  await call("POST", "/v1/agents", { token: admin, body: { id: "retry-bot", label: "Retry" } });
  const token: string = (await call("POST", "/v1/agents/retry-bot/keys", { token: admin, body: { label: "r" } })).data.token;
  const decide = async (key: string, lamports: string) => {
    const res = await fetch(`${base}/v1/decisions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}`, "idempotency-key": key },
      body: toJson({ transfer: { kind: "sol", to: VENDOR, amount: lamports, decimals: 9 } } as never),
    });
    return { status: res.status, replayed: res.headers.get("idempotent-replayed"), body: fromJson(await res.text()) as { data: any; error: string | null } };
  };

  const first = await decide("order-1", "1000");
  assert.equal(first.status, 200);
  assert.equal(first.replayed, null);

  // The IETF draft sends the key as a quoted string; both spellings name the same key.
  const retry = await decide('"order-1"', "1000");
  assert.equal(retry.status, 200);
  assert.equal(retry.replayed, "true");
  assert.equal(retry.body.data.replayed, true);
  assert.equal(retry.body.data.receipt.body.receiptId, first.body.data.receipt.body.receiptId);

  const reused = await decide("order-1", "2000");
  assert.equal(reused.status, 422);
  assert.match(reused.body.error ?? "", /different transfer/);
  for (const bad of ["", "x".repeat(256), "café"]) {
    assert.equal((await decide(bad, "1000")).status, 400, JSON.stringify(bad));
  }
  const state = await call("GET", "/v1/agents/retry-bot", { token });
  assert.equal(state.data.state.callsInWindow, 1, "the retries took no second decision");
});

test("requests are logged without credentials, and errors are uniform", async () => {
  assert.equal((await call("GET", "/v1/nothing")).status, 404);
  assert.equal((await call("PUT", "/v1/decisions")).status, 405);
  const agentToken: string = (await call("POST", "/v1/agents/desk-bot/keys", { token: admin, body: { label: "log" } })).data.token;
  const raw = await fetch(`${base}/v1/decisions`, { method: "POST", headers: { "content-type": "text/plain", authorization: `Bearer ${agentToken}` }, body: "x" });
  assert.equal(raw.status, 415);
  // An admin is not an agent: it cannot take decisions on anyone's behalf.
  assert.equal((await pay(admin, "1")).status, 403);
  assert.ok(logs.length > 10);
  assert.equal(logs.some((l) => l.includes("gk_")), false, "no credential reaches the logs");
  const line = JSON.parse(logs[0] as string);
  assert.ok("status" in line && "ms" in line && "path" in line);

  // A client holding a failed response can name the log line that explains it.
  const missing = await fetch(`${base}/v1/nothing`);
  const id = missing.headers.get("x-request-id") ?? "";
  assert.match(id, /^[0-9a-f]{16}$/);
  assert.ok(logs.some((l) => JSON.parse(l).id === id && JSON.parse(l).status === 404));
});
