/**
 * The gateway's foundations: the ledger rules that turn stored history into the AgentState the
 * engine reasons over, the API key scheme, and the SQLite store.
 *
 * The engine trusts the state it is handed. In the gateway that state comes from here, never
 * from the agent, so these rules are part of enforcement: a window that never rolls is a cap
 * that never lifts, and a call that is not counted is a rate limit an agent can probe past.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { afterDecision, initialState, stateAt } from "../src/gateway/ledger.ts";
import { bearerToken, generateApiKey, hashSecret, parseApiKey, secretMatches } from "../src/gateway/auth.ts";
import { openDatabase } from "../src/gateway/db.ts";
import { ConflictError, createStore } from "../src/gateway/store.ts";
import { generateKeypair, hashReceiptBody, signReceipt } from "../src/receipt/sign.ts";
import type { ReceiptBody } from "../src/receipt/types.ts";

const T0 = Date.UTC(2026, 9, 2, 9, 0, 0);

test("a window rolls over once its length has passed, and not before", () => {
  const s = { ...initialState(T0), spentInWindow: 70n, callsInWindow: 4 };
  assert.deepEqual(stateAt(s, 3600, T0 + 3_599_999), s);
  const rolled = stateAt(s, 3600, T0 + 3_600_000);
  assert.equal(rolled.spentInWindow, 0n);
  assert.equal(rolled.callsInWindow, 0);
  assert.equal(rolled.windowStartedAt, T0 + 3_600_000);
  // No window length means the window never rolls: the cap is a lifetime cap.
  assert.deepEqual(stateAt(s, undefined, T0 + 10 * 86_400_000), s);
  // A clock that went backwards never resets anything.
  assert.deepEqual(stateAt(s, 3600, T0 - 1), s);
});

test("every decision is a call; only an allow spends", () => {
  const s = initialState(T0);
  const allowed = afterDecision(s, "allow", 25n);
  assert.equal(allowed.callsInWindow, 1);
  assert.equal(allowed.spentInWindow, 25n);
  for (const verdict of ["deny", "escalate"] as const) {
    const next = afterDecision(allowed, verdict, 1_000n);
    assert.equal(next.callsInWindow, 2, verdict);
    assert.equal(next.spentInWindow, 25n, verdict);
  }
  // A non-positive amount never credits the window, even when allowed.
  assert.equal(afterDecision(s, "allow", -5n).spentInWindow, 0n);
  assert.equal(afterDecision(s, "allow", undefined).spentInWindow, 0n);
  // Inputs are never mutated.
  assert.equal(s.callsInWindow, 0);
});

test("an API key carries a public id and a secret, and only the secret's hash is kept", () => {
  const key = generateApiKey();
  assert.match(key.token, /^gk_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$/);
  const parsed = parseApiKey(key.token);
  assert.deepEqual(parsed, { keyId: key.keyId, secret: key.secret });
  assert.equal(secretMatches(key.secret, hashSecret(key.secret)), true);
  const last = key.secret.slice(-1);
  const forged = `${key.secret.slice(0, -1)}${last === "A" ? "B" : "A"}`;
  assert.equal(secretMatches(forged, hashSecret(key.secret)), false);
  assert.notEqual(generateApiKey().keyId, key.keyId);

  for (const bad of ["", "gk_", `gk_${key.keyId}`, `gk_${key.keyId}_short`, `xx_${key.keyId}_${key.secret}`, `${key.token} `]) {
    assert.equal(parseApiKey(bad), null, bad);
  }
  assert.equal(bearerToken(`Bearer ${key.token}`), key.token);
  assert.equal(bearerToken(`bearer ${key.token}`), key.token);
  assert.equal(bearerToken(`Basic ${key.token}`), null);
  assert.equal(bearerToken(undefined), null);
});

function receipt(agentId: string, previous: string | null, n: number) {
  const body: ReceiptBody = {
    receiptId: `r-${agentId}-${n}`,
    schemaVersion: 1,
    policyHash: "ab".repeat(32),
    request: { agentId, tool: "solana_transfer", requestedAt: T0 + n, params: {} },
    state: initialState(T0),
    decision: { verdict: n % 2 === 0 ? "allow" : "deny", reasons: [], policyId: "p", policyVersion: 1, decidedAt: T0 + n },
    previousReceiptHash: previous,
  };
  return signReceipt(body, KEYS);
}
const KEYS = generateKeypair();

test("the store keeps agents, keys, ledgers, receipts and an audit trail", () => {
  const db = openDatabase(":memory:");
  const store = createStore(db);

  const agent = store.createAgent({ id: "desk-bot", label: "Desk bot", now: T0 });
  assert.equal(agent.revoked, false);
  assert.throws(() => store.createAgent({ id: "desk-bot", label: "again", now: T0 }), ConflictError);
  assert.deepEqual(store.listAgents().map((a) => a.id), ["desk-bot"]);

  const key = generateApiKey();
  store.insertKey({ keyId: key.keyId, hash: hashSecret(key.secret), role: "agent", agentId: "desk-bot", label: "prod", now: T0 });
  const found = store.findKey(key.keyId);
  assert.equal(found?.role, "agent");
  assert.equal(found?.agentId, "desk-bot");
  assert.ok(found && secretMatches(key.secret, found.hash));
  assert.equal(store.listKeys("desk-bot")[0]?.keyId, key.keyId);
  assert.equal("hash" in (store.listKeys("desk-bot")[0] as object), false, "listing never exposes hashes");
  // An agent key must name an agent that exists.
  assert.throws(() => store.insertKey({ keyId: "000000000000", hash: hashSecret("x"), role: "agent", agentId: "ghost", label: "", now: T0 }));

  const ledger = store.getLedger("desk-bot");
  assert.equal(ledger?.seq, 0);
  assert.equal(ledger?.lastReceiptHash, null);

  const first = receipt("desk-bot", null, 0);
  store.commitDecision({ agentId: "desk-bot", expectedVersion: ledger!.version, nextState: afterDecision(ledger!.state, "allow", 10n), receipt: first, signedTransaction: "AQID", now: T0 });
  const after1 = store.getLedger("desk-bot");
  assert.equal(after1?.seq, 1);
  assert.equal(after1?.lastReceiptHash, hashReceiptBody(first.body));
  assert.equal(after1?.state.spentInWindow, 10n);

  // A writer holding a stale version loses: two decisions cannot both spend the same budget.
  assert.throws(
    () => store.commitDecision({ agentId: "desk-bot", expectedVersion: ledger!.version, nextState: ledger!.state, receipt: receipt("desk-bot", null, 9), now: T0 }),
    ConflictError,
  );

  const second = receipt("desk-bot", hashReceiptBody(first.body), 1);
  store.commitDecision({ agentId: "desk-bot", expectedVersion: after1!.version, nextState: after1!.state, receipt: second, now: T0 });

  const stored = store.getReceipt(first.body.receiptId);
  assert.equal(stored?.seq, 1);
  assert.equal(stored?.signedTransaction, "AQID");
  assert.deepEqual(stored?.receipt, first);
  const page = store.listReceipts("desk-bot", { afterSeq: 0, limit: 1 });
  assert.equal(page.total, 2);
  assert.deepEqual(page.items.map((r) => r.seq), [1]);
  assert.deepEqual(store.listReceipts("desk-bot", { afterSeq: 1, limit: 10 }).items.map((r) => r.seq), [2]);

  store.setRevoked("desk-bot", true);
  assert.equal(store.getAgent("desk-bot")?.revoked, true);
  store.setDrawdown("desk-bot", 5_000n);
  assert.equal(store.getLedger("desk-bot")?.state.drawdownFromPeak, 5_000n);

  assert.equal(store.revokeKey(key.keyId, T0 + 1), true);
  assert.equal(store.findKey(key.keyId)?.revokedAt, T0 + 1);
  assert.equal(store.revokeKey(key.keyId, T0 + 2), false, "revoking twice changes nothing");

  store.audit({ at: T0, actor: "key_admin", action: "agent.create", subject: "desk-bot", detail: { label: "Desk bot" } });
  const audit = store.listAudit({ afterId: 0, limit: 10 });
  assert.equal(audit.items[0]?.action, "agent.create");
  assert.deepEqual(audit.items[0]?.detail, { label: "Desk bot" });
  db.close();
});

test("migrations are idempotent and the schema version is recorded", () => {
  const db = openDatabase(":memory:");
  const version = (db.prepare("SELECT MAX(version) AS v FROM schema_migrations").get() as { v: number }).v;
  assert.ok(version >= 1);
  // Reopening the same database must not reapply anything.
  const again = createStore(db);
  assert.deepEqual(again.listAgents(), []);
  db.close();
});
