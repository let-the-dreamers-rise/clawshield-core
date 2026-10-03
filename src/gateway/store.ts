/**
 * The gateway's repository: every read and write the gateway makes, behind one interface, so
 * the service and HTTP layers never touch SQL and a different backend means one new file.
 *
 * Rows are converted at this boundary. Amounts come back as bigints, receipts are re-parsed and
 * re-validated on the way out (a row is data from disk, not something to trust blindly), and
 * key hashes never leave except through findKey, which authentication alone uses.
 */

import type { DatabaseSync, SQLOutputValue } from "node:sqlite";
import { fromJson, toJson } from "../io/json.ts";
import { parseSignedReceipt } from "../io/schema.ts";
import { hashReceiptBody } from "../receipt/sign.ts";
import type { AgentState } from "../policy/types.ts";
import type { SignedReceipt } from "../receipt/types.ts";
import type { Role } from "./auth.ts";
import { initialState } from "./ledger.ts";
import { transaction } from "./db.ts";

export class ConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConflictError";
  }
}

export interface AgentRecord {
  readonly id: string;
  readonly label: string;
  readonly revoked: boolean;
  readonly createdAt: number;
}

export interface KeyRecord {
  readonly keyId: string;
  readonly role: Role;
  readonly agentId?: string;
  readonly label: string;
  readonly createdAt: number;
  readonly lastUsedAt?: number;
  readonly revokedAt?: number;
}

export interface KeyWithHash extends KeyRecord {
  readonly hash: Uint8Array;
}

export interface Ledger {
  /** Without `revoked`, which lives on the agent; the service joins the two. */
  readonly state: AgentState;
  readonly lastReceiptHash: string | null;
  readonly seq: number;
  readonly version: number;
}

export interface StoredReceipt {
  readonly receipt: SignedReceipt;
  readonly agentId: string;
  readonly seq: number;
  readonly signedTransaction?: string;
  readonly submittedSignature?: string;
}

export interface AuditEntry {
  readonly id?: number;
  readonly at: number;
  readonly actor: string;
  readonly action: string;
  readonly subject?: string;
  readonly detail?: Readonly<Record<string, unknown>>;
}

export interface Page<T> {
  readonly items: readonly T[];
  readonly total: number;
}

/** A client's Idempotency-Key and what it was bound to. */
export interface IdempotencyBinding {
  readonly key: string;
  /** The hash of the transfer the key names. */
  readonly requestHash: string;
  /** A key created at or before this time has lapsed. */
  readonly lapsedAt: number;
}

export interface CommitDecision {
  readonly agentId: string;
  /** The ledger version the decision was taken against. A newer version refuses the commit. */
  readonly expectedVersion: number;
  readonly nextState: AgentState;
  readonly receipt: SignedReceipt;
  readonly signedTransaction?: string;
  readonly now: number;
  /** Bound in the same transaction, so a recorded decision is never left without its key. */
  readonly idempotency?: IdempotencyBinding;
}

type Row = Record<string, SQLOutputValue>;
/** A cell read by column name; absent and NULL are the same thing to every caller here. */
type Cell = SQLOutputValue | undefined;

const nil = (v: Cell): v is null | undefined => v === null || v === undefined;
const text = (v: Cell): string => String(v ?? "");
const num = (v: Cell): number => Number(v ?? NaN);
const optText = (v: Cell): string | undefined => (nil(v) ? undefined : String(v));

const agentOf = (r: Row): AgentRecord => ({ id: text(r["id"]), label: text(r["label"]), revoked: r["revoked"] === 1, createdAt: num(r["created_at"]) });

function keyOf(r: Row): KeyRecord {
  const role = text(r["role"]) as Role;
  const out: KeyRecord = {
    keyId: text(r["key_id"]),
    role,
    label: text(r["label"]),
    createdAt: num(r["created_at"]),
    ...(nil(r["agent_id"]) ? {} : { agentId: text(r["agent_id"]) }),
    ...(nil(r["last_used_at"]) ? {} : { lastUsedAt: num(r["last_used_at"]) }),
    ...(nil(r["revoked_at"]) ? {} : { revokedAt: num(r["revoked_at"]) }),
  };
  return out;
}

function receiptOf(r: Row): StoredReceipt {
  return {
    receipt: parseSignedReceipt(fromJson(text(r["json"])), "receipt"),
    agentId: text(r["agent_id"]),
    seq: num(r["seq"]),
    ...(nil(r["signed_transaction"]) ? {} : { signedTransaction: text(r["signed_transaction"]) }),
    ...(nil(r["submitted_signature"]) ? {} : { submittedSignature: text(r["submitted_signature"]) }),
  };
}

export type GatewayStore = ReturnType<typeof createStore>;

export function createStore(db: DatabaseSync) {
  const one = (sql: string, ...params: (string | number | null | Uint8Array)[]): Row | undefined =>
    db.prepare(sql).get(...params) as Row | undefined;
  const all = (sql: string, ...params: (string | number | null)[]): Row[] => db.prepare(sql).all(...params) as Row[];
  const run = (sql: string, ...params: (string | number | null | Uint8Array)[]) => db.prepare(sql).run(...params);

  function createAgent(a: { readonly id: string; readonly label: string; readonly now: number }): AgentRecord {
    if (one("SELECT 1 FROM agents WHERE id = ?", a.id)) throw new ConflictError(`Agent ${a.id} already exists`);
    const s = initialState(a.now);
    transaction(db, () => {
      run("INSERT INTO agents (id, label, revoked, created_at) VALUES (?, ?, 0, ?)", a.id, a.label, a.now);
      run(
        "INSERT INTO agent_state (agent_id, spent_in_window, window_started_at, calls_in_window, drawdown_from_peak) VALUES (?, ?, ?, ?, ?)",
        a.id, s.spentInWindow.toString(), s.windowStartedAt, s.callsInWindow, s.drawdownFromPeak.toString(),
      );
    });
    return { id: a.id, label: a.label, revoked: false, createdAt: a.now };
  }

  const getAgent = (id: string): AgentRecord | undefined => {
    const r = one("SELECT * FROM agents WHERE id = ?", id);
    return r ? agentOf(r) : undefined;
  };

  const listAgents = (): readonly AgentRecord[] => all("SELECT * FROM agents ORDER BY created_at, id").map(agentOf);

  function setRevoked(id: string, revoked: boolean): AgentRecord | undefined {
    run("UPDATE agents SET revoked = ? WHERE id = ?", revoked ? 1 : 0, id);
    return getAgent(id);
  }

  function setDrawdown(agentId: string, drawdown: bigint): void {
    run("UPDATE agent_state SET drawdown_from_peak = ?, version = version + 1 WHERE agent_id = ?", drawdown.toString(), agentId);
  }

  function insertKey(k: { readonly keyId: string; readonly hash: Uint8Array; readonly role: Role; readonly agentId?: string; readonly label: string; readonly now: number }): void {
    run(
      "INSERT INTO api_keys (key_id, hash, role, agent_id, label, created_at) VALUES (?, ?, ?, ?, ?, ?)",
      k.keyId, k.hash, k.role, k.agentId ?? null, k.label, k.now,
    );
  }

  const findKey = (keyId: string): KeyWithHash | undefined => {
    const r = one("SELECT * FROM api_keys WHERE key_id = ?", keyId);
    return r ? { ...keyOf(r), hash: new Uint8Array(r["hash"] as Uint8Array) } : undefined;
  };

  const touchKey = (keyId: string, now: number): void => void run("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", now, keyId);

  const revokeKey = (keyId: string, now: number): boolean =>
    Number(run("UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL", now, keyId).changes) === 1;

  const listKeys = (agentId?: string): readonly KeyRecord[] =>
    (agentId === undefined
      ? all("SELECT * FROM api_keys ORDER BY created_at, key_id")
      : all("SELECT * FROM api_keys WHERE agent_id = ? ORDER BY created_at, key_id", agentId)
    ).map(keyOf);

  function getLedger(agentId: string): Ledger | undefined {
    const r = one("SELECT * FROM agent_state WHERE agent_id = ?", agentId);
    if (!r) return undefined;
    return {
      state: {
        spentInWindow: BigInt(text(r["spent_in_window"])),
        windowStartedAt: num(r["window_started_at"]),
        callsInWindow: num(r["calls_in_window"]),
        drawdownFromPeak: BigInt(text(r["drawdown_from_peak"])),
        revoked: false,
      },
      lastReceiptHash: optText(r["last_receipt_hash"]) ?? null,
      seq: num(r["seq"]),
      version: num(r["version"]),
    };
  }

  /**
   * Record a decision and advance the ledger in one transaction, or neither. The version check
   * is what stops two decisions taken against the same ledger state from both spending it.
   */
  function commitDecision(c: CommitDecision): number {
    const bodyHash = hashReceiptBody(c.receipt.body);
    return transaction(db, () => {
      const updated = one(
        `UPDATE agent_state
           SET spent_in_window = ?, window_started_at = ?, calls_in_window = ?, last_receipt_hash = ?,
               seq = seq + 1, version = version + 1
         WHERE agent_id = ? AND version = ?
         RETURNING seq`,
        c.nextState.spentInWindow.toString(), c.nextState.windowStartedAt, c.nextState.callsInWindow, bodyHash, c.agentId, c.expectedVersion,
      );
      if (!updated) throw new ConflictError(`Ledger for ${c.agentId} moved on; the decision was not recorded`);
      const seq = num(updated["seq"]);
      run(
        `INSERT INTO receipts (receipt_id, agent_id, seq, body_hash, verdict, decided_at, json, signed_transaction, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        c.receipt.body.receiptId, c.agentId, seq, bodyHash, c.receipt.body.decision.verdict, c.receipt.body.decision.decidedAt,
        toJson(c.receipt as never), c.signedTransaction ?? null, c.now,
      );
      if (c.idempotency) {
        // Lapsed keys are purged on each keyed commit, so the table holds about a day of keys.
        run("DELETE FROM idempotency_keys WHERE created_at <= ?", c.idempotency.lapsedAt);
        run(
          "INSERT INTO idempotency_keys (agent_id, key, request_hash, receipt_id, created_at) VALUES (?, ?, ?, ?, ?)",
          c.agentId, c.idempotency.key, c.idempotency.requestHash, c.receipt.body.receiptId, c.now,
        );
      }
      return seq;
    });
  }

  /** The decision a live Idempotency-Key names, if any. */
  function findIdempotent(agentId: string, key: string, lapsedAt: number): { readonly requestHash: string; readonly receiptId: string } | undefined {
    const r = one("SELECT request_hash, receipt_id FROM idempotency_keys WHERE agent_id = ? AND key = ? AND created_at > ?", agentId, key, lapsedAt);
    return r ? { requestHash: text(r["request_hash"]), receiptId: text(r["receipt_id"]) } : undefined;
  }

  const recordSubmission = (receiptId: string, signature: string, now: number): void =>
    void run("UPDATE receipts SET submitted_signature = ?, submitted_at = ? WHERE receipt_id = ?", signature, now, receiptId);

  const getReceipt = (receiptId: string): StoredReceipt | undefined => {
    const r = one("SELECT * FROM receipts WHERE receipt_id = ?", receiptId);
    return r ? receiptOf(r) : undefined;
  };

  function listReceipts(agentId: string, page: { readonly afterSeq: number; readonly limit: number }): Page<StoredReceipt> {
    const total = num((one("SELECT COUNT(*) AS n FROM receipts WHERE agent_id = ?", agentId) as Row)["n"]);
    const items = all("SELECT * FROM receipts WHERE agent_id = ? AND seq > ? ORDER BY seq LIMIT ?", agentId, page.afterSeq, page.limit).map(receiptOf);
    return { items, total };
  }

  function audit(e: AuditEntry): void {
    run(
      "INSERT INTO audit_log (at, actor, action, subject, detail) VALUES (?, ?, ?, ?, ?)",
      e.at, e.actor, e.action, e.subject ?? null, e.detail === undefined ? null : toJson(e.detail as never),
    );
  }

  function listAudit(page: { readonly afterId: number; readonly limit: number }): Page<AuditEntry> {
    const total = num((one("SELECT COUNT(*) AS n FROM audit_log") as Row)["n"]);
    const items = all("SELECT * FROM audit_log WHERE id > ? ORDER BY id LIMIT ?", page.afterId, page.limit).map(
      (r): AuditEntry => ({
        id: num(r["id"]),
        at: num(r["at"]),
        actor: text(r["actor"]),
        action: text(r["action"]),
        ...(nil(r["subject"]) ? {} : { subject: text(r["subject"]) }),
        ...(nil(r["detail"]) ? {} : { detail: fromJson(text(r["detail"])) as Record<string, unknown> }),
      }),
    );
    return { items, total };
  }

  return Object.freeze({
    createAgent, getAgent, listAgents, setRevoked, setDrawdown,
    insertKey, findKey, touchKey, revokeKey, listKeys,
    getLedger, commitDecision, findIdempotent, recordSubmission, getReceipt, listReceipts,
    audit, listAudit,
    /** Liveness of the database itself, for /readyz. */
    ping: (): boolean => one("SELECT 1 AS ok")?.["ok"] === 1,
  });
}

