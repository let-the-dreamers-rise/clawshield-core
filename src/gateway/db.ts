/**
 * The gateway's database: SQLite through node:sqlite, so persistence adds no dependency.
 *
 * SQLite fits the job. A gateway holds one vault key and serialises each agent's decisions, so
 * its write load is a handful of small transactions per decision, and a single file is trivial
 * to back up (`sqlite3 genkai.db .backup`) and to reason about. One gateway process per database
 * file: the per-agent ordering guarantee is enforced in process, and the version check in
 * commitDecision turns any second writer into a refused decision rather than a double spend.
 *
 * Migrations are append-only and numbered. Each runs once, inside a transaction, and the
 * applied version is recorded, so opening a database twice changes nothing.
 */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

const MIGRATIONS: readonly string[] = [
  `
  CREATE TABLE agents (
    id          TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    created_at  INTEGER NOT NULL
  );

  CREATE TABLE api_keys (
    key_id       TEXT PRIMARY KEY,
    hash         BLOB NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('admin', 'agent')),
    agent_id     TEXT REFERENCES agents(id),
    label        TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER,
    CHECK ((role = 'agent') = (agent_id IS NOT NULL))
  );
  CREATE INDEX api_keys_agent ON api_keys(agent_id);

  -- Amounts are decimal TEXT: they are u64-scale and SQLite integers are signed 64-bit.
  CREATE TABLE agent_state (
    agent_id            TEXT PRIMARY KEY REFERENCES agents(id),
    spent_in_window     TEXT NOT NULL,
    window_started_at   INTEGER NOT NULL,
    calls_in_window     INTEGER NOT NULL,
    drawdown_from_peak  TEXT NOT NULL,
    last_receipt_hash   TEXT,
    seq                 INTEGER NOT NULL DEFAULT 0,
    version             INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE receipts (
    receipt_id          TEXT PRIMARY KEY,
    agent_id            TEXT NOT NULL REFERENCES agents(id),
    seq                 INTEGER NOT NULL,
    body_hash           TEXT NOT NULL UNIQUE,
    verdict             TEXT NOT NULL CHECK (verdict IN ('allow', 'deny', 'escalate')),
    decided_at          INTEGER NOT NULL,
    json                TEXT NOT NULL,
    signed_transaction  TEXT,
    submitted_signature TEXT,
    submitted_at        INTEGER,
    created_at          INTEGER NOT NULL,
    UNIQUE (agent_id, seq)
  );

  CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       INTEGER NOT NULL,
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    subject  TEXT,
    detail   TEXT
  );
  `,
  `
  -- An agent's Idempotency-Key, bound to the decision it produced, so a retry replays it.
  CREATE TABLE idempotency_keys (
    agent_id      TEXT NOT NULL REFERENCES agents(id),
    key           TEXT NOT NULL,
    request_hash  TEXT NOT NULL,
    receipt_id    TEXT NOT NULL REFERENCES receipts(receipt_id),
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (agent_id, key)
  );
  CREATE INDEX idempotency_keys_created ON idempotency_keys(created_at);
  `,
];

export function openDatabase(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;");
  migrate(db);
  return db;
}

export function migrate(db: DatabaseSync): number {
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  MIGRATIONS.forEach((sql, i) => {
    const version = i + 1;
    if (version <= row.v) return;
    transaction(db, () => {
      db.exec(sql);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(version, Date.now());
    });
  });
  return MIGRATIONS.length;
}

/** Run fn inside BEGIN IMMEDIATE, so the write lock is taken up front, not on first write. */
export function transaction<T>(db: DatabaseSync, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}
