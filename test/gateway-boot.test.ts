/**
 * Booting the gateway the way an operator would: from environment variables and files, with
 * every configuration mistake reported before the port opens, and no secret ever echoed back.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { ConfigError, parseGatewayEnv } from "../src/gateway/config.ts";
import { startGateway } from "../src/gateway/boot.ts";
import { generateKeypair } from "../src/receipt/sign.ts";
import { solanaSecretKey } from "../src/solana/keys.ts";
import { toJson } from "../src/io/json.ts";
import { DEMO_POLICY } from "../src/cli/demo.ts";

const MAIN = fileURLToPath(new URL("../src/cli/main.ts", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "genkai-gw-"));
const vaultFile = join(dir, "vault.json");
const policyFile = join(dir, "policy.json");
const secretBytes = solanaSecretKey(generateKeypair());
writeFileSync(vaultFile, JSON.stringify([...secretBytes]));
writeFileSync(policyFile, toJson(DEMO_POLICY as never));

test("configuration problems are all reported at once", () => {
  assert.throws(
    () => parseGatewayEnv({ GENKAI_EXECUTION: "broadcast", GENKAI_CLUSTER: "moonnet", PORT: "99999", GENKAI_PUBLIC_RECEIPTS: "maybe" }),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      const all = err.problems.join("\n");
      for (const name of ["GENKAI_VAULT_KEY", "GENKAI_POLICY_FILE", "GENKAI_CLUSTER", "GENKAI_RPC_URL", "PORT", "GENKAI_PUBLIC_RECEIPTS"]) assert.match(all, new RegExp(name));
      return true;
    },
  );
  assert.throws(() => parseGatewayEnv({ GENKAI_VAULT_KEY_FILE: vaultFile, GENKAI_DEPLOYMENT_FILE: "d.json", GENKAI_RPC_URL: "https://x" }), /AUTHORITY/);
  assert.throws(() => parseGatewayEnv({ GENKAI_VAULT_KEY_FILE: vaultFile, GENKAI_POLICY_FILE: "p", GENKAI_DEPLOYMENT_FILE: "d" }), /not both/);
  assert.throws(() => parseGatewayEnv({ GENKAI_VAULT_KEY_FILE: vaultFile, GENKAI_POLICY_FILE: "p", GENKAI_RPC_URL: "ftp://x" }), /http/);

  const ok = parseGatewayEnv({ GENKAI_VAULT_KEY_FILE: vaultFile, GENKAI_POLICY_FILE: policyFile, GENKAI_WINDOW_SECONDS: "86400" });
  assert.equal(ok.mode.kind, "plaintext");
  assert.equal(ok.execution, "sign");
  assert.equal(ok.publicReceipts, true);
  assert.equal(ok.windowSeconds, 86400);
  assert.equal(ok.host, "127.0.0.1");
});

test("a gateway boots from files, serves, and shuts down cleanly", async () => {
  const settings = parseGatewayEnv({ GENKAI_VAULT_KEY_FILE: vaultFile, GENKAI_POLICY_FILE: policyFile, GENKAI_DB_PATH: join(dir, "db", "g.db"), PORT: "0" });
  const lines: string[] = [];
  const gw = await startGateway(settings, (l) => lines.push(l));
  try {
    const ready = (await (await fetch(`${gw.url}/readyz`)).json()) as { data: { database: string; rpc: string } };
    assert.equal(ready.data.database, "ok");
    assert.equal(ready.data.rpc, "offline");
    const trust = (await (await fetch(`${gw.url}/v1/trust`)).json()) as { data: { vault: string; mode: string } };
    assert.equal(trust.data.vault, gw.vault);
    assert.equal(trust.data.mode, "plaintext");
    assert.ok(lines.some((l) => l.includes("gateway.start")));
  } finally {
    await gw.close();
  }
});

test("a bad key is refused at boot without echoing what was in it", async () => {
  const leaky = join(dir, "leaky.json");
  writeFileSync(leaky, `[${[...secretBytes].slice(0, 63).join(",")}, "sk"]`);
  const notJson = join(dir, "notjson.json");
  writeFileSync(notJson, `secret-material-${[...secretBytes].join("")}`);
  for (const file of [leaky, notJson, join(dir, "missing.json")]) {
    const settings = parseGatewayEnv({ GENKAI_VAULT_KEY_FILE: file, GENKAI_POLICY_FILE: policyFile, GENKAI_DB_PATH: join(dir, "x.db"), PORT: "0" });
    await assert.rejects(startGateway(settings, () => {}), (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.doesNotMatch(err.message, /secret-material|\d{1,3},\d{1,3},\d{1,3}/);
      return true;
    });
  }
});

test("the first admin key is minted offline by whoever holds the database", () => {
  const db = join(dir, "admin.db");
  const run = (...args: string[]) => spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", MAIN, ...args], { encoding: "utf8" });

  const made = run("gateway-admin", "create-admin-key", "--db", db, "--label", "ops");
  assert.equal(made.status, 0, made.stderr);
  const token = /gk_[0-9a-f]{12}_[A-Za-z0-9_-]{43}/.exec(made.stdout)?.[0];
  assert.ok(token, made.stdout);

  const listed = run("gateway-admin", "list-keys", "--db", db);
  assert.equal(listed.status, 0, listed.stderr);
  const keyId = token.slice(3, 15);
  assert.match(listed.stdout, new RegExp(keyId));
  assert.doesNotMatch(listed.stdout, new RegExp(token.slice(16)), "listing never prints a secret");

  assert.equal(run("gateway-admin", "revoke-key", keyId, "--db", db).status, 0);
  assert.match(run("gateway-admin", "list-keys", "--db", db).stdout, /revoked/);
  assert.equal(run("gateway-admin", "revoke-key", keyId, "--db", db).status, 1);
  assert.equal(run("gateway-admin", "nonsense", "--db", db).status, 2);
  assert.equal(run("gateway", "--port", "x").status, 2);
});
