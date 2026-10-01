/**
 * The command line, end to end, as an operator and an auditor would use it.
 *
 * The demo writes what an operator would publish - receipts, and either the policy or only the
 * sealed trust anchor - and the verify commands check it as a stranger would, from files alone.
 */

import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { fromJson, toJson } from "../src/io/json.ts";
import { decodeBase58 } from "../src/solana/base58.ts";

const MAIN = fileURLToPath(new URL("../src/cli/main.ts", import.meta.url));

function cli(...args: string[]) {
  const r = spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", MAIN, ...args], { encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

const dir = mkdtempSync(join(tmpdir(), "genkai-cli-"));

test("the offline demo produces allow, deny and escalate receipts in both modes", () => {
  const r = cli("demo", "--out", dir);
  assert.equal(r.code, 0, r.err);
  for (const verdict of ["allow", "deny", "escalate"]) assert.match(r.out, new RegExp(verdict));
  for (const f of ["plaintext/receipts.json", "plaintext/policy.json", "sealed/receipts.json", "sealed/trust.json"]) {
    assert.ok(existsSync(join(dir, f)), f);
  }
  // The sealed directory is what a desk would publish. The policy must not be in it.
  assert.equal(existsSync(join(dir, "sealed/policy.json")), false);
  const sealedText = readFileSync(join(dir, "sealed/receipts.json"), "utf8");
  assert.doesNotMatch(sealedText, /exceeds|threshold|cap \d/);
});

test("a stranger verifies the published chains from files alone", () => {
  const plain = cli("verify-chain", join(dir, "plaintext/receipts.json"), "--policy", join(dir, "plaintext/policy.json"));
  assert.equal(plain.code, 0, plain.out + plain.err);
  assert.match(plain.out, /valid/i);

  const sealed = cli("verify-chain", join(dir, "sealed/receipts.json"), "--trust", join(dir, "sealed/trust.json"));
  assert.equal(sealed.code, 0, sealed.out + sealed.err);
});

test("a single receipt verifies, and a tampered one fails with a non-zero exit", () => {
  const receipts = fromJson(readFileSync(join(dir, "plaintext/receipts.json"), "utf8")) as Record<string, any>[];
  const one = join(dir, "one.json");
  writeFileSync(one, toJson(receipts[0] as never));
  assert.equal(cli("verify", one, "--policy", join(dir, "plaintext/policy.json")).code, 0);

  const forged = { ...receipts[0], body: { ...receipts[0]?.body, decision: { ...receipts[0]?.body.decision, verdict: "deny" } } };
  writeFileSync(one, toJson(forged as never));
  const r = cli("verify", one, "--policy", join(dir, "plaintext/policy.json"));
  assert.equal(r.code, 1);
  assert.match(r.out, /bad_signature/);
});

test("keygen writes a solana-keygen file and refuses to overwrite one", () => {
  const path = join(dir, "vault.json");
  const r = cli("keygen", path);
  assert.equal(r.code, 0, r.err);
  const bytes = JSON.parse(readFileSync(path, "utf8")) as number[];
  assert.equal(bytes.length, 64);
  const address = r.out.trim().split(/\s+/).pop() ?? "";
  assert.deepEqual([...decodeBase58(address)], bytes.slice(32));
  // The secret never reaches stdout.
  assert.doesNotMatch(r.out, /\[\d+,/);

  assert.equal(cli("keygen", path).code, 2);
});

test("seal reports the commitment and refuses a policy the circuit cannot hold", () => {
  const policyPath = join(dir, "plaintext/policy.json");
  const out = join(dir, "sealed-secret.json");
  const r = cli("seal", policyPath, out);
  assert.equal(r.code, 0, r.err);
  const sealed = JSON.parse(readFileSync(out, "utf8")) as { commitment: string; salt: string };
  assert.match(sealed.commitment, /^[0-9a-f]{64}$/);
  assert.match(sealed.salt, /^[0-9a-f]{64}$/);
  assert.match(r.out, new RegExp(sealed.commitment));
  assert.doesNotMatch(r.out, new RegExp(sealed.salt), "the salt is secret");

  const tooBig = join(dir, "too-big.json");
  const policy = fromJson(readFileSync(policyPath, "utf8")) as Record<string, unknown>;
  writeFileSync(tooBig, toJson({ ...policy, allowedMints: Array.from({ length: 9 }, (_, i) => `m${i}`) } as never));
  const bad = cli("seal", tooBig, join(dir, "nope.json"));
  assert.equal(bad.code, 2);
  assert.match(bad.err, /allowedMints/);
});

test("usage errors exit with 2 and say what was wrong", () => {
  assert.equal(cli().code, 2);
  assert.equal(cli("frobnicate").code, 2);
  const r = cli("verify", join(dir, "one.json"));
  assert.equal(r.code, 2);
  assert.match(r.err, /--policy or --trust/);
});
