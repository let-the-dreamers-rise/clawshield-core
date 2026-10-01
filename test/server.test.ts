/**
 * The hosted verifier.
 *
 * Anyone can post a receipt and get an answer, so the server is a public, unauthenticated
 * endpoint and is built like one: bounded request bodies, strict content types, per-client
 * rate limiting, no stack traces in responses, and a uniform response envelope.
 */

import { strict as assert } from "node:assert";
import { after, before, test } from "node:test";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createVerifierServer } from "../src/server/verifier-server.ts";
import { toJson } from "../src/io/json.ts";
import { generateKeypair, hashReceiptBody } from "../src/receipt/sign.ts";
import { createPlaintextPolicyProvider, createSealedPolicyProvider, sealedCommitment } from "../src/policy/sealed.ts";
import { createStubMxe } from "../src/mxe/stub.ts";
import { createSolanaAdapter } from "../src/solana/adapter.ts";
import { solanaAddress } from "../src/solana/keys.ts";
import { NATIVE_SOL_MINT, SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID } from "../src/solana/types.ts";
import type { Policy } from "../src/policy/types.ts";
import type { SignedReceipt } from "../src/receipt/types.ts";

const AT = Date.UTC(2026, 8, 3, 8, 0, 0);
const KEYS = generateKeypair();
const VAULT = solanaAddress(KEYS.publicKey);
const SALT = "5f".repeat(32);
const policy: Policy = {
  policyId: "ops",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  allowedClusters: ["devnet"],
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  allowedMints: [NATIVE_SOL_MINT],
  maxAmountPerMint: { [NATIVE_SOL_MINT]: 1_000_000n },
};

let server: Server;
let base = "";
let plainReceipts: SignedReceipt[] = [];
let sealedReceipt: SignedReceipt;
let trust: Record<string, string>;

const submitWith = (provider: ReturnType<typeof createPlaintextPolicyProvider>) => {
  const adapter = createSolanaAdapter({ agentId: "bot", keys: KEYS, provider });
  return (amount: bigint, previousReceiptHash: string | null = null) =>
    adapter.submit({
      transfer: { kind: "sol", programId: SYSTEM_PROGRAM_ID, cluster: "devnet", from: VAULT, to: SYSTEM_PROGRAM_ID, decimals: 9, amount, requestedAt: AT },
      state: { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false },
      decidedAt: AT,
      recentBlockhash: "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N",
      previousReceiptHash,
    });
};

before(async () => {
  const plain = submitWith(createPlaintextPolicyProvider(policy));
  const first = await plain(10n);
  const second = await plain(5_000_000n, hashReceiptBody(first.receipt.body));
  plainReceipts = [first.receipt, second.receipt];

  const mxe = createStubMxe({ policy, salt: SALT, circuitId: "genkai.policy.v1", keys: generateKeypair() });
  const provider = createSealedPolicyProvider({
    commitment: sealedCommitment(policy, SALT),
    circuitId: "genkai.policy.v1",
    clusterPublicKey: mxe.clusterPublicKey,
    mxe,
  });
  sealedReceipt = (await submitWith(provider)(10n)).receipt;
  trust = { commitment: provider.commitment, circuitId: "genkai.policy.v1", clusterPublicKey: mxe.clusterPublicKey };

  server = createVerifierServer({ rateLimit: { capacity: 30, refillPerSecond: 0 }, maxBodyBytes: 64 * 1024 });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => new Promise<void>((resolve) => server.close(() => resolve())));

const post = (path: string, body: string, contentType = "application/json") =>
  fetch(`${base}${path}`, { method: "POST", headers: { "content-type": contentType }, body });

test("health check answers in the standard envelope", async () => {
  const res = await fetch(`${base}/healthz`);
  assert.equal(res.status, 200);
  const json = (await res.json()) as { success: boolean; data: { status: string } };
  assert.deepEqual([json.success, json.data.status], [true, "ok"]);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
});

test("a plaintext receipt is verified by replay", async () => {
  const res = await post("/v1/receipts/verify", toJson({ receipt: plainReceipts[0], policy } as never));
  const json = (await res.json()) as { success: boolean; data: { valid: boolean; mode: string } };
  assert.equal(res.status, 200);
  assert.deepEqual([json.data.valid, json.data.mode], [true, "plaintext"]);
});

test("a sealed receipt is verified against pinned trust", async () => {
  const res = await post("/v1/receipts/verify", toJson({ receipt: sealedReceipt, trust } as never));
  const json = (await res.json()) as { data: { valid: boolean; mode: string; failures: string[] } };
  assert.deepEqual([json.data.valid, json.data.mode], [true, "sealed"]);

  const wrong = await post("/v1/receipts/verify", toJson({ receipt: sealedReceipt, trust: { ...trust, commitment: "cd".repeat(32) } } as never));
  const wrongJson = (await wrong.json()) as { data: { valid: boolean; failures: string[] } };
  assert.equal(wrongJson.data.valid, false);
  assert.ok(wrongJson.data.failures.includes("commitment_mismatch"));
});

test("a chain is verified end to end, and a gap is reported", async () => {
  const ok = await post("/v1/chains/verify", toJson({ receipts: plainReceipts, policy } as never));
  assert.equal(((await ok.json()) as { data: { valid: boolean } }).data.valid, true);

  const gapped = await post("/v1/chains/verify", toJson({ receipts: [plainReceipts[1]], policy } as never));
  const json = (await gapped.json()) as { data: { valid: boolean; failures: string[] } };
  assert.equal(json.data.valid, false);
  assert.ok(json.data.failures.includes("chain_broken"));
});

test("a malformed receipt is a 400 naming the field, never a 500", async () => {
  const res = await post("/v1/receipts/verify", JSON.stringify({ receipt: { body: {} }, policy: {} }));
  assert.equal(res.status, 400);
  const json = (await res.json()) as { success: boolean; error: string; data: null };
  assert.equal(json.success, false);
  assert.equal(json.data, null);
  assert.match(json.error, /receipt\./);
  assert.doesNotMatch(json.error, /at .*\.ts:\d+/, "no stack traces");
});

test("supplying both a policy and a trust anchor is ambiguous and refused", async () => {
  const res = await post("/v1/receipts/verify", toJson({ receipt: sealedReceipt, policy, trust } as never));
  assert.equal(res.status, 400);
});

test("bodies that are not JSON, too large, or the wrong type are refused", async () => {
  assert.equal((await post("/v1/receipts/verify", "{not json")).status, 400);
  assert.equal((await post("/v1/receipts/verify", "{}", "text/plain")).status, 415);
  assert.equal((await post("/v1/receipts/verify", JSON.stringify({ pad: "x".repeat(70 * 1024) }))).status, 413);
  assert.equal((await fetch(`${base}/v1/receipts/verify`)).status, 405);
  assert.equal((await fetch(`${base}/nope`)).status, 404);
});

test("the browser verifier page is served with a restrictive CSP", async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /text\/html/);
  assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/);
  assert.match(await res.text(), /GENKAI/);
});

test("clients are rate limited with Retry-After", async () => {
  const limited = createVerifierServer({ rateLimit: { capacity: 2, refillPerSecond: 0 } });
  await new Promise<void>((resolve) => limited.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(limited.address() as AddressInfo).port}/healthz`;
  try {
    const statuses = [];
    for (let i = 0; i < 4; i++) statuses.push((await fetch(url)).status);
    assert.deepEqual(statuses, [200, 200, 429, 429]);
    const res = await fetch(url);
    assert.ok(Number(res.headers.get("retry-after")) >= 1);
  } finally {
    await new Promise<void>((resolve) => limited.close(() => resolve()));
  }
});
