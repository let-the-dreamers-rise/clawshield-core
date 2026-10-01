/**
 * The live path end to end, against a fake cluster: the demo sealing through the Arcium client,
 * the hosted verifier's handlers reading DecisionRecords, and the deployment manifest that ties
 * them together.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { keypairFromSeed, solanaAddress } from "../src/solana/keys.ts";
import { decodeRequestFields, encodeRequestFields, policyRecordAddress } from "../src/mxe/onchain.ts";
import { encodeRequest } from "../src/mxe/encoding.ts";
import { sealedCommitment } from "../src/policy/sealed.ts";
import { DEMO_POLICY, runDemo } from "../src/cli/demo.ts";
import { parseDeployment, trustOf, type Deployment } from "../src/cli/deployment.ts";
import { handleVerifyChain, handleVerifyReceipt, MAX_ONCHAIN_CHAIN_LENGTH } from "../src/server/handlers.ts";
import { fromJson } from "../src/io/json.ts";
import { SchemaError } from "../src/io/schema.ts";
import { SYSTEM_PROGRAM_ID, toActionRequest } from "../src/solana/types.ts";
import { PROGRAM, fakeCluster, policyIdBytes } from "./helpers/chain.ts";

const AUTHORITY = keypairFromSeed(new Uint8Array(32).fill(5));
const AUTHORITY_ADDRESS = solanaAddress(AUTHORITY.publicKey);
const POLICY = policyRecordAddress(PROGRAM, AUTHORITY_ADDRESS, policyIdBytes(DEMO_POLICY.policyId));
const COMMITMENT = sealedCommitment(DEMO_POLICY, "ef".repeat(32));

const deployment: Deployment = {
  cluster: "devnet",
  rpc: "https://api.devnet.solana.com",
  programId: PROGRAM,
  clusterOffset: 456,
  circuitId: "genkai.policy.v2",
  policy: POLICY,
  policyId: DEMO_POLICY.policyId,
  commitment: COMMITMENT,
  authority: AUTHORITY_ADDRESS,
};

const cluster = () => fakeCluster({ authority: AUTHORITY_ADDRESS, policyId: DEMO_POLICY.policyId, commitment: COMMITMENT, policy: POLICY, sealedPolicy: DEMO_POLICY });

test("request fields decode back to exactly what was encoded", () => {
  const at = Date.UTC(2026, 9, 2, 23, 59, 0);
  const request = toActionRequest(
    { kind: "sol", programId: SYSTEM_PROGRAM_ID, cluster: "devnet", from: AUTHORITY_ADDRESS, to: "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE", decimals: 9, amount: 123_456_789n, requestedAt: at },
    "bot",
  );
  const encoded = encodeRequest(request, { spentInWindow: 7n, windowStartedAt: at, callsInWindow: 3, drawdownFromPeak: 9n, revoked: true });
  assert.deepEqual(decodeRequestFields(encodeRequestFields(encoded)), encoded);
  assert.throws(() => decodeRequestFields(new Uint8Array(120)), RangeError);
});

test("a deployment manifest parses strictly and yields the trust a verifier pins", () => {
  assert.deepEqual(parseDeployment({ ...deployment, note: "public facts only" }), deployment);
  assert.deepEqual(trustOf(deployment), { commitment: COMMITMENT, circuitId: "genkai.policy.v2", programId: PROGRAM, policy: POLICY });
  assert.throws(() => parseDeployment({ ...deployment, programId: "nope" }), SchemaError);
  assert.throws(() => parseDeployment({ ...deployment, salt: "ab" }), SchemaError);
  assert.throws(() => parseDeployment({ ...deployment, clusterOffset: -1 }), SchemaError);
});

test("the live demo seals every proposal through the cluster and verifies each receipt on chain", async () => {
  const chain = cluster();
  const out = mkdtempSync(join(tmpdir(), "genkai-live-"));
  const lines: string[] = [];
  try {
    const result = await runDemo({ out, live: { deployment, rpc: chain.rpc, authority: AUTHORITY }, log: (l) => lines.push(l) });
    assert.equal(result.sealedValid, true, lines.join("\n"));
    assert.equal(result.plaintextValid, true);
    assert.equal(chain.sent.length, 5, "one evaluate transaction per proposal");
    assert.ok(lines.some((l) => l.includes("decided by Arcium cluster 456 on devnet")));

    const receipts = fromJson(readFileSync(join(out, "sealed", "receipts.json"), "utf8")) as unknown[];
    const trust = fromJson(readFileSync(join(out, "sealed", "trust.json"), "utf8"));
    assert.deepEqual(trust, trustOf(deployment));

    // The hosted verifier, with and without RPC.
    const live = await handleVerifyChain({ receipts, trust }, { rpc: chain.rpc });
    assert.equal(live.valid, true, live.detail.join("; "));
    const offline = await handleVerifyChain({ receipts, trust });
    assert.equal(offline.valid, false);
    assert.ok(offline.failures.every((f) => f === "attestation_unchecked"));

    const one = await handleVerifyReceipt({ receipt: receipts[0], trust, expectedPreviousHash: null }, { rpc: chain.rpc });
    assert.equal(one.valid, true, one.detail.join("; "));

    // A record that disappears (closed, or never written on this cluster) is a failure.
    chain.accounts.clear();
    const gone = await handleVerifyReceipt({ receipt: receipts[0], trust }, { rpc: chain.rpc });
    assert.equal(gone.valid, false);
    assert.ok(gone.failures.includes("attestation_invalid"));

    // Too long a chain to fan out over RPC is refused up front.
    const many = Array.from({ length: MAX_ONCHAIN_CHAIN_LENGTH + 1 }, () => receipts[0]);
    await assert.rejects(handleVerifyChain({ receipts: many, trust }, { rpc: chain.rpc }), SchemaError);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
