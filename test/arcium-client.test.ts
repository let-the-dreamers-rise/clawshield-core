/**
 * The live MXE client: queue evaluate on the GENKAI program, wait for the cluster's callback,
 * and hand back the verdict with an attestation that points at the DecisionRecord.
 *
 * The account derivations are checked against constants published in the program's IDL and
 * the Arcium SDK, so a seed that drifts is caught here rather than as a failed transaction.
 * The client is driven against a fake chain whose "cluster" runs the circuit model.
 */

import { strict as assert } from "node:assert";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { keypairFromSeed, solanaAddress } from "../src/solana/keys.ts";
import { decodeBase58 } from "../src/solana/base58.ts";
import {
  ARCIUM_CLOCK_ACCOUNT,
  ARCIUM_FEE_POOL_ACCOUNT,
  ARCIUM_PROGRAM_ID,
  EVALUATE_DISCRIMINATOR,
  compDefOffset,
  evaluateAccounts,
  evaluateInstruction,
} from "../src/mxe/arcium-accounts.ts";
import { ArciumMxeError, createArciumMxeClient, type ArciumMxeConfig } from "../src/mxe/arcium.ts";
import { decisionRecordAddress, encodeRequestFields, policyRecordAddress, REQUEST_FIELDS_SIZE } from "../src/mxe/onchain.ts";
import { encodeRequest } from "../src/mxe/encoding.ts";
import { createSealedPolicyProvider, sealedCommitment, SealedPolicyError } from "../src/policy/sealed.ts";
import { verifySealedReceipt, verifySealedReceiptOnChain } from "../src/receipt/verify-sealed.ts";
import { signReceipt } from "../src/receipt/sign.ts";
import { DEMO_POLICY } from "../src/cli/demo.ts";
import { SYSTEM_PROGRAM_ID, toActionRequest } from "../src/solana/types.ts";
import type { AgentState } from "../src/policy/types.ts";
import { PROGRAM, decisionRecordBytes, fakeChain, policyIdBytes, policyRecordBytes, type FakeChain } from "./helpers/chain.ts";

const AUTHORITY = keypairFromSeed(new Uint8Array(32).fill(3));
const AUTHORITY_ADDRESS = solanaAddress(AUTHORITY.publicKey);
const CLUSTER_OFFSET = 456;
const OFFSET = 77n;
const SALT = "cd".repeat(32);
const COMMITMENT = sealedCommitment(DEMO_POLICY, SALT);
const CIRCUIT = "genkai.policy.v2";
const AT = Date.UTC(2026, 9, 2, 12, 0, 0);
const POLICY = policyRecordAddress(PROGRAM, AUTHORITY_ADDRESS, policyIdBytes(DEMO_POLICY.policyId));
const DECISION = decisionRecordAddress(PROGRAM, POLICY, OFFSET);

const state: AgentState = { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
const request = (lamports: bigint) =>
  toActionRequest(
    { kind: "sol", programId: SYSTEM_PROGRAM_ID, cluster: "devnet", from: AUTHORITY_ADDRESS, to: "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE", decimals: 9, amount: lamports, requestedAt: AT },
    "desk-bot",
  );

/** The last byte of evaluate's instruction data is disclose_rules. */
function discloseFlagOf(wire: Uint8Array): boolean {
  return wire[wire.length - 1] === 1;
}

/** A chain whose cluster answers `polls` reads after the queue transaction lands. */
function liveChain(opts: { polls?: number; never?: boolean; status?: number; tamper?: bigint; authority?: string } = {}) {
  let reads = 0;
  let pending: Uint8Array | undefined;
  const chain = fakeChain(
    { [POLICY]: { data: policyRecordBytes({ authority: opts.authority ?? AUTHORITY_ADDRESS, policyId: DEMO_POLICY.policyId, commitment: COMMITMENT, status: opts.status }) } },
    (wire, c) => {
      if (opts.never) return;
      const lamports = currentLamports;
      pending = decisionRecordBytes({
        policy: POLICY,
        offset: OFFSET,
        sealedPolicy: DEMO_POLICY,
        request: request(lamports),
        state,
        discloseRules: discloseFlagOf(wire),
        fieldsFor: opts.tamper === undefined ? undefined : request(opts.tamper),
      });
      c.accounts.set(DECISION, { data: decisionRecordBytes({ policy: POLICY, offset: OFFSET, sealedPolicy: DEMO_POLICY, request: request(lamports), state, status: 0 }) });
    },
  );
  const getAccountInfo = chain.rpc.getAccountInfo;
  (chain as { rpc: FakeChain["rpc"] }).rpc = {
    ...chain.rpc,
    getAccountInfo: async (address: string) => {
      if (address === DECISION && pending && ++reads >= (opts.polls ?? 2)) chain.accounts.set(DECISION, { data: pending });
      return getAccountInfo(address);
    },
  };
  return chain;
}

let currentLamports = 0n;

function client(chain: FakeChain, over: Partial<ArciumMxeConfig> = {}) {
  return createArciumMxeClient({
    rpc: chain.rpc,
    programId: PROGRAM,
    clusterOffset: CLUSTER_OFFSET,
    policy: POLICY,
    authority: AUTHORITY,
    circuitId: CIRCUIT,
    pollIntervalMs: 1,
    timeoutMs: 1_000,
    sleep: async () => {},
    randomOffset: () => OFFSET,
    ...over,
  });
}

async function evaluateWith(chain: FakeChain, lamports: bigint, disclosure?: "rules" | "verdict") {
  currentLamports = lamports;
  return client(chain).evaluate({ policyCommitment: COMMITMENT, request: request(lamports), state, decidedAt: AT, disclosure });
}

test("Arcium account derivations match the addresses the IDL and SDK publish", () => {
  assert.equal(ARCIUM_PROGRAM_ID, "Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ");
  // Fixed addresses in programs/genkai's IDL. Deriving them proves the seed scheme is right.
  assert.equal(ARCIUM_FEE_POOL_ACCOUNT, "G2sRWJvi3xoyh5k2gY49eG9L8YhAEWQPtNb1zb1GXTtC");
  assert.equal(ARCIUM_CLOCK_ACCOUNT, "7EbMUTLo5DjdzbN7s8BXeZwXzEwNQb1hScfRvWg8a6ot");
  assert.deepEqual([...EVALUATE_DISCRIMINATOR], [179, 211, 142, 183, 108, 104, 20, 214]);
  // comp_def_offset(name) in arcium-anchor and getCompDefAccOffset in the SDK: sha256(name)[0..4] LE.
  assert.equal(compDefOffset("evaluate_policy"), createHash("sha256").update("evaluate_policy").digest().readUInt32LE(0));
  assert.notEqual(compDefOffset("evaluate_policy"), compDefOffset("add_together"));
});

test("evaluate is laid out exactly as the program's IDL declares", () => {
  const fields = encodeRequestFields(encodeRequest(request(1n), state));
  const ix = evaluateInstruction({ programId: PROGRAM, clusterOffset: CLUSTER_OFFSET, authority: AUTHORITY_ADDRESS, policy: POLICY, computationOffset: OFFSET, requestFields: fields, discloseRules: true });
  const accounts = evaluateAccounts({ programId: PROGRAM, clusterOffset: CLUSTER_OFFSET, authority: AUTHORITY_ADDRESS, policy: POLICY, computationOffset: OFFSET });
  assert.equal(ix.programId, PROGRAM);
  assert.deepEqual(
    ix.keys.map((k) => [k.isSigner, k.isWritable]),
    [[true, true], [false, false], [false, true], [false, true], [false, false], [false, true], [false, true], [false, true], [false, false], [false, true], [false, true], [false, true], [false, false], [false, false]],
  );
  assert.equal(ix.keys[0]?.pubkey, AUTHORITY_ADDRESS);
  assert.equal(ix.keys[2]?.pubkey, DECISION);
  assert.equal(ix.keys[2]?.pubkey, accounts.decision);
  assert.equal(ix.keys[10]?.pubkey, ARCIUM_FEE_POOL_ACCOUNT);
  assert.equal(ix.keys[13]?.pubkey, ARCIUM_PROGRAM_ID);
  assert.equal(ix.data.length, 8 + 8 + REQUEST_FIELDS_SIZE + 1);
  assert.deepEqual([...ix.data.subarray(0, 8)], [...EVALUATE_DISCRIMINATOR]);
  assert.equal(Buffer.from(ix.data).readBigUInt64LE(8), OFFSET);
  assert.equal(ix.data[ix.data.length - 1], 1);
  // Different clusters queue into different mempools.
  assert.notEqual(accounts.mempool, evaluateAccounts({ programId: PROGRAM, clusterOffset: 1, authority: AUTHORITY_ADDRESS, policy: POLICY, computationOffset: OFFSET }).mempool);
});

test("the live client queues one signed transaction and returns the cluster's recorded verdict", async () => {
  const cases: [bigint, string, readonly string[]][] = [
    [10_000_000n, "allow", ["all_checks_passed"]],
    [30_000_000n, "escalate", ["human_approval_required"]],
    [200_000_000n, "deny", ["mint_cap_exceeded", "amount_exceeds_window"]],
  ];
  for (const [lamports, verdict, rules] of cases) {
    const chain = liveChain();
    const out = await evaluateWith(chain, lamports);
    assert.equal(out.verdict, verdict);
    assert.deepEqual(out.ruleIds, rules);
    assert.equal(out.policyCommitment, COMMITMENT);
    assert.equal(chain.sent.length, 1);
    const wire = chain.sent[0] as Uint8Array;
    assert.ok(wire.length <= 1232, `transaction is ${wire.length} bytes`);
    assert.equal(discloseFlagOf(wire), true);
    assert.deepEqual(out.attestation, {
      kind: "onchain",
      circuitId: CIRCUIT,
      programId: PROGRAM,
      policy: POLICY,
      decision: DECISION,
      computationOffset: OFFSET,
      queueSignature: out.attestation.kind === "onchain" ? out.attestation.queueSignature : "",
    });
    assert.equal(decodeBase58(out.attestation.kind === "onchain" ? out.attestation.queueSignature : "").length, 64);
  }
});

test("verdict-only disclosure is asked of the circuit itself, not trimmed afterwards", async () => {
  const chain = liveChain();
  const out = await evaluateWith(chain, 200_000_000n, "verdict");
  assert.equal(out.verdict, "deny");
  assert.deepEqual(out.ruleIds, []);
  assert.equal(out.attestation.disclosure, "verdict");
  assert.equal(discloseFlagOf(chain.sent[0] as Uint8Array), false);
});

test("every failure surfaces as a named error, never a guessed verdict", async () => {
  const cases: [string, FakeChain, string, Partial<ArciumMxeConfig>?][] = [
    ["cluster never answers", liveChain({ never: true }), "timeout"],
    ["policy not active", liveChain({ status: 0 }), "policy_not_active"],
    ["policy owned by someone else", liveChain({ authority: "GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW" }), "not_authority"],
    ["no policy at the address", fakeChain({}), "policy_unavailable"],
    ["record holds different request fields", liveChain({ tamper: 11_000_000n }), "bad_record"],
  ];
  for (const [label, chain, code, over] of cases) {
    currentLamports = 10_000_000n;
    await assert.rejects(
      client(chain, over).evaluate({ policyCommitment: COMMITMENT, request: request(10_000_000n), state, decidedAt: AT }),
      (err: unknown) => err instanceof ArciumMxeError && err.code === code,
      label,
    );
  }

  const failed = liveChain({ never: true });
  failed.statusErr = { InstructionError: [2, { Custom: 6003 }] };
  currentLamports = 10_000_000n;
  await assert.rejects(
    client(failed).evaluate({ policyCommitment: COMMITMENT, request: request(10_000_000n), state, decidedAt: AT }),
    (err: unknown) => err instanceof ArciumMxeError && err.code === "queue_failed",
  );
});

test("a sealed provider on the live client issues receipts a third party verifies from chain state alone", async () => {
  const chain = liveChain();
  currentLamports = 200_000_000n;
  const provider = createSealedPolicyProvider({
    commitment: COMMITMENT,
    circuitId: CIRCUIT,
    mxe: client(chain),
    onChain: { rpc: chain.rpc, programId: PROGRAM, policy: POLICY },
  });
  const { decision, attestation, commitment } = await provider.decide(request(200_000_000n), state, AT);
  assert.equal(decision.verdict, "deny");
  const receipt = signReceipt(
    { receiptId: "r1", schemaVersion: 1, policyHash: commitment, request: request(200_000_000n), state, decision, attestation, previousReceiptHash: null },
    keypairFromSeed(new Uint8Array(32).fill(9)),
  );

  const trust = { commitment: COMMITMENT, circuitId: CIRCUIT, programId: PROGRAM, policy: POLICY };
  const live = await verifySealedReceiptOnChain(receipt, trust, { rpc: chain.rpc });
  assert.equal(live.valid, true, live.detail.join("; "));

  // Offline, the same receipt is not called valid: the evidence is on chain.
  const offline = verifySealedReceipt(receipt, trust);
  assert.deepEqual(offline.failures, ["attestation_unchecked"]);

  // A copycat policy record with the same commitment is not the pinned one.
  const copycat = await verifySealedReceiptOnChain(receipt, { ...trust, policy: "GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW" }, { rpc: chain.rpc });
  assert.equal(copycat.valid, false);
  assert.ok(copycat.failures.includes("attestation_invalid"));

  // The verdict flipped after the cluster answered.
  const flipped = signReceipt(
    { ...receipt.body, decision: { ...decision, verdict: "allow" } },
    keypairFromSeed(new Uint8Array(32).fill(9)),
  );
  const flippedResult = await verifySealedReceiptOnChain(flipped, trust, { rpc: chain.rpc });
  assert.equal(flippedResult.valid, false);
});

test("the provider refuses an on-chain answer it cannot confirm on chain", async () => {
  const chain = liveChain();
  currentLamports = 10_000_000n;
  const provider = createSealedPolicyProvider({
    commitment: COMMITMENT,
    circuitId: CIRCUIT,
    mxe: client(chain),
    onChain: { rpc: chain.rpc, programId: PROGRAM, policy: "GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW" },
  });
  await assert.rejects(provider.decide(request(10_000_000n), state, AT), (err: unknown) => err instanceof SealedPolicyError && err.code === "bad_attestation");
});
