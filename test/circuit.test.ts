/**
 * The circuit model against the engine.
 *
 * An MPC circuit cannot take strings, maps or variable-length lists, so a sealed policy is
 * encoded into fixed-width integers and evaluated by branch-free arithmetic. That is a second
 * implementation of the rule set, and two implementations of a security policy will drift
 * unless something forces them not to.
 *
 * This suite is that something. It runs the engine and the circuit model side by side over
 * thousands of seeded random policies, requests and states, and requires the same verdict and
 * the same firing rules, in the same order, every time. The Rust circuit in arcium/ mirrors
 * the model line for line, so this is the evidence that a sealed decision equals the plaintext
 * decision the operator would have got.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { evaluate } from "../src/policy/engine.ts";
import {
  CAPACITY,
  EncodingError,
  POLICY_FIELD_COUNT,
  REQUEST_FIELD_COUNT,
  encodePolicy,
  encodeRequest,
  flattenPolicy,
  flattenRequest,
  idOf,
} from "../src/mxe/encoding.ts";
import { RULE_ORDER, evaluateCircuit, ruleIdsOf, verdictOf } from "../src/mxe/circuit.ts";
import {
  NATIVE_SOL_MINT,
  SOLANA_TRANSFER_TOOL,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  USDC_MAINNET_MINT,
} from "../src/solana/types.ts";
import type { ActionRequest, AgentState, Policy } from "../src/policy/types.ts";

/** mulberry32: small, seeded, and good enough to explore a rule space reproducibly. */
function prng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  const chance = (p: number) => next() < p;
  const pick = <T>(xs: readonly T[]): T => xs[int(xs.length)] as T;
  const subset = <T>(xs: readonly T[], max: number): T[] => xs.filter(() => chance(0.5)).slice(0, max);
  return { next, int, chance, pick, subset };
}

const TOOLS = [SOLANA_TRANSFER_TOOL, "transfer_usdc", "swap", "drain_wallet"];
const PEOPLE = [
  "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE",
  "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
  "0xVendorA",
  "0xVendorB",
];
const CLUSTERS = ["mainnet-beta", "devnet", "testnet"];
const PROGRAMS = [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, SYSTEM_PROGRAM_ID];
const MINTS = [USDC_MAINNET_MINT, NATIVE_SOL_MINT, "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"];
const VAULT = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";

/** Amounts cluster around a few thresholds so equality edges are hit often. */
const MAGNITUDES = [0n, 1n, 999n, 1_000n, 1_001n, 50_000n, 100_000n, 100_001n, 1_000_000n, (1n << 64n) - 1n];

function randomPolicy(r: ReturnType<typeof prng>): Policy {
  const amount = () => r.pick(MAGNITUDES);
  const caps: Record<string, bigint> = {};
  for (const mint of r.subset(MINTS, CAPACITY.mintCaps)) caps[mint] = amount();
  const start = r.int(1441);
  return {
    policyId: `p${r.int(1000)}`,
    version: r.int(5),
    allowedTools: r.subset(TOOLS, CAPACITY.tools),
    counterpartyAllowlist: r.chance(0.5) ? r.subset(PEOPLE, CAPACITY.counterparties) : undefined,
    maxAmountPerAction: r.chance(0.5) ? amount() : undefined,
    maxAmountPerWindow: r.chance(0.5) ? amount() : undefined,
    maxCallsPerWindow: r.chance(0.4) ? r.int(6) : undefined,
    drawdownHaltThreshold: r.chance(0.3) ? amount() : undefined,
    escalateAboveAmount: r.chance(0.5) ? amount() : undefined,
    allowedHoursUtc: r.chance(0.3) ? [start, start + r.int(1441 - start)] : undefined,
    allowedDaysUtc: r.chance(0.3) ? r.subset([0, 1, 2, 3, 4, 5, 6, 7, -1], 9) : undefined,
    allowedClusters: r.chance(0.8) ? r.subset(CLUSTERS, CAPACITY.clusters) : undefined,
    allowedPrograms: r.chance(0.8) ? r.subset(PROGRAMS, CAPACITY.programs) : undefined,
    allowedMints: r.chance(0.8) ? r.subset(MINTS, CAPACITY.mints) : undefined,
    maxAmountPerMint: r.chance(0.7) ? caps : undefined,
  };
}

function randomRequest(r: ReturnType<typeof prng>): ActionRequest {
  const amount = r.chance(0.9) ? (r.chance(0.15) ? -1n : 1n) * r.pick(MAGNITUDES) : undefined;
  const kind = r.int(4);
  const params =
    kind === 0
      ? {}
      : kind === 1
        ? { chain: "solana" }
        : { chain: "solana", cluster: r.pick(CLUSTERS), programId: r.pick(PROGRAMS), decimals: r.int(10), from: VAULT };
  return {
    agentId: "agent",
    tool: r.pick(TOOLS),
    counterparty: r.chance(0.85) ? r.pick(PEOPLE) : undefined,
    amount,
    asset: r.chance(0.8) ? r.pick(MINTS) : undefined,
    requestedAt: Date.UTC(2026, 0, 1) + r.int(14 * 24 * 60) * 60_000,
    params,
  };
}

function randomState(r: ReturnType<typeof prng>): AgentState {
  return {
    spentInWindow: r.pick(MAGNITUDES.slice(0, -1)),
    windowStartedAt: 0,
    callsInWindow: r.int(8),
    drawdownFromPeak: r.pick(MAGNITUDES.slice(0, -1)),
    revoked: r.chance(0.05),
  };
}

test("the circuit model agrees with the engine on 20,000 random cases", () => {
  const r = prng(0x6e6b6169);
  const verdicts = { allow: 0, deny: 0, escalate: 0 };
  for (let i = 0; i < 20_000; i++) {
    const policy = randomPolicy(r);
    const request = randomRequest(r);
    const state = randomState(r);

    const expected = evaluate(policy, request, state, 0);
    const out = evaluateCircuit(encodePolicy(policy), encodeRequest(request, state));
    const label = `case ${i}`;
    assert.equal(verdictOf(out), expected.verdict, label);
    assert.deepEqual(ruleIdsOf(out), expected.reasons.map((x) => x.rule), label);
    verdicts[expected.verdict]++;
  }
  // The generator must actually reach every verdict, or agreement proves little.
  for (const [verdict, count] of Object.entries(verdicts)) {
    assert.ok(count > 500, `only ${count} ${verdict} cases were generated`);
  }
});

test("every rule in the engine is reachable through the circuit", () => {
  const r = prng(7);
  const seen = new Set<string>();
  for (let i = 0; i < 20_000 && seen.size < RULE_ORDER.length + 2; i++) {
    const out = evaluateCircuit(encodePolicy(randomPolicy(r)), encodeRequest(randomRequest(r), randomState(r)));
    for (const id of ruleIdsOf(out)) seen.add(id);
  }
  for (const id of [...RULE_ORDER, "all_checks_passed"]) {
    assert.ok(seen.has(id), `rule ${id} never fired`);
  }
});

test("identifiers are 128-bit, stable and distinct", () => {
  const a = idOf(USDC_MAINNET_MINT);
  assert.equal(a, idOf(USDC_MAINNET_MINT));
  assert.notEqual(a, idOf(NATIVE_SOL_MINT));
  assert.ok(a > 0n && a < 1n << 128n);
});

test("the flattened layouts have a fixed width, whatever the policy says", () => {
  const r = prng(99);
  for (let i = 0; i < 50; i++) {
    assert.equal(flattenPolicy(encodePolicy(randomPolicy(r))).length, POLICY_FIELD_COUNT);
    assert.equal(flattenRequest(encodeRequest(randomRequest(r), randomState(r))).length, REQUEST_FIELD_COUNT);
  }
  // A fixed width is a confidentiality property: a ciphertext whose length depended on the
  // number of allowlisted mints would leak that number to anyone who saw it.
});

test("a policy the circuit cannot represent is refused at sealing time, not at decision time", () => {
  const base: Policy = { policyId: "p", version: 1, allowedTools: [SOLANA_TRANSFER_TOOL] };
  const tooMany = Array.from({ length: CAPACITY.mints + 1 }, (_, i) => `mint-${i}`);
  for (const bad of [
    { ...base, allowedMints: tooMany },
    { ...base, maxAmountPerAction: -1n },
    { ...base, maxAmountPerWindow: 1n << 64n },
    { ...base, maxCallsPerWindow: 2.5 },
    { ...base, allowedHoursUtc: [0, 1441] as const },
    { ...base, drawdownHaltThreshold: -5n },
  ]) {
    assert.throws(() => encodePolicy(bad), EncodingError, JSON.stringify(bad, (_k, v) => (typeof v === "bigint" ? `${v}` : v)));
  }
});

test("state and amounts outside the circuit's range are refused", () => {
  const state: AgentState = { spentInWindow: 0n, windowStartedAt: 0, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
  const request: ActionRequest = { agentId: "a", tool: "t", amount: 1n, requestedAt: 0, params: {} };
  assert.throws(() => encodeRequest({ ...request, amount: 1n << 64n }, state), EncodingError);
  assert.throws(() => encodeRequest({ ...request, amount: -(1n << 64n) }, state), EncodingError);
  assert.throws(() => encodeRequest(request, { ...state, spentInWindow: -1n }), EncodingError);
  assert.throws(() => encodeRequest({ ...request, requestedAt: Number.NaN }, state), EncodingError);
});

test("a mint named like an Object.prototype member gets no cap it was never given", () => {
  // The engine used to look caps up with a plain property access, so a mint literally named
  // "constructor" found Object's constructor instead of undefined. The circuit has no
  // prototype chain; the engine must not have one either.
  const policy: Policy = {
    policyId: "p",
    version: 1,
    allowedTools: [SOLANA_TRANSFER_TOOL],
    allowedClusters: ["devnet"],
    allowedPrograms: [TOKEN_PROGRAM_ID],
    allowedMints: ["constructor"],
    maxAmountPerMint: {},
  };
  const request: ActionRequest = {
    agentId: "a",
    tool: SOLANA_TRANSFER_TOOL,
    amount: 1n,
    asset: "constructor",
    requestedAt: 0,
    params: { chain: "solana", cluster: "devnet", programId: TOKEN_PROGRAM_ID, decimals: 6, from: VAULT },
  };
  const state: AgentState = { spentInWindow: 0n, windowStartedAt: 0, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
  const decision = evaluate(policy, request, state, 0);
  assert.deepEqual(decision.reasons.map((x) => x.rule), ["mint_cap_missing"]);
  assert.deepEqual(ruleIdsOf(evaluateCircuit(encodePolicy(policy), encodeRequest(request, state))), ["mint_cap_missing"]);
});
