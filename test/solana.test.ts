/**
 * Solana rule evaluators.
 *
 * The adversarial cases here are the point of the file. A chain-specific rule set that only
 * covers the happy path is decoration.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { evaluate } from "../src/policy/engine.ts";
import type { ActionRequest, AgentState, Policy } from "../src/policy/types.ts";
import {
  LAMPORTS_PER_SOL,
  NATIVE_SOL_MINT,
  SOLANA_TRANSFER_TOOL,
  SOL_DECIMALS,
  SYSTEM_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  USDC_MAINNET_MINT,
  isValidSolanaAddress,
  readSolanaParams,
  toActionRequest,
  type SolanaTransfer,
} from "../src/solana/types.ts";
import {
  checkClusterAllowed,
  checkMintAllowed,
  checkMintSpendCap,
  checkProgramAllowed,
  checkTransferAmount,
} from "../src/solana/rules.ts";

const AT = Date.UTC(2026, 6, 31, 12, 0, 0);
const VAULT = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";

const policy: Policy = {
  policyId: "solana-treasury-v1",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  allowedClusters: ["mainnet-beta"],
  allowedPrograms: [TOKEN_PROGRAM_ID],
  allowedMints: [USDC_MAINNET_MINT],
  maxAmountPerMint: { [USDC_MAINNET_MINT]: 100_000_000n },
};

const freshState: AgentState = {
  spentInWindow: 0n,
  windowStartedAt: AT,
  callsInWindow: 0,
  drawdownFromPeak: 0n,
  revoked: false,
};

const transfer = (over: Partial<SolanaTransfer> = {}): SolanaTransfer => ({
  kind: "spl",
  programId: TOKEN_PROGRAM_ID,
  cluster: "mainnet-beta",
  from: VAULT,
  to: VENDOR,
  mint: USDC_MAINNET_MINT,
  decimals: 6,
  amount: 10_000_000n,
  requestedAt: AT,
  ...over,
});

const req = (over: Partial<SolanaTransfer> = {}): ActionRequest =>
  toActionRequest(transfer(over), "agent-1");

test("address validation rejects anything that is not a base58 pubkey", () => {
  assert.equal(isValidSolanaAddress(VAULT), true);
  assert.equal(isValidSolanaAddress(SYSTEM_PROGRAM_ID), true);
  // Base58 excludes 0, O, I and l precisely so these cannot be confused.
  assert.equal(isValidSolanaAddress("0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl"), false);
  assert.equal(isValidSolanaAddress(""), false);
  assert.equal(isValidSolanaAddress("short"), false);
  assert.equal(isValidSolanaAddress(`${VAULT}${VAULT}`), false);
});

test("a transfer maps onto the core ActionRequest without a parallel type", () => {
  const r = req();
  assert.equal(r.tool, SOLANA_TRANSFER_TOOL);
  assert.equal(r.counterparty, VENDOR);
  // The mint is carried in the existing `asset` field, not duplicated into params.
  assert.equal(r.asset, USDC_MAINNET_MINT);
  assert.equal(r.amount, 10_000_000n);
  // Solana has no numeric chain id, so the core field stays absent rather than being faked.
  assert.equal(r.chainId, undefined);

  const params = readSolanaParams(r);
  assert.ok(params);
  assert.equal(params.programId, TOKEN_PROGRAM_ID);
  assert.equal(params.cluster, "mainnet-beta");
  assert.equal(params.from, VAULT);
});

test("native SOL is keyed by the wrapped-SOL mint so caps are uniform", () => {
  const r = req({ kind: "sol", programId: SYSTEM_PROGRAM_ID, mint: undefined, decimals: SOL_DECIMALS, amount: LAMPORTS_PER_SOL });
  assert.equal(r.asset, NATIVE_SOL_MINT);
  assert.equal(r.amount, 1_000_000_000n);
});

test("an in-policy USDC transfer is allowed", () => {
  const decision = evaluate(policy, req(), freshState, AT);
  assert.equal(decision.verdict, "allow", JSON.stringify(decision.reasons));
});

test("a program outside the allowlist is denied", () => {
  const decision = evaluate(policy, req({ programId: SYSTEM_PROGRAM_ID }), freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "program_not_allowed"));
});

test("a mint outside the allowlist is denied", () => {
  const decision = evaluate(policy, req({ mint: NATIVE_SOL_MINT }), freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "mint_not_allowed"));
});

test("a cluster outside the allowlist is denied", () => {
  const decision = evaluate(policy, req({ cluster: "devnet" }), freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "cluster_not_allowed"));
});

test("absent Solana allowlists permit nothing", () => {
  // Deny by default. A policy that never mentions Solana must not authorise Solana.
  const silent: Policy = { policyId: "p", version: 1, allowedTools: [SOLANA_TRANSFER_TOOL] };
  const decision = evaluate(silent, req(), freshState, AT);
  assert.equal(decision.verdict, "deny");
  const rules = decision.reasons.map((r) => r.rule);
  assert.ok(rules.includes("cluster_not_allowed"));
  assert.ok(rules.includes("program_not_allowed"));
  assert.ok(rules.includes("mint_not_allowed"));
});

test("a per-mint cap is enforced independently of the global cap", () => {
  const decision = evaluate(policy, req({ amount: 100_000_001n }), freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "mint_cap_exceeded"));
});

test("an allowlisted mint with no configured cap is denied, not defaulted to unlimited", () => {
  const gap: Policy = {
    ...policy,
    allowedMints: [USDC_MAINNET_MINT, NATIVE_SOL_MINT],
    maxAmountPerMint: { [USDC_MAINNET_MINT]: 100_000_000n },
  };
  const decision = evaluate(gap, req({ mint: NATIVE_SOL_MINT }), freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "mint_cap_missing"));
});

test("a negative amount is denied before it can credit the spend window", () => {
  // The attack: window spend is computed as spent + amount, so a negative amount would pass
  // every cap AND increase remaining headroom. bigint permits negatives, so this must be
  // rejected explicitly rather than assumed away.
  const r = req({ amount: -50_000_000n });
  const decision = evaluate(policy, r, freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((x) => x.rule === "amount_not_positive"));

  const projected = freshState.spentInWindow + (r.amount ?? 0n);
  assert.ok(projected < freshState.spentInWindow, "precondition: negative amount reduces spend");
});

test("a zero amount is denied", () => {
  const decision = evaluate(policy, req({ amount: 0n }), freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "amount_not_positive"));
});

test("Solana rules do not fire on non-Solana requests", () => {
  // Every existing receipt must keep replaying identically after these rules are wired in.
  const evm: ActionRequest = {
    agentId: "agent-1",
    tool: "transfer_usdc",
    counterparty: "0xVendorA",
    amount: 1n,
    asset: "USDC",
    chainId: 8453,
    requestedAt: AT,
    params: {},
  };
  assert.equal(readSolanaParams(evm), null);
  for (const rule of [checkClusterAllowed, checkProgramAllowed, checkMintAllowed, checkMintSpendCap, checkTransferAmount]) {
    assert.equal(rule(policy, evm, freshState), null, `${rule.name} fired on a non-Solana request`);
  }
});

test("malformed Solana params are denied rather than ignored", () => {
  // An agent that forges params to dodge the chain-specific rules must not fall through to a
  // permissive path. Claiming to be Solana with a broken shape is a denial.
  const forged: ActionRequest = {
    agentId: "agent-1",
    tool: SOLANA_TRANSFER_TOOL,
    counterparty: VENDOR,
    amount: 1n,
    asset: USDC_MAINNET_MINT,
    requestedAt: AT,
    params: { chain: "solana" },
  };
  assert.equal(readSolanaParams(forged), null);
  const decision = evaluate(policy, forged, freshState, AT);
  assert.equal(decision.verdict, "deny");
  assert.ok(decision.reasons.some((r) => r.rule === "solana_params_malformed"));
});
