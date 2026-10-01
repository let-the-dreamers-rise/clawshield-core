/**
 * Generate the fixtures the on-chain Arcium test runs against.
 *
 * The circuit model in src/mxe/circuit.ts is the source of truth for what the MPC circuit must
 * output, and it is itself pinned to the engine by test/circuit.test.ts. This script runs the
 * demo policy and proposals through the encoder and the model and writes the encoded inputs
 * with the expected verdict and mask, so arcium/genkai/tests/genkai.ts can require the live
 * cluster to agree with the model bit for bit.
 *
 *   node --experimental-strip-types scripts/arcium-fixtures.ts
 */

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DEMO_POLICY } from "../src/cli/demo.ts";
import { encodePolicy, encodeRequest, flattenPolicy, POLICY_FIELD_COUNT, type EncodedRequest } from "../src/mxe/encoding.ts";
import { evaluateCircuit, ruleIdsOf, verdictOf } from "../src/mxe/circuit.ts";
import { sealedCommitment } from "../src/policy/sealed.ts";
import { toActionRequest } from "../src/solana/types.ts";
import { SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID, USDC_MAINNET_MINT } from "../src/solana/types.ts";
import type { AgentState } from "../src/policy/types.ts";

const VAULT = "9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj";
const VENDOR_A = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const VENDOR_B = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const STRANGER = "GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW";
/** Fixed so the fixture is reproducible. Never reuse a fixture salt for a real policy. */
const FIXTURE_SALT = "f1x7".repeat(16);
const AT = Date.UTC(2026, 9, 1, 12, 0, 0);

const fresh: AgentState = { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };

const CASES: readonly { intent: string; to: string; lamports: bigint; state?: Partial<AgentState>; programId?: string; mint?: string }[] = [
  { intent: "in policy: pay vendor A", to: VENDOR_A, lamports: 10_000_000n },
  { intent: "counterparty not allowlisted", to: STRANGER, lamports: 5_000_000n },
  { intent: "above the escalation threshold", to: VENDOR_B, lamports: 30_000_000n },
  { intent: "over the per-mint cap and the window", to: VENDOR_A, lamports: 200_000_000n },
  { intent: "window already nearly spent", to: VENDOR_B, lamports: 15_000_000n, state: { spentInWindow: 90_000_000n } },
  { intent: "rate limited and revoked", to: VENDOR_A, lamports: 1_000n, state: { callsInWindow: 10, revoked: true } },
  { intent: "wrong program and mint", to: VENDOR_A, lamports: 1_000n, programId: TOKEN_PROGRAM_ID, mint: USDC_MAINNET_MINT },
];

const fields = (r: EncodedRequest) => ({
  toolId: r.toolId.toString(),
  hasCounterparty: r.hasCounterparty,
  counterpartyId: r.counterpartyId.toString(),
  hasAmount: r.hasAmount,
  amountNegative: r.amountNegative,
  amountMagnitude: r.amountMagnitude.toString(),
  isSolana: r.isSolana,
  solanaValid: r.solanaValid,
  clusterId: r.clusterId.toString(),
  programId: r.programId.toString(),
  mintId: r.mintId.toString(),
  minuteOfDay: r.minuteOfDay,
  dayOfWeek: r.dayOfWeek,
  revoked: r.revoked,
  spentInWindow: r.spentInWindow.toString(),
  callsInWindow: r.callsInWindow.toString(),
  drawdownFromPeak: r.drawdownFromPeak.toString(),
});

const policy = encodePolicy(DEMO_POLICY);
const flat = flattenPolicy(policy);
if (flat.length !== POLICY_FIELD_COUNT) throw new Error("policy layout drifted");

const requests = CASES.map((c) => {
  const request = toActionRequest(
    {
      kind: c.programId ? "spl" : "sol",
      programId: c.programId ?? SYSTEM_PROGRAM_ID,
      cluster: "devnet",
      from: VAULT,
      to: c.to,
      amount: c.lamports,
      mint: c.mint,
      decimals: c.mint ? 6 : 9,
      requestedAt: AT,
    },
    "desk-bot",
  );
  const encoded = encodeRequest(request, { ...fresh, ...c.state });
  const out = evaluateCircuit(policy, encoded);
  return { intent: c.intent, fields: fields(encoded), expected: { verdict: out.verdict, mask: out.mask, verdictName: verdictOf(out), rules: ruleIdsOf(out) } };
});

const fixture = {
  circuitId: "genkai.policy.v1",
  policyId: DEMO_POLICY.policyId,
  commitment: sealedCommitment(DEMO_POLICY, FIXTURE_SALT),
  policyFields: flat.map((x) => x.toString()),
  requests,
};

const out = fileURLToPath(new URL("../arcium/genkai/tests/fixtures.json", import.meta.url));
writeFileSync(out, `${JSON.stringify(fixture, null, 2)}\n`);
process.stdout.write(`Wrote ${out}: ${flat.length} policy fields, ${requests.length} requests\n`);
for (const r of requests) process.stdout.write(`  ${r.expected.verdictName.padEnd(9)} ${r.intent}  [${r.expected.rules.join(", ")}]\n`);
