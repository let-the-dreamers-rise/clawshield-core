/**
 * Parsers for receipts, policies and sealed trust anchors read from outside the process.
 *
 * Every parser takes an optional root path so errors point at the field as the caller sees
 * it ("receipt.body.request.amount"), and returns a fresh object built from known keys only.
 */

import type { ActionRequest, AgentState, Decision, Policy, RuleResult, Verdict } from "../policy/types.ts";
import type { AuthorisedTransaction, ExecutionOutcome, ReceiptBody, SignedReceipt } from "../receipt/types.ts";
import type { MxeAttestation } from "../mxe/types.ts";
import type { SealedTrust } from "../receipt/verify-sealed.ts";
import {
  SchemaError,
  array,
  at,
  big,
  bool,
  compact,
  finite,
  hex64,
  int,
  oneOf,
  opt,
  record,
  str,
  strings,
  type Obj,
} from "./validate.ts";

export { SchemaError } from "./validate.ts";

const VERDICTS: readonly Verdict[] = ["allow", "deny", "escalate"];

function parseParams(v: unknown, path: string): Readonly<Record<string, unknown>> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new SchemaError(path, "expected an object");
  return Object.fromEntries(Object.entries(v));
}

function parseRequest(v: unknown, path: string): ActionRequest {
  const o = record(v, path, ["agentId", "tool", "requestedAt", "params"], ["counterparty", "amount", "asset", "chainId"]);
  return compact({
    agentId: str(o["agentId"], at(path, "agentId")),
    tool: str(o["tool"], at(path, "tool")),
    counterparty: opt(o, "counterparty", path, str),
    amount: opt(o, "amount", path, big),
    asset: opt(o, "asset", path, str),
    chainId: opt(o, "chainId", path, (x, p) => int(x, p)),
    requestedAt: finite(o["requestedAt"], at(path, "requestedAt")),
    params: parseParams(o["params"], at(path, "params")),
  });
}

function parseState(v: unknown, path: string): AgentState {
  const o = record(v, path, ["spentInWindow", "windowStartedAt", "callsInWindow", "drawdownFromPeak", "revoked"]);
  return {
    spentInWindow: big(o["spentInWindow"], at(path, "spentInWindow")),
    windowStartedAt: finite(o["windowStartedAt"], at(path, "windowStartedAt")),
    callsInWindow: int(o["callsInWindow"], at(path, "callsInWindow"), 0),
    drawdownFromPeak: big(o["drawdownFromPeak"], at(path, "drawdownFromPeak")),
    revoked: bool(o["revoked"], at(path, "revoked")),
  };
}

function parseRuleResult(v: unknown, path: string): RuleResult {
  const o = record(v, path, ["rule", "verdict", "reason"]);
  return {
    rule: str(o["rule"], at(path, "rule")),
    verdict: oneOf(o["verdict"], at(path, "verdict"), VERDICTS),
    reason: str(o["reason"], at(path, "reason")),
  };
}

function parseDecision(v: unknown, path: string): Decision {
  const o = record(v, path, ["verdict", "reasons", "policyId", "policyVersion", "decidedAt"]);
  return {
    verdict: oneOf(o["verdict"], at(path, "verdict"), VERDICTS),
    reasons: array(o["reasons"], at(path, "reasons"), parseRuleResult, 64),
    policyId: str(o["policyId"], at(path, "policyId")),
    policyVersion: int(o["policyVersion"], at(path, "policyVersion")),
    decidedAt: finite(o["decidedAt"], at(path, "decidedAt")),
  };
}

function parseOutcome(v: unknown, path: string): ExecutionOutcome {
  const o = record(v, path, ["executed"], ["txHash", "chainId", "balanceBefore", "balanceAfter", "error"]);
  return compact({
    executed: bool(o["executed"], at(path, "executed")),
    txHash: opt(o, "txHash", path, str),
    chainId: opt(o, "chainId", path, (x, p) => int(x, p)),
    balanceBefore: opt(o, "balanceBefore", path, big),
    balanceAfter: opt(o, "balanceAfter", path, big),
    error: opt(o, "error", path, str),
  });
}

function parseAttestation(v: unknown, path: string): MxeAttestation {
  const o = record(v, path, ["circuitId", "clusterPublicKey", "signature"], ["disclosure"]);
  return compact({
    circuitId: str(o["circuitId"], at(path, "circuitId"), { nonEmpty: true }),
    clusterPublicKey: str(o["clusterPublicKey"], at(path, "clusterPublicKey"), { nonEmpty: true }),
    signature: str(o["signature"], at(path, "signature"), { nonEmpty: true }),
    disclosure: opt(o, "disclosure", path, (x, p) => oneOf(x, p, ["verdict"] as const)),
  });
}

function parseTransaction(v: unknown, path: string): AuthorisedTransaction {
  const o = record(v, path, ["signature", "messageSha256", "recentBlockhash"], ["computeUnitLimit", "computeUnitPrice"]);
  return compact({
    signature: str(o["signature"], at(path, "signature"), { nonEmpty: true, max: 128 }),
    messageSha256: hex64(o["messageSha256"], at(path, "messageSha256")),
    recentBlockhash: str(o["recentBlockhash"], at(path, "recentBlockhash"), { nonEmpty: true, max: 64 }),
    computeUnitLimit: opt(o, "computeUnitLimit", path, (x, p) => int(x, p, 0)),
    computeUnitPrice: opt(o, "computeUnitPrice", path, big),
  });
}

function parseBody(v: unknown, path: string): ReceiptBody {
  const o: Obj = record(
    v,
    path,
    ["receiptId", "schemaVersion", "policyHash", "request", "state", "decision", "previousReceiptHash"],
    ["modelReasoning", "outcome", "rulesetVersion", "attestation", "transaction"],
  );
  if (o["schemaVersion"] !== 1) throw new SchemaError(at(path, "schemaVersion"), "unsupported schema version");
  const previous = o["previousReceiptHash"];
  return compact({
    receiptId: str(o["receiptId"], at(path, "receiptId"), { nonEmpty: true, max: 128 }),
    schemaVersion: 1 as const,
    policyHash: hex64(o["policyHash"], at(path, "policyHash")),
    request: parseRequest(o["request"], at(path, "request")),
    state: parseState(o["state"], at(path, "state")),
    decision: parseDecision(o["decision"], at(path, "decision")),
    modelReasoning: opt(o, "modelReasoning", path, (x, p) => str(x, p, { max: 64 * 1024 })),
    outcome: opt(o, "outcome", path, parseOutcome),
    rulesetVersion: opt(o, "rulesetVersion", path, (x, p) => int(x, p, 0)),
    attestation: opt(o, "attestation", path, parseAttestation),
    transaction: opt(o, "transaction", path, parseTransaction),
    previousReceiptHash: previous === null ? null : hex64(previous, at(path, "previousReceiptHash")),
  });
}

export function parseSignedReceipt(v: unknown, path = ""): SignedReceipt {
  const o = record(v, path, ["body", "signature", "publicKey", "algorithm"]);
  return {
    body: parseBody(o["body"], at(path, "body")),
    signature: str(o["signature"], at(path, "signature"), { nonEmpty: true, max: 256 }),
    publicKey: str(o["publicKey"], at(path, "publicKey"), { nonEmpty: true, max: 256 }),
    algorithm: oneOf(o["algorithm"], at(path, "algorithm"), ["ed25519"] as const),
  };
}

function parseHours(v: unknown, path: string): readonly [number, number] {
  const xs = array(v, path, finite, 2);
  if (xs.length !== 2) throw new SchemaError(path, "expected [start, end]");
  return [xs[0] as number, xs[1] as number];
}

function parseCaps(v: unknown, path: string): Readonly<Record<string, bigint>> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new SchemaError(path, "expected an object");
  // fromEntries defines own properties, so a key named "__proto__" cannot reach the prototype.
  return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, big(x, at(path, k))]));
}

export function parsePolicy(v: unknown, path = ""): Policy {
  const o = record(
    v,
    path,
    ["policyId", "version", "allowedTools"],
    [
      "counterpartyAllowlist",
      "maxAmountPerAction",
      "maxAmountPerWindow",
      "windowSeconds",
      "maxCallsPerWindow",
      "drawdownHaltThreshold",
      "escalateAboveAmount",
      "allowedHoursUtc",
      "allowedDaysUtc",
      "allowedClusters",
      "allowedPrograms",
      "allowedMints",
      "maxAmountPerMint",
    ],
  );
  return compact({
    policyId: str(o["policyId"], at(path, "policyId")),
    version: int(o["version"], at(path, "version")),
    allowedTools: strings(o["allowedTools"], at(path, "allowedTools")),
    counterpartyAllowlist: opt(o, "counterpartyAllowlist", path, strings),
    maxAmountPerAction: opt(o, "maxAmountPerAction", path, big),
    maxAmountPerWindow: opt(o, "maxAmountPerWindow", path, big),
    windowSeconds: opt(o, "windowSeconds", path, finite),
    maxCallsPerWindow: opt(o, "maxCallsPerWindow", path, finite),
    drawdownHaltThreshold: opt(o, "drawdownHaltThreshold", path, big),
    escalateAboveAmount: opt(o, "escalateAboveAmount", path, big),
    allowedHoursUtc: opt(o, "allowedHoursUtc", path, parseHours),
    allowedDaysUtc: opt(o, "allowedDaysUtc", path, (x, p) => array(x, p, finite, 7)),
    allowedClusters: opt(o, "allowedClusters", path, strings),
    allowedPrograms: opt(o, "allowedPrograms", path, strings),
    allowedMints: opt(o, "allowedMints", path, strings),
    maxAmountPerMint: opt(o, "maxAmountPerMint", path, parseCaps),
  });
}

export function parseSealedTrust(v: unknown, path = ""): SealedTrust {
  const o = record(v, path, ["commitment", "circuitId", "clusterPublicKey"]);
  return {
    commitment: hex64(o["commitment"], at(path, "commitment")),
    circuitId: str(o["circuitId"], at(path, "circuitId"), { nonEmpty: true, max: 128 }),
    clusterPublicKey: str(o["clusterPublicKey"], at(path, "clusterPublicKey"), { nonEmpty: true, max: 256 }),
  };
}
