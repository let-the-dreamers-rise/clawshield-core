/**
 * The tools an agent gets: ask for a payment, read its own spend, fetch a receipt.
 *
 * The agent holds an agent key and nothing more. It cannot see the policy, change it, or pay
 * by any other route through this server: the gateway decides every payment and keeps the
 * ledger. What the tools add is input a model gets wrong caught before it reaches anyone, and
 * answers phrased so the model acts on them correctly.
 */

import { toJson } from "../io/json.ts";
import { parseSignedReceipt } from "../io/schema.ts";
import { address, amount, decimals, onlyKnown, optionalAddress, requestId, text } from "./args.ts";
import { GatewayError, type GatewayClient } from "./client.ts";
import { decisionResult, readDecided } from "./describe.ts";
import { ToolError, type JsonObject, type McpTool, type ToolContext, type ToolResult } from "./protocol.ts";

export const GENKAI_INSTRUCTIONS = [
  "GENKAI pays from a Solana treasury on your behalf, under a spending policy you cannot see. The policy decides every request_transfer, and every decision leaves a signed receipt anyone can verify.",
  "ALLOWED: the payment was signed, and sent if this gateway broadcasts. DENIED: final. Do not retry it, split it into smaller payments or pay another way; tell the user. ESCALATED: a person must approve it, and nothing was paid; tell the user.",
  "Give every new payment its own request_id, such as an invoice number. Reuse a request_id only to retry the same payment after an error or a timeout: the gateway then returns the decision it already made, and nothing is paid twice.",
  'Amounts are whole tokens written as decimal strings, such as "0.015" for 0.015 SOL, never lamports.',
].join("\n\n");

export interface GenkaiToolsConfig {
  readonly client: GatewayClient;
  readonly agentId: string;
  /** How often a slow decision reports that it is still alive, for clients that asked. */
  readonly heartbeatMs?: number;
}

const TRANSFER_ARGS = ["to", "amount", "token", "decimals", "reason", "request_id"] as const;
const REASON_MAX = 2000;

const TRANSFER_SCHEMA: JsonObject = {
  type: "object",
  properties: {
    to: { type: "string", description: "The recipient's Solana address, base58." },
    amount: { type: "string", pattern: "^[0-9]+(\\.[0-9]+)?$", description: 'How much, in whole tokens as a decimal string: "0.015" is 0.015 SOL. Not lamports.' },
    token: { type: "string", description: "The SPL token's mint address. Leave it out to pay SOL." },
    decimals: { type: "integer", minimum: 0, maximum: 18, description: "The token mint's decimal places, such as 6 for USDC. Required with token; SOL is always 9." },
    reason: { type: "string", minLength: 1, maxLength: REASON_MAX, description: "What the payment is for. Recorded in the receipt for whoever audits it; it does not sway the policy." },
    request_id: { type: "string", minLength: 1, maxLength: 255, description: "Your unique id for this payment, such as an invoice number. Reuse it only to retry this same payment." },
  },
  required: ["to", "amount", "reason", "request_id"],
  additionalProperties: false,
};

const NO_ARGS: JsonObject = { type: "object", properties: {}, additionalProperties: false };

const RECEIPT_SCHEMA: JsonObject = {
  type: "object",
  properties: { receipt_id: { type: "string", minLength: 1, maxLength: 128, description: "The receipt id a request_transfer answer gave." } },
  required: ["receipt_id"],
  additionalProperties: false,
};

const READ_ONLY = { readOnlyHint: true, openWorldHint: false } as const;

const why = (err: GatewayError): string => (err.status === undefined ? err.message : `The gateway answered HTTP ${err.status}: ${err.message}`);

/** A gateway failure, in words the model can act on. Anything else is a fault and propagates. */
function explained(err: unknown, special: Readonly<Record<number, string>> = {}): never {
  if (!(err instanceof GatewayError)) throw err;
  const known = err.status === undefined ? undefined : special[err.status];
  if (known !== undefined) throw new ToolError(known);
  if (err.status === 401 || err.status === 403) {
    throw new ToolError(`The gateway refused this agent's key (HTTP ${err.status}: ${err.message}). It may have been revoked; tell the user.`);
  }
  throw new ToolError(`${why(err)}.`);
}

const transient = (err: unknown): boolean => err instanceof GatewayError && (err.status === undefined || err.status >= 500 || err.status === 409 || err.status === 429);

async function keepAlive<T>(context: ToolContext, everyMs: number, work: () => Promise<T>): Promise<T> {
  const started = Date.now();
  const timer = setInterval(() => context.progress(`Waiting for the policy decision, ${Math.round((Date.now() - started) / 1000)} s so far`), everyMs);
  try {
    return await work();
  } finally {
    clearInterval(timer);
  }
}

function readTransfer(args: JsonObject) {
  onlyKnown(args, TRANSFER_ARGS);
  const to = address(args, "to");
  const token = optionalAddress(args, "token");
  const places = decimals(args, token);
  const units = amount(args, places);
  const what = `${String(args["amount"])} ${token === undefined ? "SOL" : `of token ${token}`}`;
  return { to, token, places, units, what, reason: text(args, "reason", REASON_MAX), id: requestId(args) };
}

async function requestTransfer(config: GenkaiToolsConfig, args: JsonObject, context: ToolContext): Promise<ToolResult> {
  const t = readTransfer(args);
  const transfer = { kind: t.token === undefined ? "sol" : "spl", to: t.to, amount: t.units.toString(), decimals: t.places, ...(t.token === undefined ? {} : { mint: t.token }) } as const;
  const data = await keepAlive(context, config.heartbeatMs ?? 5000, () => config.client.decide({ transfer, modelReasoning: t.reason }, t.id)).catch((err: unknown) => {
    if (transient(err)) {
      throw new ToolError(`No decision came back. ${why(err as GatewayError)}. Calling again with the same request_id is safe: if this payment was decided, you get that decision back, not a second payment.`);
    }
    return explained(err, { 422: `request_id ${JSON.stringify(t.id)} was already used for a different transfer. Use a new request_id for a new payment.` });
  });
  return decisionResult(readDecided(data), { requestId: t.id, what: t.what, to: t.to });
}

function field<T>(o: Record<string, unknown>, key: string, type: string): T {
  if (typeof o[key] !== type || o[key] === null) throw new Error(`the gateway's status answer has no ${key}`);
  return o[key] as T;
}

async function spendingStatus(config: GenkaiToolsConfig, args: JsonObject): Promise<ToolResult> {
  onlyKnown(args, []);
  const answer = await config.client.agent(config.agentId).catch((err: unknown) => explained(err));
  if (typeof answer !== "object" || answer === null) throw new Error("the gateway's status answer is not an object");
  const data = answer as Record<string, unknown>;
  const state = field<Record<string, unknown>>(data, "state", "object");
  const spent = field<bigint>(state, "spentInWindow", "bigint");
  const calls = field<number>(state, "callsInWindow", "number");
  const revoked = field<boolean>(state, "revoked", "boolean");
  const since = new Date(field<number>(state, "windowStartedAt", "number")).toISOString();
  const receipts = typeof data["receipts"] === "number" ? data["receipts"] : 0;
  const lines = [
    revoked ? `Agent ${config.agentId} is REVOKED: every payment it asks for will be denied. Tell the user.` : `Agent ${config.agentId} is active.`,
    `In the current window, since ${since}: ${calls} request${calls === 1 ? "" : "s"} decided and ${spent} minor units spent, counted the way the policy counts them (lamports for SOL).`,
    `${receipts} receipt${receipts === 1 ? "" : "s"} in all. Its limits are not visible here: the gateway enforces them, and only its decisions show what they allow.`,
  ];
  return {
    text: lines.join(" "),
    structured: { agent: config.agentId, revoked, spentInWindow: spent.toString(), callsInWindow: calls, windowStartedAt: since, receipts },
  };
}

async function getReceipt(config: GenkaiToolsConfig, args: JsonObject): Promise<ToolResult> {
  onlyKnown(args, ["receipt_id"]);
  const id = text(args, "receipt_id", 128);
  const data = await config.client.receipt(id).catch((err: unknown) => explained(err, { 404: `No receipt ${JSON.stringify(id)} on this gateway.` }));
  const receipt = parseSignedReceipt(data, "receipt");
  const json = toJson(receipt as never, 2);
  return { text: json, structured: { receiptId: receipt.body.receiptId, verdict: receipt.body.decision.verdict, receipt: JSON.parse(json) as JsonObject } };
}

export function genkaiTools(config: GenkaiToolsConfig): readonly McpTool[] {
  return [
    {
      name: "request_transfer",
      title: "Request a transfer",
      description:
        "Ask the GENKAI gateway to pay SOL or an SPL token from the treasury it guards. A spending policy you cannot see decides: ALLOWED (signed, and sent if the gateway broadcasts), DENIED (final) or ESCALATED (needs a person). Every call leaves a signed receipt. Use a new request_id for each payment, and the same one to retry it.",
      inputSchema: TRANSFER_SCHEMA,
      annotations: { title: "Request a transfer", readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
      call: (args, context) => requestTransfer(config, args, context),
    },
    {
      name: "get_spending_status",
      title: "Spending status",
      description: "What this agent has spent and how many requests it has made in the current policy window, and whether it is revoked. The policy's limits are not shown.",
      inputSchema: NO_ARGS,
      annotations: { title: "Spending status", ...READ_ONLY },
      call: (args) => spendingStatus(config, args),
    },
    {
      name: "get_receipt",
      title: "Get a receipt",
      description: "Fetch a signed decision receipt by id, as JSON anyone can verify against the published policy commitment, for example at https://genkai-inky.vercel.app.",
      inputSchema: RECEIPT_SCHEMA,
      annotations: { title: "Get a receipt", ...READ_ONLY },
      call: (args) => getReceipt(config, args),
    },
  ];
}
