/**
 * A decision in the words a model acts on, and the same answer as data.
 *
 * Each sentence carries the instruction that matters at the moment it matters: a refusal is
 * final, an escalation waits for a person, and a failed send is retried under the same
 * request_id, which cannot pay twice.
 */

import { parseSignedReceipt } from "../io/schema.ts";
import type { SignedReceipt } from "../receipt/types.ts";
import type { JsonObject, ToolResult } from "./protocol.ts";

export interface Decided {
  readonly receipt: SignedReceipt;
  readonly seq: number;
  readonly signedTransaction?: string;
  readonly submittedSignature?: string;
  readonly submitError?: string;
  readonly replayed: boolean;
}

/** The payment as the caller described it, for the sentences. */
export interface Payment {
  readonly requestId: string;
  /** "0.015 SOL", or "12.5 of token <mint>". */
  readonly what: string;
  readonly to: string;
}

const EXPLORER_CLUSTERS: ReadonlySet<string> = new Set(["devnet", "testnet", "mainnet-beta"]);

/** The gateway's answer to POST /v1/decisions, checked rather than trusted. */
export function readDecided(data: unknown): Decided {
  if (typeof data !== "object" || data === null) throw new Error("the gateway's answer is not a decision");
  const o = data as Record<string, unknown>;
  const seq = o["seq"];
  if (typeof seq !== "number" || !Number.isInteger(seq)) throw new Error("the gateway's answer has no sequence number");
  const optional = (key: string): string | undefined => (typeof o[key] === "string" ? (o[key] as string) : undefined);
  return {
    receipt: parseSignedReceipt(o["receipt"], "receipt"),
    seq,
    signedTransaction: optional("signedTransaction"),
    submittedSignature: optional("submittedSignature"),
    submitError: optional("submitError"),
    replayed: o["replayed"] === true,
  };
}

function explorer(signature: string, cluster: unknown): string | undefined {
  if (typeof cluster !== "string" || !EXPLORER_CLUSTERS.has(cluster)) return undefined;
  return `https://explorer.solana.com/tx/${signature}${cluster === "mainnet-beta" ? "" : `?cluster=${cluster}`}`;
}

function allowed(d: Decided, p: Payment, link: string | undefined): string {
  const signature = d.receipt.body.transaction?.signature;
  if (signature === undefined) {
    const why = d.receipt.body.outcome?.error;
    return `ALLOWED, but no transaction could be built${why ? `: ${why}` : ""}. Nothing was paid. You may ask again later under a new request_id.`;
  }
  if (d.submittedSignature !== undefined) {
    return `ALLOWED. ${p.what} to ${p.to} was signed and sent as transaction ${signature}${link ? ` (${link})` : ""}.`;
  }
  if (d.submitError !== undefined) {
    return `ALLOWED and signed, but sending it failed: ${d.submitError}. Call request_transfer again with the same request_id to resend it; that cannot pay twice. If it keeps failing, tell the user instead of starting a new payment.`;
  }
  return `ALLOWED. ${p.what} to ${p.to} was signed as transaction ${signature}. This gateway does not broadcast: the signed transaction is in signedTransaction, for whoever submits it.`;
}

function sentence(d: Decided, p: Payment, rules: readonly string[], link: string | undefined): string {
  const fired = rules.length > 0 ? ` (${rules.join(", ")})` : "";
  switch (d.receipt.body.decision.verdict) {
    case "deny":
      return `DENIED by the spending policy${fired}. Nothing was signed. This is final for this request: do not retry it, split it into smaller payments or send it another way. Tell the user what was refused and why.`;
    case "escalate":
      return `ESCALATED${fired}: this payment needs a person's approval before it can be made. Nothing was signed or paid. Tell the user; do not retry it or split it into smaller payments.`;
    case "allow":
      return allowed(d, p, link);
  }
}

export function decisionResult(d: Decided, payment: Payment): ToolResult {
  const body = d.receipt.body;
  const rules = body.decision.reasons.map((r) => r.rule);
  const signature = body.transaction?.signature;
  // Only a sent transaction has anything to show on an explorer.
  const link = signature === undefined || d.submittedSignature === undefined ? undefined : explorer(signature, body.request.params["cluster"]);
  const unsent = d.signedTransaction !== undefined && d.submittedSignature === undefined;
  const structured: JsonObject = {
    verdict: body.decision.verdict,
    rules,
    reasons: body.decision.reasons.map((r) => r.reason),
    receiptId: body.receiptId,
    seq: d.seq,
    replayed: d.replayed,
    transaction:
      signature === undefined
        ? null
        : { signature, submitted: d.submittedSignature !== undefined, ...(d.submitError === undefined ? {} : { error: d.submitError }) },
    ...(unsent ? { signedTransaction: d.signedTransaction } : {}),
    ...(link === undefined ? {} : { explorer: link }),
  };
  const replay = d.replayed ? ` This is the decision already recorded for request_id ${JSON.stringify(payment.requestId)}, not a new one.` : "";
  return { text: `${sentence(d, payment, rules, link)}${replay} Receipt ${body.receiptId}.`, structured };
}
