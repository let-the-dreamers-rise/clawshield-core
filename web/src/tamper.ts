/**
 * The page's tamper demonstration: the forgery an operator would most want, a denial rewritten
 * as a clean approval. Kept apart from the DOM code so the claim the page makes about it (that
 * verification catches it) is tested.
 */

import { fromJson, toJson } from "../../src/io/json.ts";
import { SEALED_REASON } from "../../src/policy/sealed.ts";
import type { Canonicalisable } from "../../src/receipt/canonical.ts";

type Obj = Readonly<Record<string, unknown>>;

const isObject = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

interface ReceiptParts {
  readonly receipt: Obj;
  readonly body: Obj;
  readonly decision: Obj;
}

function partsOf(receipt: unknown): ReceiptParts | undefined {
  const body = isObject(receipt) ? receipt["body"] : undefined;
  const decision = isObject(body) ? body["decision"] : undefined;
  return isObject(receipt) && isObject(body) && isObject(decision) ? { receipt, body, decision } : undefined;
}

/** The verdict and reasons of an approval under a sealed policy. Everything else is left alone. */
function forgeApproval(parts: ReceiptParts): Obj {
  const reasons = [{ rule: "all_checks_passed", verdict: "allow", reason: SEALED_REASON }];
  return { ...parts.receipt, body: { ...parts.body, decision: { ...parts.decision, verdict: "allow", reasons } } };
}

export interface Forgery {
  /** The receipts with the forgery in place, as JSON text. */
  readonly text: string;
  /** Which receipt was rewritten. */
  readonly index: number;
}

export function rewriteFirstDenial(text: string): Forgery {
  const receipts: unknown = fromJson(text);
  if (!Array.isArray(receipts)) throw new Error("The sample is not a list of receipts");
  const parts = receipts.map((r: unknown) => partsOf(r));
  const index = parts.findIndex((p) => p?.decision["verdict"] === "deny");
  const target = parts[index];
  if (target === undefined) throw new Error("The sample has no denial to rewrite");
  const forged = receipts.map((r: unknown, i) => (i === index ? forgeApproval(target) : r));
  return { text: toJson(forged as unknown as Canonicalisable, 2), index };
}

export const tamperNote = (index: number): string =>
  `Receipt #${index + 1} was rewritten from a denial into a clean approval, and nothing else was touched. ` +
  "An operator holding the signing key could re-sign it and every receipt after it, but the DecisionRecord the Arcium cluster wrote on devnet would still say deny.";
