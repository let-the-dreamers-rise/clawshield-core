/**
 * Verification as the browser page runs it.
 *
 * Nothing here re-implements a check. Input goes through the same parsers and handlers as
 * `genkai verify-chain` and the hosted API (src/server/handlers.ts); this module only decides
 * which handler a pasted document calls for and reshapes the answer into rows the page can
 * render. In the browser bundle node:crypto is replaced by audited @noble implementations
 * (web/shims/crypto.ts). Under Node, where the tests run it, it is node:crypto itself.
 */

import { fromJson } from "../../src/io/json.ts";
import { SchemaError, parseSignedReceipt } from "../../src/io/schema.ts";
import { isOnChainAttestation } from "../../src/mxe/types.ts";
import { handleVerifyChain, handleVerifyReceipt, type VerificationData } from "../../src/server/handlers.ts";
import { RpcError, createRpcClient, type FetchLike, type RpcClient } from "../../src/solana/rpc.ts";
import type { Verdict } from "../../src/policy/types.ts";
import type { SignedReceipt } from "../../src/receipt/types.ts";
import { clusterOf, describeAction } from "./format.ts";

export const DEFAULT_RPC = "https://api.devnet.solana.com";

/** Why a verification could not be carried out. Distinct from a receipt that fails to verify. */
export class VerifyError extends Error {
  readonly kind: "input" | "rpc";

  constructor(kind: "input" | "rpc", message: string) {
    super(message);
    this.name = "VerifyError";
    this.kind = kind;
  }
}

export interface ReceiptRow {
  readonly index: number;
  readonly receiptId: string;
  readonly agentId: string;
  readonly verdict: Verdict;
  readonly rules: readonly string[];
  readonly action: string;
  readonly decidedAt: number;
  readonly cluster?: string;
  /** Sealed receipts only: what the cluster was allowed to reveal. */
  readonly disclosure?: "rules" | "verdict";
  readonly decisionRecord?: string;
  readonly queueSignature?: string;
  readonly transactionSignature?: string;
  /**
   * Whether the bound transaction is on chain. The receipt is signed before broadcast, so its
   * own outcome cannot say; this is read from the RPC, and stays undefined without one.
   */
  readonly transactionStatus?: TransactionStatus;
  /** Empty when every check on this receipt passed. */
  readonly problems: readonly string[];
}

export type TransactionStatus =
  | { readonly state: "landed" | "failed"; readonly slot: number }
  | { readonly state: "not_found" }
  | { readonly state: "unknown"; readonly reason: string };

export interface Report {
  readonly mode: "plaintext" | "sealed";
  readonly valid: boolean;
  /** On-chain attestations were checked against their DecisionRecords over RPC. */
  readonly onChain: boolean;
  /** The input was a run of receipts, so the links between them were checked too. */
  readonly chained: boolean;
  /** Distinct failure codes, in the order first seen. */
  readonly failures: readonly string[];
  /** Findings that belong to no single receipt. */
  readonly general: readonly string[];
  readonly rows: readonly ReceiptRow[];
}

export interface VerifyRequest {
  /** One receipt, or an ordered array of one agent's receipts. JSON text. */
  readonly receipts: string;
  /** A plaintext policy, or a sealed trust anchor. JSON text. */
  readonly anchor: string;
  /** Where on-chain attestations are read. Without one they report attestation_unchecked. */
  readonly rpcEndpoint?: string;
  readonly fetch?: FetchLike;
}

function parseText(text: string, what: string): unknown {
  if (text.trim() === "") throw new VerifyError("input", `Paste or load the ${what} first`);
  try {
    return fromJson(text);
  } catch (err) {
    throw new VerifyError("input", `The ${what} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** A trust anchor always carries a commitment, and parsePolicy rejects that key, so this never guesses. */
function anchorField(value: unknown): { readonly policy: unknown } | { readonly trust: unknown } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new VerifyError("input", "The policy or trust anchor must be a JSON object");
  }
  return Object.hasOwn(value, "commitment") ? { trust: value } : { policy: value };
}

function rpcOf(endpoint: string | undefined, fetch: FetchLike | undefined): RpcClient | undefined {
  if (endpoint === undefined || endpoint.trim() === "") return undefined;
  try {
    return createRpcClient({ endpoint: endpoint.trim(), fetch, retries: 2, timeoutMs: 20_000 });
  } catch (err) {
    throw new VerifyError("input", err instanceof Error ? err.message : String(err));
  }
}

async function guarded<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (err) {
    if (err instanceof SchemaError) throw new VerifyError("input", err.message);
    if (err instanceof RpcError) throw new VerifyError("rpc", `The RPC endpoint could not be read: ${err.message}`);
    throw err;
  }
}

const RECEIPT_LINE = /^Receipt (\d+): ([\s\S]*)$/;

interface Attributed {
  readonly index: number | null;
  readonly text: string;
}

function attribute(detail: readonly string[], single: boolean): readonly Attributed[] {
  return detail.map((line) => {
    if (single) return { index: 0, text: line };
    const match = RECEIPT_LINE.exec(line);
    return match ? { index: Number(match[1]), text: match[2] ?? "" } : { index: null, text: line };
  });
}

function rowOf(receipt: SignedReceipt, index: number, problems: readonly string[]): ReceiptRow {
  const body = receipt.body;
  const attestation = body.attestation;
  const onChain = attestation && isOnChainAttestation(attestation) ? attestation : undefined;
  return {
    index,
    receiptId: body.receiptId,
    agentId: body.request.agentId,
    verdict: body.decision.verdict,
    rules: body.decision.reasons.map((r) => r.rule),
    action: describeAction(body.request),
    decidedAt: body.decision.decidedAt,
    cluster: clusterOf(body.request),
    disclosure: attestation === undefined ? undefined : attestation.disclosure === "verdict" ? "verdict" : "rules",
    decisionRecord: onChain?.decision,
    queueSignature: onChain?.queueSignature,
    transactionSignature: body.transaction?.signature,
    problems,
  };
}

/** getSignatureStatuses takes at most 256 signatures per call. */
const STATUS_BATCH = 256;

/**
 * The on-chain status of every bound transaction, in one RPC call per 256. Informational: a
 * failure to read it never changes the verification result, it only leaves the status unknown.
 */
async function transactionStatuses(rpc: RpcClient | undefined, receipts: readonly SignedReceipt[]): Promise<ReadonlyMap<string, TransactionStatus>> {
  const signatures = [...new Set(receipts.flatMap((r) => (r.body.transaction ? [r.body.transaction.signature] : [])))];
  if (rpc === undefined || signatures.length === 0) return new Map();
  const batches = Array.from({ length: Math.ceil(signatures.length / STATUS_BATCH) }, (_, i) => signatures.slice(i * STATUS_BATCH, (i + 1) * STATUS_BATCH));
  try {
    const statuses = (await Promise.all(batches.map((batch) => rpc.getSignatureStatuses(batch)))).flat();
    return new Map(
      signatures.map((signature, i): [string, TransactionStatus] => {
        const status = statuses[i];
        if (!status) return [signature, { state: "not_found" }];
        return [signature, { state: status.err === null ? "landed" : "failed", slot: status.slot }];
      }),
    );
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return new Map(signatures.map((signature): [string, TransactionStatus] => [signature, { state: "unknown", reason }]));
  }
}

function reportOf(
  data: VerificationData,
  receipts: readonly SignedReceipt[],
  single: boolean,
  onChain: boolean,
  statuses: ReadonlyMap<string, TransactionStatus>,
): Report {
  const attributed = attribute(data.detail, single);
  const known = (a: Attributed) => a.index !== null && a.index < receipts.length;
  return {
    mode: data.mode,
    valid: data.valid,
    onChain,
    chained: !single,
    failures: [...new Set(data.failures)],
    general: attributed.filter((a) => !known(a)).map((a) => a.text),
    rows: receipts.map((receipt, index) => {
      const row = rowOf(receipt, index, attributed.filter((a) => known(a) && a.index === index).map((a) => a.text));
      const status = row.transactionSignature === undefined ? undefined : statuses.get(row.transactionSignature);
      return status === undefined ? row : { ...row, transactionStatus: status };
    }),
  };
}

/**
 * Verify pasted documents. A single receipt is checked on its own; an array is checked as one
 * agent's chain, starting from its first receipt.
 */
export async function verifyDocuments(request: VerifyRequest): Promise<Report> {
  const receiptsValue = parseText(request.receipts, "receipts");
  const anchorValue = parseText(request.anchor, "policy or trust anchor");
  const anchor = anchorField(anchorValue);
  const rpc = rpcOf(request.rpcEndpoint, request.fetch);
  const single = !Array.isArray(receiptsValue);

  const data = await guarded(() =>
    single
      ? handleVerifyReceipt({ receipt: receiptsValue, ...anchor }, { rpc })
      : handleVerifyChain({ receipts: receiptsValue, ...anchor }, { rpc }),
  );
  // The handler has already parsed every receipt, so these parses cannot fail.
  const receipts = single
    ? [parseSignedReceipt(receiptsValue, "receipt")]
    : (receiptsValue as readonly unknown[]).map((r, i) => parseSignedReceipt(r, `receipts[${i}]`));
  const onChain = data.mode === "sealed" && rpc !== undefined && Object.hasOwn(anchorValue as object, "programId");
  return reportOf(data, receipts, single, onChain, await transactionStatuses(rpc, receipts));
}
