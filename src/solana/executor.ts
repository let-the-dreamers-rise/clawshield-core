/**
 * Broadcast, confirmation, and on-chain verification.
 *
 * The executor is the only component that talks to a cluster, and it holds no key. Its job is
 * mechanical: ask the adapter for a decision, fetch a blockhash once it allows, broadcast
 * exactly the bytes the adapter signed, and watch until the transaction lands or its blockhash
 * expires.
 *
 * It does not write "executed: true" into anything. Whether a transfer executed is a fact the
 * chain records, and verifyExecution checks that fact against the receipt for anyone who asks.
 * An operator's word that a transfer landed adds nothing to that, so it is not asked for.
 */

import { createHash } from "node:crypto";
import { decodeBase58 } from "./base58.ts";
import { RpcError, type Blockhash, type Commitment, type RpcClient } from "./rpc.ts";
import type { SolanaAdapter, SolanaSubmission } from "./adapter.ts";
import type { TransactionFees } from "./compose.ts";
import type { SolanaTransfer } from "./types.ts";
import type { AgentState } from "../policy/types.ts";
import type { SignedReceipt } from "../receipt/types.ts";

export interface ExecutorConfig {
  readonly adapter: SolanaAdapter;
  readonly rpc: RpcClient;
  /** The decision clock. Injected so tests and replays are deterministic. */
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly pollIntervalMs?: number;
  /** Upper bound on status polls, independent of blockhash expiry. */
  readonly maxPolls?: number;
  readonly commitment?: Exclude<Commitment, "processed">;
  readonly fees?: TransactionFees;
}

export interface ExecuteOptions {
  readonly transfer: SolanaTransfer;
  readonly state: AgentState;
  readonly previousReceiptHash?: string | null;
  readonly modelReasoning?: string;
  readonly fees?: TransactionFees;
}

export type ExecutionStatus = "confirmed" | "finalized" | "failed" | "expired" | "rejected" | "unknown";

export interface ExecutionReport {
  readonly signature: string;
  readonly status: ExecutionStatus;
  readonly slot?: number;
  readonly error?: string;
}

export interface ExecutionResult {
  readonly submission: SolanaSubmission;
  /** Absent when nothing was signed: a deny, an escalation, or an unbuildable transfer. */
  readonly execution?: ExecutionReport;
}

const reached = (status: Commitment | null, wanted: Commitment): boolean =>
  status === "finalized" || (wanted === "confirmed" && status === "confirmed");

export function createExecutor(config: ExecutorConfig) {
  const now = config.now ?? (() => Date.now());
  const sleep = config.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const pollIntervalMs = config.pollIntervalMs ?? 1_000;
  const maxPolls = config.maxPolls ?? 600;
  const commitment = config.commitment ?? "confirmed";

  async function watch(signature: string, lastValidBlockHeight: number): Promise<ExecutionReport> {
    for (let poll = 0; poll < maxPolls; poll++) {
      const [status] = await config.rpc.getSignatureStatuses([signature]);
      if (status) {
        if (status.err !== null) {
          return { signature, status: "failed", slot: status.slot, error: JSON.stringify(status.err) };
        }
        if (reached(status.confirmationStatus, commitment)) {
          return { signature, status: status.confirmationStatus === "finalized" ? "finalized" : "confirmed", slot: status.slot };
        }
      } else if ((await config.rpc.getBlockHeight(commitment)) > lastValidBlockHeight) {
        // The blockhash has expired and the cluster never saw the transaction: it can no
        // longer land, so this is final rather than pending.
        return { signature, status: "expired" };
      }
      await sleep(pollIntervalMs);
    }
    return { signature, status: "unknown", error: `No final status after ${maxPolls} polls` };
  }

  async function execute(options: ExecuteOptions): Promise<ExecutionResult> {
    // Fetched only once the adapter has an allow, so the wait for a verdict (an MPC round trip
    // under seal) does not eat into the blockhash's lifetime. The watch uses the same fetch.
    let fetched: Promise<Blockhash> | undefined;
    const latest = () => (fetched ??= config.rpc.getLatestBlockhash(commitment));
    const submission = await config.adapter.submit({
      transfer: options.transfer,
      state: options.state,
      decidedAt: now(),
      recentBlockhash: async () => (await latest()).blockhash,
      fees: options.fees ?? config.fees,
      previousReceiptHash: options.previousReceiptHash,
      modelReasoning: options.modelReasoning,
    });

    const signature = submission.receipt.body.transaction?.signature;
    if (!submission.signedTransaction || !signature) return { submission };

    try {
      await config.rpc.sendTransaction(submission.signedTransaction);
    } catch (err) {
      // The cluster answered and refused (simulation failure, insufficient funds): final.
      if (err instanceof RpcError && err.code === "rpc") {
        return { submission, execution: { signature, status: "rejected", error: err.message } };
      }
      // A transport failure is ambiguous: the bytes may have reached a leader. Watch anyway.
      if (!(err instanceof RpcError)) throw err;
    }

    return { submission, execution: await watch(signature, (await latest()).lastValidBlockHeight) };
  }

  return Object.freeze({ execute });
}

export type ExecutionFailure =
  | "no_transaction"
  | "not_found"
  | "signature_mismatch"
  | "message_mismatch"
  | "failed_on_chain";

export interface ExecutionVerification {
  readonly executed: boolean;
  readonly slot: number | undefined;
  readonly failure: ExecutionFailure | undefined;
}

/**
 * Check against the chain that the transaction a receipt binds actually executed, and that the
 * bytes on chain are the bytes whose hash the receipt binds. Pair with verifyReceipt, which
 * proves those bytes move exactly what the policy evaluated.
 */
export async function verifyExecution(receipt: SignedReceipt, rpc: RpcClient): Promise<ExecutionVerification> {
  const result = (executed: boolean, slot?: number, failure?: ExecutionFailure): ExecutionVerification => ({
    executed,
    slot,
    failure,
  });

  const bound = receipt.body.transaction;
  if (!bound) return result(false, undefined, "no_transaction");

  const onChain = await rpc.getTransaction(bound.signature);
  if (!onChain) return result(false, undefined, "not_found");

  const wire = onChain.wire;
  if (wire[0] !== 1 || !Buffer.from(wire.subarray(1, 65)).equals(Buffer.from(decodeBase58(bound.signature)))) {
    return result(false, onChain.slot, "signature_mismatch");
  }
  const hash = createHash("sha256").update(wire.subarray(65)).digest("hex");
  if (hash !== bound.messageSha256) return result(false, onChain.slot, "message_mismatch");
  if (onChain.err !== null) return result(false, onChain.slot, "failed_on_chain");
  return result(true, onChain.slot);
}
