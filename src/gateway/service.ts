/**
 * The gateway's decision service: one place where an agent's proposal becomes a recorded,
 * signed decision.
 *
 * For each proposal it:
 *
 *   1. takes the agent's slot in a per-agent queue
 *   2. reads the agent's ledger and rolls the spend window as of now
 *   3. builds the transfer itself: the vault, cluster and time come from the gateway, never
 *      from the agent, so an agent cannot spend from another account or backdate a request
 *   4. asks the policy provider through the signing adapter, which signs only on allow, with a
 *      blockhash fetched after the verdict so a slow sealed decision cannot leave it stale
 *   5. records the receipt and advances the ledger in one transaction
 *   6. in broadcast mode, submits the signed transaction and records the signature
 *
 * Step 5 happens before step 6 on purpose: a transaction is never sent for a decision the
 * gateway has not durably recorded.
 *
 * A request may carry an Idempotency-Key. A sealed decision takes seconds, long enough for an
 * agent's HTTP client to give up and retry, and a retry must not become a second decision and
 * a second transfer. Within a day, the same key for the same transfer replays the recorded
 * decision instead of asking again.
 */

import { createHash } from "node:crypto";
import { canonicalBytes, type Canonicalisable } from "../receipt/canonical.ts";
import { createSolanaAdapter } from "../solana/adapter.ts";
import type { TransactionFees } from "../solana/compose.ts";
import { solanaAddress } from "../solana/keys.ts";
import type { RpcClient } from "../solana/rpc.ts";
import { SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID, type SolanaCluster, type SolanaTransfer } from "../solana/types.ts";
import type { PolicyProvider } from "../policy/sealed.ts";
import type { Decision } from "../policy/types.ts";
import type { Keypair } from "../receipt/sign.ts";
import type { SignedReceipt } from "../receipt/types.ts";
import { afterDecision, stateAt } from "./ledger.ts";
import { createKeyedMutex } from "./mutex.ts";
import type { GatewayStore } from "./store.ts";

/** Used when the gateway has no RPC: transactions are signed but can never land. */
export const OFFLINE_BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";

export type ExecutionMode = "sign" | "broadcast";

/** How long an Idempotency-Key keeps naming its decision. */
export const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

export class IdempotencyMismatchError extends Error {
  constructor() {
    super("This Idempotency-Key was already used for a different transfer");
    this.name = "IdempotencyMismatchError";
  }
}

export interface GatewayServiceConfig {
  readonly store: GatewayStore;
  readonly provider: PolicyProvider;
  readonly vault: Keypair;
  readonly cluster: SolanaCluster;
  /** The spend window length. In sealed mode the policy is not readable, so this is configured. */
  readonly windowSeconds?: number;
  readonly rpc?: RpcClient;
  /** sign: return the signed transaction. broadcast: also submit it. Needs rpc. */
  readonly execution: ExecutionMode;
  readonly fees?: TransactionFees;
  readonly now?: () => number;
  readonly maxQueuedPerAgent?: number;
}

/** What an agent may say about a transfer. Everything else is the gateway's to decide. */
export interface TransferInput {
  readonly kind: "sol" | "spl";
  readonly to: string;
  readonly amount: bigint;
  readonly decimals: number;
  readonly mint?: string;
  readonly programId?: string;
}

export interface DecideOptions {
  /** Recorded in the receipt for accountability. Never used for enforcement. */
  readonly modelReasoning?: string;
  /** The client's name for this transfer. A retry under the same key replays the decision. */
  readonly idempotencyKey?: string;
}

export interface DecisionResult {
  readonly decision: Decision;
  readonly receipt: SignedReceipt;
  readonly seq: number;
  readonly signedTransaction?: string;
  readonly submittedSignature?: string;
  readonly submitError?: string;
  /** Present when an Idempotency-Key matched: this is the earlier decision, not a new one. */
  readonly replayed?: true;
}

/**
 * What an Idempotency-Key is bound to: the transfer. Not the reasoning, which a model may word
 * differently on a retry of the same payment.
 */
const transferHash = (input: TransferInput): string =>
  createHash("sha256").update(canonicalBytes({ ...input } as unknown as Canonicalisable)).digest("hex");

export type GatewayService = ReturnType<typeof createGatewayService>;

export function createGatewayService(config: GatewayServiceConfig) {
  if (config.execution === "broadcast" && !config.rpc) throw new Error("Broadcast mode needs an RPC endpoint");
  const now = config.now ?? (() => Date.now());
  const mutex = createKeyedMutex(config.maxQueuedPerAgent);
  const vaultAddress = solanaAddress(config.vault.publicKey);
  const rpc = config.rpc;
  const latestBlockhash = rpc ? async () => (await rpc.getLatestBlockhash("confirmed")).blockhash : OFFLINE_BLOCKHASH;

  function transferOf(input: TransferInput, requestedAt: number): SolanaTransfer {
    return {
      kind: input.kind,
      programId: input.programId ?? (input.kind === "sol" ? SYSTEM_PROGRAM_ID : TOKEN_PROGRAM_ID),
      cluster: config.cluster,
      from: vaultAddress,
      to: input.to,
      amount: input.amount,
      ...(input.mint === undefined ? {} : { mint: input.mint }),
      decimals: input.decimals,
      requestedAt,
    };
  }

  async function submit(receiptId: string, wire: string, at: number): Promise<Pick<DecisionResult, "submittedSignature" | "submitError">> {
    try {
      const signature = await (config.rpc as RpcClient).sendTransaction(wire);
      config.store.recordSubmission(receiptId, signature, at);
      return { submittedSignature: signature };
    } catch (err) {
      // The decision stands and is recorded; only delivery failed. The agent can retry the
      // signed transaction itself, and the chain is the judge of whether it ever landed.
      return { submitError: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * The decision an Idempotency-Key already names. In broadcast mode a transaction whose first
   * delivery failed is sent again: the cluster executes a signature at most once, so resending
   * the same signed bytes can deliver the transfer but never repeat it.
   */
  async function replay(receiptId: string, at: number): Promise<DecisionResult> {
    const stored = config.store.getReceipt(receiptId);
    if (!stored) throw new Error(`An idempotency key names receipt ${receiptId}, which is missing`);
    const { signedTransaction, submittedSignature } = stored;
    const resend = config.execution === "broadcast" && signedTransaction !== undefined && submittedSignature === undefined;
    const delivery = resend ? await submit(receiptId, signedTransaction, at) : submittedSignature === undefined ? {} : { submittedSignature };
    return {
      decision: stored.receipt.body.decision,
      receipt: stored.receipt,
      seq: stored.seq,
      ...(signedTransaction === undefined ? {} : { signedTransaction }),
      ...delivery,
      replayed: true,
    };
  }

  async function decideNow(agentId: string, input: TransferInput, options: DecideOptions): Promise<DecisionResult> {
    const agent = config.store.getAgent(agentId);
    const ledger = config.store.getLedger(agentId);
    if (!agent || !ledger) throw new NotFoundError(`No agent ${agentId}`);

    const at = now();
    const binding =
      options.idempotencyKey === undefined
        ? undefined
        : { key: options.idempotencyKey, requestHash: transferHash(input), lapsedAt: at - IDEMPOTENCY_TTL_MS };
    const prior = binding && config.store.findIdempotent(agentId, binding.key, binding.lapsedAt);
    if (binding && prior) {
      if (prior.requestHash !== binding.requestHash) throw new IdempotencyMismatchError();
      return replay(prior.receiptId, at);
    }

    const state = stateAt({ ...ledger.state, revoked: agent.revoked }, config.windowSeconds, at);
    const adapter = createSolanaAdapter({ agentId, keys: config.vault, provider: config.provider });
    const submission = await adapter.submit({
      transfer: transferOf(input, at),
      state,
      decidedAt: at,
      recentBlockhash: latestBlockhash,
      fees: config.fees,
      previousReceiptHash: ledger.lastReceiptHash,
      modelReasoning: options.modelReasoning,
    });

    const verdict = submission.decision.verdict;
    // Only a signed transaction can move funds. An allow that could not be signed is still a
    // decision, and so a call, but it charges nothing to the window.
    const spent = submission.signedTransaction === undefined ? undefined : input.amount;
    const seq = config.store.commitDecision({
      agentId,
      expectedVersion: ledger.version,
      nextState: afterDecision(state, verdict, spent),
      receipt: submission.receipt,
      signedTransaction: submission.signedTransaction,
      now: at,
      ...(binding ? { idempotency: binding } : {}),
    });
    config.store.audit({ at, actor: `agent:${agentId}`, action: "decision", subject: submission.receipt.body.receiptId, detail: { verdict, seq } });

    const delivery =
      config.execution === "broadcast" && submission.signedTransaction !== undefined
        ? await submit(submission.receipt.body.receiptId, submission.signedTransaction, at)
        : {};
    return {
      decision: submission.decision,
      receipt: submission.receipt,
      seq,
      ...(submission.signedTransaction === undefined ? {} : { signedTransaction: submission.signedTransaction }),
      ...delivery,
    };
  }

  /** What an agent or the operator may see about an agent: identity, current state, chain head. */
  function status(agentId: string) {
    const agent = config.store.getAgent(agentId);
    const ledger = config.store.getLedger(agentId);
    if (!agent || !ledger) throw new NotFoundError(`No agent ${agentId}`);
    return {
      agent,
      state: stateAt({ ...ledger.state, revoked: agent.revoked }, config.windowSeconds, now()),
      receipts: ledger.seq,
      lastReceiptHash: ledger.lastReceiptHash,
    };
  }

  return Object.freeze({
    vaultAddress,
    operatorPublicKey: config.vault.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    cluster: config.cluster,
    execution: config.execution,
    status,
    decide: (agentId: string, input: TransferInput, options: DecideOptions = {}): Promise<DecisionResult> =>
      mutex.run(agentId, () => decideNow(agentId, input, options)),
  });
}
