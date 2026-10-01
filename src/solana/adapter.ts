/**
 * The Solana signing boundary.
 *
 * This is the only place in the system that holds a signing key, and the only place that can
 * produce a signature. The guarantee is structural, not procedural:
 *
 *   - the keypair is a closure variable, never a property, so it cannot be read off the
 *     returned object, enumerated, or serialised
 *   - the returned object is frozen and exposes exactly two things: the public key and submit()
 *   - this module exports one function. Nothing here signs a transfer on demand, so there is
 *     no bypass to call
 *
 * An agent asks for a transfer and receives either a signature or a refusal. It never holds
 * the means to sign. "The adapter checks the policy first" would be a claim about discipline;
 * this is a claim about reachability.
 *
 * Both verdicts produce a receipt. A refusal that leaves no evidence is not a control - the
 * denials are the part of the record a regulator actually wants.
 */

import { createHash } from "node:crypto";
import { canonicalBytes, type Canonicalisable } from "../receipt/canonical.ts";
import { signReceipt, type Keypair } from "../receipt/sign.ts";
import { RULESET_VERSION } from "../policy/engine.ts";
import type { PolicyProvider } from "../policy/sealed.ts";
import type { AgentState, Decision } from "../policy/types.ts";
import type { AuthorisedTransaction, ExecutionOutcome, ReceiptBody, SignedReceipt } from "../receipt/types.ts";
import { ComposeError, composeTransferMessage, type TransactionFees } from "./compose.ts";
import { SolanaAdapterError } from "./errors.ts";
import { solanaAddress } from "./keys.ts";
import { MessageError } from "./message.ts";
import { signLegacyTransaction } from "./transaction.ts";
import { toActionRequest, type SolanaTransfer } from "./types.ts";

export interface SolanaAdapterConfig {
  readonly agentId: string;
  /** Held in closure scope from here on. Never stored on the returned object. */
  readonly keys: Keypair;
  /** Plaintext or sealed. The adapter cannot tell the difference and does not need to. */
  readonly provider: PolicyProvider;
}

export interface SubmitOptions {
  readonly transfer: SolanaTransfer;
  /** Observed state from the ledger. Never supplied by the agent. */
  readonly state: AgentState;
  /** Passed in rather than read from a clock, so the decision stays replayable. */
  readonly decidedAt: number;
  /**
   * Fetched by the caller, because fetching it is IO and the adapter does none. Bound into the
   * receipt so a verifier can rebuild the signed message.
   */
  readonly recentBlockhash: string;
  readonly fees?: TransactionFees;
  readonly previousReceiptHash?: string | null;
  /** Recorded for accountability. Never consulted for enforcement. */
  readonly modelReasoning?: string;
}

export interface SolanaSubmission {
  readonly decision: Decision;
  readonly receipt: SignedReceipt;
  /**
   * The base64 wire transaction, ready to broadcast. Present only when the verdict was allow
   * and the transfer could be encoded. Absent for deny and for escalate alike.
   */
  readonly signedTransaction?: string;
}

export interface SolanaAdapter {
  readonly publicKey: string;
  submit(options: SubmitOptions): Promise<SolanaSubmission>;
}

/**
 * Derive a receipt id deterministically from what the receipt is about.
 *
 * A random id would make the adapter impure for no benefit and would let the same decision
 * produce two different receipts. Deriving it means a duplicate submission is visibly a
 * duplicate rather than looking like two independent authorisations.
 */
function deriveReceiptId(payload: Canonicalisable): string {
  return createHash("sha256").update(canonicalBytes(payload)).digest("hex").slice(0, 32);
}

export function createSolanaAdapter(config: SolanaAdapterConfig): SolanaAdapter {
  // Captured here and never referenced from anything the caller can reach.
  const keys = config.keys;
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const vaultAddress = solanaAddress(keys.publicKey);

  interface Signed {
    readonly wire: string;
    readonly transaction: AuthorisedTransaction;
  }

  /**
   * Build and sign the real transaction for an authorised transfer.
   *
   * A transfer the policy allowed but the encoder cannot build - a program with no encoder, an
   * oversized message - returns an error string instead of throwing. The decision was taken
   * and must still be evidenced; what failed was construction, and the receipt says so.
   */
  function signAuthorisedTransfer(receiptId: string, options: SubmitOptions): Signed | string {
    try {
      const message = composeTransferMessage(options.transfer, {
        recentBlockhash: options.recentBlockhash,
        receiptId,
        ...options.fees,
      });
      const signed = signLegacyTransaction(message, keys);
      return {
        wire: Buffer.from(signed.wire).toString("base64"),
        transaction: {
          signature: signed.signature,
          messageSha256: createHash("sha256").update(message).digest("hex"),
          recentBlockhash: options.recentBlockhash,
          computeUnitLimit: options.fees?.computeUnitLimit,
          computeUnitPrice: options.fees?.computeUnitPrice,
        },
      };
    } catch (err) {
      if (err instanceof ComposeError || err instanceof MessageError) return err.message;
      throw err;
    }
  }

  async function submit(options: SubmitOptions): Promise<SolanaSubmission> {
    // Not a policy question: this adapter cannot produce a valid signature for any other
    // account, so a request naming one is malformed rather than deniable.
    if (options.transfer.from !== vaultAddress) {
      throw new SolanaAdapterError(
        "signer_mismatch",
        `This adapter signs for ${vaultAddress}; the transfer names ${options.transfer.from}`,
      );
    }
    const request = toActionRequest(options.transfer, config.agentId);
    const previousReceiptHash = options.previousReceiptHash ?? null;

    // The verdict is reached before anything is signed, and the key is not in scope for the
    // provider. A provider cannot sign, and the signer cannot decide.
    const { decision, commitment, attestation } = await config.provider.decide(
      request,
      options.state,
      options.decidedAt,
    );

    const receiptId = deriveReceiptId({
      agentId: config.agentId,
      request,
      decidedAt: options.decidedAt,
      previousReceiptHash,
    } as unknown as Canonicalisable);

    const signed = decision.verdict === "allow" ? signAuthorisedTransfer(receiptId, options) : undefined;
    const built = typeof signed === "object" ? signed : undefined;
    // Signed, not broadcast. Submission to a cluster is a separate step with its own failure
    // modes, and conflating the two would let a receipt assert an on-chain effect that never
    // happened. Whether the transaction landed is checked against the chain by its id.
    const outcome: ExecutionOutcome =
      typeof signed === "string" ? { executed: false, error: signed } : { executed: false };

    const body: ReceiptBody = {
      receiptId,
      schemaVersion: 1,
      policyHash: commitment,
      request,
      state: options.state,
      decision,
      modelReasoning: options.modelReasoning,
      rulesetVersion: RULESET_VERSION,
      attestation,
      transaction: built?.transaction,
      outcome,
      previousReceiptHash,
    };

    return Object.freeze({
      decision,
      receipt: signReceipt(body, keys),
      signedTransaction: built?.wire,
    });
  }

  return Object.freeze({ publicKey, submit });
}
