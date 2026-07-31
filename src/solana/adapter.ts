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

import { createHash, sign } from "node:crypto";
import { canonicalBytes, type Canonicalisable } from "../receipt/canonical.ts";
import { signReceipt, type Keypair } from "../receipt/sign.ts";
import { RULESET_VERSION } from "../policy/engine.ts";
import type { PolicyProvider } from "../policy/sealed.ts";
import type { AgentState, Decision } from "../policy/types.ts";
import type { ReceiptBody, SignedReceipt } from "../receipt/types.ts";
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
  readonly previousReceiptHash?: string | null;
  /** Recorded for accountability. Never consulted for enforcement. */
  readonly modelReasoning?: string;
}

export interface SolanaSubmission {
  readonly decision: Decision;
  readonly receipt: SignedReceipt;
  /** Present only when the verdict was allow. Absent for deny and for escalate alike. */
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

  /**
   * Sign the transfer itself.
   *
   * Interim note, stated rather than hidden: this signs the canonical form of the transfer,
   * not a serialised Solana transaction message. Building a real message means recent
   * blockhash fetching and instruction encoding, which is IO and a wire format, and neither
   * belongs in the same commit as the authority model. The signature already commits to the
   * destination, mint, amount, program and cluster, so the property under test - that a
   * signature covers the exact transfer that was authorised, and exists only after an allow -
   * is the property that will carry over unchanged when the message encoder lands.
   */
  function signAuthorisedTransfer(receiptId: string, transfer: SolanaTransfer): string {
    const message = canonicalBytes({ receiptId, transfer } as unknown as Canonicalisable);
    return sign(null, message, keys.privateKey).toString("base64");
  }

  async function submit(options: SubmitOptions): Promise<SolanaSubmission> {
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

    const signedTransaction =
      decision.verdict === "allow" ? signAuthorisedTransfer(receiptId, options.transfer) : undefined;

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
      // Signed, not broadcast. Submission to a cluster is a separate step with its own failure
      // modes, and conflating the two would let a receipt assert an on-chain effect that never
      // happened. executed flips to true only when a confirmed signature comes back.
      outcome: { executed: false },
      previousReceiptHash,
    };

    return Object.freeze({
      decision,
      receipt: signReceipt(body, keys),
      signedTransaction,
    });
  }

  return Object.freeze({ publicKey, submit });
}
