/**
 * The live MXE client: GENKAI's policy evaluated on ciphertext by an Arcium cluster on Solana.
 *
 * evaluate() sends one transaction, the program's `evaluate` instruction, which records the
 * plaintext request fields in a fresh DecisionRecord and queues the evaluate_policy circuit
 * against the encrypted PolicyRecord. The cluster computes, signs the output, and the Arcium
 * program calls back into GENKAI, which writes the verdict only once that signature verifies.
 * This client then reads the record back and returns it, with an attestation that names where
 * it lives so any third party can read the same record.
 *
 * What the client holds: the policy authority's Solana key, which is needed because evaluation
 * is authority-only (an open evaluator would be an oracle for the limits). What it never
 * holds: the policy. It runs nothing but encoding and RPC; there is no Arcium SDK here.
 *
 * Every way this can go wrong ends in a named ArciumMxeError. In particular a computation the
 * cluster aborts leaves its DecisionRecord pending, which surfaces as a timeout, never as a
 * default verdict.
 */

import { randomBytes } from "node:crypto";
import { setComputeUnitLimit, setComputeUnitPrice, type Instruction } from "../solana/instructions.ts";
import { compileLegacyMessage } from "../solana/message.ts";
import { signLegacyTransaction } from "../solana/transaction.ts";
import { solanaAddress } from "../solana/keys.ts";
import type { RpcClient } from "../solana/rpc.ts";
import type { Keypair } from "../receipt/sign.ts";
import { encodeRequest } from "./encoding.ts";
import { ruleIdsOf, verdictOf } from "./circuit.ts";
import { evaluateAccounts, evaluateInstruction } from "./arcium-accounts.ts";
import { decodeDecisionRecord, decodePolicyRecord, encodeRequestFields, type DecisionRecordView, type PolicyRecordView } from "./onchain.ts";
import type { MxeClient, MxeEvaluationInput, MxeEvaluationOutput, OnChainAttestation } from "./types.ts";

export type ArciumMxeErrorCode =
  | "policy_unavailable"
  | "policy_not_active"
  | "not_authority"
  | "queue_failed"
  | "timeout"
  | "bad_record";

export class ArciumMxeError extends Error {
  readonly code: ArciumMxeErrorCode;

  constructor(code: ArciumMxeErrorCode, message: string) {
    super(message);
    this.name = "ArciumMxeError";
    this.code = code;
  }
}

export interface ArciumMxeConfig {
  readonly rpc: RpcClient;
  /** The deployed GENKAI program. */
  readonly programId: string;
  /** The Arcium cluster the program's MXE was initialised on (456 on devnet). */
  readonly clusterOffset: number;
  /** The PolicyRecord holding the encrypted policy. */
  readonly policy: string;
  /** The policy's authority: the only key the program lets evaluate it. */
  readonly authority: Keypair;
  readonly circuitId: string;
  /** Default 400,000. evaluate creates two accounts and CPIs into Arcium to queue the job. */
  readonly computeUnitLimit?: number;
  /** Priority fee in micro-lamports per CU; omitted means none. */
  readonly computeUnitPrice?: bigint;
  readonly pollIntervalMs?: number;
  /** How long to wait for the cluster's callback. Default three minutes. */
  readonly timeoutMs?: number;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  /** Injected for tests. Must be unique per computation; the default is 64 random bits. */
  readonly randomOffset?: () => bigint;
}

const DEFAULT_CU_LIMIT = 400_000;

export function createArciumMxeClient(config: ArciumMxeConfig): MxeClient {
  const authority = solanaAddress(config.authority.publicKey);
  const now = config.now ?? (() => Date.now());
  const sleep = config.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const pollIntervalMs = config.pollIntervalMs ?? 2_000;
  const timeoutMs = config.timeoutMs ?? 180_000;
  const randomOffset = config.randomOffset ?? (() => randomBytes(8).readBigUInt64LE(0));

  async function loadPolicy(): Promise<PolicyRecordView> {
    const account = await config.rpc.getAccountInfo(config.policy);
    if (!account || account.owner !== config.programId) {
      throw new ArciumMxeError("policy_unavailable", `No GENKAI policy record at ${config.policy}`);
    }
    let policy: PolicyRecordView;
    try {
      policy = decodePolicyRecord(account.data);
    } catch (err) {
      throw new ArciumMxeError("policy_unavailable", `Unreadable policy record: ${(err as Error).message}`);
    }
    if (policy.status !== "active") throw new ArciumMxeError("policy_not_active", `Policy record is ${policy.status}`);
    if (policy.authority !== authority) {
      throw new ArciumMxeError("not_authority", `Policy authority is ${policy.authority}; this client signs as ${authority}`);
    }
    return policy;
  }

  async function queue(instructions: readonly Instruction[]): Promise<string> {
    const { blockhash } = await config.rpc.getLatestBlockhash("confirmed");
    const message = compileLegacyMessage({ payer: authority, recentBlockhash: blockhash, instructions });
    const signed = signLegacyTransaction(message, config.authority);
    try {
      return await config.rpc.sendTransaction(Buffer.from(signed.wire).toString("base64"));
    } catch (err) {
      throw new ArciumMxeError("queue_failed", `evaluate was not accepted: ${(err as Error).message}`);
    }
  }

  async function awaitDecision(decision: string, queueSignature: string): Promise<DecisionRecordView> {
    const deadline = now() + timeoutMs;
    for (;;) {
      const [status] = await config.rpc.getSignatureStatuses([queueSignature]);
      if (status && status.err !== null) {
        throw new ArciumMxeError("queue_failed", `evaluate failed on chain: ${JSON.stringify(status.err)}`);
      }
      const account = await config.rpc.getAccountInfo(decision);
      if (account && account.owner === config.programId) {
        let record: DecisionRecordView;
        try {
          record = decodeDecisionRecord(account.data);
        } catch (err) {
          throw new ArciumMxeError("bad_record", `Unreadable decision record: ${(err as Error).message}`);
        }
        if (record.status === 1) return record;
      }
      if (now() >= deadline) {
        throw new ArciumMxeError("timeout", `No verdict recorded at ${decision} within ${timeoutMs} ms; the computation may have been aborted`);
      }
      await sleep(pollIntervalMs);
    }
  }

  async function evaluate(input: MxeEvaluationInput): Promise<MxeEvaluationOutput> {
    const policy = await loadPolicy();
    const requestFields = encodeRequestFields(encodeRequest(input.request, input.state));
    const discloseRules = input.disclosure !== "verdict";
    const computationOffset = randomOffset();
    const target = { programId: config.programId, clusterOffset: config.clusterOffset, authority, policy: config.policy, computationOffset };
    const { decision } = evaluateAccounts(target);

    const queueSignature = await queue([
      setComputeUnitLimit(config.computeUnitLimit ?? DEFAULT_CU_LIMIT),
      ...(config.computeUnitPrice === undefined ? [] : [setComputeUnitPrice(config.computeUnitPrice)]),
      evaluateInstruction({ ...target, requestFields, discloseRules }),
    ]);
    const record = await awaitDecision(decision, queueSignature);

    // The record must be the one this call created, for exactly this request. Anything else
    // means the address was squatted or the program is not the one we think it is.
    const sameFields = Buffer.from(record.requestFields).equals(Buffer.from(requestFields));
    if (record.policy !== config.policy || record.computationOffset !== computationOffset || !sameFields || record.discloseRules !== discloseRules) {
      throw new ArciumMxeError("bad_record", `Decision record at ${decision} does not match the request that was queued`);
    }
    if (record.verdict > 2) throw new ArciumMxeError("bad_record", `Unknown verdict code ${record.verdict}`);

    const out = { verdict: record.verdict as 0 | 1 | 2, mask: record.mask };
    const attestation: OnChainAttestation = {
      kind: "onchain",
      circuitId: config.circuitId,
      programId: config.programId,
      policy: config.policy,
      decision,
      computationOffset,
      queueSignature,
      ...(discloseRules ? {} : { disclosure: "verdict" as const }),
    };
    return {
      policyCommitment: policy.commitment,
      verdict: verdictOf(out),
      ruleIds: discloseRules ? [...ruleIdsOf(out)] : [],
      attestation,
    };
  }

  return Object.freeze({ circuitId: config.circuitId, evaluate });
}
