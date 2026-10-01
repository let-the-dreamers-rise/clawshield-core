/**
 * From an authorised transfer to the exact message that will be signed.
 *
 * This is a pure function of the transfer plus three operational inputs: the recent blockhash,
 * the receipt id written into the memo, and optional compute-budget fees. All three are bound
 * into the receipt, so a verifier holding only the receipt can rebuild the message byte for
 * byte from the request the policy evaluated, and check the signature over it.
 *
 * The instruction set is closed: a compute-budget prefix, one transfer, one memo. Nothing else
 * the policy did not evaluate can ride along in the same transaction.
 */

import { associatedTokenAddress } from "./pda.ts";
import { memo, setComputeUnitLimit, setComputeUnitPrice, systemTransfer, transferChecked, type Instruction } from "./instructions.ts";
import { compileLegacyMessage } from "./message.ts";
import type { ActionRequest } from "../policy/types.ts";
import {
  NATIVE_SOL_MINT,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  readSolanaParams,
  type SolanaCluster,
  type SolanaTransfer,
} from "./types.ts";

export const RECEIPT_MEMO_PREFIX = "genkai:";
const U64_MAX = (1n << 64n) - 1n;
const TOKEN_PROGRAMS: ReadonlySet<string> = new Set([TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]);

export class ComposeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ComposeError";
  }
}

export interface TransactionFees {
  readonly computeUnitLimit?: number;
  /** Priority fee in micro-lamports per compute unit. */
  readonly computeUnitPrice?: bigint;
}

export interface ComposeOptions extends TransactionFees {
  readonly recentBlockhash: string;
  readonly receiptId: string;
}

function transferInstruction(transfer: SolanaTransfer): Instruction {
  if (transfer.amount <= 0n || transfer.amount > U64_MAX) {
    throw new ComposeError(`Amount ${transfer.amount} is not encodable as a positive u64`);
  }

  if (transfer.kind === "sol") {
    if (transfer.programId !== SYSTEM_PROGRAM_ID) {
      throw new ComposeError(`A SOL transfer must use the system program, not ${transfer.programId}`);
    }
    if (transfer.mint !== undefined && transfer.mint !== NATIVE_SOL_MINT) {
      throw new ComposeError(`A SOL transfer cannot name mint ${transfer.mint}`);
    }
    return systemTransfer(transfer.from, transfer.to, transfer.amount);
  }

  if (!TOKEN_PROGRAMS.has(transfer.programId)) {
    throw new ComposeError(`No encoder for token program ${transfer.programId}`);
  }
  if (transfer.mint === undefined) {
    throw new ComposeError("An SPL transfer must name its mint");
  }
  // Token accounts are derived from the owners, never accepted from the caller. See pda.ts.
  return transferChecked({
    source: associatedTokenAddress(transfer.from, transfer.mint, transfer.programId),
    mint: transfer.mint,
    destination: associatedTokenAddress(transfer.to, transfer.mint, transfer.programId),
    owner: transfer.from,
    amount: transfer.amount,
    decimals: transfer.decimals,
    programId: transfer.programId,
  });
}

export function composeTransferMessage(transfer: SolanaTransfer, options: ComposeOptions): Uint8Array {
  const fees = [
    ...(options.computeUnitLimit !== undefined ? [setComputeUnitLimit(options.computeUnitLimit)] : []),
    ...(options.computeUnitPrice !== undefined ? [setComputeUnitPrice(options.computeUnitPrice)] : []),
  ];
  return compileLegacyMessage({
    payer: transfer.from,
    recentBlockhash: options.recentBlockhash,
    instructions: [...fees, transferInstruction(transfer), memo(`${RECEIPT_MEMO_PREFIX}${options.receiptId}`)],
  });
}

/**
 * The inverse of toActionRequest. A verifier has the request, not the transfer, and must be
 * able to rebuild the transaction from exactly what the policy saw.
 */
export function transferFromRequest(request: ActionRequest): SolanaTransfer | null {
  const params = readSolanaParams(request);
  if (params === null || request.counterparty === undefined || request.amount === undefined) return null;

  const kind = params.programId === SYSTEM_PROGRAM_ID ? "sol" : "spl";
  const asset = request.asset ?? NATIVE_SOL_MINT;
  return {
    kind,
    programId: params.programId,
    cluster: params.cluster as SolanaCluster,
    from: params.from,
    to: request.counterparty,
    amount: request.amount,
    mint: kind === "sol" && asset === NATIVE_SOL_MINT ? undefined : asset,
    decimals: params.decimals,
    requestedAt: request.requestedAt,
  };
}
