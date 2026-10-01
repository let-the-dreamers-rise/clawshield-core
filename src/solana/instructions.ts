/**
 * Instruction builders for the handful of programs a governed transfer touches.
 *
 * Deliberately narrow. Each builder encodes one instruction whose layout is fixed by its
 * program, and every amount is range-checked before encoding: a u64 field given a negative or
 * oversized bigint would otherwise wrap, and the cluster would execute a transfer of a
 * different size than the one the policy evaluated.
 */

import { SYSTEM_PROGRAM_ID } from "./types.ts";

export const COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111";
export const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

const U64_MAX = (1n << 64n) - 1n;
const U32_MAX = 0xffff_ffff;

export interface AccountMeta {
  readonly pubkey: string;
  readonly isSigner: boolean;
  readonly isWritable: boolean;
}

export interface Instruction {
  readonly programId: string;
  readonly keys: readonly AccountMeta[];
  readonly data: Uint8Array;
}

export function u64le(value: bigint): Uint8Array {
  if (value < 0n || value > U64_MAX) {
    throw new RangeError(`${value} does not fit in a u64`);
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function u32le(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > U32_MAX) {
    throw new RangeError(`${value} does not fit in a u32`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, true);
  return out;
}

const concat = (...parts: readonly Uint8Array[]): Uint8Array => Uint8Array.from(parts.flatMap((p) => [...p]));

const signerWritable = (pubkey: string): AccountMeta => ({ pubkey, isSigner: true, isWritable: true });
const writable = (pubkey: string): AccountMeta => ({ pubkey, isSigner: false, isWritable: true });
const readonly = (pubkey: string): AccountMeta => ({ pubkey, isSigner: false, isWritable: false });

/** System program Transfer: instruction index 2 as a u32, then lamports as a u64. */
export function systemTransfer(from: string, to: string, lamports: bigint): Instruction {
  return {
    programId: SYSTEM_PROGRAM_ID,
    keys: [signerWritable(from), writable(to)],
    data: concat(u32le(2), u64le(lamports)),
  };
}

export interface TransferCheckedArgs {
  readonly source: string;
  readonly mint: string;
  readonly destination: string;
  readonly owner: string;
  readonly amount: bigint;
  readonly decimals: number;
  readonly programId: string;
}

/**
 * SPL Token TransferChecked (index 12). Checked rather than plain Transfer because it makes the
 * program verify the mint and its decimals: a transfer built against the wrong mint fails on
 * chain instead of moving a different asset.
 */
export function transferChecked(args: TransferCheckedArgs): Instruction {
  if (!Number.isInteger(args.decimals) || args.decimals < 0 || args.decimals > 255) {
    throw new RangeError(`Decimals ${args.decimals} do not fit in a u8`);
  }
  return {
    programId: args.programId,
    keys: [
      writable(args.source),
      readonly(args.mint),
      writable(args.destination),
      { pubkey: args.owner, isSigner: true, isWritable: false },
    ],
    data: concat(Uint8Array.of(12), u64le(args.amount), Uint8Array.of(args.decimals)),
  };
}

export function setComputeUnitLimit(units: number): Instruction {
  return { programId: COMPUTE_BUDGET_PROGRAM_ID, keys: [], data: concat(Uint8Array.of(2), u32le(units)) };
}

export function setComputeUnitPrice(microLamports: bigint): Instruction {
  return { programId: COMPUTE_BUDGET_PROGRAM_ID, keys: [], data: concat(Uint8Array.of(3), u64le(microLamports)) };
}

/**
 * An SPL memo with no signer accounts. GENKAI writes the receipt id here so the on-chain
 * transaction names the receipt that authorised it, and anyone reading the chain can find it.
 */
export function memo(text: string): Instruction {
  return { programId: MEMO_PROGRAM_ID, keys: [], data: new TextEncoder().encode(text) };
}
