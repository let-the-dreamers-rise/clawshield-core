/**
 * Legacy transaction message compilation.
 *
 * The account ordering reproduces @solana/web3.js's CompiledKeys exactly: the fee payer first,
 * then every key in first-seen order with an instruction's program id seen before its accounts,
 * partitioned into writable signers, readonly signers, writable non-signers and readonly
 * non-signers. Matching the reference byte for byte is what lets the test suite prove the
 * message is the one the cluster will execute.
 */

import { decodePubkey } from "./base58.ts";
import type { Instruction } from "./instructions.ts";

/** Maximum serialised transaction size the cluster accepts (IPv6 MTU minus headers). */
export const PACKET_DATA_SIZE = 1232;
const SIGNATURE_LENGTH = 64;

export class MessageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MessageError";
  }
}

export interface MessageInput {
  readonly payer: string;
  readonly recentBlockhash: string;
  readonly instructions: readonly Instruction[];
}

interface KeyMeta {
  readonly isSigner: boolean;
  readonly isWritable: boolean;
}

export function compactU16(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new MessageError(`${value} does not fit in a compact-u16`);
  }
  const out: number[] = [];
  let rest = value;
  for (;;) {
    const low = rest & 0x7f;
    rest >>= 7;
    if (rest === 0) {
      out.push(low);
      return Uint8Array.from(out);
    }
    out.push(low | 0x80);
  }
}

function collectKeys(input: MessageInput): ReadonlyMap<string, KeyMeta> {
  const merge = (map: ReadonlyMap<string, KeyMeta>, key: string, meta: KeyMeta): Map<string, KeyMeta> => {
    const prior = map.get(key);
    const next = new Map(map);
    next.set(key, {
      isSigner: (prior?.isSigner ?? false) || meta.isSigner,
      isWritable: (prior?.isWritable ?? false) || meta.isWritable,
    });
    return next;
  };

  const none: KeyMeta = { isSigner: false, isWritable: false };
  return input.instructions.reduce<ReadonlyMap<string, KeyMeta>>(
    (acc, ix) => ix.keys.reduce((inner, k) => merge(inner, k.pubkey, k), merge(acc, ix.programId, none)),
    merge(new Map(), input.payer, { isSigner: true, isWritable: true }),
  );
}

export function compileLegacyMessage(input: MessageInput): Uint8Array {
  const blockhash = decodePubkey(input.recentBlockhash);
  const entries = [...collectKeys(input).entries()];
  const pick = (signer: boolean, write: boolean) =>
    entries.filter(([, m]) => m.isSigner === signer && m.isWritable === write).map(([k]) => k);

  const ordered = [...pick(true, true), ...pick(true, false), ...pick(false, true), ...pick(false, false)];
  if (ordered.length > 256) {
    throw new MessageError(`A legacy message addresses at most 256 accounts, got ${ordered.length}`);
  }
  const index = new Map(ordered.map((k, i) => [k, i]));
  const numSigners = pick(true, true).length + pick(true, false).length;

  const header = Uint8Array.of(numSigners, pick(true, false).length, pick(false, false).length);
  const keys = ordered.map((k) => decodePubkey(k));
  const instructions = input.instructions.map((ix) => {
    const accounts = ix.keys.map((k) => index.get(k.pubkey) ?? 0);
    return [
      Uint8Array.of(index.get(ix.programId) ?? 0),
      compactU16(accounts.length),
      Uint8Array.from(accounts),
      compactU16(ix.data.length),
      ix.data,
    ];
  });

  const parts = [
    header,
    compactU16(keys.length),
    ...keys,
    blockhash,
    compactU16(instructions.length),
    ...instructions.flat(),
  ];
  const message = Uint8Array.from(parts.flatMap((p) => [...p]));

  const wireSize = compactU16(numSigners).length + numSigners * SIGNATURE_LENGTH + message.length;
  if (wireSize > PACKET_DATA_SIZE) {
    throw new MessageError(`Transaction would be ${wireSize} bytes; the cluster accepts at most ${PACKET_DATA_SIZE}`);
  }
  return message;
}
