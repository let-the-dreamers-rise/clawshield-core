/**
 * Arcium account derivation and the GENKAI evaluate instruction, with no SDK.
 *
 * The Arcium program keeps every account it owns at a PDA seeded by an ASCII account name and,
 * where there is one, a cluster offset (u32 LE), a computation offset (u64 LE) or the MXE
 * program id. These mirror the seed constants in @arcium-hq/client and the derive_*_pda!
 * macros in arcium-anchor; test/arcium-client.test.ts derives the fee pool and clock accounts
 * and compares them with the fixed addresses in the program's IDL, which pins the scheme.
 *
 * The evaluate instruction follows programs/genkai's IDL: Anchor's 8-byte discriminator
 * (sha256("global:evaluate")[0..8]), then computation_offset u64, RequestFields (borsh), and
 * disclose_rules bool, with accounts in declaration order.
 */

import { createHash } from "node:crypto";
import { decodePubkey } from "../solana/base58.ts";
import { findProgramAddress } from "../solana/pda.ts";
import { SYSTEM_PROGRAM_ID } from "../solana/types.ts";
import type { AccountMeta, Instruction } from "../solana/instructions.ts";
import { decisionRecordAddress, REQUEST_FIELDS_SIZE } from "./onchain.ts";

export const ARCIUM_PROGRAM_ID = "Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ";

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);

function u32le(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw new RangeError(`${value} does not fit in a u32`);
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
}

function u64le(value: bigint): Uint8Array {
  if (value < 0n || value >= 1n << 64n) throw new RangeError(`${value} does not fit in a u64`);
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(value);
  return out;
}

const arciumPda = (...seeds: Uint8Array[]): string => findProgramAddress(seeds, ARCIUM_PROGRAM_ID).address;

export const ARCIUM_FEE_POOL_ACCOUNT = arciumPda(ascii("FeePool"));
export const ARCIUM_CLOCK_ACCOUNT = arciumPda(ascii("ClockAccount"));

/** comp_def_offset(name) in arcium-anchor: the first four bytes of sha256(name), little endian. */
export function compDefOffset(circuitName: string): number {
  return createHash("sha256").update(circuitName, "utf8").digest().readUInt32LE(0);
}

export const mxeAccountAddress = (programId: string): string => arciumPda(ascii("MXEAccount"), decodePubkey(programId));
export const mempoolAddress = (clusterOffset: number): string => arciumPda(ascii("Mempool"), u32le(clusterOffset));
export const executingPoolAddress = (clusterOffset: number): string => arciumPda(ascii("Execpool"), u32le(clusterOffset));
export const clusterAddress = (clusterOffset: number): string => arciumPda(ascii("Cluster"), u32le(clusterOffset));
export const computationAddress = (clusterOffset: number, computationOffset: bigint): string =>
  arciumPda(ascii("ComputationAccount"), u32le(clusterOffset), u64le(computationOffset));
export const compDefAddress = (programId: string, circuitName: string): string =>
  arciumPda(ascii("ComputationDefinitionAccount"), decodePubkey(programId), u32le(compDefOffset(circuitName)));
/** Owned by the MXE program itself, not by Arcium: it signs the CPI that queues computations. */
export const signPdaAddress = (programId: string): string => findProgramAddress([ascii("ArciumSignerAccount")], programId).address;

export const EVALUATE_DISCRIMINATOR: Uint8Array = createHash("sha256").update("global:evaluate").digest().subarray(0, 8);

export interface EvaluateTarget {
  readonly programId: string;
  readonly clusterOffset: number;
  readonly authority: string;
  readonly policy: string;
  readonly computationOffset: bigint;
}

export interface EvaluateAccounts {
  readonly authority: string;
  readonly policy: string;
  readonly decision: string;
  readonly signPda: string;
  readonly mxe: string;
  readonly mempool: string;
  readonly executingPool: string;
  readonly computation: string;
  readonly compDef: string;
  readonly cluster: string;
}

export function evaluateAccounts(t: EvaluateTarget): EvaluateAccounts {
  return {
    authority: t.authority,
    policy: t.policy,
    decision: decisionRecordAddress(t.programId, t.policy, t.computationOffset),
    signPda: signPdaAddress(t.programId),
    mxe: mxeAccountAddress(t.programId),
    mempool: mempoolAddress(t.clusterOffset),
    executingPool: executingPoolAddress(t.clusterOffset),
    computation: computationAddress(t.clusterOffset, t.computationOffset),
    compDef: compDefAddress(t.programId, "evaluate_policy"),
    cluster: clusterAddress(t.clusterOffset),
  };
}

const meta = (pubkey: string, isWritable: boolean, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable });

export interface EvaluateArgs extends EvaluateTarget {
  readonly requestFields: Uint8Array;
  readonly discloseRules: boolean;
}

export function evaluateInstruction(args: EvaluateArgs): Instruction {
  if (args.requestFields.length !== REQUEST_FIELDS_SIZE) {
    throw new RangeError(`RequestFields is ${REQUEST_FIELDS_SIZE} bytes, got ${args.requestFields.length}`);
  }
  const a = evaluateAccounts(args);
  return {
    programId: args.programId,
    keys: [
      meta(a.authority, true, true),
      meta(a.policy, false),
      meta(a.decision, true),
      meta(a.signPda, true),
      meta(a.mxe, false),
      meta(a.mempool, true),
      meta(a.executingPool, true),
      meta(a.computation, true),
      meta(a.compDef, false),
      meta(a.cluster, true),
      meta(ARCIUM_FEE_POOL_ACCOUNT, true),
      meta(ARCIUM_CLOCK_ACCOUNT, true),
      meta(SYSTEM_PROGRAM_ID, false),
      meta(ARCIUM_PROGRAM_ID, false),
    ],
    data: new Uint8Array(
      Buffer.concat([EVALUATE_DISCRIMINATOR, u64le(args.computationOffset), args.requestFields, Uint8Array.of(args.discloseRules ? 1 : 0)]),
    ),
  };
}
