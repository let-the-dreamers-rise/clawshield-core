/**
 * Program-derived addresses and associated token accounts.
 *
 * An SPL transfer moves tokens between token accounts, not wallets. The policy reasons about
 * the destination WALLET (the counterparty allowlist is a list of owners), so the token account
 * actually written to must be derived from that wallet deterministically. Deriving it here,
 * rather than accepting a token account from the caller, is what stops an agent from naming an
 * allowlisted owner in the request and an attacker-controlled token account in the transaction.
 */

import { createHash } from "node:crypto";
import { decodePubkey, encodeBase58 } from "./base58.ts";
import { isOnCurve } from "./curve.ts";

export const ASSOCIATED_TOKEN_PROGRAM_ID = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

const MAX_SEED_LENGTH = 32;
const MAX_SEEDS = 16;
const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

export class ProgramAddressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProgramAddressError";
  }
}

function checkSeeds(seeds: readonly Uint8Array[]): void {
  if (seeds.length > MAX_SEEDS) {
    throw new ProgramAddressError(`At most ${MAX_SEEDS} seeds are allowed, got ${seeds.length}`);
  }
  for (const seed of seeds) {
    if (seed.length > MAX_SEED_LENGTH) {
      throw new ProgramAddressError(`A seed is at most ${MAX_SEED_LENGTH} bytes, got ${seed.length}`);
    }
  }
}

/** Throws when the derived address lands on the curve, exactly as the runtime does. */
export function createProgramAddress(seeds: readonly Uint8Array[], programId: string): string {
  checkSeeds(seeds);
  const hash = createHash("sha256");
  for (const seed of seeds) hash.update(seed);
  hash.update(decodePubkey(programId));
  hash.update(PDA_MARKER);
  const digest = new Uint8Array(hash.digest());

  if (isOnCurve(digest)) {
    throw new ProgramAddressError("Derived address is on the curve and therefore not a valid program address");
  }
  return encodeBase58(digest);
}

export interface ProgramAddress {
  readonly address: string;
  readonly bump: number;
}

/** The canonical bump is the highest one, searched downward from 255. */
export function findProgramAddress(seeds: readonly Uint8Array[], programId: string): ProgramAddress {
  checkSeeds([...seeds, Uint8Array.of(0)]);
  for (let bump = 255; bump >= 0; bump--) {
    try {
      return { address: createProgramAddress([...seeds, Uint8Array.of(bump)], programId), bump };
    } catch (err) {
      if (!(err instanceof ProgramAddressError)) throw err;
    }
  }
  throw new ProgramAddressError("No viable bump seed found");
}

export function associatedTokenAddress(owner: string, mint: string, tokenProgramId: string): string {
  return findProgramAddress(
    [decodePubkey(owner), decodePubkey(tokenProgramId), decodePubkey(mint)],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  ).address;
}
