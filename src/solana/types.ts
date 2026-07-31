/**
 * Solana-specific request types.
 *
 * Design decision: this file does NOT introduce a parallel request type the engine has to
 * learn about. A Solana transfer is mapped onto the existing ActionRequest, because every
 * receipt already issued binds that shape and the verifier replays against it. A second
 * request type would fork the engine and split the replay guarantee in two.
 *
 * The mapping is deliberate about where each field goes:
 *
 *   counterparty -> destination address, so the existing counterparty allowlist works unchanged
 *   asset        -> mint address, single source of truth, never duplicated into params
 *   amount       -> integer minor units, bigint, never a float and never a UI amount
 *   chainId      -> absent. Solana has no numeric chain id and inventing one would be a lie
 *                   baked into a signed receipt.
 *
 * Everything genuinely Solana-shaped lives in params under a `chain: "solana"` discriminant.
 */

import type { ActionRequest } from "../policy/types.ts";

export const SYSTEM_PROGRAM_ID = "11111111111111111111111111111111";
export const TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const TOKEN_2022_PROGRAM_ID = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
export const USDC_MAINNET_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/**
 * Native SOL is keyed by the wrapped-SOL mint address rather than a sentinel like "SOL".
 * A per-mint cap table then has one uniform key space and no rule needs a special case for
 * the native asset.
 */
export const NATIVE_SOL_MINT = "So11111111111111111111111111111111111111112";

export const LAMPORTS_PER_SOL = 1_000_000_000n;
export const SOL_DECIMALS = 9;
export const USDC_DECIMALS = 6;

/** The single tool name a governed Solana transfer presents as. */
export const SOLANA_TRANSFER_TOOL = "solana_transfer";

export type SolanaCluster = "mainnet-beta" | "devnet" | "testnet" | "localnet";

/** A proposed transfer, before any policy has looked at it. */
export interface SolanaTransfer {
  /** "sol" moves lamports via the system program, "spl" moves token minor units. */
  readonly kind: "sol" | "spl";
  readonly programId: string;
  readonly cluster: SolanaCluster;
  readonly from: string;
  readonly to: string;
  /** Integer minor units: lamports for SOL, mint minor units for SPL. Never a float. */
  readonly amount: bigint;
  /** Absent for native SOL, which is keyed by NATIVE_SOL_MINT downstream. */
  readonly mint?: string;
  readonly decimals: number;
  readonly requestedAt: number;
}

/** The Solana-shaped half of an ActionRequest, carried in `params`. */
export interface SolanaActionParams {
  readonly chain: "solana";
  readonly cluster: string;
  readonly programId: string;
  readonly decimals: number;
  readonly from: string;
}

/**
 * Base58 as Solana uses it. The alphabet excludes 0, O, I and l specifically so visually
 * similar characters cannot be confused, and a 32-byte pubkey encodes to 32-44 characters.
 *
 * This is a shape check, not a curve check. It rejects typos and obvious garbage; it does not
 * prove the point is on the ed25519 curve. Anything that passes here still has to survive
 * every allowlist, so the check is a cheap early filter rather than a security boundary.
 */
const BASE58_PUBKEY = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export function isValidSolanaAddress(value: unknown): value is string {
  return typeof value === "string" && BASE58_PUBKEY.test(value);
}

/**
 * Read the Solana half of a request, validating its shape at the boundary.
 *
 * Returns null in two distinct situations that callers must treat differently:
 *   - the request is not a Solana request at all (no `chain` discriminant)
 *   - the request claims to be Solana but its params are malformed
 *
 * `isSolanaRequest` separates the two so a forged request cannot silently take the
 * not-my-problem path through every Solana rule. See checkSolanaParams in rules.ts.
 */
export function readSolanaParams(request: ActionRequest): SolanaActionParams | null {
  const p = request.params as Record<string, unknown>;
  if (p?.["chain"] !== "solana") return null;

  const { cluster, programId, decimals, from } = p as Record<string, unknown>;
  if (typeof cluster !== "string" || cluster.length === 0) return null;
  if (!isValidSolanaAddress(programId)) return null;
  if (!isValidSolanaAddress(from)) return null;
  if (typeof decimals !== "number" || !Number.isInteger(decimals) || decimals < 0 || decimals > 18) {
    return null;
  }

  return { chain: "solana", cluster, programId, decimals, from };
}

/** True when a request claims to be Solana, regardless of whether its params are well formed. */
export function isSolanaRequest(request: ActionRequest): boolean {
  return (request.params as Record<string, unknown>)?.["chain"] === "solana";
}

/** The mint a request spends. Native SOL resolves to the wrapped-SOL mint. */
export function mintOf(request: ActionRequest): string {
  return request.asset ?? NATIVE_SOL_MINT;
}

/**
 * Map a proposed transfer onto the core ActionRequest.
 *
 * Pure, and separate from the adapter on purpose: the adapter is about the signing-key trust
 * boundary, and a mapping function that can be tested without ever constructing a keypair is
 * a mapping function that will actually get tested.
 */
export function toActionRequest(transfer: SolanaTransfer, agentId: string): ActionRequest {
  const params: SolanaActionParams = {
    chain: "solana",
    cluster: transfer.cluster,
    programId: transfer.programId,
    decimals: transfer.decimals,
    from: transfer.from,
  };

  return {
    agentId,
    tool: SOLANA_TRANSFER_TOOL,
    counterparty: transfer.to,
    amount: transfer.amount,
    asset: transfer.mint ?? NATIVE_SOL_MINT,
    requestedAt: transfer.requestedAt,
    // SolanaActionParams is a closed shape; ActionRequest.params is an open record. The cast
    // is the one place the two meet, and readSolanaParams re-validates on the way back out.
    params: params as unknown as Readonly<Record<string, unknown>>,
  };
}

/** Convert whole SOL to lamports without ever touching a float. */
export function solToLamports(whole: bigint): bigint {
  return whole * LAMPORTS_PER_SOL;
}
