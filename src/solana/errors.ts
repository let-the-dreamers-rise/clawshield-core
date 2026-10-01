/**
 * Errors raised by the signing boundary.
 *
 * Kept out of adapter.ts on purpose: that module exports exactly one function, and the test
 * suite asserts it, because the shape of its exports is part of the guarantee that nothing
 * there signs on demand.
 */

export type SolanaAdapterErrorCode = "signer_mismatch";

export class SolanaAdapterError extends Error {
  readonly code: SolanaAdapterErrorCode;

  constructor(code: SolanaAdapterErrorCode, message: string) {
    super(message);
    this.name = "SolanaAdapterError";
    this.code = code;
  }
}
