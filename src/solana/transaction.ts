/**
 * Signing a compiled legacy message.
 *
 * GENKAI only ever builds single-signer transactions: the governed vault pays the fee and
 * authorises the transfer. A message needing any other signature is outside what the policy
 * evaluated, so it is refused rather than partially signed.
 */

import { sign } from "node:crypto";
import { encodeBase58 } from "./base58.ts";
import { publicKeyBytes } from "./keys.ts";
import { MessageError } from "./message.ts";
import type { Keypair } from "../receipt/sign.ts";

export interface SignedTransaction {
  /** The full wire transaction: signature count, signature, message. */
  readonly wire: Uint8Array;
  /** Base58 of the fee payer's signature, which is the transaction id on chain. */
  readonly signature: string;
}

function feePayerOf(message: Uint8Array): Uint8Array {
  const numSigners = message[0];
  const numKeys = message[3];
  // Legacy messages here never exceed 127 accounts, so the key count is a single byte.
  if (numSigners !== 1 || numKeys === undefined || numKeys >= 0x80 || message.length < 36) {
    throw new MessageError("Only single-signer legacy messages are signed");
  }
  return message.subarray(4, 36);
}

export function signLegacyTransaction(message: Uint8Array, keys: Keypair): SignedTransaction {
  const payer = feePayerOf(message);
  if (!Buffer.from(payer).equals(Buffer.from(publicKeyBytes(keys.publicKey)))) {
    throw new MessageError("The signing key is not the fee payer of this message");
  }

  const signature = new Uint8Array(sign(null, message, keys.privateKey));
  const wire = Uint8Array.from([1, ...signature, ...message]);
  return { wire, signature: encodeBase58(signature) };
}
