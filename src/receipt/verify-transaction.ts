/**
 * Does the transaction bound into a receipt move exactly what the policy evaluated?
 *
 * The check rebuilds the message from the receipt's own request, hashes it, and verifies the
 * fee payer's signature over it. It needs no RPC and no trust in the operator. Whether that
 * transaction then landed on chain is a separate question, answered by verifyExecution.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { decodeBase58, decodePubkey } from "../solana/base58.ts";
import { composeTransferMessage, transferFromRequest } from "../solana/compose.ts";
import type { ReceiptBody } from "./types.ts";

export function rebuildBoundMessage(body: ReceiptBody): Uint8Array {
  const tx = body.transaction;
  if (!tx) throw new Error("The receipt binds no transaction");
  const transfer = transferFromRequest(body.request);
  if (!transfer) throw new Error("The receipt's request is not a Solana transfer");
  return composeTransferMessage(transfer, {
    recentBlockhash: tx.recentBlockhash,
    receiptId: body.receiptId,
    computeUnitLimit: tx.computeUnitLimit,
    computeUnitPrice: tx.computeUnitPrice,
  });
}

function verifyEd25519(message: Uint8Array, signature: Uint8Array, signer: string): boolean {
  const key = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(decodePubkey(signer)).toString("base64url") },
    format: "jwk",
  });
  return cryptoVerify(null, message, key, signature);
}

/** Returns a description of the problem, or null when the bound transaction is sound. */
export function checkBoundTransaction(body: ReceiptBody): string | null {
  const tx = body.transaction;
  if (!tx) return null;
  if (body.decision.verdict !== "allow") {
    return `A transaction is bound to a receipt whose verdict is "${body.decision.verdict}"`;
  }

  try {
    const message = rebuildBoundMessage(body);
    const hash = createHash("sha256").update(message).digest("hex");
    if (hash !== tx.messageSha256) {
      return `The bound message hash ${tx.messageSha256} does not match the message rebuilt from the request (${hash})`;
    }
    const transfer = transferFromRequest(body.request);
    if (!transfer || !verifyEd25519(message, decodeBase58(tx.signature), transfer.from)) {
      return "The bound signature is not the fee payer's signature over the rebuilt message";
    }
    return null;
  } catch (err) {
    return `The bound transaction cannot be rebuilt: ${err instanceof Error ? err.message : String(err)}`;
  }
}
