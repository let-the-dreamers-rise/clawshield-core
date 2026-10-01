/**
 * The receipt binds the exact transaction that was signed.
 *
 * Before this, a receipt proved a decision and a separate signature existed. Nothing tied the
 * two together for a third party: an operator could sign one transfer and file a receipt for
 * another. Now the receipt carries the transaction id and the inputs needed to rebuild the
 * message, and the verifier rebuilds it from the request the policy evaluated. If the signed
 * bytes move anything other than what the policy saw, verification fails.
 */

import { strict as assert } from "node:assert";
import { createHash, verify as cryptoVerify } from "node:crypto";
import { test } from "node:test";
import { generateKeypair, hashPolicy, signReceipt } from "../src/receipt/sign.ts";
import { verifyReceipt } from "../src/receipt/verify.ts";
import { createPlaintextPolicyProvider } from "../src/policy/sealed.ts";
import { createSolanaAdapter } from "../src/solana/adapter.ts";
import { SolanaAdapterError } from "../src/solana/errors.ts";
import { composeTransferMessage, transferFromRequest } from "../src/solana/compose.ts";
import { decodeBase58 } from "../src/solana/base58.ts";
import { solanaAddress } from "../src/solana/keys.ts";
import { MEMO_PROGRAM_ID } from "../src/solana/instructions.ts";
import {
  NATIVE_SOL_MINT,
  SOLANA_TRANSFER_TOOL,
  SYSTEM_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  USDC_MAINNET_MINT,
  toActionRequest,
  type SolanaTransfer,
} from "../src/solana/types.ts";
import type { AgentState, Policy } from "../src/policy/types.ts";

const AT = Date.UTC(2026, 6, 31, 12, 0, 0);
const KEYS = generateKeypair();
const VAULT = solanaAddress(KEYS.publicKey);
const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";
const OTHER_BLOCKHASH = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM";
const CUSTOM_PROGRAM = "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS";

const policy: Policy = {
  policyId: "treasury",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  allowedClusters: ["devnet"],
  allowedPrograms: [TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, CUSTOM_PROGRAM],
  allowedMints: [USDC_MAINNET_MINT, NATIVE_SOL_MINT],
  maxAmountPerMint: { [USDC_MAINNET_MINT]: 100_000_000n, [NATIVE_SOL_MINT]: 5_000_000_000n },
};

const state: AgentState = { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };

const spl = (over: Partial<SolanaTransfer> = {}): SolanaTransfer => ({
  kind: "spl",
  programId: TOKEN_PROGRAM_ID,
  cluster: "devnet",
  from: VAULT,
  to: VENDOR,
  mint: USDC_MAINNET_MINT,
  decimals: 6,
  amount: 10_000_000n,
  requestedAt: AT,
  ...over,
});

const sol = (over: Partial<SolanaTransfer> = {}): SolanaTransfer => ({
  kind: "sol",
  programId: SYSTEM_PROGRAM_ID,
  cluster: "devnet",
  from: VAULT,
  to: VENDOR,
  decimals: 9,
  amount: 1_000_000n,
  requestedAt: AT,
  ...over,
});

const adapter = createSolanaAdapter({ agentId: "agent-1", keys: KEYS, provider: createPlaintextPolicyProvider(policy) });
const submit = (transfer: SolanaTransfer, extra: Record<string, unknown> = {}) =>
  adapter.submit({ transfer, state, decidedAt: AT, recentBlockhash: BLOCKHASH, ...extra });

function splitWire(base64: string): { signature: Uint8Array; message: Uint8Array } {
  const wire = Buffer.from(base64, "base64");
  assert.equal(wire[0], 1, "exactly one signature");
  return { signature: wire.subarray(1, 65), message: wire.subarray(65) };
}

test("an allowed transfer yields a real wire transaction signed by the vault", async () => {
  for (const transfer of [spl(), sol()]) {
    const result = await submit(transfer);
    assert.equal(result.decision.verdict, "allow");
    assert.ok(result.signedTransaction);

    const { signature, message } = splitWire(result.signedTransaction);
    assert.equal(cryptoVerify(null, message, KEYS.publicKey, signature), true);

    const expected = composeTransferMessage(transfer, { recentBlockhash: BLOCKHASH, receiptId: result.receipt.body.receiptId });
    assert.deepEqual(new Uint8Array(message), expected);
  }
});

test("the receipt names the transaction id and the message hash", async () => {
  const result = await submit(spl());
  const tx = result.receipt.body.transaction;
  assert.ok(tx);
  const { signature, message } = splitWire(result.signedTransaction ?? "");
  assert.deepEqual(decodeBase58(tx.signature), new Uint8Array(signature));
  assert.equal(tx.messageSha256, createHash("sha256").update(message).digest("hex"));
  assert.equal(tx.recentBlockhash, BLOCKHASH);
});

test("the on-chain memo names the receipt that authorised the transfer", async () => {
  const result = await submit(spl());
  const { message } = splitWire(result.signedTransaction ?? "");
  assert.ok(Buffer.from(message).includes(Buffer.from(`genkai:${result.receipt.body.receiptId}`)));
  assert.ok(Buffer.from(message).includes(Buffer.from(decodeBase58(MEMO_PROGRAM_ID))));
});

test("a receipt with a bound transaction verifies", async () => {
  const result = await submit(spl(), { fees: { computeUnitLimit: 50_000, computeUnitPrice: 2_500n } });
  assert.equal(result.receipt.body.transaction?.computeUnitPrice, 2_500n);
  const verified = verifyReceipt(result.receipt, policy);
  assert.equal(verified.valid, true, verified.detail.join("; "));
});

test("rewriting the bound transaction is caught even when the operator re-signs the receipt", async () => {
  const result = await submit(spl());
  const body = result.receipt.body;
  const tx = body.transaction;
  assert.ok(tx);

  const forgeries = [
    { ...tx, recentBlockhash: OTHER_BLOCKHASH },
    { ...tx, computeUnitPrice: 1n },
    { ...tx, messageSha256: "00".repeat(32) },
    // A real signature, from a different transaction.
    { ...tx, signature: (await submit(spl({ amount: 1n }))).receipt.body.transaction?.signature ?? "" },
  ];
  for (const forged of forgeries) {
    const resigned = signReceipt({ ...body, transaction: forged }, KEYS);
    const verified = verifyReceipt(resigned, policy);
    assert.equal(verified.valid, false, JSON.stringify(forged, (_k, v) => (typeof v === "bigint" ? `${v}` : v)));
    assert.ok(verified.failures.includes("transaction_mismatch"));
  }
});

test("a transaction attached to a denial is caught", async () => {
  const allowed = await submit(spl());
  const denied = await submit(spl({ amount: 500_000_000n }));
  assert.equal(denied.decision.verdict, "deny");
  assert.equal(denied.receipt.body.transaction, undefined);

  const forged = signReceipt({ ...denied.receipt.body, transaction: allowed.receipt.body.transaction }, KEYS);
  const verified = verifyReceipt(forged, policy);
  assert.equal(verified.valid, false);
  assert.ok(verified.failures.includes("transaction_mismatch"));
});

test("the adapter will not sign for an account whose key it does not hold", async () => {
  await assert.rejects(
    () => submit(spl({ from: VENDOR })),
    (err: unknown) => err instanceof SolanaAdapterError && err.code === "signer_mismatch",
  );
});

test("an allowed transfer the encoder cannot build leaves a receipt and no signature", async () => {
  // The policy allowlists a program this adapter has no encoder for. The decision still
  // stands and is evidenced; the failure to build is recorded rather than thrown away.
  const result = await submit(spl({ programId: CUSTOM_PROGRAM }));
  assert.equal(result.decision.verdict, "allow");
  assert.equal(result.signedTransaction, undefined);
  assert.equal(result.receipt.body.transaction, undefined);
  assert.match(result.receipt.body.outcome?.error ?? "", /program/i);
  assert.equal(verifyReceipt(result.receipt, policy).valid, true);
});

test("a request maps back to the transfer it came from", () => {
  for (const transfer of [spl(), sol(), spl({ amount: 1n, decimals: 0 })]) {
    const request = toActionRequest(transfer, "agent-1");
    const back = transferFromRequest(request);
    assert.ok(back);
    assert.deepEqual(toActionRequest(back, "agent-1"), request);
  }
  assert.equal(transferFromRequest({ ...toActionRequest(sol(), "a"), params: {} }), null);
});

test("policy hash binding is unchanged by the new receipt field", async () => {
  const result = await submit(sol());
  assert.equal(result.receipt.body.policyHash, hashPolicy(policy));
});
