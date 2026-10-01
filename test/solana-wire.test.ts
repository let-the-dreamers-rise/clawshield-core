/**
 * The Solana wire format.
 *
 * Every vector in test/fixtures/solana-vectors.json was produced by the reference
 * implementation (@solana/web3.js 1.x and @solana/spl-token 0.4), run once outside this repo.
 * The encoder here has no dependencies, so byte-for-byte agreement with the reference is the
 * only evidence that a transaction it signs is the transaction the cluster will execute.
 */

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { Base58Error, decodeBase58, decodePubkey, encodeBase58 } from "../src/solana/base58.ts";
import { isOnCurve } from "../src/solana/curve.ts";
import { associatedTokenAddress, createProgramAddress, findProgramAddress } from "../src/solana/pda.ts";
import { keypairFromSeed, keypairFromSolanaSecretKey, solanaAddress } from "../src/solana/keys.ts";
import {
  memo,
  setComputeUnitLimit,
  setComputeUnitPrice,
  systemTransfer,
  transferChecked,
} from "../src/solana/instructions.ts";
import { compileLegacyMessage, MessageError } from "../src/solana/message.ts";
import { signLegacyTransaction } from "../src/solana/transaction.ts";
import { TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID, USDC_MAINNET_MINT } from "../src/solana/types.ts";
import { generateKeypair } from "../src/receipt/sign.ts";

interface TxVector {
  readonly message: string;
  readonly tx: string;
  readonly signature: string;
  readonly src?: string;
  readonly dst?: string;
}

const V = JSON.parse(readFileSync(new URL("./fixtures/solana-vectors.json", import.meta.url), "utf8")) as {
  seedHex: string;
  payer: string;
  blockhash: string;
  sol: TxVector;
  solPlain: TxVector;
  spl: TxVector;
  spl22: TxVector;
  pda: { address: string; bump: number; seedHex: string };
  curve: [string, boolean][];
  b58: [string, string][];
};

const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const seed = Buffer.from(V.seedHex, "hex");
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");

test("base58 round-trips the reference vectors", () => {
  for (const [hex, text] of V.b58) {
    assert.equal(encodeBase58(Buffer.from(hex, "hex")), text, hex);
    assert.equal(Buffer.from(decodeBase58(text)).toString("hex"), hex, text);
  }
});

test("base58 rejects characters outside the alphabet instead of skipping them", () => {
  for (const bad of ["0", "O", "I", "l", "abc+", " 1"]) {
    assert.throws(() => decodeBase58(bad), Base58Error, bad);
  }
});

test("a pubkey must decode to exactly 32 bytes", () => {
  assert.equal(decodePubkey(V.payer).length, 32);
  assert.throws(() => decodePubkey("JxF12TrwUP45BMd"), Base58Error);
  // 33 bytes: a valid base58 string that would silently truncate if length were not checked.
  assert.throws(() => decodePubkey(encodeBase58(new Uint8Array(33).fill(7))), Base58Error);
});

test("the curve check agrees with the reference on every vector", () => {
  for (const [hex, expected] of V.curve) {
    assert.equal(isOnCurve(Buffer.from(hex, "hex")), expected, hex);
  }
});

test("every key node:crypto generates is on the curve", () => {
  for (let i = 0; i < 32; i++) {
    const address = solanaAddress(generateKeypair().publicKey);
    assert.equal(isOnCurve(decodePubkey(address)), true, address);
  }
});

test("program addresses match the reference, including the bump", () => {
  const programId = "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS";
  const seeds = [Buffer.from("policy"), Buffer.from(V.pda.seedHex, "hex")];
  const found = findProgramAddress(seeds, programId);
  assert.deepEqual(found, { address: V.pda.address, bump: V.pda.bump });
  assert.equal(createProgramAddress([...seeds, Uint8Array.of(found.bump)], programId), V.pda.address);
});

test("a seed longer than 32 bytes is refused", () => {
  assert.throws(() => findProgramAddress([new Uint8Array(33)], TOKEN_PROGRAM_ID), /seed/i);
});

test("associated token addresses match the reference for both token programs", () => {
  assert.equal(associatedTokenAddress(V.payer, USDC_MAINNET_MINT, TOKEN_PROGRAM_ID), V.spl.src);
  assert.equal(associatedTokenAddress(VENDOR, USDC_MAINNET_MINT, TOKEN_PROGRAM_ID), V.spl.dst);
  assert.equal(associatedTokenAddress(V.payer, USDC_MAINNET_MINT, TOKEN_2022_PROGRAM_ID), V.spl22.src);
  assert.equal(associatedTokenAddress(VENDOR, USDC_MAINNET_MINT, TOKEN_2022_PROGRAM_ID), V.spl22.dst);
});

test("a keypair from a seed has the reference address", () => {
  const keys = keypairFromSeed(seed);
  assert.equal(solanaAddress(keys.publicKey), V.payer);
});

test("a 64-byte Solana secret key is accepted only when its halves agree", () => {
  const good = Buffer.concat([seed, decodePubkey(V.payer)]);
  assert.equal(solanaAddress(keypairFromSolanaSecretKey(good).publicKey), V.payer);

  // A secret key file whose public half names a different account is a corrupted or forged
  // file. Signing with it would produce transactions for an account the operator did not name.
  const mismatched = Buffer.concat([seed, decodePubkey(VENDOR)]);
  assert.throws(() => keypairFromSolanaSecretKey(mismatched), /does not match/);
  assert.throws(() => keypairFromSolanaSecretKey(new Uint8Array(32)), /64 bytes/);
});

test("a SOL transfer with compute budget and memo is byte-identical to the reference", () => {
  const keys = keypairFromSeed(seed);
  const message = compileLegacyMessage({
    payer: V.payer,
    recentBlockhash: V.blockhash,
    instructions: [
      setComputeUnitLimit(200_000),
      setComputeUnitPrice(1_000n),
      systemTransfer(V.payer, VENDOR, 1_000_000n),
      memo("genkai:abc123"),
    ],
  });
  assert.equal(b64(message), V.sol.message);

  const signed = signLegacyTransaction(message, keys);
  assert.equal(b64(signed.wire), V.sol.tx);
  assert.equal(signed.signature, V.sol.signature);
});

test("a bare SOL transfer is byte-identical to the reference", () => {
  const message = compileLegacyMessage({
    payer: V.payer,
    recentBlockhash: V.blockhash,
    instructions: [systemTransfer(V.payer, VENDOR, 5n)],
  });
  assert.equal(b64(message), V.solPlain.message);
  assert.equal(signLegacyTransaction(message, keypairFromSeed(seed)).signature, V.solPlain.signature);
});

test("an SPL TransferChecked is byte-identical to the reference for both token programs", () => {
  const keys = keypairFromSeed(seed);
  for (const [programId, vector, memoText] of [
    [TOKEN_PROGRAM_ID, V.spl, "genkai:def456"],
    [TOKEN_2022_PROGRAM_ID, V.spl22, undefined],
  ] as const) {
    const instructions = [
      transferChecked({
        source: associatedTokenAddress(V.payer, USDC_MAINNET_MINT, programId),
        mint: USDC_MAINNET_MINT,
        destination: associatedTokenAddress(VENDOR, USDC_MAINNET_MINT, programId),
        owner: V.payer,
        amount: 10_000_000n,
        decimals: 6,
        programId,
      }),
      ...(memoText ? [memo(memoText)] : []),
    ];
    const message = compileLegacyMessage({ payer: V.payer, recentBlockhash: V.blockhash, instructions });
    assert.equal(b64(message), vector.message, programId);
    assert.equal(signLegacyTransaction(message, keys).signature, vector.signature, programId);
  }
});

test("amounts outside u64 are refused rather than wrapped", () => {
  // A wrapped amount would sign a transfer of a different size than the one the policy saw.
  assert.throws(() => systemTransfer(V.payer, VENDOR, -1n), RangeError);
  assert.throws(() => systemTransfer(V.payer, VENDOR, 1n << 64n), RangeError);
  assert.doesNotThrow(() => systemTransfer(V.payer, VENDOR, (1n << 64n) - 1n));
});

test("malformed messages are refused", () => {
  assert.throws(
    () => compileLegacyMessage({ payer: V.payer, recentBlockhash: "not-base58-0OIl", instructions: [] }),
    Base58Error,
  );
  // Larger than the 1232-byte packet limit: the cluster would drop it, so it is never signed.
  assert.throws(
    () =>
      compileLegacyMessage({
        payer: V.payer,
        recentBlockhash: V.blockhash,
        instructions: new Array(300).fill(memo("x")),
      }),
    MessageError,
  );
});

test("signing refuses a key that is not the fee payer", () => {
  const message = compileLegacyMessage({
    payer: V.payer,
    recentBlockhash: V.blockhash,
    instructions: [systemTransfer(V.payer, VENDOR, 5n)],
  });
  // The cluster would reject it anyway, but a signature from the wrong key is still a
  // signature over the operator's intent, and it must not leave this process.
  assert.throws(() => signLegacyTransaction(message, generateKeypair()), /fee payer/);
});
