/**
 * Bring a deployed GENKAI program to life on a cluster: register the circuit, then encrypt a
 * sealed policy to the MXE, stage it, activate it, and write the public deployment manifest.
 *
 *   ANCHOR_PROVIDER_URL=<rpc> ANCHOR_WALLET=<authority keypair> \
 *     npx ts-node -T -P tsconfig.json scripts/devnet-setup.ts <seal.json> <cluster-offset> <manifest.json>
 *
 * <seal.json> comes from scripts/seal-for-chain.ts in the repository root and is secret. The
 * one-time x25519 key used to encrypt it is generated here and never written anywhere, so once
 * the ciphertext is on chain only the cluster can read it.
 *
 * Idempotent: an existing computation definition is reused, and a policy record that is
 * already active with the same commitment is left alone. A record with a different commitment
 * is an error - the record is immutable, so a new policy needs a new policy id.
 */

import * as anchor from "@anchor-lang/core";
import { PublicKey, Transaction } from "@solana/web3.js";
import {
  RescueCipher,
  deserializeLE,
  getArciumAccountBaseSeed,
  getArciumProgram,
  getArciumProgramId,
  getCompDefAccOffset,
  getLookupTableAddress,
  getMXEAccAddress,
  getMXEPublicKey,
  x25519,
} from "@arcium-hq/client";
import { randomBytes } from "crypto";
import * as fs from "fs";

const CHUNK = 24;
const FIELDS = 87;

interface Seal {
  circuitId: string;
  policyId: string;
  commitment: string;
  policyFields: string[];
}

async function main(): Promise<void> {
  const [sealPath, offsetArg, manifestPath] = process.argv.slice(2);
  if (!sealPath || !offsetArg || !manifestPath) throw new Error("usage: devnet-setup.ts <seal.json> <cluster-offset> <manifest.json>");
  const seal: Seal = JSON.parse(fs.readFileSync(sealPath, "utf8"));
  if (seal.policyFields.length !== FIELDS) throw new Error(`expected ${FIELDS} policy fields, got ${seal.policyFields.length}`);

  // Blockhashes at "processed" (Anchor's default) are often unknown to the public RPC node
  // that simulates the transaction; "confirmed" ones are not.
  const env = anchor.AnchorProvider.env();
  const provider = new anchor.AnchorProvider(env.connection, env.wallet, { commitment: "confirmed", preflightCommitment: "confirmed" });
  anchor.setProvider(provider);
  const idl = JSON.parse(fs.readFileSync("target/idl/genkai.json", "utf8"));
  const program = new anchor.Program(idl, provider);
  const authority = provider.wallet.publicKey;
  const log = (line: string) => process.stdout.write(`${line}\n`);
  log(`program ${program.programId.toBase58()}, authority ${authority.toBase58()}`);

  await ensureCompDef(provider, program, log);

  const policyId = Buffer.alloc(32);
  Buffer.from(seal.policyId).copy(policyId);
  const [policy] = PublicKey.findProgramAddressSync([Buffer.from("policy"), authority.toBuffer(), policyId], program.programId);
  const existing = await (program.account as any).policyRecord.fetchNullable(policy);
  if (existing) {
    const commitment = Buffer.from(existing.commitment).toString("hex");
    if (commitment !== seal.commitment) throw new Error(`policy record ${policy.toBase58()} already commits to ${commitment}; use a new policy id`);
    if (existing.status !== 1) throw new Error(`policy record ${policy.toBase58()} exists with status ${existing.status}; finish or replace it by hand`);
    log(`policy ${policy.toBase58()} already active`);
  } else {
    await stagePolicy(provider, program, policy, policyId, seal, log);
  }

  const manifest = {
    cluster: "devnet",
    rpc: provider.connection.rpcEndpoint,
    programId: program.programId.toBase58(),
    clusterOffset: Number(offsetArg),
    circuitId: seal.circuitId,
    policy: policy.toBase58(),
    policyId: seal.policyId,
    commitment: seal.commitment,
    authority: authority.toBase58(),
    note: "Public facts only. Pin programId, policy, commitment and circuitId to verify receipts.",
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  log(`wrote ${manifestPath}`);
}

async function ensureCompDef(provider: anchor.AnchorProvider, program: anchor.Program, log: (l: string) => void): Promise<void> {
  const offset = getCompDefAccOffset("evaluate_policy");
  const [compDef] = PublicKey.findProgramAddressSync(
    [getArciumAccountBaseSeed("ComputationDefinitionAccount"), program.programId.toBuffer(), offset],
    getArciumProgramId(),
  );
  if (await provider.connection.getAccountInfo(compDef)) {
    log(`computation definition ${compDef.toBase58()} exists`);
    return;
  }
  const mxeAccount = getMXEAccAddress(program.programId);
  const mxe = await getArciumProgram(provider).account.mxeAccount.fetch(mxeAccount);
  const sig = await send(provider, () =>
    program.methods
      .initEvaluatePolicyCompDef()
      .accounts({
        compDefAccount: compDef,
        payer: provider.wallet.publicKey,
        mxeAccount,
        addressLookupTable: getLookupTableAddress(program.programId, mxe.lutOffsetSlot),
      } as never)
      .transaction(),
  );
  log(`computation definition ${compDef.toBase58()} registered (off-chain circuit): ${sig}`);
}

async function stagePolicy(
  provider: anchor.AnchorProvider,
  program: anchor.Program,
  policy: PublicKey,
  policyId: Buffer,
  seal: Seal,
  log: (l: string) => void,
): Promise<void> {
  const mxePublicKey = await mxeKey(provider, program.programId, log);
  const secret = x25519.utils.randomSecretKey();
  const cipher = new RescueCipher(x25519.getSharedSecret(secret, mxePublicKey));
  const nonce = randomBytes(16);
  const ciphertexts = cipher.encrypt(seal.policyFields.map((f) => BigInt(f)), nonce);
  const accounts = { authority: provider.wallet.publicKey, policy };

  await send(provider, () =>
    program.methods
      .createPolicy(Array.from(policyId), Array.from(Buffer.from(seal.commitment, "hex")), Array.from(x25519.getPublicKey(secret)), new anchor.BN(deserializeLE(nonce).toString()))
      .accountsPartial(accounts)
      .transaction(),
  );
  log(`policy record ${policy.toBase58()} created`);
  for (let start = 0; start < ciphertexts.length; start += CHUNK) {
    await send(provider, () =>
      program.methods
        .stageCiphertexts(start, ciphertexts.slice(start, start + CHUNK).map((c) => Array.from(c)))
        .accountsPartial(accounts)
        .transaction(),
    );
    log(`  staged fields ${start}..${Math.min(start + CHUNK, ciphertexts.length) - 1}`);
  }
  await send(provider, () => program.methods.activatePolicy().accountsPartial(accounts).transaction());
  log("policy active");
}

/** The MXE's x25519 key appears once the cluster finishes key generation after deployment. */
async function mxeKey(provider: anchor.AnchorProvider, programId: PublicKey, log: (l: string) => void): Promise<Uint8Array> {
  for (let attempt = 1; attempt <= 60; attempt++) {
    try {
      const key = await getMXEPublicKey(provider, programId);
      if (key) return key;
    } catch {
      // not ready yet
    }
    if (attempt % 6 === 0) log("  waiting for MXE key generation...");
    await new Promise((r) => setTimeout(r, 5_000));
  }
  throw new Error("MXE public key unavailable after 5 minutes");
}

/**
 * Sign and send one transaction, confirming against the same blockhash it was built on.
 *
 * Not Anchor's .rpc(): on the public devnet endpoint its preflight repeatedly failed with
 * "Blockhash not found" while the identical transaction, built and simulated by hand, passed.
 *
 * Retries cover only the two cases where the transaction provably did not execute: preflight
 * rejecting the blockhash (nothing was sent) and expiry (it can no longer land). Anything else
 * is the program's answer and is thrown at once.
 */
async function send(provider: anchor.AnchorProvider, build: () => Promise<Transaction>, attempts = 5): Promise<string> {
  for (let attempt = 1; ; attempt++) {
    try {
      const tx = await build();
      const { blockhash, lastValidBlockHeight } = await provider.connection.getLatestBlockhash("confirmed");
      tx.recentBlockhash = blockhash;
      tx.feePayer = provider.wallet.publicKey;
      const signed = await provider.wallet.signTransaction(tx);
      const signature = await provider.connection.sendRawTransaction(signed.serialize(), { preflightCommitment: "confirmed" });
      const result = await provider.connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
      if (result.value.err) throw new Error(`${signature} failed on chain: ${JSON.stringify(result.value.err)}`);
      return signature;
    } catch (err) {
      if (attempt >= attempts || !/Blockhash not found|block height exceeded/i.test(String(err))) throw err;
      await new Promise((r) => setTimeout(r, 2_000 * attempt));
    }
  }
}

main().catch((err) => {
  process.stderr.write(`devnet-setup: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
