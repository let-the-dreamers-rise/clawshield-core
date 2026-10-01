/**
 * GENKAI on a live Arcium localnet.
 *
 * Encrypts the demo policy under a one-time x25519 key shared with the MXE, stages and
 * activates it on chain, then runs every fixture request through the real MPC cluster. Each
 * DecisionRecord the callback writes must carry exactly the verdict and rule mask the
 * TypeScript circuit model predicts - the model that test/circuit.test.ts holds to the engine.
 *
 * Also checks the program's guard rails: chunks out of order, evaluation before activation,
 * evaluation by someone other than the authority, and staging after activation.
 *
 * Regenerate the fixtures with: node --experimental-strip-types scripts/arcium-fixtures.ts
 */

import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { PublicKey, Keypair } from "@solana/web3.js";
import { Genkai } from "../target/types/genkai";
import { randomBytes } from "crypto";
import {
  awaitComputationFinalization,
  getArciumEnv,
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgramId,
  getArciumProgram,
  uploadCircuit,
  RescueCipher,
  deserializeLE,
  getMXEPublicKey,
  getMXEAccAddress,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  getComputationAccAddress,
  getClusterAccAddress,
  getLookupTableAddress,
  x25519,
} from "@arcium-hq/client";
import * as fs from "fs";
import * as os from "os";
import { expect } from "chai";

interface Fixture {
  circuitId: string;
  policyId: string;
  commitment: string;
  policyFields: string[];
  requests: {
    intent: string;
    fields: Record<string, string | number | boolean>;
    expected: { verdict: number; mask: number; verdictName: string; rules: string[] };
  }[];
}

const FIXTURE: Fixture = JSON.parse(fs.readFileSync("tests/fixtures.json", "utf8"));
const CHUNK = 24;

const bn = (x: string | number) => new anchor.BN(x.toString());
const u128Fields = new Set(["toolId", "counterpartyId", "clusterId", "programId", "mintId"]);
const u64Fields = new Set(["amountMagnitude", "spentInWindow", "callsInWindow", "drawdownFromPeak"]);

function requestArgs(fields: Fixture["requests"][number]["fields"]) {
  return Object.fromEntries(
    Object.entries(fields).map(([k, v]) => [k, u128Fields.has(k) || u64Fields.has(k) ? bn(v as string) : v]),
  );
}

describe("GENKAI", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.Genkai as Program<Genkai>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const arciumProgram = getArciumProgram(provider);
  const arciumEnv = getArciumEnv();
  const clusterAccount = getClusterAccAddress(arciumEnv.arciumClusterOffset);
  const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);

  const policyIdBytes = Buffer.alloc(32);
  Buffer.from(FIXTURE.policyId).copy(policyIdBytes);
  const [policyPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("policy"), owner.publicKey.toBuffer(), policyIdBytes],
    program.programId,
  );

  const evaluateAccounts = (computationOffset: anchor.BN) => ({
    computationAccount: getComputationAccAddress(arciumEnv.arciumClusterOffset, computationOffset),
    clusterAccount,
    mxeAccount: getMXEAccAddress(program.programId),
    mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
    executingPool: getExecutingPoolAccAddress(arciumEnv.arciumClusterOffset),
    compDefAccount: getCompDefAccAddress(
      program.programId,
      Buffer.from(getCompDefAccOffset("evaluate_policy")).readUInt32LE(),
    ),
    policy: policyPda,
  });

  const decisionPda = (computationOffset: anchor.BN) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("decision"), policyPda.toBuffer(), computationOffset.toArrayLike(Buffer, "le", 8)],
      program.programId,
    )[0];

  before(async () => {
    await initEvaluatePolicyCompDef(program, owner);
  });

  it("stages an encrypted policy in order and refuses evaluation before activation", async () => {
    const mxePublicKey = await getMXEPublicKeyWithRetry(provider, program.programId);
    // One-time key: used to encrypt this upload, then dropped. Only the cluster can decrypt
    // the ciphertext once it is on chain.
    const secret = x25519.utils.randomSecretKey();
    const cipher = new RescueCipher(x25519.getSharedSecret(secret, mxePublicKey));
    const nonce = randomBytes(16);
    const ciphertexts = cipher.encrypt(FIXTURE.policyFields.map((f) => BigInt(f)), nonce);
    expect(ciphertexts.length).to.equal(FIXTURE.policyFields.length);

    await program.methods
      .createPolicy(
        Array.from(policyIdBytes),
        Array.from(Buffer.from(FIXTURE.commitment, "hex")),
        Array.from(x25519.getPublicKey(secret)),
        bn(deserializeLE(nonce).toString()),
      )
      .accountsPartial({ authority: owner.publicKey, policy: policyPda })
      .signers([owner])
      .rpc({ commitment: "confirmed" });

    // Out of order is refused.
    await expectError(
      program.methods.stageCiphertexts(CHUNK, ciphertexts.slice(CHUNK, 2 * CHUNK).map((c) => Array.from(c)))
        .accountsPartial({ authority: owner.publicKey, policy: policyPda }).signers([owner]).rpc(),
      "OutOfOrderChunk",
    );

    for (let start = 0; start < ciphertexts.length; start += CHUNK) {
      await program.methods
        .stageCiphertexts(start, ciphertexts.slice(start, start + CHUNK).map((c) => Array.from(c)))
        .accountsPartial({ authority: owner.publicKey, policy: policyPda })
        .signers([owner])
        .rpc({ commitment: "confirmed" });
    }

    const offset = new anchor.BN(randomBytes(8), "hex");
    await expectError(
      program.methods.evaluate(offset, requestArgs(FIXTURE.requests[0].fields) as never)
        .accountsPartial(evaluateAccounts(offset)).rpc({ skipPreflight: false }),
      "PolicyNotActive",
    );

    await program.methods.activatePolicy()
      .accountsPartial({ authority: owner.publicKey, policy: policyPda }).signers([owner]).rpc({ commitment: "confirmed" });

    // Immutable once active.
    await expectError(
      program.methods.stageCiphertexts(0, [Array.from(ciphertexts[0])])
        .accountsPartial({ authority: owner.publicKey, policy: policyPda }).signers([owner]).rpc(),
      "PolicyNotStaging",
    );

    const record = await program.account.policyRecord.fetch(policyPda);
    expect(Buffer.from(record.commitment).toString("hex")).to.equal(FIXTURE.commitment);
    expect(record.status).to.equal(1);
  });

  for (const [i, req] of FIXTURE.requests.entries()) {
    it(`decides on ciphertext: ${req.intent} -> ${req.expected.verdictName}`, async () => {
      const offset = new anchor.BN(randomBytes(8), "hex");
      await program.methods
        .evaluate(offset, requestArgs(req.fields) as never)
        .accountsPartial({ authority: owner.publicKey, ...evaluateAccounts(offset) })
        .signers([owner])
        .rpc({ skipPreflight: true, commitment: "confirmed" });

      await awaitComputationFinalization(provider, offset, program.programId, "confirmed");

      const decision = await program.account.decisionRecord.fetch(decisionPda(offset));
      expect(decision.status, `request ${i} not decided`).to.equal(1);
      expect(decision.verdict, req.intent).to.equal(req.expected.verdict);
      expect(decision.mask, req.intent).to.equal(req.expected.mask);
      expect(decision.policy.toBase58()).to.equal(policyPda.toBase58());
    });
  }

  it("refuses evaluation by anyone but the authority, so the policy cannot be used as an oracle", async () => {
    const stranger = Keypair.generate();
    const sig = await provider.connection.requestAirdrop(stranger.publicKey, 1_000_000_000);
    await provider.connection.confirmTransaction(sig, "confirmed");
    const offset = new anchor.BN(randomBytes(8), "hex");
    await expectError(
      program.methods.evaluate(offset, requestArgs(FIXTURE.requests[0].fields) as never)
        .accountsPartial({ authority: stranger.publicKey, ...evaluateAccounts(offset) })
        .signers([stranger]).rpc(),
      "NotAuthority",
    );
  });

  async function initEvaluatePolicyCompDef(program: Program<Genkai>, owner: anchor.web3.Keypair): Promise<void> {
    const offset = getCompDefAccOffset("evaluate_policy");
    const compDefPDA = PublicKey.findProgramAddressSync(
      [getArciumAccountBaseSeed("ComputationDefinitionAccount"), program.programId.toBuffer(), offset],
      getArciumProgramId(),
    )[0];
    const mxeAccount = getMXEAccAddress(program.programId);
    const mxeAcc = await arciumProgram.account.mxeAccount.fetch(mxeAccount);

    await program.methods
      .initEvaluatePolicyCompDef()
      .accounts({
        compDefAccount: compDefPDA,
        payer: owner.publicKey,
        mxeAccount,
        addressLookupTable: getLookupTableAddress(program.programId, mxeAcc.lutOffsetSlot),
      })
      .signers([owner])
      .rpc({ commitment: "confirmed" });

    await uploadCircuit(provider, "evaluate_policy", program.programId, fs.readFileSync("build/evaluate_policy.arcis"), true, 500, {
      skipPreflight: true,
      preflightCommitment: "confirmed",
      commitment: "confirmed",
    });
  }
});

async function expectError(p: Promise<unknown>, code: string): Promise<void> {
  try {
    await p;
  } catch (err) {
    expect(String(err)).to.contain(code);
    return;
  }
  throw new Error(`expected ${code}, but the transaction succeeded`);
}

async function getMXEPublicKeyWithRetry(provider: anchor.AnchorProvider, programId: PublicKey, attempts = 20): Promise<Uint8Array> {
  for (let i = 1; i <= attempts; i++) {
    try {
      const key = await getMXEPublicKey(provider, programId);
      if (key) return key;
    } catch {
      // the MXE may not be ready yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`MXE public key unavailable after ${attempts} attempts`);
}

function readKpJson(path: string): anchor.web3.Keypair {
  return anchor.web3.Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(path).toString())));
}
