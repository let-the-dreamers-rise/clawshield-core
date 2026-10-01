/**
 * Prepare a policy for upload to the GENKAI program: encode it to the circuit's 87 fields and
 * commit to it under a fresh salt.
 *
 *   node --experimental-strip-types scripts/seal-for-chain.ts <policy.json | --demo> <out.json>
 *
 * The output is SECRET - it holds the plaintext policy fields and the salt - and is written
 * exclusively with owner-only permissions. arcium/genkai/scripts/devnet-setup.ts reads it,
 * encrypts the fields to the MXE and stages them; only the commitment is ever published. Keep
 * it if you may later need to open the commitment to an auditor.
 */

import { randomBytes } from "node:crypto";
import { DEMO_POLICY } from "../src/cli/demo.ts";
import { readJsonFile, writeSecretFile } from "../src/cli/files.ts";
import { parsePolicy } from "../src/io/schema.ts";
import { encodePolicy, flattenPolicy, POLICY_FIELD_COUNT } from "../src/mxe/encoding.ts";
import { sealedCommitment } from "../src/policy/sealed.ts";

/** The circuit generation these fields are laid out for; see arcium/genkai/encrypted-ixs. */
const CIRCUIT_ID = "genkai.policy.v2";

const [source, out] = process.argv.slice(2);
if (source === undefined || out === undefined) {
  process.stderr.write("usage: seal-for-chain.ts <policy.json | --demo> <out.json>\n");
  process.exit(2);
}

const policy = source === "--demo" ? DEMO_POLICY : parsePolicy(readJsonFile(source), "policy");
if (Buffer.byteLength(policy.policyId) > 32) {
  process.stderr.write(`policyId must be at most 32 bytes; it seeds the PolicyRecord address\n`);
  process.exit(2);
}
const fields = flattenPolicy(encodePolicy(policy));
if (fields.length !== POLICY_FIELD_COUNT) throw new Error("policy layout drifted");

const salt = randomBytes(32).toString("hex");
const commitment = sealedCommitment(policy, salt);
writeSecretFile(
  out,
  `${JSON.stringify({ circuitId: CIRCUIT_ID, policyId: policy.policyId, commitment, salt, policyFields: fields.map(String) }, null, 2)}\n`,
);
process.stdout.write(`Wrote ${out} (SECRET). Commitment to publish: ${commitment}\n`);
