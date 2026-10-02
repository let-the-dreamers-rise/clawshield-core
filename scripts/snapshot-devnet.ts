/**
 * Refresh test/fixtures/devnet-accounts.json: the public devnet state the example receipts point
 * at, so the verifier's tests run offline against the real runs.
 *
 *   node --experimental-strip-types --no-warnings scripts/snapshot-devnet.ts [rpc-url]
 *
 * It reads the program and PolicyRecord the deployment manifest names, every DecisionRecord the
 * example receipts cite, and the status of every transaction they bind. All of it is public chain
 * state; nothing here holds or reads a key.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fromJson } from "../src/io/json.ts";
import { parseSignedReceipt } from "../src/io/schema.ts";
import { createRpcClient } from "../src/solana/rpc.ts";
import { ROOT } from "./web-bundle.ts";

const DEFAULT_RPC = "https://api.devnet.solana.com";
const MANIFEST = "arcium/genkai/deployments/devnet.json";
export const RECEIPT_FILES = ["examples/devnet/sealed-receipts.json", "examples/devnet/gateway/receipts.json"] as const;
const OUT = "test/fixtures/devnet-accounts.json";

const read = (path: string): unknown => fromJson(readFileSync(join(ROOT, path), "utf8"));

async function snapshot(endpoint: string): Promise<void> {
  const rpc = createRpcClient({ endpoint });
  const manifest = read(MANIFEST) as { readonly programId: string; readonly policy: string };
  const receipts = RECEIPT_FILES.flatMap((file) =>
    (read(file) as readonly unknown[]).map((receipt, i) => parseSignedReceipt(receipt, `${file}[${i}]`)),
  );

  const decisions = receipts.flatMap((r) => (r.body.attestation?.kind === "onchain" ? [r.body.attestation.decision] : []));
  const accounts = Object.fromEntries(
    await Promise.all(
      [manifest.programId, manifest.policy, ...decisions].map(async (address) => {
        const info = await rpc.getAccountInfo(address);
        if (!info) throw new Error(`${address} does not exist on ${endpoint}`);
        const data = Buffer.from(info.data).toString("base64");
        return [address, { owner: info.owner, lamports: Number(info.lamports), executable: info.executable, data }] as const;
      }),
    ),
  );

  // Only a finalized, successful transaction is recorded as landed; it can no longer change.
  const signatures = receipts.flatMap((r) => (r.body.transaction ? [r.body.transaction.signature] : []));
  const statuses = signatures.length > 0 ? await rpc.getSignatureStatuses(signatures) : [];
  const landed = Object.fromEntries(
    signatures.flatMap((signature, i) => {
      const status = statuses[i];
      return status && status.err === null && status.confirmationStatus === "finalized" ? [[signature, status.slot] as const] : [];
    }),
  );

  const note = "Snapshot of the devnet accounts the receipts in examples/devnet point at, and which of their transactions landed, for offline tests. Public chain state. Refresh with scripts/snapshot-devnet.ts.";
  writeFileSync(join(ROOT, OUT), `${JSON.stringify({ note, rpc: endpoint, accounts, landed }, null, 2)}\n`);
  process.stdout.write(`Wrote ${OUT}: ${Object.keys(accounts).length} accounts, ${Object.keys(landed).length} of ${signatures.length} transactions landed\n`);
}

await snapshot(process.argv[2] ?? DEFAULT_RPC);
