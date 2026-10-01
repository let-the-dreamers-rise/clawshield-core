/**
 * A GENKAI deployment manifest: the public facts a live client and a verifier need, written by
 * arcium/genkai/scripts/devnet-setup.ts and committed under arcium/genkai/deployments/.
 *
 * Nothing secret belongs here. The salt behind the commitment and the authority's key live
 * elsewhere; the manifest only names the authority's address so a mismatched key is caught
 * before a transaction is sent.
 */

import { decodePubkey } from "../solana/base58.ts";
import { SchemaError, at, hex64, int, record, str, type Obj } from "../io/validate.ts";
import type { OnChainTrust } from "../receipt/verify-sealed.ts";

export interface Deployment {
  readonly cluster: string;
  readonly rpc: string;
  readonly programId: string;
  readonly clusterOffset: number;
  readonly circuitId: string;
  readonly policy: string;
  readonly policyId: string;
  readonly commitment: string;
  readonly authority: string;
}

function address(o: Obj, key: string, path: string): string {
  const s = str(o[key], at(path, key), { nonEmpty: true, max: 44 });
  try {
    decodePubkey(s);
  } catch {
    throw new SchemaError(at(path, key), "expected a base58 public key");
  }
  return s;
}

export function parseDeployment(v: unknown, path = ""): Deployment {
  const o = record(v, path, ["cluster", "rpc", "programId", "clusterOffset", "circuitId", "policy", "policyId", "commitment", "authority"], ["note"]);
  return {
    cluster: str(o["cluster"], at(path, "cluster"), { nonEmpty: true, max: 32 }),
    rpc: str(o["rpc"], at(path, "rpc"), { nonEmpty: true, max: 512 }),
    programId: address(o, "programId", path),
    clusterOffset: int(o["clusterOffset"], at(path, "clusterOffset"), 0),
    circuitId: str(o["circuitId"], at(path, "circuitId"), { nonEmpty: true, max: 128 }),
    policy: address(o, "policy", path),
    policyId: str(o["policyId"], at(path, "policyId"), { nonEmpty: true, max: 32 }),
    commitment: hex64(o["commitment"], at(path, "commitment")),
    authority: address(o, "authority", path),
  };
}

/** What a verifier pins for receipts issued against this deployment. */
export function trustOf(d: Deployment): OnChainTrust {
  return { commitment: d.commitment, circuitId: d.circuitId, programId: d.programId, policy: d.policy };
}
