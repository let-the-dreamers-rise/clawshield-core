/**
 * Gateway configuration from the environment, validated before anything starts.
 *
 * Every problem is collected and reported at once, so a misconfigured deployment fails on boot
 * with a complete list rather than one error per restart. Secrets arrive as files (the Docker
 * and Kubernetes convention) or, where a platform only offers environment variables, as the
 * solana-keygen JSON array itself. They are never logged.
 *
 *   GENKAI_DB_PATH            SQLite file                          ./data/genkai.db
 *   GENKAI_VAULT_KEY_FILE     vault keypair (solana-keygen JSON)   required, or GENKAI_VAULT_KEY
 *   GENKAI_POLICY_FILE        plaintext policy                     one of these two modes
 *   GENKAI_DEPLOYMENT_FILE    sealed: deployment manifest          with GENKAI_AUTHORITY_KEY_FILE
 *   GENKAI_RPC_URL            Solana RPC                           required when sealed or broadcasting
 *   GENKAI_CLUSTER            devnet | mainnet-beta | testnet | localnet      devnet
 *   GENKAI_EXECUTION          sign | broadcast                     sign
 *   GENKAI_WINDOW_SECONDS     spend window; sealed mode needs it   policy.windowSeconds
 *   GENKAI_PUBLIC_RECEIPTS    true | false                         true
 *   GENKAI_TRUST_PROXY        true | false                         false
 *   PORT, HOST                listen address                       8788, 127.0.0.1
 */

import type { SolanaCluster } from "../solana/types.ts";
import type { ExecutionMode } from "./service.ts";

export type Env = Readonly<Record<string, string | undefined>>;

export class ConfigError extends Error {
  readonly problems: readonly string[];
  constructor(problems: readonly string[]) {
    super(`Invalid gateway configuration:\n  - ${problems.join("\n  - ")}`);
    this.name = "ConfigError";
    this.problems = problems;
  }
}

/** A secret given either as a file path or inline. Inline wins only when no file is named. */
export type SecretSource = { readonly file: string } | { readonly inline: string };

export type PolicyMode =
  | { readonly kind: "plaintext"; readonly policyFile: string }
  | { readonly kind: "sealed"; readonly deploymentFile: string; readonly authorityKey: SecretSource };

export interface GatewaySettings {
  readonly dbPath: string;
  readonly vaultKey: SecretSource;
  readonly mode: PolicyMode;
  readonly rpcUrl?: string;
  readonly cluster: SolanaCluster;
  readonly execution: ExecutionMode;
  readonly windowSeconds?: number;
  readonly publicReceipts: boolean;
  readonly trustProxy: boolean;
  readonly port: number;
  readonly host: string;
}

const CLUSTERS: readonly SolanaCluster[] = ["devnet", "mainnet-beta", "testnet", "localnet"];

function flag(env: Env, name: string, fallback: boolean, problems: string[]): boolean {
  const v = env[name];
  if (v === undefined || v === "") return fallback;
  if (v === "true" || v === "1") return true;
  if (v === "false" || v === "0") return false;
  problems.push(`${name} must be true or false`);
  return fallback;
}

function secret(env: Env, base: string): SecretSource | undefined {
  const file = env[`${base}_FILE`];
  if (file) return { file };
  const inline = env[base];
  return inline ? { inline } : undefined;
}

function integer(env: Env, name: string, min: number, max: number, problems: string[]): number | undefined {
  const v = env[name];
  if (v === undefined || v === "") return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) {
    problems.push(`${name} must be an integer from ${min} to ${max}`);
    return undefined;
  }
  return n;
}

export function parseGatewayEnv(env: Env): GatewaySettings {
  const problems: string[] = [];

  const vaultKey = secret(env, "GENKAI_VAULT_KEY");
  if (!vaultKey) problems.push("GENKAI_VAULT_KEY_FILE (or GENKAI_VAULT_KEY) is required: the vault's solana-keygen keypair");

  const policyFile = env["GENKAI_POLICY_FILE"];
  const deploymentFile = env["GENKAI_DEPLOYMENT_FILE"];
  const authorityKey = secret(env, "GENKAI_AUTHORITY_KEY");
  let mode: PolicyMode | undefined;
  if (policyFile && deploymentFile) problems.push("Set GENKAI_POLICY_FILE (plaintext) or GENKAI_DEPLOYMENT_FILE (sealed), not both");
  else if (policyFile) mode = { kind: "plaintext", policyFile };
  else if (deploymentFile) {
    if (!authorityKey) problems.push("Sealed mode needs GENKAI_AUTHORITY_KEY_FILE: the policy authority evaluates on chain");
    else mode = { kind: "sealed", deploymentFile, authorityKey };
  } else problems.push("Set GENKAI_POLICY_FILE (plaintext) or GENKAI_DEPLOYMENT_FILE (sealed)");

  const rpcUrl = env["GENKAI_RPC_URL"] || undefined;
  if (rpcUrl !== undefined && !/^https?:\/\//.test(rpcUrl)) problems.push("GENKAI_RPC_URL must be an http(s) URL");

  const cluster = (env["GENKAI_CLUSTER"] || "devnet") as SolanaCluster;
  if (!CLUSTERS.includes(cluster)) problems.push(`GENKAI_CLUSTER must be one of ${CLUSTERS.join(", ")}`);

  const execution = (env["GENKAI_EXECUTION"] || "sign") as ExecutionMode;
  if (execution !== "sign" && execution !== "broadcast") problems.push("GENKAI_EXECUTION must be sign or broadcast");
  if (execution === "broadcast" && !rpcUrl) problems.push("GENKAI_EXECUTION=broadcast needs GENKAI_RPC_URL");
  if (deploymentFile && !rpcUrl) problems.push("Sealed mode needs GENKAI_RPC_URL to reach the GENKAI program");

  const windowSeconds = integer(env, "GENKAI_WINDOW_SECONDS", 1, 366 * 86_400, problems);
  const port = integer(env, "PORT", 0, 65_535, problems) ?? 8788;
  const publicReceipts = flag(env, "GENKAI_PUBLIC_RECEIPTS", true, problems);
  const trustProxy = flag(env, "GENKAI_TRUST_PROXY", false, problems);

  if (problems.length > 0 || !vaultKey || !mode) throw new ConfigError(problems);
  return {
    dbPath: env["GENKAI_DB_PATH"] || "./data/genkai.db",
    vaultKey,
    mode,
    ...(rpcUrl === undefined ? {} : { rpcUrl }),
    cluster,
    execution,
    ...(windowSeconds === undefined ? {} : { windowSeconds }),
    publicReceipts,
    trustProxy,
    port,
    host: env["HOST"] || "127.0.0.1",
  };
}
