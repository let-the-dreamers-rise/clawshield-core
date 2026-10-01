/**
 * Assemble a gateway from validated settings: load the keys and the policy or deployment,
 * build the provider, open the database, and listen. Returns a handle that shuts it all down.
 *
 * Startup fails before the port opens if anything is wrong - an unreadable key, a policy the
 * circuit cannot encode, a deployment manifest that does not parse - because a gateway that is
 * up but cannot decide is worse than one that is visibly down.
 */

import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fromJson } from "../io/json.ts";
import { parsePolicy } from "../io/schema.ts";
import { createArciumMxeClient } from "../mxe/arcium.ts";
import { createPlaintextPolicyProvider, createSealedPolicyProvider, type PolicyProvider } from "../policy/sealed.ts";
import { hashPolicy, type Keypair } from "../receipt/sign.ts";
import { keypairFromSolanaSecretKey, solanaAddress } from "../solana/keys.ts";
import { createRpcClient, type RpcClient } from "../solana/rpc.ts";
import { parseDeployment } from "../cli/deployment.ts";
import { openDatabase } from "./db.ts";
import { createStore } from "./store.ts";
import { createGatewayService } from "./service.ts";
import { createGatewayServer, type TrustInfo } from "./server.ts";
import { ConfigError, type GatewaySettings, type SecretSource } from "./config.ts";

export interface RunningGateway {
  readonly server: Server;
  readonly url: string;
  readonly vault: string;
  readonly mode: "plaintext" | "sealed";
  close(): Promise<void>;
}

const isKeyBytes = (v: unknown): v is number[] =>
  Array.isArray(v) && v.length === 64 && v.every((b) => Number.isInteger(b) && b >= 0 && b < 256);

/**
 * Every failure here is a fixed message. JSON.parse errors quote a snippet of their input, and
 * the input is a private key, so no underlying message is ever passed through.
 */
function readSecretKey(source: SecretSource, what: string): Keypair {
  let text: string;
  if ("file" in source) {
    try {
      text = readFileSync(source.file, "utf8");
    } catch (err) {
      throw new ConfigError([`${what}: cannot read ${source.file} (${(err as NodeJS.ErrnoException).code ?? "error"})`]);
    }
  } else {
    text = source.inline;
  }
  let bytes: unknown;
  try {
    bytes = JSON.parse(text);
  } catch {
    throw new ConfigError([`${what}: not valid JSON`]);
  }
  if (!isKeyBytes(bytes)) throw new ConfigError([`${what}: expected a solana-keygen JSON array of 64 bytes`]);
  try {
    return keypairFromSolanaSecretKey(Uint8Array.from(bytes));
  } catch {
    throw new ConfigError([`${what}: not a valid Ed25519 keypair`]);
  }
}

function readJson(path: string, what: string): unknown {
  try {
    return fromJson(readFileSync(path, "utf8"));
  } catch (err) {
    throw new ConfigError([`${what} (${path}): ${(err as Error).message}`]);
  }
}

interface Assembled {
  readonly provider: PolicyProvider;
  readonly trust: TrustInfo;
  readonly windowSeconds?: number;
}

function assemble(settings: GatewaySettings, rpc: RpcClient | undefined): Assembled {
  const mode = settings.mode;
  if (mode.kind === "plaintext") {
    const policy = parsePolicy(readJson(mode.policyFile, "GENKAI_POLICY_FILE"), "policy");
    return {
      provider: createPlaintextPolicyProvider(policy),
      trust: { mode: "plaintext", commitment: hashPolicy(policy), policyDocument: policy },
      windowSeconds: settings.windowSeconds ?? policy.windowSeconds,
    };
  }

  const deployment = parseDeployment(readJson(mode.deploymentFile, "GENKAI_DEPLOYMENT_FILE"), "deployment");
  const authority = readSecretKey(mode.authorityKey, "GENKAI_AUTHORITY_KEY");
  if (solanaAddress(authority.publicKey) !== deployment.authority) {
    throw new ConfigError([`The authority key is ${solanaAddress(authority.publicKey)}, but the deployment's policy authority is ${deployment.authority}`]);
  }
  const live = rpc as RpcClient;
  const mxe = createArciumMxeClient({ rpc: live, programId: deployment.programId, clusterOffset: deployment.clusterOffset, policy: deployment.policy, authority, circuitId: deployment.circuitId });
  return {
    provider: createSealedPolicyProvider({ commitment: deployment.commitment, circuitId: deployment.circuitId, mxe, onChain: { rpc: live, programId: deployment.programId, policy: deployment.policy } }),
    trust: { mode: "sealed", commitment: deployment.commitment, circuitId: deployment.circuitId, programId: deployment.programId, policy: deployment.policy },
    windowSeconds: settings.windowSeconds,
  };
}

export async function startGateway(settings: GatewaySettings, log: (line: string) => void = (l) => process.stdout.write(`${l}\n`)): Promise<RunningGateway> {
  const vault = readSecretKey(settings.vaultKey, "GENKAI_VAULT_KEY");
  const rpc = settings.rpcUrl ? createRpcClient({ endpoint: settings.rpcUrl }) : undefined;
  const { provider, trust, windowSeconds } = assemble(settings, rpc);

  const db = openDatabase(settings.dbPath);
  const store = createStore(db);
  const service = createGatewayService({
    store,
    provider,
    vault,
    cluster: settings.cluster,
    ...(windowSeconds === undefined ? {} : { windowSeconds }),
    ...(rpc === undefined ? {} : { rpc }),
    execution: settings.execution,
  });
  const server = createGatewayServer({ store, service, trust, publicReceipts: settings.publicReceipts, trustProxy: settings.trustProxy, ...(rpc === undefined ? {} : { rpc }), log });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(settings.port, settings.host, () => resolve());
  });
  const address = server.address() as AddressInfo;
  const url = `http://${settings.host}:${address.port}`;
  log(JSON.stringify({ level: "info", event: "gateway.start", url, mode: trust.mode, vault: service.vaultAddress, cluster: settings.cluster, execution: settings.execution, rpc: rpc ? "configured" : "offline" }));

  return {
    server,
    url,
    vault: service.vaultAddress,
    mode: trust.mode,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => {
          db.close();
          resolve();
        });
        server.closeIdleConnections();
      }),
  };
}
