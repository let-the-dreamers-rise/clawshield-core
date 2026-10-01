/**
 * genkai - command line for operators and auditors.
 *
 *   genkai keygen <out.json>                          new vault key, solana-keygen format
 *   genkai seal <policy.json> <out.json>              commitment + secret salt for a policy
 *   genkai verify <receipt.json> --policy p | --trust t [--previous <hash>] [--rpc <url>]
 *   genkai verify-chain <receipts.json> --policy p | --trust t [--rpc <url>]
 *   genkai verify-execution <receipt.json> --rpc <url>
 *   genkai verify-onchain <receipt.json> --decision <address> --program <id> --rpc <url> [--policy-record <address>]
 *   genkai serve [--port 8787] [--host 127.0.0.1] [--trust-proxy] [--rpc <url>]
 *   genkai demo [--out dir] [--devnet --keypair file [--rpc url]] [--live deployment.json --authority file]
 *
 * --rpc on verify and verify-chain is what lets a receipt from the live Arcium MXE verify: its
 * evidence is a DecisionRecord on chain. Without it such a receipt reports attestation_unchecked.
 *
 * Exit codes: 0 success or valid, 1 verified invalid, 2 usage or input error.
 */

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseArgs, type ParseArgsConfig } from "node:util";
import { generateKeypair } from "../receipt/sign.ts";
import { sealedCommitment } from "../policy/sealed.ts";
import { encodePolicy, EncodingError } from "../mxe/encoding.ts";
import { SchemaError, parsePolicy, parseSignedReceipt } from "../io/schema.ts";
import { handleVerifyChain, handleVerifyReceipt, type VerificationData } from "../server/handlers.ts";
import { createVerifierServer } from "../server/verifier-server.ts";
import { createRpcClient } from "../solana/rpc.ts";
import { verifyExecution } from "../solana/executor.ts";
import { verifyOnChainDecision } from "../mxe/onchain.ts";
import { keypairFromSolanaSecretKey, solanaAddress, solanaSecretKey } from "../solana/keys.ts";
import { UsageError, readJsonFile, writeSecretFile } from "./files.ts";
import { runDemo, type LiveOptions } from "./demo.ts";
import { parseDeployment } from "./deployment.ts";
import type { Keypair } from "../receipt/sign.ts";

const DEVNET_RPC = "https://api.devnet.solana.com";
const out = (line: string) => process.stdout.write(`${line}\n`);

function parse<const O extends NonNullable<ParseArgsConfig["options"]>>(argv: readonly string[], options: O) {
  try {
    return parseArgs({ args: [...argv], options, allowPositionals: true, strict: true } as const);
  } catch (err) {
    throw new UsageError((err as Error).message);
  }
}

function positional(values: readonly string[], index: number, name: string): string {
  const v = values[index];
  if (v === undefined) throw new UsageError(`Missing <${name}>`);
  return v;
}

function anchorArgs(values: { policy?: unknown; trust?: unknown }): Record<string, unknown> {
  if ((values.policy === undefined) === (values.trust === undefined)) {
    throw new UsageError("Supply exactly one of --policy or --trust");
  }
  return values.policy !== undefined
    ? { policy: readJsonFile(String(values.policy)) }
    : { trust: readJsonFile(String(values.trust)) };
}

function readSolanaKey(path: string): Keypair {
  let secret: Uint8Array;
  try {
    secret = Uint8Array.from(JSON.parse(readFileSync(path, "utf8")) as number[]);
    return keypairFromSolanaSecretKey(secret);
  } catch (err) {
    throw new UsageError(`${path} is not a solana-keygen keypair file: ${(err as Error).message}`);
  }
}

const rpcOf = (url: string | undefined) => (url ? { rpc: createRpcClient({ endpoint: url }) } : {});

function report(result: VerificationData): number {
  if (result.valid) {
    out(`VALID (${result.mode})`);
    return 0;
  }
  out(`INVALID (${result.mode}): ${result.failures.join(", ")}`);
  for (const d of result.detail) out(`  - ${d}`);
  return 1;
}

const commands: Record<string, (argv: readonly string[]) => Promise<number> | number> = {
  keygen(argv) {
    const { positionals } = parse(argv, {});
    const path = positional(positionals, 0, "out.json");
    const keys = generateKeypair();
    writeSecretFile(path, JSON.stringify([...solanaSecretKey(keys)]));
    out(`Wrote ${path} (keep it secret). Address: ${solanaAddress(keys.publicKey)}`);
    return 0;
  },

  seal(argv) {
    const { positionals } = parse(argv, {});
    const policy = parsePolicy(readJsonFile(positional(positionals, 0, "policy.json")), "policy");
    encodePolicy(policy);
    const salt = randomBytes(32).toString("hex");
    const commitment = sealedCommitment(policy, salt);
    writeSecretFile(positional(positionals, 1, "out.json"), `${JSON.stringify({ commitment, salt }, null, 2)}\n`);
    out(`Sealed. Publish this commitment; keep the output file secret: ${commitment}`);
    return 0;
  },

  async verify(argv) {
    const { values, positionals } = parse(argv, { policy: { type: "string" }, trust: { type: "string" }, previous: { type: "string" }, rpc: { type: "string" } });
    const receipt = readJsonFile(positional(positionals, 0, "receipt.json"));
    return report(await handleVerifyReceipt({ receipt, ...anchorArgs(values), expectedPreviousHash: values.previous }, rpcOf(values.rpc)));
  },

  async "verify-chain"(argv) {
    const { values, positionals } = parse(argv, { policy: { type: "string" }, trust: { type: "string" }, rpc: { type: "string" } });
    const receipts = readJsonFile(positional(positionals, 0, "receipts.json"));
    return report(await handleVerifyChain({ receipts, ...anchorArgs(values) }, rpcOf(values.rpc)));
  },

  async "verify-execution"(argv) {
    const { values, positionals } = parse(argv, { rpc: { type: "string" } });
    if (!values.rpc) throw new UsageError("Missing --rpc <url>");
    const receipt = parseSignedReceipt(readJsonFile(positional(positionals, 0, "receipt.json")), "receipt");
    const result = await verifyExecution(receipt, createRpcClient({ endpoint: values.rpc }));
    out(result.executed ? `EXECUTED at slot ${result.slot}` : `NOT EXECUTED: ${result.failure}`);
    return result.executed ? 0 : 1;
  },

  async "verify-onchain"(argv) {
    const { values, positionals } = parse(argv, { decision: { type: "string" }, program: { type: "string" }, rpc: { type: "string" }, "policy-record": { type: "string" } });
    if (!values.decision || !values.program || !values.rpc) throw new UsageError("Needs --decision, --program and --rpc");
    const receipt = parseSignedReceipt(readJsonFile(positional(positionals, 0, "receipt.json")), "receipt");
    const result = await verifyOnChainDecision(receipt, {
      rpc: createRpcClient({ endpoint: values.rpc }),
      programId: values.program,
      decision: values.decision,
      policy: values["policy-record"],
    });
    if (values["policy-record"] === undefined) {
      out("note: no --policy-record pinned; a look-alike policy record with the same commitment would also pass");
    }
    if (result.valid) {
      out(`VALID (on-chain): the cluster recorded this verdict at slot ${result.decidedSlot}`);
      return 0;
    }
    out(`INVALID (on-chain): ${result.failures.join(", ")}`);
    for (const d of result.detail) out(`  - ${d}`);
    return 1;
  },

  serve(argv) {
    const { values } = parse(argv, { port: { type: "string" }, host: { type: "string" }, "trust-proxy": { type: "boolean" }, rpc: { type: "string" } });
    const port = Number(values.port ?? process.env["PORT"] ?? 8787);
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new UsageError(`Bad port ${values.port}`);
    const host = values.host ?? "127.0.0.1";
    const server = createVerifierServer({ trustProxy: values["trust-proxy"] ?? false, ...rpcOf(values.rpc ?? process.env["GENKAI_RPC"]) });
    server.listen(port, host, () => out(`GENKAI verifier listening on http://${host}:${port}`));
    const stop = () => server.close(() => process.exit(0));
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    return new Promise<number>(() => {});
  },

  async demo(argv) {
    const { values } = parse(argv, {
      out: { type: "string" },
      devnet: { type: "boolean" },
      keypair: { type: "string" },
      rpc: { type: "string" },
      live: { type: "string" },
      authority: { type: "string" },
    });
    const outDir = values.out ?? "demo-out";
    const live = liveOptions(values.live, values.authority);
    if (!values.devnet) {
      const r = await runDemo({ out: outDir, live });
      return r.plaintextValid && r.sealedValid ? 0 : 1;
    }
    if (!values.keypair) throw new UsageError("--devnet needs --keypair <file> holding a funded devnet key");
    const vault = readSolanaKey(values.keypair);
    const rpc = createRpcClient({ endpoint: values.rpc ?? DEVNET_RPC });
    const account = await rpc.getAccountInfo(solanaAddress(vault.publicKey));
    if (!account || account.lamports < 100_000_000n) {
      throw new UsageError(`Fund ${solanaAddress(vault.publicKey)} with at least 0.1 devnet SOL first: solana airdrop 1 ${solanaAddress(vault.publicKey)} --url devnet`);
    }
    const r = await runDemo({ out: outDir, vault, rpc, live });
    return r.plaintextValid && r.sealedValid ? 0 : 1;
  },
};

function liveOptions(deploymentPath: string | undefined, authorityPath: string | undefined): LiveOptions | undefined {
  if (deploymentPath === undefined) {
    if (authorityPath !== undefined) throw new UsageError("--authority is only used with --live");
    return undefined;
  }
  if (authorityPath === undefined) throw new UsageError("--live needs --authority <file>: the policy authority's keypair");
  const deployment = parseDeployment(readJsonFile(deploymentPath), "deployment");
  const authority = readSolanaKey(authorityPath);
  if (solanaAddress(authority.publicKey) !== deployment.authority) {
    throw new UsageError(`${authorityPath} is ${solanaAddress(authority.publicKey)}, but the policy authority is ${deployment.authority}`);
  }
  return { deployment, authority, rpc: createRpcClient({ endpoint: deployment.rpc }) };
}

async function main(argv: readonly string[]): Promise<number> {
  const [name, ...rest] = argv;
  const command = name === undefined ? undefined : commands[name];
  if (!command) {
    process.stderr.write(`Usage: genkai <${Object.keys(commands).join("|")}> ...\n`);
    return 2;
  }
  try {
    return await command(rest);
  } catch (err) {
    if (err instanceof UsageError || err instanceof SchemaError || err instanceof EncodingError) {
      process.stderr.write(`genkai ${name}: ${err.message}\n`);
      return 2;
    }
    throw err;
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`genkai: unexpected error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 2;
  },
);
