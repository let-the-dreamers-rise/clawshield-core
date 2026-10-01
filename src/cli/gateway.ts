/**
 * CLI entry points for the gateway.
 *
 *   genkai gateway [--port n] [--host h] [--db path]        run it, configured from GENKAI_* env
 *   genkai gateway-admin create-admin-key --db path [--label l]
 *   genkai gateway-admin list-keys --db path
 *   genkai gateway-admin revoke-key <keyId> --db path
 *
 * gateway-admin works on the database file directly. It is how the first admin key comes to
 * exist, and the break-glass path when every admin key is lost: whoever holds the file holds
 * the gateway, so this needs no further credential.
 */

import { parseArgs } from "node:util";
import { issueAdminKey } from "../gateway/admin.ts";
import { startGateway } from "../gateway/boot.ts";
import { ConfigError, parseGatewayEnv } from "../gateway/config.ts";
import { openDatabase } from "../gateway/db.ts";
import { createStore } from "../gateway/store.ts";
import { UsageError } from "./files.ts";

const out = (line: string) => process.stdout.write(`${line}\n`);

function flags(argv: readonly string[], names: readonly string[]) {
  try {
    return parseArgs({ args: [...argv], options: Object.fromEntries(names.map((n) => [n, { type: "string" as const }])), allowPositionals: true, strict: true });
  } catch (err) {
    throw new UsageError((err as Error).message);
  }
}

export async function runGateway(argv: readonly string[]): Promise<number> {
  const { values } = flags(argv, ["port", "host", "db"]);
  if (values.port !== undefined && !/^[0-9]{1,5}$/.test(String(values.port))) throw new UsageError(`Bad --port ${values.port}`);
  const env = {
    ...process.env,
    ...(values.port === undefined ? {} : { PORT: String(values.port) }),
    ...(values.host === undefined ? {} : { HOST: String(values.host) }),
    ...(values.db === undefined ? {} : { GENKAI_DB_PATH: String(values.db) }),
  };
  let gateway;
  try {
    gateway = await startGateway(parseGatewayEnv(env));
  } catch (err) {
    if (err instanceof ConfigError) {
      process.stderr.write(`${err.message}\n`);
      return 2;
    }
    throw err;
  }
  const running = gateway;
  await new Promise<void>((resolve) => {
    const stop = () => void running.close().then(resolve);
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
  return 0;
}

export function runGatewayAdmin(argv: readonly string[]): number {
  const { values, positionals } = flags(argv, ["db", "label"]);
  const [command, arg] = positionals;
  if (!values.db) throw new UsageError("gateway-admin needs --db <path to the gateway database>");
  const db = openDatabase(String(values.db));
  const store = createStore(db);
  try {
    switch (command) {
      case "create-admin-key": {
        const key = issueAdminKey(store, { label: String(values.label ?? "admin"), now: Date.now() });
        out("Admin key created. It is shown once; store it in your secret manager:");
        out(key.token);
        return 0;
      }
      case "list-keys": {
        for (const k of store.listKeys()) {
          out(`${k.keyId}  ${k.role.padEnd(5)}  ${(k.agentId ?? "-").padEnd(20)}  ${k.revokedAt === undefined ? "active " : "revoked"}  ${k.label}`);
        }
        return 0;
      }
      case "revoke-key": {
        if (!arg) throw new UsageError("revoke-key needs <keyId>");
        const revoked = store.revokeKey(arg, Date.now());
        if (revoked) store.audit({ at: Date.now(), actor: "operator", action: "key.revoke", subject: arg });
        out(revoked ? `Revoked ${arg}` : `No active key ${arg}`);
        return revoked ? 0 : 1;
      }
      default:
        throw new UsageError("gateway-admin <create-admin-key|list-keys|revoke-key>");
    }
  } finally {
    db.close();
  }
}
