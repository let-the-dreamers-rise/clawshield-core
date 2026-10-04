/**
 * genkai mcp - the gateway as tools for an AI agent, over the Model Context Protocol on stdio.
 *
 *   GENKAI_GATEWAY_URL      the gateway; https unless it runs on this machine   required
 *   GENKAI_AGENT_KEY_FILE   file holding the agent's key, gk_...               required, or GENKAI_AGENT_KEY
 *   GENKAI_AGENT_ID         the agent that key belongs to                       required
 *   GENKAI_ALLOW_HTTP       true allows plain http to another host              false
 *
 * An MCP client launches this as a subprocess and speaks JSON-RPC over stdin and stdout, so
 * stdout carries protocol messages only. Everything meant for a person goes to stderr.
 */

import { readFileSync } from "node:fs";
import { parseApiKey } from "../gateway/auth.ts";
import { agentId } from "../gateway/requests.ts";
import { SchemaError } from "../io/schema.ts";
import { createGatewayClient } from "../mcp/client.ts";
import { createMcpServer } from "../mcp/protocol.ts";
import { lineWriter, serveStdio } from "../mcp/stdio.ts";
import { GENKAI_INSTRUCTIONS, genkaiTools } from "../mcp/tools.ts";
import { UsageError } from "./files.ts";

type Env = Readonly<Record<string, string | undefined>>;

export interface McpSettings {
  readonly url: string;
  readonly agentKey: string;
  readonly agentId: string;
}

const isLoopback = (host: string): boolean =>
  host === "localhost" || host.endsWith(".localhost") || host === "[::1]" || /^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(host);

function gatewayUrl(env: Env, problems: string[]): string | undefined {
  const raw = env["GENKAI_GATEWAY_URL"];
  if (!raw) {
    problems.push("GENKAI_GATEWAY_URL is required: the gateway's address, such as https://genkai.example.com");
    return undefined;
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    problems.push("GENKAI_GATEWAY_URL is not a URL");
    return undefined;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    problems.push("GENKAI_GATEWAY_URL must be an http(s) URL");
    return undefined;
  }
  const allowHttp = env["GENKAI_ALLOW_HTTP"] === "true" || env["GENKAI_ALLOW_HTTP"] === "1";
  if (url.protocol === "http:" && !isLoopback(url.hostname) && !allowHttp) {
    problems.push(
      `GENKAI_GATEWAY_URL must use https to reach ${url.hostname}: plain http would send the agent key in the clear. Set GENKAI_ALLOW_HTTP=true only on a private network you trust`,
    );
    return undefined;
  }
  return raw;
}

/** The key itself is never repeated in a message: these lines end up in client logs. */
function agentKey(env: Env, problems: string[]): string | undefined {
  const file = env["GENKAI_AGENT_KEY_FILE"];
  const source = file ? "GENKAI_AGENT_KEY_FILE" : "GENKAI_AGENT_KEY";
  let token: string | undefined;
  if (file) {
    try {
      token = readFileSync(file, "utf8").trim();
    } catch (err) {
      problems.push(`GENKAI_AGENT_KEY_FILE: cannot read ${file}: ${(err as NodeJS.ErrnoException).code ?? String(err)}`);
      return undefined;
    }
  } else {
    token = env["GENKAI_AGENT_KEY"]?.trim();
  }
  if (!token) {
    problems.push(file ? `GENKAI_AGENT_KEY_FILE: ${file} is empty` : "GENKAI_AGENT_KEY_FILE (or GENKAI_AGENT_KEY) is required: the agent's API key, gk_...");
    return undefined;
  }
  if (!parseApiKey(token)) {
    problems.push(`${source} does not hold a GENKAI key: expected gk_<key id>_<secret>`);
    return undefined;
  }
  return token;
}

function agent(env: Env, problems: string[]): string | undefined {
  const raw = env["GENKAI_AGENT_ID"];
  if (!raw) {
    problems.push("GENKAI_AGENT_ID is required: the id of the agent the key belongs to");
    return undefined;
  }
  try {
    return agentId(raw, "GENKAI_AGENT_ID");
  } catch (err) {
    if (!(err instanceof SchemaError)) throw err;
    problems.push(err.message);
    return undefined;
  }
}

export function parseMcpEnv(env: Env): McpSettings {
  const problems: string[] = [];
  const url = gatewayUrl(env, problems);
  const key = agentKey(env, problems);
  const id = agent(env, problems);
  if (problems.length > 0 || !url || !key || !id) throw new UsageError(`invalid configuration:\n  - ${problems.join("\n  - ")}`);
  return { url, agentKey: key, agentId: id };
}

function packageVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { readonly version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "unknown";
  } catch {
    return "unknown";
  }
}

export async function runMcp(argv: readonly string[]): Promise<number> {
  if (argv.length > 0) throw new UsageError("mcp takes no arguments; it is configured from GENKAI_* environment variables");
  const settings = parseMcpEnv(process.env);
  // The client went away mid-answer. There is no one left to answer, so stop.
  process.stdout.on("error", (err: NodeJS.ErrnoException) => {
    process.stderr.write(`genkai mcp: stdout closed (${err.code ?? err.message}); exiting\n`);
    process.exit(err.code === "EPIPE" ? 0 : 1);
  });
  const server = createMcpServer({
    name: "genkai",
    title: "GENKAI",
    version: packageVersion(),
    instructions: GENKAI_INSTRUCTIONS,
    tools: genkaiTools({ client: createGatewayClient({ url: settings.url, agentKey: settings.agentKey }), agentId: settings.agentId }),
    send: lineWriter(process.stdout),
  });
  process.stderr.write(`genkai mcp: agent ${settings.agentId} through ${new URL(settings.url).origin}\n`);
  await serveStdio(server);
  return 0;
}
