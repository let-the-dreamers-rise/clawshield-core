/**
 * A Model Context Protocol server, independent of transport: JSON-RPC 2.0 messages in, messages
 * out through `send`.
 *
 * It implements what a tool server needs and no more: initialize with version negotiation,
 * ping, tools/list, and tools/call with progress notifications for slow calls. Written to the
 * 2025-06-18 specification and answering clients of the two versions before it. There is no SDK
 * behind it: the protocol is small, and GENKAI keeps its rule of no runtime dependencies.
 */

export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"] as const;
export const LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;

export type JsonObject = { readonly [key: string]: unknown };

export interface ToolResult {
  /** What the model reads. */
  readonly text: string;
  /** The same answer as data, for clients that use structured content. */
  readonly structured?: JsonObject;
  readonly isError?: boolean;
}

export interface ToolContext {
  /** Tell the client a slow call is still alive. Sent only if the client asked for progress. */
  readonly progress: (message: string) => void;
}

export interface McpTool {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly inputSchema: JsonObject;
  readonly annotations?: JsonObject;
  readonly call: (args: JsonObject, context: ToolContext) => Promise<ToolResult>;
}

export interface McpServerConfig {
  readonly name: string;
  readonly title: string;
  readonly version: string;
  /** Guidance a client may hand to its model, sent once at initialize. */
  readonly instructions: string;
  readonly tools: readonly McpTool[];
  readonly send: (message: JsonObject) => void;
  /** Where unexpected failures are reported: stderr by default, never the protocol stream. */
  readonly log?: (line: string) => void;
}

/** A failure written for the model: returned verbatim as an error result, not logged as a fault. */
export class ToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolError";
  }
}

type Id = string | number;

const isObject = (v: unknown): v is JsonObject => typeof v === "object" && v !== null && !Array.isArray(v);
const isId = (v: unknown): v is Id => typeof v === "string" || (typeof v === "number" && Number.isInteger(v));

export function createMcpServer(config: McpServerConfig) {
  const tools = new Map(config.tools.map((t) => [t.name, t] as const));
  const log = config.log ?? ((line: string) => void process.stderr.write(`${line}\n`));
  const reply = (id: Id, result: JsonObject): void => config.send({ jsonrpc: "2.0", id, result });
  const fail = (id: Id | null, code: number, message: string): void => config.send({ jsonrpc: "2.0", id, error: { code, message } });

  function initialize(params: JsonObject): JsonObject {
    const requested = params["protocolVersion"];
    const known = SUPPORTED_PROTOCOL_VERSIONS.find((v) => v === requested);
    return {
      protocolVersion: known ?? LATEST_PROTOCOL_VERSION,
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: config.name, title: config.title, version: config.version },
      instructions: config.instructions,
    };
  }

  const describe = (t: McpTool): JsonObject => ({
    name: t.name,
    title: t.title,
    description: t.description,
    inputSchema: t.inputSchema,
    ...(t.annotations ? { annotations: t.annotations } : {}),
  });

  async function callTool(id: Id, params: JsonObject): Promise<void> {
    const name = params["name"];
    const tool = typeof name === "string" ? tools.get(name) : undefined;
    if (!tool) return fail(id, INVALID_PARAMS, `Unknown tool: ${String(name)}`);

    const meta = params["_meta"];
    const token = isObject(meta) ? meta["progressToken"] : undefined;
    let progress = 0;
    const context: ToolContext = {
      progress: (message) => {
        if (!isId(token)) return;
        progress += 1;
        config.send({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: token, progress, message } });
      },
    };

    const args = isObject(params["arguments"]) ? params["arguments"] : {};
    // Through a promise, so a tool that throws before its first await is caught the same way.
    const result = await Promise.resolve()
      .then(() => tool.call(args, context))
      .catch((err: unknown): ToolResult => {
        if (err instanceof ToolError) return { text: err.message, isError: true };
        const message = err instanceof Error ? err.message : String(err);
        log(JSON.stringify({ level: "error", event: "mcp.tool_failed", tool: tool.name, error: message }));
        return { text: `${tool.name} failed: ${message}`, isError: true };
      });
    reply(id, {
      content: [{ type: "text", text: result.text }],
      ...(result.structured ? { structuredContent: result.structured } : {}),
      isError: result.isError === true,
    });
  }

  /** Handle one message. Resolves once its answer, if it has one, has been sent. */
  async function receive(line: string): Promise<void> {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      return fail(null, PARSE_ERROR, "Parse error");
    }
    if (!isObject(message)) return fail(null, INVALID_REQUEST, Array.isArray(message) ? "Batches are not supported" : "Invalid request");

    const id = message["id"];
    const method = message["method"];
    // A response from the client: this server never asks the client anything, so it is dropped.
    if (method === undefined && ("result" in message || "error" in message)) return;
    if (message["jsonrpc"] !== "2.0" || typeof method !== "string") return fail(isId(id) ? id : null, INVALID_REQUEST, "Invalid request");
    // A notification (initialized, cancelled, ...) is never answered.
    if (!isId(id)) return;

    const params = isObject(message["params"]) ? message["params"] : {};
    switch (method) {
      case "initialize":
        return reply(id, initialize(params));
      case "ping":
        return reply(id, {});
      case "tools/list":
        return reply(id, { tools: config.tools.map(describe) });
      case "tools/call":
        return callTool(id, params);
      default:
        return fail(id, METHOD_NOT_FOUND, `Method not found: ${method}`);
    }
  }

  return Object.freeze({ receive });
}
