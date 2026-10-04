/**
 * The Model Context Protocol layer, without the gateway: version negotiation, the tool calls a
 * client makes, progress for long calls, and the JSON-RPC errors a client must be able to rely
 * on. Then the one piece of arithmetic the tools do themselves: turning "0.015" into lamports.
 */

import { strict as assert } from "node:assert";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { LATEST_PROTOCOL_VERSION, createMcpServer, type McpTool } from "../src/mcp/protocol.ts";
import { serveStdio } from "../src/mcp/stdio.ts";
import { toMinorUnits } from "../src/solana/units.ts";

type Message = Record<string, any>;

function harness(tools: readonly McpTool[]) {
  const sent: Message[] = [];
  const server = createMcpServer({
    name: "genkai",
    title: "GENKAI",
    version: "9.9.9",
    instructions: "Be careful.",
    tools,
    send: (m) => void sent.push(m as Message),
    log: () => {},
  });
  const request = async (id: number, method: string, params?: unknown): Promise<Message | undefined> => {
    await server.receive(JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) }));
    return sent.find((m) => m["id"] === id);
  };
  return { server, sent, request };
}

const echo: McpTool = {
  name: "echo",
  title: "Echo",
  description: "Returns its input.",
  inputSchema: { type: "object", properties: { text: { type: "string" } }, required: ["text"], additionalProperties: false },
  annotations: { readOnlyHint: true },
  call: async (args, context) => {
    context.progress("halfway");
    if (args["text"] === "boom") throw new Error("kaboom");
    return { text: String(args["text"]), structured: { echoed: args["text"] } };
  },
};

test("initialize negotiates the protocol version and describes the server", async () => {
  const { request, sent, server } = harness([echo]);
  const init = await request(1, "initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  assert.equal(init?.["result"].protocolVersion, "2025-03-26", "a version the server supports is echoed");
  assert.deepEqual(init?.["result"].capabilities, { tools: { listChanged: false } });
  assert.deepEqual(init?.["result"].serverInfo, { name: "genkai", title: "GENKAI", version: "9.9.9" });
  assert.equal(init?.["result"].instructions, "Be careful.");

  const unknown = await request(2, "initialize", { protocolVersion: "1999-01-01", capabilities: {}, clientInfo: { name: "t", version: "1" } });
  assert.equal(unknown?.["result"].protocolVersion, LATEST_PROTOCOL_VERSION, "anything else gets the latest the server speaks");

  const count = sent.length;
  await server.receive(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
  await server.receive(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 7 } }));
  assert.equal(sent.length, count, "a notification is never answered");
  assert.deepEqual((await request(3, "ping"))?.["result"], {});
});

test("tools are listed with their schemas and called, with progress only when asked for", async () => {
  const { request, sent } = harness([echo]);
  const list = await request(1, "tools/list");
  assert.deepEqual(list?.["result"].tools, [
    { name: "echo", title: "Echo", description: "Returns its input.", inputSchema: echo.inputSchema, annotations: { readOnlyHint: true } },
  ]);

  const call = await request(2, "tools/call", { name: "echo", arguments: { text: "hi" }, _meta: { progressToken: "p1" } });
  assert.deepEqual(call?.["result"], { content: [{ type: "text", text: "hi" }], structuredContent: { echoed: "hi" }, isError: false });
  const progress = sent.filter((m) => m["method"] === "notifications/progress");
  assert.deepEqual(progress.map((m) => m["params"]), [{ progressToken: "p1", progress: 1, message: "halfway" }]);

  await request(3, "tools/call", { name: "echo", arguments: { text: "quiet" } });
  assert.equal(sent.filter((m) => m["method"] === "notifications/progress").length, 1);

  // A tool that fails says so in its result, where the model can read it, not as a protocol error.
  const failed = await request(4, "tools/call", { name: "echo", arguments: { text: "boom" } });
  assert.equal(failed?.["result"].isError, true);
  assert.match(failed?.["result"].content[0].text, /kaboom/);
});

test("protocol mistakes get the JSON-RPC error a client expects", async () => {
  const { request, sent, server } = harness([echo]);
  assert.equal((await request(1, "tools/call", { name: "nope", arguments: {} }))?.["error"].code, -32602);
  assert.equal((await request(2, "resources/list"))?.["error"].code, -32601);

  await server.receive("{not json");
  assert.deepEqual(sent.at(-1), { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
  await server.receive(JSON.stringify({ jsonrpc: "2.0", id: 9 }));
  assert.equal(sent.at(-1)?.["error"].code, -32600);
  assert.equal(sent.at(-1)?.["id"], 9);
  await server.receive(JSON.stringify([{ jsonrpc: "2.0", id: 10, method: "ping" }]));
  assert.equal(sent.at(-1)?.["error"].code, -32600, "batches were removed from the protocol");

  // A response from the client (the server never asks it anything) is ignored.
  const count = sent.length;
  await server.receive(JSON.stringify({ jsonrpc: "2.0", id: 11, result: {} }));
  assert.equal(sent.length, count);
});

test("over stdio, calls run concurrently and every line out is one protocol message", async () => {
  let release: () => void = () => {};
  const slow: McpTool = { ...echo, name: "slow", call: () => new Promise((r) => (release = () => r({ text: "done" }))) };
  const sent: Message[] = [];
  const server = createMcpServer({ name: "g", title: "G", version: "1", instructions: "", tools: [slow], send: (m) => void sent.push(m as Message), log: () => {} });
  const input = new PassThrough();
  const serving = serveStdio(server, input);

  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "slow", arguments: {} } })}\n`);
  input.write(`\n${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })}\r\n`);
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(sent.map((m) => m["id"]), [2], "a slow call does not hold up a ping");

  input.end();
  release();
  await serving;
  assert.deepEqual(sent.map((m) => m["id"]), [2, 1], "the transport waits for work in flight before it finishes");
});

test("a tool that throws before it awaits, or a message that fails outright, does not stop the server", async () => {
  const eager: McpTool = { ...echo, name: "eager", call: () => { throw new Error("thrown synchronously"); } };
  const { request } = harness([eager]);
  const result = await request(1, "tools/call", { name: "eager", arguments: {} });
  assert.equal(result?.["result"].isError, true);
  assert.match(result?.["result"].content[0].text, /eager failed: thrown synchronously/);

  const reported: unknown[] = [];
  const input = new PassThrough();
  let calls = 0;
  const flaky = { receive: async () => { calls += 1; if (calls === 1) throw new Error("stdout is gone"); } };
  const serving = serveStdio(flaky, input, (err) => void reported.push(err));
  input.end('{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n');
  await serving;
  assert.equal(calls, 2, "the second message was still served");
  assert.match(String(reported[0]), /stdout is gone/);
});

test("amounts become minor units exactly, never through a float", () => {
  assert.equal(toMinorUnits("0.015", 9), 15_000_000n);
  assert.equal(toMinorUnits("1", 9), 1_000_000_000n);
  assert.equal(toMinorUnits("12.5", 6), 12_500_000n);
  assert.equal(toMinorUnits("007.10", 2), 710n);
  assert.equal(toMinorUnits("18446744073709551615", 0), (1n << 64n) - 1n);
  for (const bad of ["", " 1", "1.", ".5", "-1", "+1", "1e9", "0x10", "1,5", "Infinity", "0.0000000001", "18446744073709551616"]) {
    assert.throws(() => toMinorUnits(bad, 9), /amount/, JSON.stringify(bad));
  }
  assert.throws(() => toMinorUnits("0.5", 0), /more than 0 decimal places/);
  assert.throws(() => toMinorUnits("1", 19), /decimals/);
});
