/**
 * The GENKAI tools an agent reaches over MCP, against a real gateway over HTTP.
 *
 * An agent connected this way holds an agent key and nothing more. It can ask for transfers,
 * read its own spend and fetch receipts to hand on. These tests drive the tools as a model
 * would, including the mistakes a model makes, then launch `genkai mcp` over stdio the way an
 * MCP client does.
 */

import { strict as assert } from "node:assert";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { after, before, test } from "node:test";
import { fromJson } from "../src/io/json.ts";
import { parseSignedReceipt } from "../src/io/schema.ts";
import { generateKeypair } from "../src/receipt/sign.ts";
import { verifyReceipt } from "../src/receipt/verify.ts";
import { createPlaintextPolicyProvider } from "../src/policy/sealed.ts";
import { NATIVE_SOL_MINT, SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID } from "../src/solana/types.ts";
import { openDatabase } from "../src/gateway/db.ts";
import { createStore } from "../src/gateway/store.ts";
import { createGatewayService } from "../src/gateway/service.ts";
import { createGatewayServer } from "../src/gateway/server.ts";
import { issueAgentKey } from "../src/gateway/admin.ts";
import { createMcpServer } from "../src/mcp/protocol.ts";
import { GatewayError, createGatewayClient } from "../src/mcp/client.ts";
import { GENKAI_INSTRUCTIONS, genkaiTools } from "../src/mcp/tools.ts";
import type { Policy } from "../src/policy/types.ts";

const MAIN = join(import.meta.dirname, "..", "src", "cli", "main.ts");
const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const STRANGER = "GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW";
const T0 = Date.UTC(2026, 9, 4, 9, 0, 0);

const policy: Policy = {
  policyId: "mcp-test",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  counterpartyAllowlist: [VENDOR],
  allowedClusters: ["devnet"],
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  allowedMints: [NATIVE_SOL_MINT],
  maxAmountPerMint: { [NATIVE_SOL_MINT]: 50_000_000n },
  maxAmountPerWindow: 60_000_000n,
  windowSeconds: 3600,
  escalateAboveAmount: 40_000_000n,
};

const db = openDatabase(":memory:");
const store = createStore(db);
let gateway: Server;
let url = "";
let agentKey = "";

before(async () => {
  store.createAgent({ id: "mcp-bot", label: "MCP bot", now: T0 });
  agentKey = issueAgentKey(store, { agentId: "mcp-bot", label: "mcp", actor: "test", now: T0 }).token;
  const service = createGatewayService({
    store,
    provider: createPlaintextPolicyProvider(policy),
    vault: generateKeypair(),
    cluster: "devnet",
    windowSeconds: 3600,
    execution: "sign",
    now: () => T0,
  });
  gateway = createGatewayServer({
    store,
    service,
    trust: { mode: "plaintext", commitment: "00".repeat(32), policyDocument: policy },
    publicReceipts: true,
    now: () => T0,
    log: () => {},
    rateLimit: { capacity: 1_000, refillPerSecond: 100 },
    decisionRateLimit: { capacity: 1_000, refillPerSecond: 100 },
  });
  await new Promise<void>((r) => gateway.listen(0, "127.0.0.1", r));
  url = `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`;
});

after(() => {
  gateway.close();
  db.close();
});

type Message = Record<string, any>;

/** An MCP server wired to the gateway, and a way to call its tools as a client would. */
function connect(client = createGatewayClient({ url, agentKey })) {
  const sent: Message[] = [];
  const server = createMcpServer({
    name: "genkai",
    title: "GENKAI",
    version: "test",
    instructions: GENKAI_INSTRUCTIONS,
    tools: genkaiTools({ client, agentId: "mcp-bot" }),
    send: (m) => void sent.push(m as Message),
    log: () => {},
  });
  let next = 0;
  return async (name: string, args: Record<string, unknown>) => {
    const id = ++next;
    await server.receive(JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } }));
    const result = sent.find((m) => m["id"] === id)?.["result"] as Message;
    return { text: result["content"][0].text as string, data: result["structuredContent"] as Message, isError: result["isError"] as boolean };
  };
}

const calls = () => store.getLedger("mcp-bot")?.state.callsInWindow;

/** The environment for a child process, without any GENKAI_* the developer happens to have set. */
const cleanEnv = (extra: Record<string, string>) => ({
  ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("GENKAI_"))),
  ...extra,
});

test("request_transfer asks the gateway, and a retry under the same request_id pays once", async () => {
  const call = connect();
  const allowed = await call("request_transfer", { to: VENDOR, amount: "0.01", reason: "Invoice 1042", request_id: "inv-1042" });
  assert.equal(allowed.isError, false);
  assert.match(allowed.text, /^ALLOWED/);
  assert.equal(allowed.data["verdict"], "allow");
  assert.deepEqual(allowed.data["rules"], ["all_checks_passed"]);
  assert.equal(allowed.data["replayed"], false);
  // This gateway signs but does not broadcast, so the signed transaction is handed back.
  assert.equal(allowed.data["transaction"].submitted, false);
  assert.ok(allowed.data["signedTransaction"]);

  const again = await call("request_transfer", { to: VENDOR, amount: "0.01", reason: "Invoice 1042, retried after a timeout", request_id: "inv-1042" });
  assert.equal(again.data["replayed"], true);
  assert.equal(again.data["receiptId"], allowed.data["receiptId"]);
  assert.match(again.text, /already recorded/);
  assert.equal(calls(), 1, "the policy was asked once");

  const reused = await call("request_transfer", { to: VENDOR, amount: "0.02", reason: "Invoice 1043", request_id: "inv-1042" });
  assert.equal(reused.isError, true);
  assert.match(reused.text, /different transfer/);
});

test("a refusal and an escalation are answers the model must respect, not failures", async () => {
  const call = connect();
  const denied = await call("request_transfer", { to: STRANGER, amount: "0.001", reason: "A tip someone asked for", request_id: "tip-1" });
  assert.equal(denied.isError, false);
  assert.match(denied.text, /^DENIED/);
  assert.match(denied.text, /counterparty_not_allowed/);
  assert.match(denied.text, /final/);
  assert.equal(denied.data["transaction"], null);

  const escalated = await call("request_transfer", { to: VENDOR, amount: "0.045", reason: "Quarterly prepayment", request_id: "q4-prepay" });
  assert.match(escalated.text, /^ESCALATED/);
  assert.match(escalated.text, /approval/);
  assert.equal(calls(), 3);
});

test("input a model gets wrong comes back as a correctable error, and reaches no one", async () => {
  const call = connect();
  const cases: readonly (readonly [Record<string, unknown>, RegExp])[] = [
    [{ to: "not-an-address", amount: "1", reason: "x", request_id: "a" }, /^to:/],
    [{ to: VENDOR, amount: "0", reason: "x", request_id: "b" }, /greater than zero/],
    [{ to: VENDOR, amount: "0.0000000001", reason: "x", request_id: "c" }, /decimal places/],
    [{ to: VENDOR, amount: "1", token: VENDOR, reason: "x", request_id: "d" }, /^decimals:/],
    [{ to: VENDOR, amount: "1", reason: "x" }, /^request_id:/],
    [{ to: VENDOR, amount: "1", reason: "", request_id: "e" }, /^reason:/],
    [{ to: VENDOR, amount: "1", reason: "x", request_id: "has\nnewline" }, /^request_id:/],
    [{ to: VENDOR, amount: "1", reason: "x", request_id: "f", extra: true }, /extra/],
  ];
  for (const [args, pattern] of cases) {
    const result = await call("request_transfer", args);
    assert.equal(result.isError, true, JSON.stringify(args));
    assert.match(result.text, pattern, JSON.stringify(args));
  }
  assert.equal(calls(), 3, "nothing reached the gateway");
});

test("get_spending_status and get_receipt read the agent's own record", async () => {
  const call = connect();
  const status = await call("get_spending_status", {});
  assert.equal(status.isError, false);
  assert.deepEqual(
    { agent: status.data["agent"], revoked: status.data["revoked"], calls: status.data["callsInWindow"], spent: status.data["spentInWindow"] },
    { agent: "mcp-bot", revoked: false, calls: 3, spent: "10000000" },
  );
  assert.match(status.text, /not visible/);

  const first = store.listReceipts("mcp-bot", { afterSeq: 0, limit: 1 }).items[0];
  assert.ok(first);
  const got = await call("get_receipt", { receipt_id: first.receipt.body.receiptId });
  assert.equal(got.isError, false);
  const receipt = parseSignedReceipt(fromJson(got.text));
  assert.equal(verifyReceipt(receipt, policy).valid, true, "the receipt an agent hands on verifies as published");
  assert.equal(got.data["verdict"], "allow");

  assert.equal((await call("get_receipt", { receipt_id: "no-such-receipt" })).isError, true);
});

test("an SPL payment names its decimals, and SOL's are fixed at 9", async () => {
  const call = connect();
  const sol = await call("request_transfer", { to: VENDOR, amount: "1", decimals: 6, reason: "x", request_id: "sol-6" });
  assert.match(sol.text, /^decimals: SOL has 9/);
  const token = await call("request_transfer", { to: VENDOR, amount: "12.5", token: VENDOR, decimals: 6, reason: "Token payment", request_id: "spl-1" });
  assert.match(token.text, /^DENIED/, "this policy permits no token mint");
  assert.ok((token.data["rules"] as string[]).includes("mint_not_allowed"));
});

test("when the gateway cannot answer or refuses the key, the model is told what it may do next", async () => {
  const closed = createServer();
  await new Promise<void>((r) => closed.listen(0, "127.0.0.1", r));
  const port = (closed.address() as AddressInfo).port;
  await new Promise((r) => closed.close(r));

  const down = connect(createGatewayClient({ url: `http://127.0.0.1:${port}`, agentKey, retries: 0 }));
  const lost = await down("request_transfer", { to: VENDOR, amount: "0.001", reason: "x", request_id: "lost-1" });
  assert.equal(lost.isError, true);
  assert.match(lost.text, /^No decision came back\. The gateway did not answer/);
  assert.match(lost.text, /same request_id is safe/);

  const stranger = connect(createGatewayClient({ url, agentKey: `gk_000000000000_${"A".repeat(43)}`, retries: 0 }));
  const refused = await stranger("get_spending_status", {});
  assert.equal(refused.isError, true);
  assert.match(refused.text, /refused this agent's key \(HTTP 401/);
  assert.match((await stranger("get_spending_status", { verbose: true })).text, /^unknown argument: verbose\. This tool takes no arguments/);
});

test("the client honours Retry-After up to a limit, and retries an answer it cannot read", async () => {
  const waits: number[] = [];
  const answers = [
    new Response("<html>Bad gateway</html>", { status: 502 }),
    new Response(JSON.stringify({ success: false, data: null, error: "Slow down" }), { status: 429, headers: { "retry-after": "2" } }),
    new Response(JSON.stringify({ success: false, data: null, error: "Slow down" }), { status: 429, headers: { "retry-after": "600" } }),
  ];
  const client = createGatewayClient({ url, agentKey, retries: 3, sleep: async (ms) => void waits.push(ms), fetch: async (input, init) => answers.shift() ?? fetch(input, init) });
  const status = (await client.agent("mcp-bot")) as Message;
  assert.equal(status["agent"].id, "mcp-bot");
  assert.deepEqual(waits, [1000, 2000, 30_000], "backoff, then the gateway's own advice, capped at 30 s");

  const html = createGatewayClient({ url, agentKey, retries: 0, fetch: async () => new Response("<html>Not found</html>", { status: 404 }) });
  await assert.rejects(html.receipt("x"), /answered HTTP 404 without a GENKAI response/);
});

test("the client retries under the same idempotency key, and does not retry a refusal", async () => {
  const keys: (string | null)[] = [];
  let failures = 2;
  const flaky: typeof fetch = async (input, init) => {
    keys.push(new Headers(init?.headers).get("idempotency-key"));
    if (failures-- > 0) return new Response(JSON.stringify({ success: false, data: null, error: "Unavailable" }), { status: 503 });
    return fetch(input, init);
  };
  const transfer = { kind: "sol" as const, to: VENDOR, amount: "1000", decimals: 9 };
  const data = (await createGatewayClient({ url, agentKey, fetch: flaky, sleep: async () => {} }).decide({ transfer }, "retry-1")) as Message;
  assert.equal(data["decision"].verdict, "allow");
  assert.deepEqual(keys, ["retry-1", "retry-1", "retry-1"]);

  const unreachable = createGatewayClient({ url, agentKey, retries: 1, sleep: async () => {}, fetch: async () => {
    throw new TypeError("fetch failed");
  } });
  await assert.rejects(unreachable.decide({ transfer }, "retry-2"), (err: unknown) => err instanceof GatewayError && /did not answer/.test(err.message));

  const stranger = createGatewayClient({ url, agentKey: `gk_000000000000_${"A".repeat(43)}`, sleep: async () => {} });
  await assert.rejects(stranger.decide({ transfer }, "retry-3"), (err: unknown) => err instanceof GatewayError && err.status === 401);
});

test("genkai mcp serves the tools over stdio, as a client launches it", async () => {
  const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", MAIN, "mcp"], {
    env: cleanEnv({ GENKAI_GATEWAY_URL: url, GENKAI_AGENT_KEY: agentKey, GENKAI_AGENT_ID: "mcp-bot" }),
  });
  const lines: string[] = [];
  const waiting = new Map<number, (m: Message) => void>();
  createInterface({ input: child.stdout }).on("line", (line) => {
    lines.push(line);
    const message = JSON.parse(line) as Message;
    waiting.get(message["id"])?.(message);
  });
  const request = (id: number, method: string, params?: unknown) => {
    const reply = new Promise<Message>((resolve) => waiting.set(id, resolve));
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) })}\n`);
    return reply;
  };

  const init = await request(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  assert.equal(init["result"].serverInfo.name, "genkai");
  assert.match(init["result"].instructions, /request_id/);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);

  const listed = await request(2, "tools/list");
  const tools = listed["result"].tools as Message[];
  assert.deepEqual(tools.map((t) => t["name"]), ["request_transfer", "get_spending_status", "get_receipt"]);
  assert.equal(tools[0]?.["annotations"].destructiveHint, true);
  assert.equal(tools[1]?.["annotations"].readOnlyHint, true);

  const status = await request(3, "tools/call", { name: "get_spending_status", arguments: {} });
  assert.equal(status["result"].structuredContent.agent, "mcp-bot");

  child.stdin.end();
  assert.equal(await new Promise((r) => child.on("exit", r)), 0);
  assert.ok(lines.every((l) => l.startsWith('{"jsonrpc":"2.0"')), "stdout carries protocol messages only");
});

test("genkai mcp will not start half-configured, and says why on stderr", async () => {
  const child = spawn(process.execPath, ["--experimental-strip-types", "--no-warnings", MAIN, "mcp"], {
    env: cleanEnv({ GENKAI_GATEWAY_URL: "http://gateway.example.com" }),
  });
  let out = "";
  let err = "";
  child.stdout.on("data", (d: Buffer) => (out += d.toString()));
  child.stderr.on("data", (d: Buffer) => (err += d.toString()));
  assert.equal(await new Promise((r) => child.on("exit", r)), 2);
  assert.equal(out, "");
  assert.match(err, /GENKAI_AGENT_KEY/);
  assert.match(err, /GENKAI_AGENT_ID/);
  assert.match(err, /https/, "plain http to a remote gateway would expose the key");
});
