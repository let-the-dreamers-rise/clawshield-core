/**
 * How `genkai mcp` reads its configuration. It runs as a subprocess of an MCP client, where a
 * mistake surfaces only in a log file, so every problem is named at once, and the agent key is
 * never repeated in any of them.
 */

import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { generateApiKey } from "../src/gateway/auth.ts";
import { parseMcpEnv, runMcp } from "../src/cli/mcp.ts";

const KEY = generateApiKey().token;
const base = { GENKAI_GATEWAY_URL: "https://genkai.example.com", GENKAI_AGENT_KEY: KEY, GENKAI_AGENT_ID: "pay-bot" };

function problems(env: Readonly<Record<string, string>>): string {
  try {
    parseMcpEnv(env);
  } catch (err) {
    return (err as Error).message;
  }
  return assert.fail("expected a configuration error");
}

test("a complete configuration is read, the key from a file when one is named", () => {
  assert.deepEqual(parseMcpEnv(base), { url: base.GENKAI_GATEWAY_URL, agentKey: KEY, agentId: "pay-bot" });
  const file = join(mkdtempSync(join(tmpdir(), "genkai-mcp-")), "agent.key");
  const other = generateApiKey().token;
  writeFileSync(file, `${other}\n`);
  assert.equal(parseMcpEnv({ ...base, GENKAI_AGENT_KEY_FILE: file }).agentKey, other, "the file wins, trimmed");
});

test("plain http is for this machine, or for a network the operator vouches for", () => {
  for (const url of ["http://localhost:8788", "http://127.0.0.1:8788", "http://[::1]:8788", "http://genkai.localhost"]) {
    assert.equal(parseMcpEnv({ ...base, GENKAI_GATEWAY_URL: url }).url, url);
  }
  assert.match(problems({ ...base, GENKAI_GATEWAY_URL: "http://10.0.0.5:8788" }), /https/);
  assert.equal(parseMcpEnv({ ...base, GENKAI_GATEWAY_URL: "http://10.0.0.5:8788", GENKAI_ALLOW_HTTP: "true" }).url, "http://10.0.0.5:8788");
  assert.match(problems({ ...base, GENKAI_GATEWAY_URL: "genkai.example.com" }), /not a URL/);
  assert.match(problems({ ...base, GENKAI_GATEWAY_URL: "ftp://genkai.example.com" }), /http\(s\)/);
});

test("every problem is named at once, and the key is never repeated", () => {
  const dir = mkdtempSync(join(tmpdir(), "genkai-mcp-"));
  const empty = join(dir, "empty.key");
  writeFileSync(empty, "\n");
  assert.match(problems({ ...base, GENKAI_AGENT_KEY_FILE: join(dir, "missing.key") }), /cannot read .*missing\.key: ENOENT/);
  assert.match(problems({ ...base, GENKAI_AGENT_KEY_FILE: empty }), /is empty/);

  const pasted = "sk-test-not-a-genkai-key-0123456789";
  const message = problems({ GENKAI_AGENT_KEY: pasted, GENKAI_AGENT_ID: "Not_An_Id" });
  assert.match(message, /GENKAI_GATEWAY_URL is required/);
  assert.match(message, /GENKAI_AGENT_KEY does not hold a GENKAI key/);
  assert.match(message, /GENKAI_AGENT_ID/);
  assert.ok(!message.includes(pasted), "a key is not echoed into a client's log");
});

test("genkai mcp takes no arguments", async () => {
  await assert.rejects(runMcp(["--port", "1"]), /no arguments/);
});
