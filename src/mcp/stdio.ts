/**
 * MCP over stdio: one JSON-RPC message per line in each direction. Stdout belongs to the
 * protocol; anything meant for a person goes to stderr.
 */

import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import type { JsonObject } from "./protocol.ts";

export interface MessageReceiver {
  readonly receive: (line: string) => Promise<void>;
}

const toStderr = (err: unknown): void =>
  void process.stderr.write(`${JSON.stringify({ level: "error", event: "mcp.message_failed", error: err instanceof Error ? err.message : String(err) })}\n`);

/**
 * Serve until the input ends, then wait for the calls still in flight. Calls run concurrently,
 * so a decision that takes seconds on the MPC cluster never holds up a ping. A message that
 * fails outright is reported and the rest are still served.
 */
export async function serveStdio(server: MessageReceiver, input: Readable = process.stdin, report: (err: unknown) => void = toStderr): Promise<void> {
  const inFlight = new Set<Promise<void>>();
  for await (const line of createInterface({ input, crlfDelay: Infinity })) {
    if (line.trim() === "") continue;
    const work: Promise<void> = server
      .receive(line)
      .catch(report)
      .finally(() => inFlight.delete(work));
    inFlight.add(work);
  }
  await Promise.all(inFlight);
}

/** One message per line. Bigints, which JSON cannot carry, are written as decimal strings. */
export function lineWriter(output: Writable = process.stdout): (message: JsonObject) => void {
  return (message) => void output.write(`${JSON.stringify(message, (_key, v: unknown) => (typeof v === "bigint" ? v.toString() : v))}\n`);
}
