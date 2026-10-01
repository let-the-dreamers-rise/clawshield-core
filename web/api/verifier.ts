/**
 * The hosted verifier as a Vercel function: the handler `genkai serve` runs, unchanged, with
 * on-chain attestations read from devnet unless GENKAI_RPC_URL names another cluster.
 *
 * Vercel overwrites X-Forwarded-For with the connecting address, so trusting it is safe here.
 * The in-memory rate limiter is per instance: a first line behind the platform's own
 * protection, not a global quota.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { createVerifierHandler } from "../../src/server/verifier-server.ts";
import { createRpcClient } from "../../src/solana/rpc.ts";

const handle = createVerifierHandler({
  trustProxy: true,
  rpc: createRpcClient({ endpoint: process.env["GENKAI_RPC_URL"] ?? "https://api.devnet.solana.com" }),
});

/**
 * Each route is deployed as its own function. The path is fixed here rather than trusted from
 * whatever URL the platform hands over, so routing cannot drift from the deployed layout.
 */
export function handlerFor(path: string): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  return (req, res) => {
    req.url = path;
    return handle(req, res);
  };
}
