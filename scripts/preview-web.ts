/**
 * Serve a built site locally the way Vercel serves it: the static files with the same headers,
 * and the verifier API on the same paths. Run `npm run build:web` first.
 *
 *   node --experimental-strip-types scripts/preview-web.ts [--port 8790]
 */

import { readFile } from "node:fs/promises";
import { createServer, type ServerResponse } from "node:http";
import { extname, join, normalize, sep } from "node:path";
import { parseArgs } from "node:util";
import { createVerifierHandler } from "../src/server/verifier-server.ts";
import { createRpcClient } from "../src/solana/rpc.ts";
import { SITE_HEADERS } from "../web/headers.ts";
import { DEFAULT_OUT } from "./build-web.ts";

const TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

const root = join(DEFAULT_OUT, "static");
const api = createVerifierHandler({ rpc: createRpcClient({ endpoint: process.env["GENKAI_RPC_URL"] ?? "https://api.devnet.solana.com" }) });

function notFound(res: ServerResponse): void {
  res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  res.end("Not found");
}

/** The file a request path names, or undefined when it would leave the site root. */
function fileFor(pathname: string): string | undefined {
  try {
    const file = normalize(join(root, pathname === "/" ? "index.html" : decodeURIComponent(pathname)));
    return file.startsWith(root + sep) ? file : undefined;
  } catch {
    return undefined;
  }
}

const server = createServer((req, res) => {
  const pathname = new URL(req.url ?? "/", "http://preview.invalid").pathname;
  if (pathname === "/healthz" || pathname.startsWith("/v1/")) {
    void api(req, res);
    return;
  }
  const file = fileFor(pathname);
  if (file === undefined) {
    notFound(res);
    return;
  }
  readFile(file).then(
    (body) => {
      res.writeHead(200, { ...SITE_HEADERS, "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
      res.end(body);
    },
    () => notFound(res),
  );
});

const { values } = parseArgs({ options: { port: { type: "string" } } });
const port = Number(values.port ?? process.env["PORT"] ?? 8790);
server.listen(port, "127.0.0.1", () => process.stdout.write(`GENKAI site preview on http://127.0.0.1:${port}\n`));
