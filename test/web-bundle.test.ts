/**
 * The artefacts that ship: the browser bundle and the Vercel functions.
 *
 * The bundle is run in a bare V8 context with no Buffer, process or require, which is what a
 * browser gives it, and must reach the same answers as the Node build of the same code: the
 * @noble shims are substitutes for node:crypto, and this is where that substitution is held to
 * account. The functions are built exactly as scripts/build-web.ts writes them for Vercel and
 * driven over real HTTP.
 */

import { strict as assert } from "node:assert";
import { webcrypto } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import vm from "node:vm";
import { after, before, test } from "node:test";
import { build } from "esbuild";
import { browserBuildOptions } from "../scripts/web-bundle.ts";
import { buildWeb } from "../scripts/build-web.ts";
import { createRpcClient } from "../src/solana/rpc.ts";
import { checkDeployment } from "../web/src/deployment.ts";
import { rewriteFirstDenial } from "../web/src/tamper.ts";
import { verifyDocuments, type VerifyRequest } from "../web/src/verify.ts";
import { DEVNET_RPC, GATEWAY_RECEIPTS, LANDED, MANIFEST, PLAINTEXT_RECEIPTS, POLICY, ROOT, SEALED_RECEIPTS, TRUST, devnetFetch } from "./helpers/devnet.ts";

interface BundledApi {
  verifyDocuments(request: VerifyRequest): Promise<unknown>;
  checkDeployment(manifest: unknown, rpc: unknown): Promise<unknown>;
  createRpcClient(config: unknown): unknown;
}

const plain = (value: unknown): unknown => JSON.parse(JSON.stringify(value));

async function loadBundle(): Promise<{ readonly api: BundledApi; readonly bytes: number }> {
  const result = await build(
    browserBuildOptions({
      stdin: {
        contents: [
          'export { verifyDocuments } from "./verify.ts";',
          'export { checkDeployment } from "./deployment.ts";',
          'export { createRpcClient } from "../../src/solana/rpc.ts";',
        ].join("\n"),
        resolveDir: join(ROOT, "web", "src"),
        loader: "ts",
        sourcefile: "bundle-entry.ts",
      },
      format: "iife",
      globalName: "GenkaiWeb",
      write: false,
    }),
  );
  const code = result.outputFiles?.[0]?.text ?? "";
  const context = vm.createContext({
    TextEncoder,
    TextDecoder,
    URL,
    AbortSignal,
    setTimeout,
    clearTimeout,
    console,
    crypto: { getRandomValues: <T extends ArrayBufferView>(a: T) => webcrypto.getRandomValues(a as never) as T },
    fetch: devnetFetch(),
  });
  assert.equal(vm.runInContext("[typeof Buffer, typeof process, typeof require].join()", context), "undefined,undefined,undefined");
  vm.runInContext(code, context, { filename: "app-bundle.js" });
  return { api: (context as { GenkaiWeb: BundledApi }).GenkaiWeb, bytes: code.length };
}

let bundle: Awaited<ReturnType<typeof loadBundle>>;
before(async () => {
  bundle = await loadBundle();
});

const requests: Readonly<Record<string, VerifyRequest>> = {
  sealed: { receipts: SEALED_RECEIPTS, anchor: TRUST, rpcEndpoint: DEVNET_RPC },
  gateway: { receipts: GATEWAY_RECEIPTS, anchor: TRUST, rpcEndpoint: DEVNET_RPC },
  forged: { receipts: rewriteFirstDenial(GATEWAY_RECEIPTS).text, anchor: TRUST, rpcEndpoint: DEVNET_RPC },
  plaintext: { receipts: PLAINTEXT_RECEIPTS, anchor: POLICY, rpcEndpoint: DEVNET_RPC },
  unchecked: { receipts: SEALED_RECEIPTS, anchor: TRUST },
};

test("the browser bundle needs no Node globals and reaches the same answers as Node", async () => {
  for (const [name, request] of Object.entries(requests)) {
    const inBrowser = plain(await bundle.api.verifyDocuments({ ...request, fetch: devnetFetch({ landed: LANDED }) }));
    const inNode = plain(await verifyDocuments({ ...request, fetch: devnetFetch({ landed: LANDED }) }));
    assert.deepEqual(inBrowser, inNode, name);
  }
  const gateway = plain(await bundle.api.verifyDocuments({ ...requests["gateway"]!, fetch: devnetFetch({ landed: LANDED }) })) as {
    valid: boolean;
    rows: { transactionStatus?: { state: string } }[];
  };
  assert.equal(gateway.valid, true, "the bundle verifies the devnet run, not merely agrees with Node about it");
  assert.deepEqual(gateway.rows.map((r) => r.transactionStatus?.state), ["landed", undefined, undefined, undefined, "landed"]);
});

test("the bundle reads the deployment from chain state as Node does", async () => {
  const rpc = bundle.api.createRpcClient({ endpoint: DEVNET_RPC, fetch: devnetFetch() });
  const inBrowser = plain(await bundle.api.checkDeployment(MANIFEST, rpc));
  const inNode = plain(await checkDeployment(MANIFEST, createRpcClient({ endpoint: DEVNET_RPC, fetch: devnetFetch() })));
  assert.deepEqual(inBrowser, inNode);
  assert.deepEqual((inBrowser as { problems: unknown[] }).problems, []);
});

test("a shared link shows a 1200x630 card, named by absolute URL as the crawlers require", () => {
  const html = readFileSync(join(ROOT, "web", "index.html"), "utf8");
  const meta = (attr: "property" | "name", key: string): string | undefined =>
    new RegExp(`<meta ${attr}="${key}" content="([^"]*)">`).exec(html)?.[1];
  const site = "https://genkai-inky.vercel.app/";
  assert.equal(meta("property", "og:url"), site);
  assert.match(html, new RegExp(`<link rel="canonical" href="${site}">`));
  assert.equal(meta("property", "og:image"), `${site}og.png`);
  assert.equal(meta("name", "twitter:image"), `${site}og.png`);
  assert.equal(meta("name", "twitter:card"), "summary_large_image");
  for (const key of ["og:title", "og:description", "og:image:alt"]) assert.ok((meta("property", key) ?? "").length > 20, key);

  // The PNG header names its size: width and height are the first fields of the IHDR chunk.
  const png = readFileSync(join(ROOT, "web", "og.png"));
  assert.equal(png.subarray(12, 16).toString("latin1"), "IHDR");
  assert.deepEqual([png.readUInt32BE(16), png.readUInt32BE(20)], [1200, 630]);
  assert.equal(meta("property", "og:image:width"), "1200");
  assert.equal(meta("property", "og:image:height"), "630");
  assert.ok(png.length < 500_000, `og.png is ${png.length} bytes; some apps skip previews over 500 KB`);
});

test("the bundle stays small enough to load on a phone", () => {
  assert.ok(bundle.bytes < 600_000, `unminified bundle is ${bundle.bytes} bytes`);
});

const out = mkdtempSync(join(tmpdir(), "genkai-web-"));
after(() => rmSync(out, { recursive: true, force: true }));

test("the Vercel build serves the page with its headers and the API as raw-stream functions", async () => {
  const appBytes = await buildWeb(out);
  assert.ok(appBytes > 10_000 && appBytes < 400_000, `app.js is ${appBytes} bytes`);
  for (const file of ["index.html", "app.js", "app.js.map", "styles.css", "favicon.svg", "og.png", "deployment.json", "examples/devnet/sealed-receipts.json", "examples/devnet/gateway/receipts.json", "examples/devnet/gateway/run.json", "examples/devnet/usdc/receipts.json", "examples/devnet/usdc/run.json", "examples/devnet/usdc/trust.json", "examples/devnet/trust.json"]) {
    assert.ok(existsSync(join(out, "static", file)), file);
  }
  const site = JSON.parse(readFileSync(join(out, "config.json"), "utf8")) as { version: number; routes: { headers?: Record<string, string> }[] };
  assert.equal(site.version, 3);
  assert.match(site.routes[0]?.headers?.["content-security-policy"] ?? "", /script-src 'self'; style-src 'self'/);

  const vc = JSON.parse(readFileSync(join(out, "functions", "v1", "chains", "verify.func", ".vc-config.json"), "utf8")) as Record<string, unknown>;
  assert.equal(vc["shouldAddHelpers"], false, "the handler reads and bounds the body itself");
  assert.equal(vc["handler"], "index.mjs");

  const fn = async (route: string) =>
    ((await import(pathToFileURL(join(out, "functions", `${route}.func`, "index.mjs")).href)) as { default: (req: unknown, res: unknown) => Promise<void> }).default;
  const chain = await fn("v1/chains/verify");
  const health = await fn("healthz");
  // Mounted at arbitrary paths: each function fixes its own route.
  const server = createServer((req, res) => void (req.url === "/a" ? chain : health)(req, res));
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const res = await fetch(`${base}/a`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"receipts":${PLAINTEXT_RECEIPTS},"policy":${POLICY}}`,
    });
    const body = (await res.json()) as { success: boolean; data: { valid: boolean; mode: string } };
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("access-control-allow-origin"), "*");
    assert.deepEqual([body.success, body.data.valid, body.data.mode], [true, true, "plaintext"]);

    const healthz = (await (await fetch(`${base}/b`)).json()) as { data: unknown };
    assert.deepEqual(healthz.data, { status: "ok", onChain: true });
  } finally {
    server.close();
  }
});
