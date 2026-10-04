/**
 * Build the public site and the hosted verifier as Vercel Build Output (v3), in .vercel/output:
 *
 *   static/                             the browser verifier and the devnet example data
 *   functions/v1/receipts/verify.func   POST, the same handler `genkai serve` runs
 *   functions/v1/chains/verify.func     POST
 *   functions/healthz.func              GET
 *
 * Deploy with `vercel deploy --prebuilt --prod`. Nothing is rebuilt on Vercel's side, so what
 * is served is exactly what this script produced from the checked-out commit.
 *
 *   node --experimental-strip-types scripts/build-web.ts
 */

import { build } from "esbuild";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ROOT, browserBuildOptions } from "./web-bundle.ts";
import { SITE_HEADERS } from "../web/headers.ts";

export const DEFAULT_OUT = join(ROOT, ".vercel", "output");

export const API_ROUTES = ["/v1/receipts/verify", "/v1/chains/verify", "/healthz"] as const;

/** [source in the repo, path served]. Example data is copied, never generated, so it stays the committed record. */
const STATIC_FILES: readonly (readonly [string, string])[] = [
  ["web/index.html", "index.html"],
  ["web/styles.css", "styles.css"],
  ["web/favicon.svg", "favicon.svg"],
  ["web/og.png", "og.png"],
  ["arcium/genkai/deployments/devnet.json", "deployment.json"],
  ["examples/devnet/sealed-receipts.json", "examples/devnet/sealed-receipts.json"],
  ["examples/devnet/gateway/receipts.json", "examples/devnet/gateway/receipts.json"],
  ["examples/devnet/gateway/run.json", "examples/devnet/gateway/run.json"],
  ["examples/devnet/trust.json", "examples/devnet/trust.json"],
  ["examples/devnet/plaintext-receipts.json", "examples/devnet/plaintext-receipts.json"],
  ["examples/devnet/policy.json", "examples/devnet/policy.json"],
];

function write(path: string, content: string | Uint8Array): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

async function buildSite(out: string): Promise<number> {
  const staticDir = join(out, "static");
  for (const [from, to] of STATIC_FILES) write(join(staticDir, to), readFileSync(join(ROOT, from)));
  const result = await build(
    browserBuildOptions({
      entryPoints: [join(ROOT, "web", "src", "main.ts")],
      outfile: join(staticDir, "app.js"),
      format: "esm",
      minify: true,
      sourcemap: "linked",
      metafile: true,
    }),
  );
  return Object.values(result.metafile?.outputs ?? {}).find((o) => o.entryPoint !== undefined)?.bytes ?? 0;
}

async function buildFunctions(out: string): Promise<void> {
  const bundle = await build({
    entryPoints: [join(ROOT, "web", "api", "verifier.ts")],
    bundle: true,
    platform: "node",
    target: "node22",
    format: "esm",
    write: false,
    logLevel: "silent",
  });
  const code = bundle.outputFiles[0]?.text;
  if (code === undefined) throw new Error("The verifier function produced no output");

  for (const route of API_ROUTES) {
    const dir = join(out, "functions", `${route.slice(1)}.func`);
    write(join(dir, "verifier.mjs"), code);
    write(join(dir, "index.mjs"), `import { handlerFor } from "./verifier.mjs";\nexport default handlerFor(${JSON.stringify(route)});\n`);
    // Without helpers Vercel hands the function a plain request stream, which the handler
    // reads and bounds itself, exactly as under node:http.
    write(
      join(dir, ".vc-config.json"),
      `${JSON.stringify({ runtime: "nodejs22.x", handler: "index.mjs", launcherType: "Nodejs", shouldAddHelpers: false, maxDuration: 60 }, null, 2)}\n`,
    );
  }
}

function writeConfig(out: string): void {
  const config = {
    version: 3,
    routes: [{ src: "^/(.*)$", headers: SITE_HEADERS, continue: true }, { handle: "filesystem" }],
  };
  write(join(out, "config.json"), `${JSON.stringify(config, null, 2)}\n`);
}

/** Replace `out` with a fresh build. Returns the size of the page script in bytes. */
export async function buildWeb(out: string = DEFAULT_OUT): Promise<number> {
  rmSync(out, { recursive: true, force: true });
  const appBytes = await buildSite(out);
  await buildFunctions(out);
  writeConfig(out);
  return appBytes;
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  buildWeb().then(
    (bytes) => process.stdout.write(`Built ${DEFAULT_OUT}\n  app.js ${(bytes / 1024).toFixed(1)} KiB\n  functions: ${API_ROUTES.join(", ")}\n`),
    (err: unknown) => {
      process.stderr.write(`build-web: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exitCode = 1;
    },
  );
}
