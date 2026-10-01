/**
 * esbuild settings shared by the site build and the bundle test, so the test exercises the
 * bundle that ships.
 *
 * The core imports node:crypto. In the browser that import resolves to web/shims/crypto.ts,
 * and the Node global Buffer to the buffer package. Any other node: import fails the build and
 * names its importer, so nothing Node-only can reach the page unnoticed.
 */

import { join, resolve } from "node:path";
import type { BuildOptions, Plugin } from "esbuild";

export const ROOT = resolve(import.meta.dirname, "..");

const browserShims: Plugin = {
  name: "genkai-browser-shims",
  setup(build) {
    build.onResolve({ filter: /^node:crypto$/ }, () => ({ path: join(ROOT, "web", "shims", "crypto.ts") }));
    build.onResolve({ filter: /^node:/ }, (args) => ({
      errors: [{ text: `${args.path} is not available in the browser (imported by ${args.importer})` }],
    }));
  },
};

export function browserBuildOptions(options: BuildOptions): BuildOptions {
  return {
    bundle: true,
    platform: "browser",
    target: ["es2022"],
    inject: [join(ROOT, "web", "shims", "buffer-global.ts")],
    plugins: [browserShims],
    logLevel: "silent",
    ...options,
  };
}
