/**
 * Browser tests for the verifier site: the built site served by scripts/preview-web.ts, which
 * applies the same headers and CSP as the Vercel deployment, at desktop and phone sizes.
 *
 *   npm run test:e2e                      Chromium, as CI runs it (npx playwright install chromium)
 *   PW_CHANNEL=msedge npm run test:e2e    an installed Edge or Chrome instead, nothing to download
 */

import { defineConfig, devices } from "@playwright/test";

const PORT = 8790;
const CI = process.env["CI"] !== undefined;
const channel = process.env["PW_CHANNEL"];
const browser = channel ? { channel } : {};

export default defineConfig({
  testDir: "test/e2e",
  fullyParallel: true,
  forbidOnly: CI,
  retries: CI ? 1 : 0,
  reporter: CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], ...browser } },
    { name: "phone", use: { ...devices["Pixel 7"], ...browser } },
  ],
  webServer: {
    command: "npm run build:web && npm run preview:web",
    url: `http://127.0.0.1:${PORT}/healthz`,
    reuseExistingServer: !CI,
    timeout: 120_000,
  },
});
