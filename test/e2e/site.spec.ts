/**
 * The verifier site in a real browser, served with the deployment's own headers and CSP, and
 * with devnet answered from the committed snapshot. These are the paths a reviewer or an auditor
 * takes: confirm the deployment, verify the live run in one click, watch a forgery get caught,
 * check their own files, and do all of it on a phone.
 */

import { join } from "node:path";
import { expect, test, type Page } from "@playwright/test";
import { LANDED, answerDevnet } from "./devnet.ts";

const EXAMPLES = join(import.meta.dirname, "..", "..", "examples", "devnet");
const PROGRAM = "AwiVMGyi8P9mN6ig5FA74CTS6sncc7bbh8CNAxKXUERk";

/** Console errors and failed CSP checks: a clean page has none. */
function watchConsole(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("pageerror", (err) => errors.push(err.message));
  return errors;
}

/** Every host the page sent a request to. */
function watchHosts(page: Page): Set<string> {
  const hosts = new Set<string>();
  page.on("request", (request) => void hosts.add(new URL(request.url()).host));
  return hosts;
}

const result = (page: Page) => page.locator("#result");

test("the deployment panel confirms the program and the policy record on devnet", async ({ page }) => {
  await answerDevnet(page);
  await page.goto("/");
  await expect(page.locator("#deployment-status")).toContainText("Confirmed on devnet just now");
  const facts = page.locator("#deployment-facts");
  await expect(facts).toContainText(PROGRAM);
  await expect(facts).toContainText("Deployed and executable");
  await expect(facts).toContainText("Status on chain: active");
});

test("one click verifies the gateway run: five sealed decisions checked on chain, both transfers landed", async ({ page }) => {
  const calls = await answerDevnet(page);
  const errors = watchConsole(page);
  const hosts = watchHosts(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Verify the devnet run" }).click();

  await expect(result(page).locator(".result-word")).toHaveText("Valid");
  await expect(result(page).locator(".result-summary")).toHaveText("5 sealed receipts, chain intact, every verdict matches the cluster's record on chain.");
  await expect(result(page).locator(".pill")).toHaveText(["allow", "deny", "escalate", "deny", "allow"]);
  await expect(result(page).locator(".receipt-status.ok")).toHaveCount(5);
  for (const slot of Object.values(LANDED)) await expect(result(page)).toContainText(`landed at slot ${slot}`);
  await expect(result(page)).toBeFocused();

  expect(calls).toContain("getSignatureStatuses");
  expect(calls.filter((m) => m === "getAccountInfo").length).toBeGreaterThanOrEqual(5);
  expect(errors).toEqual([]);
  expect([...hosts].sort()).toEqual(["127.0.0.1:8790", "api.devnet.solana.com"]);
});

test("a denial rewritten as an approval is caught, and the page says which receipt", async ({ page }) => {
  await answerDevnet(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Rewrite a denial as an approval" }).click();

  await expect(result(page).locator(".result-word")).toHaveText("Invalid");
  await expect(result(page).locator(".callout")).toContainText("Receipt #2 was rewritten from a denial into a clean approval");
  await expect(result(page).locator(".receipt").nth(1)).toHaveClass(/\bbad\b/);
  await expect(result(page).locator(".failures")).toBeVisible();
});

test("the CLI run verifies, its transfers signed but never broadcast", async ({ page }) => {
  await answerDevnet(page);
  await page.goto("/");
  await page.getByRole("button", { name: "CLI run, signed only" }).click();
  await expect(result(page).locator(".result-word")).toHaveText("Valid");
  await expect(result(page)).toContainText("signed, not broadcast");
});

test("the plaintext run is replayed against its published policy", async ({ page }) => {
  await answerDevnet(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Plaintext run, replayed" }).click();
  await expect(result(page).locator(".result-word")).toHaveText("Valid");
  await expect(result(page).locator(".tags li")).toHaveText(["plaintext", "replayed", "chain of 5"]);
});

test("receipts loaded from disk verify, and nothing pasted leaves the browser", async ({ page }) => {
  await answerDevnet(page);
  const hosts = watchHosts(page);
  await page.goto("/");
  await page.locator('input[data-target="receipts-input"]').setInputFiles(join(EXAMPLES, "gateway", "receipts.json"));
  await page.locator('input[data-target="anchor-input"]').setInputFiles(join(EXAMPLES, "trust.json"));
  await expect(page.locator("#form-note")).toHaveText("Loaded trust.json.");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(result(page).locator(".result-word")).toHaveText("Valid");
  expect([...hosts].sort()).toEqual(["127.0.0.1:8790", "api.devnet.solana.com"]);

  await page.locator("#rpc-input").fill("https://api.devnet.solana.com/");
  await expect(page.locator("#form-note")).toHaveText("The inputs changed. Verify again to update the result.");
  await expect(result(page)).toHaveClass(/\bstale\b/);
});

test("input that cannot be checked is reported as unchecked, never as invalid", async ({ page }) => {
  await answerDevnet(page);
  await page.goto("/");
  await page.locator("#receipts-input").fill("{not json");
  await page.locator("#anchor-input").fill("{}");
  await page.getByRole("button", { name: "Verify", exact: true }).click();
  await expect(result(page).locator(".result-word")).toHaveText("Not verified");
  await expect(result(page).locator(".result-summary")).toContainText("not valid JSON");
});

test("an unreachable chain is reported as such, not as a forgery", async ({ page }) => {
  await answerDevnet(page, { down: true });
  await page.goto("/");
  await expect(page.locator("#deployment-status")).toContainText("Could not read devnet");
  await page.getByRole("button", { name: "Verify the devnet run" }).click();
  await expect(result(page).locator(".result-word")).toHaveText("Chain unreachable");
  await expect(result(page)).toContainText("Nothing was judged invalid");
});

test("served with the deployment's security headers, and the API example names this origin", async ({ page, baseURL }) => {
  await answerDevnet(page);
  const response = await page.goto("/");
  const headers = response?.headers() ?? {};
  expect(headers["content-security-policy"]).toContain("default-src 'none'");
  expect(headers["content-security-policy"]).toContain("script-src 'self'");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["referrer-policy"]).toBe("no-referrer");
  await expect(page.locator("#api-example")).toContainText(`ORIGIN=${baseURL}`);

  const card = await page.request.get("/og.png");
  expect(card.status()).toBe(200);
  expect(card.headers()["content-type"]).toBe("image/png");
  await expect(page.locator('meta[property="og:image"]')).toHaveAttribute("content", "https://genkai-inky.vercel.app/og.png");
});

test("the page fits the screen at every size, with a result showing", async ({ page }) => {
  await answerDevnet(page);
  await page.goto("/");
  await page.getByRole("button", { name: "Verify the devnet run" }).click();
  await expect(result(page).locator(".result-word")).toHaveText("Valid");
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, "no horizontal scrolling").toBeLessThanOrEqual(0);
});
