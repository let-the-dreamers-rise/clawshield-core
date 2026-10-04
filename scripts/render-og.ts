/**
 * Render the link-preview card, web/og.png (1200x630), from scripts/og-card.html in a headless
 * browser. Run it after changing the card, and commit the image:
 *
 *   node --experimental-strip-types scripts/render-og.ts
 *   PW_CHANNEL=msedge node --experimental-strip-types scripts/render-og.ts    an installed browser
 */

import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { chromium } from "@playwright/test";

const ROOT = join(import.meta.dirname, "..");
const OUT = join(ROOT, "web", "og.png");
const channel = process.env["PW_CHANNEL"];

const browser = await chromium.launch(channel ? { channel } : {});
try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(join(ROOT, "scripts", "og-card.html")).href);
  await page.screenshot({ path: OUT, type: "png" });
  process.stdout.write(`Wrote ${OUT}\n`);
} finally {
  await browser.close();
}
