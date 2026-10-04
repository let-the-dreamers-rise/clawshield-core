/**
 * Write the README's architecture diagram, docs/architecture.svg and its dark twin, from one
 * description so the two never drift apart.
 *
 *   node --experimental-strip-types scripts/architecture-svg.ts
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";

interface Palette {
  readonly text: string;
  readonly muted: string;
  readonly line: string;
  readonly box: string;
  readonly accent: string;
  readonly accentSoft: string;
  readonly ok: string;
}

const LIGHT: Palette = { text: "#18181c", muted: "#5d5d67", line: "#a9a8a0", box: "#ffffff", accent: "#3730a3", accentSoft: "#eeedfc", ok: "#11703f" };
const DARK: Palette = { text: "#ececf1", muted: "#a3a3ae", line: "#5c5c6a", box: "#1a1a21", accent: "#a5b4fc", accentSoft: "#23234a", ok: "#4ad295" };

interface Box {
  readonly x: number;
  readonly y: number;
  readonly w: number;
  readonly h: number;
  readonly title: string;
  readonly lines: readonly string[];
  readonly strong?: boolean;
}

const BOXES: readonly Box[] = [
  { x: 20, y: 40, w: 210, h: 120, title: "AI agent", lines: ["MCP: request_transfer", "or HTTP, with an agent key", "never holds a signing key"] },
  {
    x: 310, y: 20, w: 300, h: 170, title: "GENKAI gateway", strong: true,
    lines: ["API keys, roles, rate limits", "SQLite ledger: spend, window, calls", "per-agent queue, idempotency keys", "vault key: signs only on allow"],
  },
  {
    x: 710, y: 20, w: 270, h: 170, title: "Policy provider",
    lines: ["sealed: an Arcium MXE evaluates", "the encrypted policy (cluster 456)", "", "plaintext: the same rules,", "replayable by anyone"],
  },
  { x: 310, y: 280, w: 300, h: 120, title: "Signed receipt chain", lines: ["every verdict: commitment, request,", "state, rules, DecisionRecord,", "transaction, previous receipt's hash"] },
  { x: 710, y: 280, w: 270, h: 120, title: "Solana", lines: ["GENKAI program: PolicyRecord,", "one DecisionRecord per verdict", "transfers, receipt id in the memo"] },
  { x: 20, y: 280, w: 210, h: 120, title: "Anyone verifies", lines: ["browser, CLI or hosted API", "against public values only;", "the policy is never revealed"] },
];

interface Arrow {
  readonly d: string;
  readonly label: string;
  readonly lx: number;
  readonly ly: number;
  readonly anchor?: "start" | "middle" | "end";
}

const ARROWS: readonly Arrow[] = [
  { d: "M230 100 H302", label: "asks", lx: 266, ly: 92 },
  { d: "M610 75 H702", label: "request,", lx: 660, ly: 58 },
  { d: "M710 140 H618", label: "verdict", lx: 660, ly: 158 },
  { d: "M845 190 V272", label: "records", lx: 853, ly: 236, anchor: "start" },
  { d: "M460 190 V272", label: "every verdict", lx: 468, ly: 236, anchor: "start" },
  { d: "M592 190 L716 278", label: "allow only:", lx: 682, ly: 226, anchor: "start" },
  { d: "M310 340 H238", label: "receipts", lx: 274, ly: 332 },
  { d: "M845 400 V440 H125 V408", label: "reads the records and transfers on chain", lx: 485, ly: 432 },
];

/** Second lines for labels that need two. */
const SECOND_LINE: Readonly<Record<string, string>> = { "request,": "ledger state", "allow only:": "signed transfer" };

const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function box(b: Box, p: Palette): string {
  const lines = b.lines.map((line, i) => `<text x="${b.x + 16}" y="${b.y + 54 + i * 19}" class="line">${esc(line)}</text>`).join("");
  return (
    `<rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="12" fill="${b.strong ? p.accentSoft : p.box}" stroke="${b.strong ? p.accent : p.line}" stroke-width="${b.strong ? 2 : 1.25}"/>` +
    `<text x="${b.x + 16}" y="${b.y + 29}" class="title"${b.strong ? ` fill="${p.accent}"` : ""}>${esc(b.title)}</text>${lines}`
  );
}

function arrow(a: Arrow): string {
  const anchor = a.anchor ?? "middle";
  const second = SECOND_LINE[a.label];
  const label = `<text x="${a.lx}" y="${a.ly}" class="label" text-anchor="${anchor}">${esc(a.label)}</text>`;
  const more = second === undefined ? "" : `<text x="${a.lx}" y="${a.ly + 15}" class="label" text-anchor="${anchor}">${esc(second)}</text>`;
  return `<path d="${a.d}" class="arrow" marker-end="url(#head)"/>${label}${more}`;
}

function svg(p: Palette): string {
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 460" width="1000" height="460" role="img" aria-labelledby="t d">`,
    `<title id="t">GENKAI architecture</title>`,
    `<desc id="d">An AI agent asks the GENKAI gateway for a transfer. The gateway sends the request and its ledger state to the policy provider, an Arcium MXE evaluating the encrypted policy, which records its verdict on Solana. The gateway signs a transfer only on allow, and writes a signed receipt for every verdict. Anyone can verify the receipts against the records on chain.</desc>`,
    `<style>text{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}.title{font-size:16px;font-weight:700;fill:${p.text}}.line{font-size:13px;fill:${p.muted}}.label{font-size:12px;font-weight:600;fill:${p.ok}}.arrow{fill:none;stroke:${p.muted};stroke-width:1.5}</style>`,
    `<defs><marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="${p.muted}"/></marker></defs>`,
    ...BOXES.map((b) => box(b, p)),
    ...ARROWS.map(arrow),
    `</svg>`,
    "",
  ].join("\n");
}

const DOCS = join(import.meta.dirname, "..", "docs");
writeFileSync(join(DOCS, "architecture.svg"), svg(LIGHT));
writeFileSync(join(DOCS, "architecture-dark.svg"), svg(DARK));
process.stdout.write(`Wrote ${join(DOCS, "architecture.svg")} and architecture-dark.svg\n`);
