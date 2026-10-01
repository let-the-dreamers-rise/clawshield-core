/**
 * Rendering of verification results and the deployment panel. Pure presentation: every
 * decision about validity has already been made by verify.ts and the core.
 */

import type { Deployment } from "../../src/cli/deployment.ts";
import type { DeploymentStatus } from "./deployment.ts";
import { byId, dot, h, link, type Child } from "./dom.ts";
import { checksFor, explorerUrl, failureLabel, formatTime, shortAddress } from "./format.ts";
import { VerifyError, type ReceiptRow, type Report } from "./verify.ts";

const plural = (n: number, noun: string): string => `${n} ${noun}${n === 1 ? "" : "s"}`;

function showResult(state: "valid" | "invalid" | "error" | "pending", ...children: readonly Child[]): HTMLElement {
  const result = byId("result");
  result.hidden = false;
  result.className = state === "pending" ? "result" : `result ${state}`;
  result.setAttribute("aria-busy", String(state === "pending"));
  result.replaceChildren(...children.filter((c): c is Node | string => c !== null && c !== undefined && c !== false));
  return result;
}

export function renderPending(message: string): void {
  showResult("pending", h("div", { class: "result-banner" }, h("span", { class: "spinner", attrs: { "aria-hidden": "true" } }), h("p", { class: "result-summary", text: message })));
}

export function renderError(err: unknown): void {
  const rpc = err instanceof VerifyError && err.kind === "rpc";
  const message = err instanceof Error ? err.message : String(err);
  showResult(
    "error",
    h(
      "div",
      { class: "result-banner" },
      h("span", { class: "result-word", text: rpc ? "Chain unreachable" : "Not verified" }),
      h("p", { class: "result-summary", text: err instanceof VerifyError ? message : `Unexpected error: ${message}` }),
    ),
    h("div", { class: "result-body" }, h("p", { class: "fine", text: rpc ? "Nothing was judged invalid: the RPC endpoint could not be read. Try again, or point the page at another endpoint." : "Nothing was judged invalid: the input could not be checked as given." })),
  );
}

function summaryOf(report: Report): string {
  const noun = plural(report.rows.length, `${report.mode} receipt`);
  if (!report.valid) {
    const failed = report.rows.filter((r) => r.problems.length > 0).length;
    return `${noun}: ${failed} failed verification${report.general.length > 0 ? ", plus findings about the input as a whole" : ""}.`;
  }
  const evidence = report.onChain
    ? "every verdict matches the cluster's record on chain"
    : report.mode === "plaintext"
      ? "every verdict reproduced by replaying the policy"
      : "attestations hold under the pinned key";
  return `${noun}${report.chained ? ", chain intact" : ""}, ${evidence}.`;
}

function tagsOf(report: Report): readonly string[] {
  return [
    report.mode,
    report.onChain ? "checked on chain" : report.mode === "plaintext" ? "replayed" : "not checked on chain",
    report.chained ? `chain of ${report.rows.length}` : "single receipt",
  ];
}

function transactionEntry(row: ReceiptRow): Child {
  const signature = row.transactionSignature;
  if (signature === undefined) return null;
  const status = row.transactionStatus;
  const href = explorerUrl("tx", signature, row.cluster);
  const value =
    status?.state === "landed"
      ? [link(shortAddress(signature), href), ` landed at slot ${status.slot}`]
      : status?.state === "failed"
        ? [link(shortAddress(signature), href), ` failed at slot ${status.slot}`]
        : status?.state === "not_found"
          ? [shortAddress(signature), " signed, not broadcast"]
          : [shortAddress(signature)];
  return h("div", {}, h("dt", { text: "Signed transfer" }), h("dd", {}, ...value));
}

function metaOf(row: ReceiptRow): readonly Child[] {
  const entry = (term: string, ...value: readonly Child[]) => h("div", {}, h("dt", { text: term }), h("dd", {}, ...value));
  return [
    entry("Rules", row.rules.length > 0 ? row.rules.join(", ") : "withheld: verdict only"),
    entry("Decided", formatTime(row.decidedAt)),
    entry("Agent", row.agentId),
    row.disclosure !== undefined && entry("Disclosure", row.disclosure === "verdict" ? "verdict only" : "verdict and rule ids"),
    row.decisionRecord !== undefined && entry("Decision record", link(shortAddress(row.decisionRecord), explorerUrl("address", row.decisionRecord, row.cluster))),
    row.queueSignature !== undefined && entry("Queued by", link(shortAddress(row.queueSignature), explorerUrl("tx", row.queueSignature, row.cluster))),
    transactionEntry(row),
  ];
}

function receiptItem(row: ReceiptRow): HTMLLIElement {
  const ok = row.problems.length === 0;
  return h(
    "li",
    { class: `receipt ${ok ? "ok" : "bad"}` },
    h(
      "div",
      { class: "receipt-head" },
      h("span", { class: "receipt-index", text: `#${row.index + 1}` }),
      h("span", { class: `pill ${row.verdict}`, text: row.verdict }),
      h("span", { class: "receipt-action", text: row.action }),
      h("span", { class: `receipt-status ${ok ? "ok" : "bad"}` }, dot(ok ? "ok" : "bad"), ok ? "Verified" : plural(row.problems.length, "problem")),
    ),
    h("dl", { class: "receipt-meta" }, ...metaOf(row)),
    !ok && h("ul", { class: "problems" }, ...row.problems.map((p) => h("li", { text: p }))),
  );
}

export function renderReport(report: Report, note?: string): HTMLElement {
  return showResult(
    report.valid ? "valid" : "invalid",
    h(
      "div",
      { class: "result-banner" },
      h("span", { class: "result-word", text: report.valid ? "Valid" : "Invalid" }),
      h("p", { class: "result-summary", text: summaryOf(report) }),
      h("ul", { class: "tags", attrs: { "aria-label": "Verification mode" } }, ...tagsOf(report).map((t) => h("li", { text: t }))),
    ),
    h(
      "div",
      { class: "result-body" },
      note !== undefined && h("p", { class: "callout", text: note }),
      !report.valid &&
        h("div", { class: "failures" }, h("h3", { text: "What failed" }), h("ul", {}, ...report.failures.map((f) => h("li", {}, h("code", { text: f }), ` ${failureLabel(f)}`)))),
      report.general.length > 0 && h("div", { class: "general" }, h("h3", { text: "About the input as a whole" }), h("ul", {}, ...report.general.map((g) => h("li", { text: g })))),
      h("details", { class: "checks", attrs: { open: "" } }, h("summary", { text: "What was checked" }), h("ul", {}, ...checksFor(report.mode, report.onChain, report.chained).map((c) => h("li", { text: c })))),
      h("ol", { class: "receipts", attrs: { "aria-label": "Receipts" } }, ...report.rows.map(receiptItem)),
    ),
  );
}

function fact(term: string, value: Child, note: string): HTMLElement {
  return h("div", { class: "fact" }, h("dt", { text: term }), h("dd", {}, value, h("span", { class: "note", text: note })));
}

export function renderDeploymentFacts(d: Deployment, status?: DeploymentStatus): void {
  const address = (a: string) => link(a, explorerUrl("address", a, d.cluster));
  const confirmed = (text: string) => (status === undefined ? "Not confirmed on chain" : text);
  byId("deployment-facts").replaceChildren(
    fact("GENKAI program", address(d.programId), confirmed(status?.programDeployed ? "Deployed and executable" : "No executable program found")),
    fact("PolicyRecord", address(d.policy), confirmed(`Status on chain: ${status?.policyStatus ?? ""}`)),
    fact("Policy commitment", d.commitment, "Salted SHA-256 commitment to the sealed policy"),
    fact("Circuit", d.circuitId, `Arcium cluster offset ${d.clusterOffset}`),
    fact("Policy authority", address(d.authority), `Policy id ${d.policyId}`),
    fact("Network", d.cluster, d.rpc),
  );
}

export function renderDeploymentStatus(state: "ok" | "bad", message: string, details: readonly string[] = []): void {
  const line = byId("deployment-status");
  line.className = `status-line ${state}`;
  line.replaceChildren(dot(state), h("span", {}, message, details.length > 0 && h("ul", {}, ...details.map((d) => h("li", { text: d })))));
}
