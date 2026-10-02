/**
 * The browser verifier page: loads inputs, calls verify.ts, renders the answer. Validity is
 * decided entirely by verify.ts and the core it shares with the CLI and the hosted API.
 */

import { parseDeployment, type Deployment } from "../../src/cli/deployment.ts";
import { fromJson } from "../../src/io/json.ts";
import { createRpcClient } from "../../src/solana/rpc.ts";
import { checkDeployment } from "./deployment.ts";
import { byId, prefersReducedMotion } from "./dom.ts";
import { renderDeploymentFacts, renderDeploymentStatus, renderError, renderPending, renderReport } from "./render.ts";
import { rewriteFirstDenial, tamperNote } from "./tamper.ts";
import { DEFAULT_RPC, verifyDocuments } from "./verify.ts";

const MAX_FILE_BYTES = 5 * 1024 * 1024;

const SAMPLES = {
  gateway: { receipts: "/examples/devnet/gateway/receipts.json", anchor: "/examples/devnet/trust.json" },
  sealed: { receipts: "/examples/devnet/sealed-receipts.json", anchor: "/examples/devnet/trust.json" },
  plaintext: { receipts: "/examples/devnet/plaintext-receipts.json", anchor: "/examples/devnet/policy.json" },
} as const;

type Sample = keyof typeof SAMPLES | "tamper";

const receiptsInput = byId<HTMLTextAreaElement>("receipts-input");
const anchorInput = byId<HTMLTextAreaElement>("anchor-input");
const rpcInput = byId<HTMLInputElement>("rpc-input");
const formNote = byId("form-note");
const result = byId("result");
const busyControls = (): readonly HTMLButtonElement[] => [...document.querySelectorAll<HTMLButtonElement>("[data-sample], #verify-button")];

async function fetchText(path: string): Promise<string> {
  const res = await fetch(path, { cache: "no-cache" });
  if (!res.ok) throw new Error(`Could not load ${path}: HTTP ${res.status}`);
  return res.text();
}

function setBusy(busy: boolean): void {
  for (const control of busyControls()) control.disabled = busy;
}

function revealResult(): void {
  result.focus({ preventScroll: true });
  result.scrollIntoView({ behavior: prefersReducedMotion() ? "auto" : "smooth", block: "start" });
}

async function runVerification(note?: string): Promise<void> {
  setBusy(true);
  formNote.textContent = "";
  renderPending("Verifying receipts and reading their records on chain…");
  try {
    const report = await verifyDocuments({ receipts: receiptsInput.value, anchor: anchorInput.value, rpcEndpoint: rpcInput.value });
    renderReport(report, note);
  } catch (err) {
    console.error(err);
    renderError(err);
  } finally {
    setBusy(false);
    revealResult();
  }
}

async function loadSample(sample: Sample): Promise<void> {
  const source = sample === "tamper" ? SAMPLES.gateway : SAMPLES[sample];
  setBusy(true);
  renderPending("Loading the devnet sample…");
  try {
    const [receipts, anchor] = await Promise.all([fetchText(source.receipts), fetchText(source.anchor)]);
    const forged = sample === "tamper" ? rewriteFirstDenial(receipts) : undefined;
    receiptsInput.value = forged?.text ?? receipts;
    anchorInput.value = anchor;
    rpcInput.value = DEFAULT_RPC;
    await runVerification(forged === undefined ? undefined : tamperNote(forged.index));
  } catch (err) {
    console.error(err);
    renderError(err);
    setBusy(false);
  }
}

async function readFileInto(file: File, target: HTMLTextAreaElement): Promise<void> {
  if (file.size > MAX_FILE_BYTES) {
    formNote.textContent = `${file.name} is larger than 5 MB, which is more than any receipt run needs.`;
    return;
  }
  target.value = await file.text();
  target.dispatchEvent(new Event("input", { bubbles: true }));
  formNote.textContent = `Loaded ${file.name}.`;
}

function markStale(): void {
  if (result.hidden || result.classList.contains("stale")) return;
  result.classList.add("stale");
  formNote.textContent = "The inputs changed. Verify again to update the result.";
}

function wireDrop(area: HTMLTextAreaElement): void {
  area.addEventListener("dragover", (event) => {
    event.preventDefault();
    area.classList.add("dragging");
  });
  area.addEventListener("dragleave", () => area.classList.remove("dragging"));
  area.addEventListener("drop", (event) => {
    area.classList.remove("dragging");
    const file = event.dataTransfer?.files[0];
    if (file === undefined) return;
    event.preventDefault();
    void readFileInto(file, area);
  });
}

function wireForm(): void {
  rpcInput.value = DEFAULT_RPC;
  byId<HTMLFormElement>("verify-form").addEventListener("submit", (event) => {
    event.preventDefault();
    void runVerification();
  });
  for (const field of [receiptsInput, anchorInput, rpcInput]) field.addEventListener("input", markStale);
  for (const area of [receiptsInput, anchorInput]) wireDrop(area);
  for (const input of document.querySelectorAll<HTMLInputElement>("input[type=file][data-target]")) {
    input.addEventListener("change", () => {
      const file = input.files?.[0];
      const target = document.getElementById(input.dataset["target"] ?? "");
      if (file !== undefined && target instanceof HTMLTextAreaElement) void readFileInto(file, target);
      input.value = "";
    });
  }
  for (const button of document.querySelectorAll<HTMLButtonElement>("[data-sample]")) {
    button.addEventListener("click", () => void loadSample(button.dataset["sample"] as Sample));
  }
}

async function loadManifest(): Promise<{ readonly manifest: unknown; readonly deployment: Deployment } | { readonly error: string }> {
  try {
    const manifest = fromJson(await fetchText("/deployment.json"));
    return { manifest, deployment: parseDeployment(manifest, "deployment") };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

async function showDeployment(): Promise<void> {
  const loaded = await loadManifest();
  if ("error" in loaded) {
    renderDeploymentStatus("bad", `The deployment manifest could not be loaded: ${loaded.error}`);
    return;
  }
  const { manifest, deployment } = loaded;
  renderDeploymentFacts(deployment);
  try {
    const status = await checkDeployment(manifest, createRpcClient({ endpoint: deployment.rpc, retries: 2 }));
    renderDeploymentFacts(deployment, status);
    if (status.problems.length === 0) {
      renderDeploymentStatus("ok", `Confirmed on ${deployment.cluster} just now: the program is deployed, the PolicyRecord is active, and its commitment and authority match the manifest.`);
    } else {
      renderDeploymentStatus("bad", "The chain disagrees with the published manifest:", status.problems);
    }
  } catch (err) {
    renderDeploymentStatus("bad", `Could not read ${deployment.cluster} to confirm the deployment: ${(err as Error).message}`);
  }
}

function showApiExample(): void {
  const example = byId("api-example");
  example.textContent = (example.textContent ?? "").replace("https://this-site", window.location.origin);
}

wireForm();
showApiExample();
void showDeployment();
