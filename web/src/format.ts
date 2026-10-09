/**
 * Display helpers for the browser verifier. Pure functions of receipt data, so they are tested
 * in Node and the page only arranges their output.
 */

import type { ActionRequest } from "../../src/policy/types.ts";
import type { VerificationFailure } from "../../src/receipt/types.ts";

/** The wrapped-SOL mint, which GENKAI policies also use to name native SOL. */
export const NATIVE_MINT = "So11111111111111111111111111111111111111112";

const EXPLORER_CLUSTERS = new Set(["devnet", "testnet", "mainnet-beta"]);
const BASE58_ID = /^[1-9A-HJ-NP-Za-km-z]{32,88}$/;

export function shortAddress(address: string): string {
  return address.length <= 12 ? address : `${address.slice(0, 4)}…${address.slice(-4)}`;
}

/** An integer amount in minor units as an exact decimal string, trailing zeros trimmed. */
export function formatUnits(amount: bigint, decimals: number): string {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) return amount.toString();
  const negative = amount < 0n;
  const magnitude = negative ? -amount : amount;
  const base = 10n ** BigInt(decimals);
  const fraction = (magnitude % base).toString().padStart(decimals, "0").replace(/0+$/, "");
  return `${negative ? "-" : ""}${magnitude / base}${fraction ? `.${fraction}` : ""}`;
}

function decimalsOf(request: ActionRequest): number {
  const d = request.params["decimals"];
  return typeof d === "number" && Number.isInteger(d) && d >= 0 && d <= 18 ? d : 0;
}

/** Tokens shown by symbol. A mint address is only that token on the cluster it was minted on. */
const TOKEN_SYMBOLS: ReadonlyMap<string, string> = new Map([
  ["devnet 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "USDC"],
  ["mainnet-beta EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "USDC"],
]);

function symbolOf(request: ActionRequest): string {
  const asset = request.asset;
  if (!asset) return "";
  if (asset === NATIVE_MINT) return "SOL";
  return TOKEN_SYMBOLS.get(`${clusterOf(request)} ${asset}`) ?? shortAddress(asset);
}

export function describeAmount(request: ActionRequest): string | undefined {
  if (request.amount === undefined) return undefined;
  return [formatUnits(request.amount, decimalsOf(request)), symbolOf(request)].filter((p) => p !== "").join(" ");
}

/** "solana transfer 0.01 SOL to 7VHU...4BmE" */
export function describeAction(request: ActionRequest): string {
  return [
    request.tool.replace(/_/g, " "),
    describeAmount(request),
    request.counterparty === undefined ? undefined : `to ${shortAddress(request.counterparty)}`,
  ]
    .filter((p): p is string => p !== undefined && p !== "")
    .join(" ");
}

export function clusterOf(request: ActionRequest): string | undefined {
  const cluster = request.params["cluster"];
  return typeof cluster === "string" ? cluster : undefined;
}

/**
 * A Solana Explorer link, or undefined when the cluster has no public explorer. Ids are
 * checked as base58 first, so receipt content can never shape the URL beyond the id itself.
 */
export function explorerUrl(kind: "address" | "tx", id: string, cluster: string | undefined): string | undefined {
  if (!BASE58_ID.test(id) || cluster === undefined || !EXPLORER_CLUSTERS.has(cluster)) return undefined;
  return `https://explorer.solana.com/${kind}/${id}${cluster === "mainnet-beta" ? "" : `?cluster=${cluster}`}`;
}

export function formatTime(ms: number): string {
  if (!Number.isFinite(ms)) return "unknown time";
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? "unknown time" : date.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

export const FAILURE_LABELS: Readonly<Record<VerificationFailure, string>> = {
  bad_signature: "The operator's signature does not cover this receipt",
  policy_hash_mismatch: "The receipt is bound to a different policy",
  decision_not_reproducible: "Replaying the policy gives a different decision",
  chain_broken: "A receipt does not link to the one before it",
  transaction_mismatch: "The signed transaction is not the one the policy evaluated",
  commitment_mismatch: "The receipt is bound to a different policy commitment",
  attestation_missing: "A sealed receipt carries no MXE attestation",
  attestation_invalid: "The MXE attestation does not hold",
  attestation_unchecked: "The on-chain decision record was not read",
  disclosure_leak: "The receipt reveals more than the cluster attested",
};

export function failureLabel(failure: string): string {
  return (FAILURE_LABELS as Readonly<Record<string, string>>)[failure] ?? failure;
}

/** What a verification of this kind establishes, in the order the verifier checks it. */
export function checksFor(mode: "plaintext" | "sealed", onChain: boolean, chained: boolean): readonly string[] {
  const shared = [
    "Ed25519 operator signature over each canonical receipt body",
    ...(chained ? ["Every receipt links to the hash of the one before it"] : []),
    "Any signed transaction is the fee payer's signature over the message rebuilt from the evaluated request",
  ];
  if (mode === "plaintext") {
    return [
      "The supplied policy hashes to the policy each receipt is bound to",
      "Replaying the policy engine reproduces every verdict and every firing rule",
      ...shared,
    ];
  }
  return [
    "Each receipt is bound to the pinned policy commitment",
    onChain
      ? "The DecisionRecord on chain was written by the pinned program, against the pinned PolicyRecord, for this computation, request, verdict and disclosure mode"
      : "The MXE attestation is checked against the pinned cluster key",
    "No reason text beyond the rule ids the cluster attested",
    ...shared,
  ];
}
