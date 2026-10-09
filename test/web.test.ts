/**
 * The browser verifier's logic, run under Node against the real devnet run.
 *
 * The receipts are the ones the Arcium cluster decided on devnet; the chain state is a snapshot
 * of the accounts they point at. What the page tells a visitor - valid, which receipt failed
 * and why, what landed on chain - is asserted here rather than eyeballed in a browser.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { fromJson, toJson } from "../src/io/json.ts";
import type { Canonicalisable } from "../src/receipt/canonical.ts";
import { createRpcClient } from "../src/solana/rpc.ts";
import { checkDeployment } from "../web/src/deployment.ts";
import { checksFor, describeAction, explorerUrl, failureLabel, formatTime, formatUnits, shortAddress } from "../web/src/format.ts";
import { rewriteFirstDenial, tamperNote } from "../web/src/tamper.ts";
import { VerifyError, verifyDocuments } from "../web/src/verify.ts";
import {
  ACCOUNTS,
  DEVNET_RPC,
  GATEWAY_RECEIPTS,
  LANDED,
  MANIFEST,
  PLAINTEXT_RECEIPTS,
  POLICY,
  SEALED_RECEIPTS,
  TRUST,
  USDC_RECEIPTS,
  USDC_RUN,
  USDC_TRUST,
  devnetFetch,
} from "./helpers/devnet.ts";

const sealed = (receipts = SEALED_RECEIPTS, fetch = devnetFetch(), anchor = TRUST) =>
  verifyDocuments({ receipts, anchor, rpcEndpoint: DEVNET_RPC, fetch });

const rejectsWith = async (work: Promise<unknown>, kind: "input" | "rpc", pattern: RegExp) => {
  await assert.rejects(work, (err: unknown) => {
    assert.ok(err instanceof VerifyError, `expected a VerifyError, got ${String(err)}`);
    assert.equal(err.kind, kind);
    assert.match(err.message, pattern);
    return true;
  });
};

test("the devnet run verifies against the cluster's records on chain", async () => {
  const calls: string[] = [];
  const report = await sealed(SEALED_RECEIPTS, devnetFetch({ calls }));

  assert.equal(report.valid, true, report.rows.flatMap((r) => r.problems).join("\n"));
  assert.equal(report.mode, "sealed");
  assert.equal(report.onChain, true);
  assert.equal(report.chained, true);
  assert.deepEqual(report.failures, []);
  assert.deepEqual(report.rows.map((r) => r.verdict), ["allow", "deny", "escalate", "deny", "allow"]);
  assert.deepEqual(report.rows.map((r) => r.problems.length), [0, 0, 0, 0, 0]);

  const first = report.rows[0];
  assert.equal(first?.action, "solana transfer 0.01 SOL to 7VHU…4BmE");
  assert.equal(first?.decisionRecord, "9dkMNMbZ6chVHSUyz2t3mkV7awHGce4TJcjJyUGTVjgG");
  assert.equal(first?.disclosure, "rules");
  assert.equal(first?.cluster, "devnet");
  assert.deepEqual(report.rows[3]?.rules, ["mint_cap_exceeded", "amount_exceeds_window"]);
  // Signed and bound, never broadcast: the page must say so rather than link to nothing.
  assert.deepEqual(first?.transactionStatus, { state: "not_found" });
  assert.equal(report.rows[1]?.transactionSignature, undefined);
  // One read per DecisionRecord, one for the PolicyRecord they share, then one batched status call.
  assert.deepEqual(calls, [...Array(6).fill("getAccountInfo"), "getSignatureStatuses"]);
});

test("the gateway run verifies on chain, and the transfers it allowed landed", async () => {
  const calls: string[] = [];
  const report = await sealed(GATEWAY_RECEIPTS, devnetFetch({ landed: LANDED, calls }));

  assert.equal(report.valid, true, report.rows.flatMap((r) => r.problems).join("\n"));
  assert.equal(report.onChain, true);
  assert.equal(report.chained, true);
  assert.deepEqual(report.rows.map((r) => r.verdict), ["allow", "deny", "escalate", "deny", "allow"]);
  assert.equal(report.rows[4]?.action, "solana transfer 0.015 SOL to 9WzD…AWWM");
  // What the gateway broadcast is on chain at the slots the snapshot recorded; a refusal binds nothing.
  assert.deepEqual(report.rows.map((r) => r.transactionStatus), [
    { state: "landed", slot: 506503732 },
    undefined,
    undefined,
    undefined,
    { state: "landed", slot: 506503976 },
  ]);
  assert.deepEqual(calls, [...Array(6).fill("getAccountInfo"), "getSignatureStatuses"]);
});

test("the USDC run verifies against its own policy record, and the USDC it allowed landed", async () => {
  const calls: string[] = [];
  const report = await sealed(USDC_RECEIPTS, devnetFetch({ landed: LANDED, calls }), USDC_TRUST);

  assert.equal(report.valid, true, report.rows.flatMap((r) => r.problems).join("\n"));
  assert.equal(report.onChain, true);
  assert.equal(report.chained, true);
  assert.deepEqual(report.rows.map((r) => r.verdict), ["allow", "deny", "escalate", "deny", "allow"]);
  assert.deepEqual(report.rows.map((r) => r.action), [
    "solana transfer 1.25 USDC to 7VHU…4BmE",
    "solana transfer 0.5 USDC to Gsbw…QRdW",
    "solana transfer 4 USDC to 9WzD…AWWM",
    "solana transfer 12 USDC to 7VHU…4BmE",
    "solana transfer 2.5 USDC to 9WzD…AWWM",
  ]);
  assert.deepEqual(report.rows[3]?.rules, ["mint_cap_exceeded", "amount_exceeds_window"]);
  // The slots the run recorded are the ones the snapshot read back from devnet.
  assert.deepEqual(
    report.rows.map((r) => r.transactionStatus),
    USDC_RUN.decisions.map((d) => (d.finalizedSlot === undefined ? undefined : { state: "landed", slot: d.finalizedSlot })),
  );
  assert.deepEqual(calls, [...Array(6).fill("getAccountInfo"), "getSignatureStatuses"]);

  // The SOL deployment's anchor pins a different PolicyRecord and commitment: nothing verifies.
  const crossed = await sealed(USDC_RECEIPTS, devnetFetch({ landed: LANDED }), TRUST);
  assert.equal(crossed.valid, false);
  assert.ok(crossed.failures.includes("commitment_mismatch"), crossed.failures.join(", "));
});

for (const [run, receipts, anchor] of [
  ["CLI run", SEALED_RECEIPTS, TRUST],
  ["gateway run", GATEWAY_RECEIPTS, TRUST],
  ["USDC run", USDC_RECEIPTS, USDC_TRUST],
] as const) {
  test(`rewriting a denial as an approval in the ${run} is caught by the signature, the chain and the record on chain`, async () => {
    const forged = rewriteFirstDenial(receipts);
    assert.equal(forged.index, 1);
    assert.match(tamperNote(forged.index), /^Receipt #2 /);

    const report = await sealed(forged.text, devnetFetch({ landed: LANDED }), anchor);
    assert.equal(report.valid, false);
    assert.deepEqual([...report.failures].sort(), ["attestation_invalid", "bad_signature", "chain_broken"]);
    assert.deepEqual(report.rows.map((r) => r.verdict), ["allow", "allow", "escalate", "deny", "allow"]);
    assert.deepEqual(report.rows.map((r) => r.problems.length > 0), [false, true, true, false, false]);
    assert.ok(report.rows[1]?.problems.some((p) => /verdict_mismatch/.test(p)), "the cluster's record still says deny");
    assert.ok(report.rows[2]?.problems.some((p) => /previous/.test(p)), "the next receipt no longer links");
    assert.deepEqual(report.general, []);
  });
}

test("the plaintext run replays against the published policy", async () => {
  const report = await verifyDocuments({ receipts: PLAINTEXT_RECEIPTS, anchor: POLICY, rpcEndpoint: DEVNET_RPC, fetch: devnetFetch() });
  assert.equal(report.valid, true);
  assert.equal(report.mode, "plaintext");
  assert.equal(report.onChain, false);
  assert.deepEqual(report.rows.map((r) => r.verdict), ["allow", "deny", "escalate", "deny", "allow"]);
  assert.equal(report.rows[0]?.disclosure, undefined);
  assert.equal(report.rows[1]?.rules[0], "counterparty_not_allowed");
});

test("a single receipt is checked on its own, and a landed transfer is reported with its slot", async () => {
  const receipts = fromJson(SEALED_RECEIPTS) as readonly Canonicalisable[];
  const last = receipts[4] as { body: { transaction: { signature: string } } };
  const fetch = devnetFetch({ landed: { [last.body.transaction.signature]: 4242 } });
  const report = await sealed(toJson(receipts[4] as Canonicalisable), fetch);
  assert.equal(report.valid, true);
  assert.equal(report.chained, false);
  assert.equal(report.rows.length, 1);
  assert.deepEqual(report.rows[0]?.transactionStatus, { state: "landed", slot: 4242 });
});

test("without an RPC endpoint an on-chain attestation is unchecked, never valid", async () => {
  const report = await verifyDocuments({ receipts: SEALED_RECEIPTS, anchor: TRUST });
  assert.equal(report.valid, false);
  assert.equal(report.onChain, false);
  assert.deepEqual(report.failures, ["attestation_unchecked"]);
  assert.equal(report.rows[0]?.transactionStatus, undefined);
});

test("a record missing from the chain fails that receipt alone", async () => {
  const { ["FZFe6LMXEuW8CisUBeW31o2pFDAZu9yoFBXVanJh2bYF"]: _gone, ...rest } = ACCOUNTS;
  const report = await sealed(SEALED_RECEIPTS, devnetFetch({ accounts: rest }));
  assert.equal(report.valid, false);
  assert.deepEqual(report.rows.map((r) => r.problems.length > 0), [false, true, false, false, false]);
  assert.match(report.rows[1]?.problems[0] ?? "", /not_found/);
});

test("input that cannot be checked is reported as such, not as an invalid receipt", async () => {
  await rejectsWith(verifyDocuments({ receipts: "  ", anchor: TRUST }), "input", /Paste or load the receipts/);
  await rejectsWith(verifyDocuments({ receipts: "[{", anchor: TRUST }), "input", /receipts is not valid JSON/);
  await rejectsWith(verifyDocuments({ receipts: SEALED_RECEIPTS, anchor: "[]" }), "input", /must be a JSON object/);
  await rejectsWith(verifyDocuments({ receipts: "[{}]", anchor: TRUST }), "input", /receipts\[0\]/);
  await rejectsWith(verifyDocuments({ receipts: SEALED_RECEIPTS, anchor: TRUST, rpcEndpoint: "ftp://devnet" }), "input", /http\(s\)/);
});

test("an unreachable RPC endpoint is an RPC error, not a verdict", async () => {
  const down = async (): Promise<Response> => {
    throw new TypeError("fetch failed");
  };
  await rejectsWith(sealed(SEALED_RECEIPTS, down), "rpc", /could not be read/);
});

test("the deployment panel confirms the manifest against the chain", async () => {
  const rpc = (accounts = ACCOUNTS) => createRpcClient({ endpoint: DEVNET_RPC, fetch: devnetFetch({ accounts }) });
  const live = await checkDeployment(MANIFEST, rpc());
  assert.deepEqual(live.problems, []);
  assert.equal(live.programDeployed, true);
  assert.equal(live.policyStatus, "active");

  const forged = await checkDeployment({ ...MANIFEST, commitment: "00".repeat(32), authority: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM" }, rpc());
  assert.equal(forged.problems.length, 2);
  assert.match(forged.problems.join("\n"), /commitment[\s\S]*authority/);

  const { [String(MANIFEST["policy"])]: _gone, ...noPolicy } = ACCOUNTS;
  const missing = await checkDeployment(MANIFEST, rpc(noPolicy));
  assert.equal(missing.policyStatus, "missing");

  const foreign = await checkDeployment(MANIFEST, rpc({ ...ACCOUNTS, [String(MANIFEST["policy"])]: { ...ACCOUNTS[String(MANIFEST["policy"])]!, owner: "11111111111111111111111111111111" } }));
  assert.equal(foreign.policyStatus, "foreign");
});

test("display helpers are exact and never shape a URL from receipt content", () => {
  assert.equal(formatUnits(10_000_000n, 9), "0.01");
  assert.equal(formatUnits(-1_500_000_000n, 9), "-1.5");
  assert.equal(formatUnits(5n, 0), "5");
  assert.equal(formatUnits(123n, 19), "123");
  assert.equal(shortAddress("short"), "short");
  assert.equal(shortAddress("7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE"), "7VHU…4BmE");
  assert.equal(
    describeAction({ agentId: "a", tool: "spl_transfer", amount: 2500n, asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", requestedAt: 0, params: { decimals: 3 } }),
    "spl transfer 2.5 EPjF…Dt1v",
  );
  assert.equal(describeAction({ agentId: "a", tool: "noop", requestedAt: 0, params: {} }), "noop");
  // A mint is named only on the cluster where that address is the token: Circle's USDC.
  const pay = (asset: string, cluster: string) =>
    describeAction({ agentId: "a", tool: "solana_transfer", amount: 1_250_000n, asset, counterparty: "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE", requestedAt: 0, params: { decimals: 6, cluster } });
  assert.equal(pay("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "devnet"), "solana transfer 1.25 USDC to 7VHU…4BmE");
  assert.equal(pay("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "mainnet-beta"), "solana transfer 1.25 USDC to 7VHU…4BmE");
  assert.equal(pay("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "mainnet-beta"), "solana transfer 1.25 4zMM…ncDU to 7VHU…4BmE");
  assert.equal(pay("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "__proto__"), "solana transfer 1.25 EPjF…Dt1v to 7VHU…4BmE");

  const address = "9dkMNMbZ6chVHSUyz2t3mkV7awHGce4TJcjJyUGTVjgG";
  assert.equal(explorerUrl("address", address, "devnet"), `https://explorer.solana.com/address/${address}?cluster=devnet`);
  assert.equal(explorerUrl("address", address, "mainnet-beta"), `https://explorer.solana.com/address/${address}`);
  assert.equal(explorerUrl("address", address, "localnet"), undefined);
  assert.equal(explorerUrl("address", address, undefined), undefined);
  assert.equal(explorerUrl("tx", "javascript:alert(1)", "devnet"), undefined);
  assert.equal(explorerUrl("tx", `${address}?x=1`, "devnet"), undefined);

  assert.equal(formatTime(0), "1970-01-01 00:00:00 UTC");
  assert.equal(formatTime(Number.NaN), "unknown time");
  assert.equal(formatTime(9e15), "unknown time");
  assert.match(failureLabel("bad_signature"), /signature/);
  assert.equal(failureLabel("something_new"), "something_new");

  assert.ok(checksFor("plaintext", false, true).some((c) => /Replaying/.test(c)));
  assert.ok(checksFor("sealed", true, false).some((c) => /DecisionRecord/.test(c)));
  assert.ok(!checksFor("sealed", true, false).some((c) => /links to the hash/.test(c)));
  assert.ok(checksFor("sealed", false, true).some((c) => /cluster key/.test(c)));
});

test("the tamper demonstration refuses input it cannot forge", () => {
  assert.throws(() => rewriteFirstDenial("{}"), /not a list/);
  assert.throws(() => rewriteFirstDenial(PLAINTEXT_RECEIPTS.replace(/"verdict": "deny"/g, '"verdict": "escalate"')), /no denial/);
});
