/**
 * The USDC run's evidence, file against file. The receipts the gateway served, the run record,
 * the agent's MCP session and the deployment manifest were written by different processes; they
 * must tell one story, or one of them is wrong.
 *
 * examples/devnet/usdc/policy.json is the policy that was sealed, published so a reader can see
 * why each verdict came out as it did. A sealed verifier never needs it, and nothing here proves
 * it is the sealed one: only the commitment, under a salt that stays secret, binds the policy.
 * Replaying it shows that it reaches every verdict the cluster reached.
 */

import { strict as assert } from "node:assert";
import { join } from "node:path";
import { test } from "node:test";
import { readJsonFile } from "../src/cli/files.ts";
import { fromJson } from "../src/io/json.ts";
import { parsePolicy, parseSignedReceipt } from "../src/io/schema.ts";
import { evaluate } from "../src/policy/engine.ts";
import { MANIFEST, ROOT, USDC_MANIFEST, USDC_RECEIPTS, USDC_RUN, USDC_TRANSCRIPT, USDC_TRUST } from "./helpers/devnet.ts";

const USDC = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

const receipts = (fromJson(USDC_RECEIPTS) as readonly unknown[]).map((r, i) => parseSignedReceipt(r, `receipts[${i}]`));

interface Line {
  readonly from: "client" | "server";
  readonly message: {
    readonly id?: number;
    readonly method?: string;
    readonly params?: { readonly name?: string; readonly arguments?: Readonly<Record<string, unknown>> };
    readonly result?: { readonly content: readonly { readonly text: string }[]; readonly structuredContent?: Readonly<Record<string, unknown>> };
  };
}

const session = USDC_TRANSCRIPT.trim().split("\n").map((line) => JSON.parse(line) as Line);
const answerTo = (id: number | undefined) => session.find((l) => l.from === "server" && l.message.id === id)?.message.result;
const payments = session.filter((l) => l.from === "client" && l.message.params?.name === "request_transfer");
const answers = payments.map((p) => answerTo(p.message.id));
const said = (n: number): string => answers[n]?.content[0]?.text ?? "";

test("the USDC run's trust anchor is its deployment's public facts: the same program, its own policy record", () => {
  const { commitment, circuitId, programId, policy, policyId, authority } = USDC_MANIFEST;
  assert.deepEqual(JSON.parse(USDC_TRUST), { commitment, circuitId, programId, policy });
  assert.equal(policyId, "desk-alpha-usdc");
  assert.equal(programId, MANIFEST["programId"]);
  assert.equal(authority, MANIFEST["authority"]);
  assert.notEqual(policy, MANIFEST["policy"]);
  assert.notEqual(commitment, MANIFEST["commitment"]);
});

test("every receipt is a devnet USDC transfer bound to the USDC commitment, and the run record agrees", () => {
  assert.equal(receipts.length, 5);
  for (const r of receipts) {
    assert.equal(r.body.request.asset, USDC);
    assert.equal(r.body.request.params["decimals"], 6);
    assert.equal(r.body.request.params["cluster"], "devnet");
    assert.equal(r.body.policyHash, USDC_MANIFEST["commitment"]);
  }
  assert.deepEqual(
    USDC_RUN.decisions.map((d) => [d.seq, d.verdict, d.signature]),
    receipts.map((r, i) => [i + 1, r.body.decision.verdict, r.body.transaction?.signature]),
  );
  // What the gateway says the agent spent is what its two allows moved: 1.25 + 2.5 USDC.
  const allowed = receipts.filter((r) => r.body.decision.verdict === "allow").reduce((sum, r) => sum + (r.body.request.amount ?? 0n), 0n);
  assert.equal(allowed, 3_750_000n);
  assert.equal(USDC_RUN.spendingStatus.spentInWindow, allowed.toString());
  assert.equal(USDC_RUN.spendingStatus.callsInWindow, 5);
});

test("the agent's MCP session is the run: one call per receipt, then a retry that paid nothing", () => {
  assert.equal(payments.length, 6);
  assert.deepEqual(answers.slice(0, 5).map((a) => a?.structuredContent?.["receiptId"]), receipts.map((r) => r.body.receiptId));
  assert.deepEqual(answers.slice(0, 5).map((a) => a?.structuredContent?.["verdict"]), receipts.map((r) => r.body.decision.verdict));
  for (const p of payments) assert.deepEqual([p.message.params?.arguments?.["token"], p.message.params?.arguments?.["decimals"]], [USDC, 6]);

  // The retry: the first request_id again, the first decision back, and no sixth receipt.
  assert.equal(payments[5]?.message.params?.arguments?.["request_id"], payments[0]?.message.params?.arguments?.["request_id"]);
  assert.equal(answers[5]?.structuredContent?.["replayed"], true);
  assert.equal(answers[5]?.structuredContent?.["receiptId"], receipts[0]?.body.receiptId);
  assert.deepEqual([USDC_RUN.replay.replayed, USDC_RUN.replay.receiptId], [true, receipts[0]?.body.receiptId]);

  // What the model was told is what was decided; an allow names the transaction it sent.
  assert.ok(said(0).startsWith(`ALLOWED. 1.25 of token ${USDC} to 7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE was signed and sent as transaction ${receipts[0]?.body.transaction?.signature}`));
  assert.match(said(1), /^DENIED by the spending policy \(counterparty_not_allowed\)\. Nothing was signed\./);
  assert.match(said(2), /^ESCALATED \(human_approval_required\): .*Nothing was signed or paid\./);
  assert.match(said(3), /^DENIED by the spending policy \(mint_cap_exceeded, amount_exceeds_window\)/);
  assert.match(said(5), /This is the decision already recorded for request_id "inv-a-1042", not a new one\./);
  // Each decision took the cluster over five seconds, so the client heard the call was alive.
  assert.equal(session.filter((l) => l.message.method === "notifications/progress").length, 5);
});

test("no API key crosses the agent's channel", () => {
  assert.doesNotMatch(USDC_TRANSCRIPT, /gk_[0-9a-f]{12}_/);
});

test("the published policy reaches every verdict the cluster reached", () => {
  const policy = parsePolicy(readJsonFile(join(ROOT, "examples", "devnet", "usdc", "policy.json")), "policy");
  for (const r of receipts) {
    const replayed = evaluate(policy, r.body.request, r.body.state, r.body.decision.decidedAt);
    assert.equal(replayed.verdict, r.body.decision.verdict, r.body.receiptId);
    assert.deepEqual(replayed.reasons.map((x) => x.rule), r.body.decision.reasons.map((x) => x.rule), r.body.receiptId);
  }
});
