/**
 * Broadcast and confirmation.
 *
 * The executor is the only component that talks to a cluster, and it holds no key. It fetches
 * a blockhash, asks the adapter for a decision, and broadcasts only what the adapter signed.
 * Whether a transfer executed is then a fact the chain records, checkable by anyone, rather
 * than a claim the operator writes into a receipt.
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { generateKeypair } from "../src/receipt/sign.ts";
import { createPlaintextPolicyProvider } from "../src/policy/sealed.ts";
import { createSolanaAdapter } from "../src/solana/adapter.ts";
import { createExecutor, verifyExecution } from "../src/solana/executor.ts";
import { solanaAddress } from "../src/solana/keys.ts";
import { RpcError, type RpcClient, type SignatureStatus } from "../src/solana/rpc.ts";
import { SOLANA_TRANSFER_TOOL, SYSTEM_PROGRAM_ID, NATIVE_SOL_MINT, type SolanaTransfer } from "../src/solana/types.ts";
import type { AgentState, Policy } from "../src/policy/types.ts";

const AT = Date.UTC(2026, 8, 1, 9, 0, 0);
const KEYS = generateKeypair();
const VAULT = solanaAddress(KEYS.publicKey);
const VENDOR = "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE";
const BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";

const policy: Policy = {
  policyId: "ops",
  version: 1,
  allowedTools: [SOLANA_TRANSFER_TOOL],
  allowedClusters: ["devnet"],
  allowedPrograms: [SYSTEM_PROGRAM_ID],
  allowedMints: [NATIVE_SOL_MINT],
  maxAmountPerMint: { [NATIVE_SOL_MINT]: 1_000_000_000n },
};
const state: AgentState = { spentInWindow: 0n, windowStartedAt: AT, callsInWindow: 0, drawdownFromPeak: 0n, revoked: false };
const transfer = (amount: bigint): SolanaTransfer => ({
  kind: "sol",
  programId: SYSTEM_PROGRAM_ID,
  cluster: "devnet",
  from: VAULT,
  to: VENDOR,
  decimals: 9,
  amount,
  requestedAt: AT,
});

interface FakeChain {
  readonly rpc: RpcClient;
  readonly sent: string[];
  height: number;
  statuses: Map<string, SignatureStatus>;
  wires: Map<string, Uint8Array>;
}

function fakeChain(opts: { confirmAfterPolls?: number; rejectSend?: boolean } = {}): FakeChain {
  const chain: FakeChain = {
    sent: [],
    height: 100,
    statuses: new Map(),
    wires: new Map(),
    rpc: undefined as unknown as RpcClient,
  };
  let polls = 0;
  let lastSig = "";
  const rpc: RpcClient = {
    getLatestBlockhash: async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 150 }),
    getBlockHeight: async () => chain.height,
    sendTransaction: async (wire) => {
      if (opts.rejectSend) throw new RpcError("rpc", "Transaction simulation failed: insufficient funds", -32002);
      chain.sent.push(wire);
      const bytes = Buffer.from(wire, "base64");
      const { encodeBase58 } = await import("../src/solana/base58.ts");
      lastSig = encodeBase58(bytes.subarray(1, 65));
      chain.wires.set(lastSig, new Uint8Array(bytes));
      return lastSig;
    },
    getSignatureStatuses: async (sigs) => {
      polls++;
      chain.height += 10;
      return sigs.map((s) => {
        if (polls >= (opts.confirmAfterPolls ?? 2) && chain.wires.has(s)) {
          return { slot: 4242, err: null, confirmationStatus: "confirmed" as const };
        }
        return null;
      });
    },
    getTransaction: async (sig) => {
      const wire = chain.wires.get(sig);
      return wire ? { slot: 4242, wire, err: null } : null;
    },
    getAccountInfo: async () => null,
  };
  return Object.assign(chain, { rpc });
}

const adapter = createSolanaAdapter({ agentId: "agent-1", keys: KEYS, provider: createPlaintextPolicyProvider(policy) });
const executorFor = (chain: FakeChain) =>
  createExecutor({ adapter, rpc: chain.rpc, now: () => AT, sleep: async () => {}, pollIntervalMs: 1 });

test("an allowed transfer is broadcast and confirmed", async () => {
  const chain = fakeChain();
  const result = await executorFor(chain).execute({ transfer: transfer(1_000n), state });

  assert.equal(result.submission.decision.verdict, "allow");
  assert.equal(chain.sent.length, 1);
  assert.equal(result.execution?.status, "confirmed");
  assert.equal(result.execution?.signature, result.submission.receipt.body.transaction?.signature);
  assert.equal(result.execution?.slot, 4242);
});

test("a denied transfer never reaches the cluster", async () => {
  const chain = fakeChain();
  const result = await executorFor(chain).execute({ transfer: transfer(2_000_000_000n), state });
  assert.equal(result.submission.decision.verdict, "deny");
  assert.equal(chain.sent.length, 0);
  assert.equal(result.execution, undefined);
});

test("a transaction that outlives its blockhash is reported as expired, not pending forever", async () => {
  const chain = fakeChain({ confirmAfterPolls: 1_000 });
  const result = await executorFor(chain).execute({ transfer: transfer(1_000n), state });
  assert.equal(result.execution?.status, "expired");
});

test("a broadcast the cluster rejects is reported with its reason", async () => {
  const chain = fakeChain({ rejectSend: true });
  const result = await executorFor(chain).execute({ transfer: transfer(1_000n), state });
  assert.equal(result.execution?.status, "rejected");
  assert.match(result.execution?.error ?? "", /insufficient funds/);
});

test("execution is verified from the chain against the receipt, not from the operator", async () => {
  const chain = fakeChain();
  const { submission } = await executorFor(chain).execute({ transfer: transfer(1_000n), state });

  const ok = await verifyExecution(submission.receipt, chain.rpc);
  assert.deepEqual(ok, { executed: true, slot: 4242, failure: undefined });

  // The chain holds a different transaction under the receipt's signature.
  const signature = submission.receipt.body.transaction?.signature ?? "";
  const tampered = new Uint8Array(chain.wires.get(signature) ?? []);
  const last = tampered.length - 1;
  tampered[last] = (tampered[last] ?? 0) ^ 1;
  chain.wires.set(signature, tampered);
  const bad = await verifyExecution(submission.receipt, chain.rpc);
  assert.equal(bad.executed, false);
  assert.equal(bad.failure, "message_mismatch");
});

test("a receipt with no bound transaction has nothing to verify on chain", async () => {
  const chain = fakeChain();
  const { submission } = await executorFor(chain).execute({ transfer: transfer(2_000_000_000n), state });
  const result = await verifyExecution(submission.receipt, chain.rpc);
  assert.deepEqual(result, { executed: false, slot: undefined, failure: "no_transaction" });
});
