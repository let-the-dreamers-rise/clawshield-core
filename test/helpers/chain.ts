/**
 * A fake GENKAI deployment: account bytes laid out exactly as programs/genkai/src/lib.rs writes
 * them, and an RpcClient that serves them. Shared by the on-chain verifier and live MXE client
 * tests so both are held to one definition of the layout.
 */

import { createHash } from "node:crypto";
import { encodeBase58, decodePubkey } from "../../src/solana/base58.ts";
import { encodePolicy, encodeRequest } from "../../src/mxe/encoding.ts";
import { evaluateCircuit } from "../../src/mxe/circuit.ts";
import { decisionRecordAddress, decodeRequestFields, encodeRequestFields, REQUEST_FIELDS_SIZE } from "../../src/mxe/onchain.ts";
import type { AccountInfo, RpcClient, SignatureStatus } from "../../src/solana/rpc.ts";
import type { ActionRequest, AgentState, Policy } from "../../src/policy/types.ts";

export const PROGRAM = "AwiVMGyi8P9mN6ig5FA74CTS6sncc7bbh8CNAxKXUERk";
export const BLOCKHASH = "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N";

const disc = (name: string) => createHash("sha256").update(`account:${name}`).digest().subarray(0, 8);

export const u64 = (x: bigint): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(x);
  return b;
};

export function policyIdBytes(policyId: string): Buffer {
  const out = Buffer.alloc(32);
  Buffer.from(policyId).copy(out);
  return out;
}

export function policyRecordBytes(o: { authority: string; policyId: string; commitment: string; status?: number }): Uint8Array {
  return Buffer.concat([
    disc("PolicyRecord"),
    decodePubkey(o.authority),
    policyIdBytes(o.policyId),
    Buffer.from(o.commitment, "hex"),
    Buffer.alloc(32, 7),
    Buffer.alloc(16, 1),
    Buffer.from([o.status ?? 1, 254, 87]),
    Buffer.alloc(5),
    Buffer.alloc(87 * 32, 9),
  ]);
}

export interface DecisionBytes {
  readonly policy: string;
  readonly offset: bigint;
  readonly sealedPolicy: Policy;
  readonly request: ActionRequest;
  readonly state: AgentState;
  readonly discloseRules?: boolean;
  readonly verdict?: number;
  readonly mask?: number;
  readonly status?: number;
  /** Record the fields of a different request than the one evaluated. */
  readonly fieldsFor?: ActionRequest;
}

/** The record the callback writes after the cluster evaluated `request` under `sealedPolicy`. */
export function decisionRecordBytes(o: DecisionBytes): Uint8Array {
  const out = evaluateCircuit(encodePolicy(o.sealedPolicy), encodeRequest(o.request, o.state));
  const disclose = o.discloseRules ?? true;
  return Buffer.concat([
    disc("DecisionRecord"),
    decodePubkey(o.policy),
    u64(o.offset),
    encodeRequestFields(encodeRequest(o.fieldsFor ?? o.request, o.state)),
    Buffer.from([o.status ?? 1, o.verdict ?? out.verdict]),
    Buffer.from(Uint32Array.of(o.mask ?? (disclose ? out.mask : 0)).buffer),
    u64(100n),
    u64(105n),
    Buffer.from([255, disclose ? 1 : 0]),
  ]);
}

/** evaluate's instruction data: discriminator, offset, RequestFields, disclose_rules. */
const EVALUATE_DATA = 8 + 8 + REQUEST_FIELDS_SIZE + 1;

/**
 * A deployment whose cluster decides whatever evaluate asks of it. evaluate is the last
 * instruction the live client sends, so its data is the tail of the wire transaction; the
 * cluster decodes it, runs the circuit model on the sealed policy and writes the record the
 * callback would.
 */
export function fakeCluster(o: { authority: string; policyId: string; commitment: string; policy: string; sealedPolicy: Policy }): FakeChain {
  return fakeChain({ [o.policy]: { data: policyRecordBytes(o) } }, (wire, chain) => {
    const data = Buffer.from(wire.subarray(wire.length - EVALUATE_DATA));
    const offset = data.readBigUInt64LE(8);
    const fields = new Uint8Array(data.subarray(16, 16 + REQUEST_FIELDS_SIZE));
    const disclose = data[EVALUATE_DATA - 1] === 1;
    const out = evaluateCircuit(encodePolicy(o.sealedPolicy), decodeRequestFields(fields));
    chain.accounts.set(decisionRecordAddress(PROGRAM, o.policy, offset), {
      data: Buffer.concat([
        disc("DecisionRecord"),
        decodePubkey(o.policy),
        u64(offset),
        fields,
        Buffer.from([1, out.verdict]),
        Buffer.from(Uint32Array.of(disclose ? out.mask : 0).buffer),
        u64(100n),
        u64(105n),
        Buffer.from([255, disclose ? 1 : 0]),
      ]),
    });
  });
}

export interface FakeAccount {
  readonly data: Uint8Array;
  readonly owner?: string;
}

export interface FakeChain {
  readonly rpc: RpcClient;
  readonly sent: Uint8Array[];
  readonly accounts: Map<string, FakeAccount>;
  statusErr: unknown;
}

/**
 * An RpcClient over a mutable account map. `onSend` lets a test play the cluster: it runs when
 * a transaction lands and may write the decision record the callback would have written.
 */
export function fakeChain(initial: Record<string, FakeAccount>, onSend?: (wire: Uint8Array, chain: FakeChain) => void): FakeChain {
  const accounts = new Map(Object.entries(initial));
  const sent: Uint8Array[] = [];
  const chain: FakeChain = {
    sent,
    accounts,
    statusErr: null,
    rpc: {
      getLatestBlockhash: async () => ({ blockhash: BLOCKHASH, lastValidBlockHeight: 1_000 }),
      getBlockHeight: async () => 10,
      sendTransaction: async (wireBase64: string) => {
        const wire = new Uint8Array(Buffer.from(wireBase64, "base64"));
        sent.push(wire);
        onSend?.(wire, chain);
        return encodeBase58(wire.subarray(1, 65));
      },
      getSignatureStatuses: async (sigs: readonly string[]) =>
        sigs.map((): SignatureStatus => ({ slot: 50, err: chain.statusErr, confirmationStatus: "confirmed" })),
      getTransaction: async () => null,
      getAccountInfo: async (address: string): Promise<AccountInfo | null> => {
        const a = accounts.get(address);
        return a ? { owner: a.owner ?? PROGRAM, lamports: 1n, data: a.data, executable: false } : null;
      },
    },
  };
  return chain;
}
