/**
 * A stand-in for the Arcium circuit.
 *
 * This runs the circuit model in process - the same fixed-width encoding and branch-free
 * evaluation the Arcis circuit runs, not the engine - against the plaintext policy, and signs
 * the result. It is NOT confidential and is not pretending to be: it holds the very policy the
 * production MXE will never see. Running the model rather than the engine means a policy the
 * circuit cannot represent fails here, at construction, exactly as it will when sealed.
 *
 * Its job is to prove the interface. Everything a caller can observe - the input shape, the
 * opaque rule ids, the attestation and its signature - is identical to what the circuit will
 * produce, so swapping in the real client changes this file and nothing above it. If that
 * turns out not to be true when the circuit lands, the interface was wrong, which is exactly
 * what this file exists to find out early.
 *
 * The one thing it cannot model is cost. An MXE round trip is a network call with real
 * latency, which is why MxeClient.evaluate is async even though this implementation could
 * answer synchronously.
 */

import { sign } from "node:crypto";
import { evaluateCircuit, ruleIdsOf, verdictOf } from "./circuit.ts";
import { encodePolicy, encodeRequest } from "./encoding.ts";
import { canonicalBytes, type Canonicalisable } from "../receipt/canonical.ts";
import type { Keypair } from "../receipt/sign.ts";
import type { Policy } from "../policy/types.ts";
import { attestedPayload, type MxeClient, type MxeEvaluationInput, type MxeEvaluationOutput } from "./types.ts";
import { sealedCommitment } from "../policy/sealed.ts";

export interface StubMxeConfig {
  readonly policy: Policy;
  /** High-entropy salt. Without it the commitment is guessable; see sealed.ts. */
  readonly salt: string;
  readonly circuitId: string;
  readonly keys: Keypair;
}

export function createStubMxe(config: StubMxeConfig): MxeClient {
  const commitment = sealedCommitment(config.policy, config.salt);
  // Encoded once. Throws EncodingError for a policy the circuit cannot hold.
  const sealed = encodePolicy(config.policy);
  const clusterPublicKey = config.keys.publicKey.export({ type: "spki", format: "der" }).toString("base64");

  async function evaluateSealed(input: MxeEvaluationInput): Promise<MxeEvaluationOutput> {
    const out = evaluateCircuit(sealed, encodeRequest(input.request, input.state));
    const verdict = verdictOf(out);
    const verdictOnly = input.disclosure === "verdict";
    const ruleIds = verdictOnly ? [] : [...ruleIdsOf(out)];

    // The circuit answers for the policy it holds, not for whatever commitment it was asked
    // about. Echoing the caller's commitment back unchecked would let a caller believe a
    // different policy had been evaluated.
    const payload = attestedPayload(
      { ...input, policyCommitment: commitment },
      config.circuitId,
      verdict,
      ruleIds,
    );
    const signature = sign(null, canonicalBytes(payload as unknown as Canonicalisable), config.keys.privateKey);

    return {
      policyCommitment: commitment,
      verdict,
      ruleIds,
      attestation: {
        circuitId: config.circuitId,
        clusterPublicKey,
        signature: signature.toString("base64"),
        disclosure: verdictOnly ? "verdict" : undefined,
      },
    };
  }

  return Object.freeze({ circuitId: config.circuitId, clusterPublicKey, evaluate: evaluateSealed });
}
