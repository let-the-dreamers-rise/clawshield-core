# ClawShield

**Verifiable authority for AI agents that move money.**

An audit log is a claim by the operator. ClawShield produces receipts that a third party can
verify without trusting the operator at all.

---

## The problem

Agents can move money now. Circle Developer Controlled Wallets, ERC-4337, x402 and stablecoin
settlement all shipped. Adoption did not follow, and the blocker is not model capability.

No operator, CFO or regulator will authorise a system they cannot bound, audit or halt. Today
the available answers are:

- **Prompting.** "We told it not to." Not a control.
- **Audit logs.** Written by the operator, editable by the operator. A regulator asking "prove
  the agent stayed inside policy" gets handed the operator's own account of events.

The existing MCP gateways - AgentGateway, Pomerium, Bifrost, ContextForge, MintMCP - all solve
authentication, rate limiting and tool-level authorization well. All of them stop at logging.

That gap is now a compliance problem. [EU AI Act Article 14](https://artificialintelligenceact.eu/article/14/)
requires high-risk systems be designed for effective human oversight, and FINRA's 2026 Annual
Regulatory Oversight Report names guardrails constraining agent behaviour as a supervisory
consideration.

## What ClawShield does differently

Every decision emits a signed receipt binding, under one Ed25519 signature:

- the **hash of the exact policy in force** at decision time
- the exact request evaluated
- the observed state the engine reasoned over
- the verdict and every rule that fired
- the resulting transaction and balance delta
- the hash of the previous receipt, forming a tamper-evident chain

A verifier holding only the public key and the receipt can then **replay the decision** and
confirm the operator enforced the policy they claim they enforced.

Anyone can sign a log. Only a deterministic engine can prove the log describes what the code
actually did.

## Design principles

**The model may only narrow the permitted action set, never widen it.** An LLM may propose an
action and its reasoning is recorded for accountability, but enforcement is deterministic code
outside the model. There is no prompt that unlocks a denied action.

**Deny by default.** An empty tool allowlist permits nothing.

**Escalation never masks a denial.** An action both above the human-approval threshold and
outside a hard cap is denied, not sent to a human for approval it should never be offered.

**Decisions are pure functions.** No clock reads, no IO inside rule evaluation. `decidedAt` is
passed in, which is precisely what makes replay-based verification possible.

**No third-party crypto dependency.** Ed25519 via `node:crypto`. A supply-chain compromise in
a signing library would invalidate every receipt ever issued.

## Verification

```
verifyReceipt(receipt, policy) checks four things independently:

  1. signature valid over the canonical body
  2. policy hash matches the policy supplied
  3. replaying the engine reproduces the recorded verdict AND the same firing rules
  4. the receipt chains correctly to its predecessor
```

Check 3 is the one that cannot be faked.

## GENKAI: the policy itself is confidential

Everything above has a property nobody talks about: **to enforce a policy, ClawShield has to
publish it.** Verification works by handing the verifier the policy and replaying the engine.

For most operators that is fine. For a fund or a trading desk it is disqualifying, because the
risk parameters *are* the strategy. "Max 50k per day through these programs" tells anyone who
reads the config, the audit log or a single receipt how the book is sized. Every agent
guardrail on the market today has this problem, because all of them enforce by inspection.

GENKAI keeps the policy **encrypted end to end** and evaluates it on ciphertext inside an
[Arcium](https://arcium.com) MXE on Solana. The limits are never decrypted - not by the agent,
not by the operator, not by the verifier. The output is a receipt proving the action was in
policy while revealing nothing about what the policy said.

### The trade, stated plainly

This is not free, and the interface is built so the cost cannot be overlooked.

| | Plaintext mode | Sealed mode |
|---|---|---|
| How a verifier checks the verdict | Re-runs the engine itself | Checks an MXE attestation |
| Who must be trusted | Nobody | The Arcium cluster and the published circuit |
| What the receipt reveals | The full policy, to anyone holding it | A salted commitment and rule identifiers |

You cannot replay a computation over inputs you are not allowed to see. So sealed mode
substitutes an attestation for the replay, and the trust assumption moves from *nobody* to
*the cluster plus the circuit*. That is a real weakening. It is worth paying because the
alternative available to a desk today is an audit log, which asks you to trust the operator
alone.

`PolicyProvider.disclose()` returns the policy in plaintext mode and `undefined` under seal, so
any code path that needs the plaintext policy fails loudly rather than silently degrading.

### Two details that are easy to get wrong

**The commitment must be salted.** A bare `hashPolicy()` is not a safe commitment to a
confidential policy. Risk limits are round numbers, mints and programs come from a small public
universe, and the space of plausible treasury policies is small enough to enumerate - an
adversary guesses until the hash matches and recovers exactly what the design set out to hide.
`sealedCommitment()` salts with a high-entropy secret held alongside the ciphertext. The salt is
never published; a verifier checks the commitment by equality against the receipt, never by
recomputing it.

**Reason strings leak.** In plaintext mode a denial reads `Amount 90000000000 exceeds
per-action cap 50000000000` and hands the reader the limit. A sealed decision carries rule
identifiers with no interpolated amounts. A rule id still discloses *which kind* of constraint
bound, which is a smaller but real leak - see the roadmap.

## Status

The policy engine, canonical serialisation, receipt signing, the verifier, the Solana rule set,
the signing adapter and the confidential-policy seam are implemented and tested. The Arcium
circuit is stubbed behind `MxeClient`; the stub runs the real engine in process and signs the
same attestation the circuit will, so landing the real one changes `src/mxe/stub.ts` and nothing
above it.

```
src/policy/types.ts       policy, request, state and decision types
src/policy/rules.ts       pure rule evaluators
src/policy/engine.ts      deterministic evaluation, deny-then-escalate ordering
src/policy/sealed.ts      PolicyProvider seam: plaintext and sealed implementations
src/mxe/types.ts          the MXE boundary and attestation format
src/mxe/stub.ts           stand-in for the Arcium circuit
src/solana/types.ts       Solana request mapping, bigint minor units
src/solana/rules.ts       cluster, program and mint allowlists, per-mint caps
src/solana/adapter.ts     the signing boundary; the key lives here and nowhere else
src/receipt/canonical.ts  deterministic serialisation, bigint-safe
src/receipt/types.ts      receipt and verification types
src/receipt/sign.ts       SHA-256 hashing, Ed25519 signing
src/receipt/verify.ts     third-party verification and chain replay
```

### Solana specifics

A Solana transfer maps onto the existing `ActionRequest` rather than forking a parallel request
type, so there stays exactly one replay path. `counterparty` is the destination, `asset` is the
mint, and `chainId` stays absent because Solana has no numeric chain id and faking one would be
a lie baked into a signed receipt. Native SOL is keyed by the wrapped-SOL mint so per-mint caps
have one uniform key space.

Unlike the core counterparty allowlist, **absent Solana allowlists deny**. A policy written
before Solana existed must not read as authorisation to move funds on Solana.

The adapter's guarantee is structural, not procedural. The keypair is a closure variable and
never a property, the returned object is frozen and exposes only `publicKey` and `submit`, and
the module exports nothing that signs a transfer on demand. An agent cannot sign even if it
wants to. Both verdicts emit a receipt - a refusal that leaves no evidence is not a control.

### Roadmap

- The real Arcium MXE circuit behind `MxeClient`, replacing the stub
- A verdict-only sealed mode, so not even the rule identifier is disclosed
- Sealed-mode verification surfaced in `verifyReceipt` alongside the plaintext replay path
- Real Solana transaction message encoding and cluster submission
- Circle Developer Controlled Wallets and ERC-4337 adapters
- MCP transport so any agent can be governed without code changes
- On-chain receipt anchoring and a hosted public verifier

## Run it

```bash
node --test --experimental-strip-types "test/*.test.ts"
```

Requires Node 22+. No dependencies.

```
# tests 42
# pass 42
# fail 0
```

The suite is built around the adversarial cases, not the happy path:

- rewriting a recorded verdict and re-signing - caught by replay
- presenting a permissive policy to an auditor after enforcing a strict one - caught by policy hash
- editing the body after signing - caught by signature
- deleting a receipt from the middle of a chain - caught by chain linkage
- a negative transfer amount, which would pass every cap *and* credit the spend window
- an allowlisted mint with no configured cap, which must deny rather than default to unlimited
- forged `chain: "solana"` params, which must deny rather than fall through the Solana rules
- an MXE answering for a different policy commitment than the one configured
- an attestation from a foreign circuit, or signed by a key other than the pinned cluster key
- a verdict flipped between the MXE and the receipt writer
- a sealed decision leaking a threshold into its reason strings

## Licence

MIT
