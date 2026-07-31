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

## Status

Early. The policy engine, canonical serialisation, receipt signing and the verifier are
implemented and tested. Wallet adapters and the MCP transport are next.

```
src/policy/types.ts       policy, request, state and decision types
src/policy/rules.ts       pure rule evaluators
src/policy/engine.ts      deterministic evaluation, deny-then-escalate ordering
src/receipt/canonical.ts  deterministic serialisation, bigint-safe
src/receipt/types.ts      receipt and verification types
src/receipt/sign.ts       SHA-256 hashing, Ed25519 signing
src/receipt/verify.ts     third-party verification and chain replay
```

### Roadmap

- Circle Developer Controlled Wallets and ERC-4337 adapters
- MCP transport so any agent can be governed without code changes
- On-chain receipt anchoring
- Hosted public verifier
- Reputation registry

## Run it

```bash
node --test --experimental-strip-types "test/*.test.ts"
```

Requires Node 22+. No dependencies.

```
# tests 9
# pass 9
# fail 0
```

The suite includes the adversarial cases that matter:

- rewriting a recorded verdict and re-signing - caught by replay
- presenting a permissive policy to an auditor after enforcing a strict one - caught by policy hash
- editing the body after signing - caught by signature
- deleting a receipt from the middle of a chain - caught by chain linkage

## Licence

MIT
