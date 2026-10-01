# Security

## Reporting a vulnerability

Please report vulnerabilities privately, not in a public issue: use GitHub's private
vulnerability reporting on this repository (Security, then "Report a vulnerability"). If that
option is not shown, open an issue asking for a private contact, with no details in it. Include
what an attacker gains, the steps to reproduce, and the commit you tested.

In scope: the TypeScript core and gateway (`src/`), the browser verifier (`web/`), the Arcium
program and circuit (`arcium/genkai/`), the container image and the deployment scripts.

## Threat model

**What is protected**

- The vault: no transfer is signed unless the policy allowed it.
- The policy's confidentiality, in sealed mode: limits, allowlists and thresholds are never
  decrypted, by the operator, the nodes or a verifier.
- The record: a receipt cannot be altered, dropped from the middle of a chain, or attributed to
  a different policy without a verifier noticing.
- The ledger: an agent cannot raise its own remaining allowance.

**Who is assumed hostile**

| Adversary | What stops them |
|---|---|
| The agent, or the model driving it | Enforcement is deterministic code outside the model. The agent holds an API key, not a signing key, and may only name a destination and an amount; vault, cluster, clock and state are the gateway's. Unknown request fields are refused |
| An agent with another agent's name | Keys are bound to one agent; an agent key cannot read or act for another agent |
| A network attacker | The gateway is run behind TLS (docs/OPERATIONS.md). Keys are high-entropy and stored only as hashes, so a leaked database does not yield usable credentials |
| The operator, toward auditors | Receipts are signed and chained; plaintext decisions are replayable; sealed decisions are checked against the DecisionRecord the cluster wrote, which the operator cannot forge even while holding the signing key |
| A look-alike deployment | Verifiers pin the program id and the PolicyRecord address, not only the public commitment |
| Malicious verification input | Bodies are bounded, parsed strictly, and never echoed into markup; the browser page renders with `textContent` under a CSP with no inline code |

**What is trusted**

- In sealed mode, the Arcium cluster's MPC protocol and the published circuit, for both
  confidentiality and correct evaluation, and the GENKAI program as deployed. Until its upgrade
  authority is removed, that includes whoever holds the upgrade authority.
- The operator, for custody of the vault key and the gateway database. Whoever holds the
  database file can mint admin keys (that is the documented break-glass path).
- The Solana RPC endpoint for liveness, not for truth: responses are validated, and an on-chain
  check that cannot be completed reports `attestation_unchecked`, never valid.

**Known limits, stated rather than hidden**

- The commitment does not prove that the on-chain ciphertext encrypts the committed policy. The
  operator can open that link to an auditor by revealing the policy, the salt and the one-time
  encryption key.
- Rules mode discloses which rule fired. Verdict-only mode discloses nothing beyond the
  verdict, at the cost of less useful denials.
- Receipts are public by default and contain the request: destination, amount, time. Set
  `GENKAI_PUBLIC_RECEIPTS=false` where that is itself sensitive.
- Rate limits are per process. Behind several replicas, put a shared limiter in front.

## Practices

- Zero runtime dependencies in the core. Ed25519 and SHA-256 come from `node:crypto`; the
  browser bundle alone uses `@noble/curves` and `@noble/hashes`, pinned to exact versions, and
  cannot sign.
- Every endpoint is rate limited; every body is bounded; every error is a fixed message or a
  schema path, never a stack trace or a secret.
- Secrets are read from files or the environment, never logged, and a malformed key fails with
  a message that does not quote it. `.gitignore` and `.dockerignore` keep keys and ledgers out
  of commits and images.
- The container runs as a non-root user on a read-only filesystem with all capabilities
  dropped. Images are published only after a smoke test, with provenance and an SBOM.
- The test suite is written around attacks: forged verdicts, lifted signatures, relabelled
  disclosure modes, negative amounts, prototype-named mints, look-alike policy records, racing
  decisions and more. See the README's security notes.
