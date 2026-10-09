# Changelog

Notable changes to GENKAI. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Until 1.0, a minor
version may change the HTTP API, the receipt format or the CLI; each such change will be listed.

## [Unreleased]

### Added

- A USDC run on devnet, in `examples/devnet/usdc`: an agent paying Circle's devnet USDC through
  `genkai mcp`, against the released 0.1.0 image, under its own sealed PolicyRecord. Both allowed
  payments landed, and a retry under the same `request_id` returned the recorded decision and
  paid nothing. The agent's whole MCP session is committed beside the receipts, and a test checks
  the receipts, the run record, the session and the published policy against one another.
- The verifier site names tokens it knows on the cluster they belong to (USDC on devnet and
  mainnet-beta), has a USDC sample, and opens any sample from a link: `/?sample=usdc`.
- `scripts/snapshot-devnet.ts` reads every deployment manifest, so the offline tests cover both
  PolicyRecords.

### Fixed

- Verifying a run on chain reads each account once, not the shared PolicyRecord once per
  receipt, and the RPC client waits as long as a rate limiter's `Retry-After` asks, up to 10 s.
  On the public devnet endpoint, a visitor clicking quickly through the site's samples could
  be told the chain was unreachable; eight verifications back to back now all complete.

## [0.1.0] - 2026-10-04

The first release: spending policies for AI agents on Solana, evaluated encrypted by an Arcium
MPC cluster, with a receipt for every decision that anyone can verify. Live on devnet.

### Policy and receipts

- A deterministic policy engine, never the model, decides `allow`, `deny` or `escalate`. Rules
  cover tools, counterparties, amounts per action and per mint, spend and call windows, a
  drawdown halt, hours and days, and Solana clusters, programs and mints. Everything is denied
  by default, and an escalation never masks a denial.
- Canonical, Ed25519-signed receipts for every verdict, chained by hash. Each binds the policy
  hash or sealed commitment, the request, the observed state, the verdict and every rule that
  fired, the ruleset version, and for an allow the exact transaction that was signed.
- Verification by replay against a plaintext policy, or under seal by attestation and the
  cluster's on-chain record, with verdict-only disclosure for policies whose rule ids are
  themselves sensitive.

### Sealed policies on Arcium

- A fixed-width encoding of a policy into 87 field elements and a branch-free circuit model,
  pinned to the engine by a 20,000-case differential test.
- The Arcis circuit `evaluate_policy` and the GENKAI Anchor program: a policy registry whose
  records cannot change once active, authority-only evaluation, and DecisionRecords written only
  after Arcium verifies the cluster's signature, bound to their own computation.
- A live MXE client with no Arcium SDK dependency, and sealed receipts that name their
  DecisionRecord, so a verifier reads the verdict from the chain.
- Deployed on Solana devnet: program `AwiVMGyi8P9mN6ig5FA74CTS6sncc7bbh8CNAxKXUERk`, sealed
  PolicyRecord `4GAuWFqwJLhEqLAguJV3cdrwYWHc3yKP4QnYVkwWQRKL`, Arcium cluster 456.

### Solana

- The wire format with no dependencies (base58, curve checks, PDAs, instructions, legacy
  messages, signing), matching `@solana/web3.js` byte for byte.
- A transfer is signed only on allow, with the receipt id in its memo. The blockhash is fetched
  after the verdict, so time spent in the MPC cluster never shortens the transaction's life.
- An RPC client that validates responses before believing them, a broadcasting executor, and
  on-chain checks that a bound transaction landed.

### Gateway

- `genkai gateway`, the production entry point for agents. API keys with admin and agent roles
  (SHA-256 at rest, constant-time comparison); a SQLite ledger the agent cannot write, under an
  optimistic version check and a per-agent queue; per-client and per-key rate limits; a kill
  switch, a drawdown halt and key revocation; an append-only audit log; health and readiness
  probes; JSON logs that never hold a credential.
- Retries that cannot pay twice: an `Idempotency-Key` names a transfer for 24 hours, a retry
  gets the recorded decision back and re-sends a transaction that was never delivered, and the
  same key on a different transfer is refused.
- A container image, `ghcr.io/let-the-dreamers-rise/genkai-gateway`, non-root on a read-only
  filesystem, smoke-tested before it is published with provenance and an SBOM.

### For AI agents

- `genkai mcp` serves the gateway to any MCP client as three tools: `request_transfer`,
  `get_spending_status` and `get_receipt`. Amounts are exact decimal strings, retries reuse the
  model's `request_id` as the idempotency key, and each verdict is worded as the model's next
  step. See [docs/MCP.md](docs/MCP.md).

### Verification anywhere

- The `genkai` CLI: `keygen`, `seal`, `verify`, `verify-chain`, `verify-execution`,
  `verify-onchain`, `serve`, `gateway`, `gateway-admin`, `mcp` and `demo`.
- A browser verifier at [genkai-inky.vercel.app](https://genkai-inky.vercel.app) that runs the
  same code with audited `@noble` cryptography, and the same checks as a hosted API.

### Quality

- 212 tests at 97% line coverage, browser tests at desktop and phone size, CodeQL, and CI on
  Node 22 and 24. Zero runtime dependencies.

[Unreleased]: https://github.com/let-the-dreamers-rise/clawshield-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/let-the-dreamers-rise/clawshield-core/releases/tag/v0.1.0
