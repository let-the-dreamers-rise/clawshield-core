# Architecture

GENKAI separates three questions that agent payment systems usually blur: who may ask, who
decides, and who can check. Each has its own component and its own trust assumption.

```
                    API key                        sealed: queue + callback
  agent ----------------------> gateway --------------------------------------> GENKAI program
                                 |  ledger (SQLite)                            |  PolicyRecord (ciphertext)
                                 |  vault key                                  |  DecisionRecord (verdict, mask)
                                 |  receipt chain                              v
                                 |                                        Arcium MXE, cluster 456
                                 |  plaintext: policy engine in process      evaluates on ciphertext
                                 v
                       signed receipt + signed transaction ----> Solana (broadcast mode)
                                 |
                                 v
            verifier (browser, CLI, hosted API): signature, chain, transaction binding,
            and replay (plaintext) or the DecisionRecord on chain (sealed)
```

## Who may ask: the gateway

`src/gateway/` turns an HTTP request into a decision without letting the caller influence
anything but the transfer it proposes.

- `auth.ts`, `authenticate.ts`: API keys as `gk_<id>_<secret>`, SHA-256 at rest, constant-time
  comparison, roles (admin, agent) and the touch-on-use timestamp.
- `requests.ts`: closed schemas. An unknown field is a 400.
- `routes.ts`, `server.ts`: one table of routes with the access rule beside each handler, per
  client and per key rate limits, one JSON log line per request.
- `service.ts`: the decision path. It takes the agent's slot in a per-agent queue, rolls the
  ledger to now, builds the transfer from the gateway's own vault, cluster and clock, asks the
  policy provider through the signing adapter, commits the receipt and the ledger advance in
  one transaction, and only then broadcasts.
- `ledger.ts`: the window arithmetic, pure. `store.ts`, `db.ts`: the SQLite schema, migrations
  and the optimistic version check that makes a racing writer fail rather than double-spend.

## Who decides: the policy provider

`src/policy/sealed.ts` defines the seam. Both providers return a verdict and the rules that
fired; only one can show the policy.

- **Plaintext**: `src/policy/engine.ts` and `rules.ts`, a deterministic engine. Deny by default,
  escalation never masks a denial, every rule evaluated.
- **Sealed**: `src/mxe/arcium.ts` sends `evaluate` to the GENKAI program and waits for the
  DecisionRecord. The policy was encoded into 87 fixed-width field elements
  (`src/mxe/encoding.ts`) and encrypted for the MXE before it was registered, so no node, no
  operator and no verifier ever reads a limit. `src/mxe/circuit.ts` is the TypeScript model of
  the Arcis circuit, held equal to the engine on 20,000 random cases and to the live cluster on
  localnet.

The signing adapter (`src/solana/adapter.ts`) holds the vault key in a closure and signs only
on an allow. There is no function anywhere that signs on request.

## What gets recorded: receipts

`src/receipt/` defines the receipt and its canonical form. A receipt binds the policy hash or
sealed commitment, the request, the ledger state, the verdict and firing rules, the MXE
attestation (for the live cluster, a pointer to the DecisionRecord), the signed transaction's
id and message hash, and the previous receipt's hash. It is signed with Ed25519 over canonical
JSON, so the bytes a verifier hashes do not depend on key order or number formatting.

## Who can check: verification

`src/receipt/verify.ts` (plaintext) and `verify-sealed.ts` (sealed) take nothing on trust from
the receipt: the policy, or the commitment, circuit, program and PolicyRecord, are pinned by the
verifier. `src/server/handlers.ts` is the one entry point the CLI, the hosted API, the gateway
and the browser page all call, so all four give the same answer to the same input.

The browser build (`web/`) swaps `node:crypto` for a verify-only shim over `@noble/curves` and
`@noble/hashes` and fails if any other Node module is reachable. `test/web-bundle.test.ts`
runs that bundle with no Node globals and requires the same results as Node.

## On chain

`arcium/genkai/programs/genkai` is an Anchor program with two account types.

- **PolicyRecord**: authority, policy id, commitment, the operator's one-time x25519 public key
  and the nonce the policy was encrypted under, and 87 ciphertexts. Staged in chunks, then
  activated, then immutable.
- **DecisionRecord**: the computation offset, the plaintext request fields the cluster was asked
  about, the verdict and rule mask, the disclosure mode, and the slots it was requested and
  decided in. The callback that writes it runs only after Arcium has verified the cluster's
  signature over the output, and it is bound to its own computation account.

The circuit (`encrypted-ixs`, compiled to `circuits/evaluate_policy.arcis`) is served from a
tag-pinned URL and checked by the Arx nodes against the hash compiled into the program.

## Trust, stated

| Mode | A verifier must trust |
|---|---|
| Plaintext | Nothing beyond the math: it replays the decision itself |
| Sealed | The Arcium cluster's MPC protocol, the published circuit, and the program as deployed (immutable once its upgrade authority is removed) |
| Either | That the vault key signs only through the adapter, which is the operator's to protect |

What no mode proves: that the ciphertext on chain encrypts the policy behind the commitment.
The operator can open that link to an auditor; see the README's security notes.
