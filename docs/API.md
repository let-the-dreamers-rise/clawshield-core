# GENKAI HTTP API

Two services speak this API.

- **The verifier** (`genkai serve`, and the public deployment at
  `https://genkai-inky.vercel.app`) is stateless and needs no key. It answers one question: do
  these receipts hold?
- **The gateway** (`genkai gateway`) is where agents ask for decisions. It authenticates every
  caller, keeps the ledger, signs receipts and serves the same verification endpoints.

## Conventions

**Envelope.** Every response, success or failure, is one JSON object:

```json
{ "success": true, "data": { "...": "..." }, "error": null, "meta": { "total": 6, "limit": 50, "next": "5" } }
```

`meta` appears on paginated lists only. On failure `data` is `null` and `error` is a message
meant for a person. Every gateway response carries an `X-Request-Id` header naming the log line
for that request; quote it when reporting a problem.

**Amounts** are integer minor units, never floats. Requests carry them as decimal strings
(`"10000000"` is 0.01 SOL). Responses and receipts write every bigint as `{"$bigint": "10000000"}`
so no amount passes through a JavaScript number.

**Bodies** must be `Content-Type: application/json`. The gateway accepts 64 KiB, the verifier
1 MiB. Unknown fields are refused, not ignored.

**Errors**

| Status | Meaning |
|---|---|
| 400 | The body is malformed; the message names the offending field, e.g. `transfer.amount: expected a whole number of minor units as a decimal string` |
| 401 | Missing or invalid API key (`WWW-Authenticate: Bearer`) |
| 403 | The key is valid but its role may not do this |
| 404 | No such route, agent, receipt or key |
| 405 | Wrong method; `Allow` lists the right one |
| 409 | The agent's ledger moved under the request. Nothing was recorded; retry |
| 413 | Body over the limit |
| 415 | Not `application/json` |
| 429 | Rate limited; honour `Retry-After` |
| 500 | Unexpected failure. No detail is returned; the server logs it with the request id |
| 503 | Not ready (`/readyz` only): the database is unavailable |

**Rate limits** are token buckets. Gateway: 120 requests burst and 2 per second sustained per
client address, plus 30 decisions burst and one every 2 seconds per agent key. Verifier: 60
burst, 1 per second per client address.

## Verification (verifier and gateway)

### `POST /v1/receipts/verify`

```json
{ "receipt": { "body": {}, "signature": "...", "publicKey": "...", "algorithm": "ed25519" },
  "trust": { "commitment": "d598...0df1", "circuitId": "genkai.policy.v2",
             "programId": "AwiVMGyi8P9mN6ig5FA74CTS6sncc7bbh8CNAxKXUERk",
             "policy": "4GAuWFqwJLhEqLAguJV3cdrwYWHc3yKP4QnYVkwWQRKL" },
  "expectedPreviousHash": null }
```

Supply exactly one anchor:

- `policy`: the plaintext policy. The receipt is replayed.
- `trust`: a sealed trust anchor. Either `{ commitment, circuitId, programId, policy }` for the
  live Arcium deployment, checked against the DecisionRecord on chain, or
  `{ commitment, circuitId, clusterPublicKey }` for a signed attestation.

`expectedPreviousHash` is optional: `null` asserts this is an agent's first receipt, a hex hash
asserts its predecessor, and omitting it skips the chain check.

```json
{ "success": true, "data": { "mode": "sealed", "valid": true, "failures": [], "detail": [] }, "error": null }
```

### `POST /v1/chains/verify`

`{ "receipts": [ ... ], "policy" | "trust": { ... } }`: one agent's receipts in order, starting
from its first. Up to 1,000 receipts, or 100 when each one is checked on chain.

A run that fails is still a `200` with `valid: false`: the request was fine, the receipts were
not. `failures` holds codes and `detail` says which receipt and why, for example
`Receipt 1: On chain (verdict_mismatch): The cluster recorded deny [counterparty_not_allowed]; the claim is allow [all_checks_passed]`.

| Failure | Meaning |
|---|---|
| `bad_signature` | The operator's signature does not cover the receipt body |
| `policy_hash_mismatch` | The supplied policy is not the one the receipt binds |
| `decision_not_reproducible` | Replaying the policy gives a different verdict or different firing rules |
| `chain_broken` | A receipt does not point at the hash of its predecessor |
| `transaction_mismatch` | The bound transaction is not the fee payer's signature over the evaluated transfer |
| `commitment_mismatch` | The receipt binds a different sealed commitment |
| `attestation_missing` | A sealed receipt carries no attestation |
| `attestation_invalid` | The attestation, or the record on chain, does not support the receipt |
| `attestation_unchecked` | An on-chain attestation checked without RPC access: not valid, not invalid |
| `disclosure_leak` | Reason text or verdicts beyond what the cluster attested |

### `GET /healthz`

Liveness. The verifier also reports whether on-chain checks are enabled:
`{ "status": "ok", "onChain": true }`.

## The gateway

### Authentication

```
Authorization: Bearer gk_3f9a1c0d2b7e_Jx0...43 characters...
```

A key is a 12-hex-digit id and a 43-character secret. The gateway stores only the SHA-256 of
the secret and compares in constant time. The token is shown once, when it is created.

| Access | Who |
|---|---|
| public | anyone |
| receipts | anyone while `GENKAI_PUBLIC_RECEIPTS=true` (the default), otherwise any valid key |
| agent | an agent key, acting for its own agent only |
| self | an admin key, or the agent key of the agent named in the path |
| admin | an admin key |

An admin key cannot take decisions. Every receipt therefore names the agent that asked.

### Endpoints

| Method and path | Access | Purpose |
|---|---|---|
| `GET /healthz` | public | Liveness |
| `GET /readyz` | public | Readiness: database, RPC, execution mode |
| `GET /v1/trust` | public | What a verifier pins: mode, commitment, the policy (plaintext) or program and PolicyRecord (sealed), vault, operator key |
| `POST /v1/receipts/verify`, `POST /v1/chains/verify` | public | As above |
| `POST /v1/decisions` | agent | Ask for a decision |
| `GET /v1/agents/:id` | self | The agent, its current ledger state and chain head |
| `GET /v1/agents/:id/receipts?after=&limit=` | receipts | The agent's receipts in order; `meta.next` is the `after` for the next page |
| `GET /v1/receipts/:id` | receipts | One receipt by receipt id |
| `GET /v1/receipts/:id/transaction` | self | The signed transaction for an allow, and the submitted signature in broadcast mode |
| `POST /v1/agents` | admin | Register an agent: `{ "id": "desk-bot", "label": "Treasury desk" }` |
| `GET /v1/agents` | admin | All agents |
| `POST /v1/agents/:id/keys` | admin | Issue an agent key: `{ "label": "prod" }`. Returns the token once |
| `GET /v1/agents/:id/keys` | admin | The agent's keys, without secrets |
| `DELETE /v1/keys/:keyId` | admin | Revoke a key; effective on the next request |
| `POST /v1/agents/:id/revoke` | admin | Kill switch: every later decision for the agent is denied |
| `POST /v1/agents/:id/reinstate` | admin | Lift the kill switch |
| `PUT /v1/agents/:id/drawdown` | admin | Report losses from peak, `{ "drawdownFromPeak": "2500000000" }`, for the drawdown halt rule |
| `GET /v1/audit?after=&limit=` | admin | The append-only audit log, up to 500 entries a page |

### `POST /v1/decisions`

```json
{
  "transfer": { "kind": "sol", "to": "7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE", "amount": "10000000", "decimals": 9 },
  "modelReasoning": "Pay vendor A invoice #1042"
}
```

An SPL transfer adds `"kind": "spl"` and the `mint`, names the owner in `to` (the token
accounts are derived, never accepted), and may set `programId` for Token-2022.
`modelReasoning` (up to 8 KiB) is recorded for accountability and never used for enforcement.

The agent says where and how much. Nothing else is its to say: the source is the vault, the
cluster is the gateway's, the time is the server clock and the state is the ledger. A body that
tries to set `from`, `state` or `requestedAt` is a 400.

```json
{
  "success": true,
  "data": {
    "decision": { "verdict": "allow", "reasons": [ { "rule": "all_checks_passed", "verdict": "allow", "reason": "No rule objected" } ],
                  "policyId": "desk-alpha-treasury", "policyVersion": 1, "decidedAt": 1790894015087 },
    "receipt": { "body": { "...": "..." }, "signature": "...", "publicKey": "...", "algorithm": "ed25519" },
    "seq": 1,
    "signedTransaction": "AW3k...base64 wire transaction..."
  },
  "error": null
}
```

A denial or an escalation is a `200` too, with its receipt and no transaction. In `broadcast`
mode an allow also carries `submittedSignature`, or `submitError` if delivery failed. The
decision stands and is recorded either way, and the signed transaction can be resubmitted.

The blockhash is fetched after the verdict, and only for an allow, so the seconds a sealed
decision spends on the MPC cluster do not come out of the transaction's validity window. If
that fetch fails, the allow is still recorded but carries no `signedTransaction`, and the
receipt's `outcome.error` says why. Ask again for a fresh decision.

**Ledger semantics.** The spend window rolls on the server clock (`GENKAI_WINDOW_SECONDS`, or
the policy's `windowSeconds`). Every decision counts toward `maxCallsPerWindow`; only an allow
that produced a signed transaction adds to the window's spend, since nothing else can move funds. Decisions for one agent are serialised, and each commits its receipt
and the ledger advance in one transaction before any broadcast.

### Walkthrough

```bash
G=http://127.0.0.1:8788
ADMIN=gk_...   # from: genkai gateway-admin create-admin-key --db data/genkai.db

curl -s $G/v1/agents -H "authorization: Bearer $ADMIN" -H 'content-type: application/json' \
  -d '{"id":"desk-bot","label":"Treasury desk"}'
AGENT=$(curl -s $G/v1/agents/desk-bot/keys -H "authorization: Bearer $ADMIN" \
  -H 'content-type: application/json' -d '{"label":"prod"}' | jq -r .data.token)

curl -s $G/v1/decisions -H "authorization: Bearer $AGENT" -H 'content-type: application/json' \
  -d '{"transfer":{"kind":"sol","to":"7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE","amount":"10000000","decimals":9}}'

# Anyone can then fetch the chain and check it against the published trust anchor.
curl -s $G/v1/agents/desk-bot/receipts | jq .data > receipts.json
curl -s $G/v1/trust | jq .data
```
