# GENKAI for AI agents: MCP

`genkai mcp` gives any [Model Context Protocol](https://modelcontextprotocol.io) client (Claude
Code, Claude Desktop, Cursor, or an agent built on an MCP SDK) three tools backed by a GENKAI
gateway. The model can ask for a payment, read its own spend and fetch receipts. It cannot see
the policy, change it, or pay by any other route. The MCP server holds an agent key and nothing
else: the vault key that signs transfers never leaves the gateway.

```
model --tools/call--> genkai mcp --HTTPS + agent key--> gateway --> policy (plaintext or Arcium MXE)
                                                           |
                                     receipt, ledger, signed transaction (broadcast if configured)
```

Seen live: in [examples/devnet/usdc](../examples/devnet/usdc) an agent pays devnet USDC through
`genkai mcp` under a sealed policy decided by an Arcium cluster, and its whole session is in
`mcp-transcript.jsonl`, next to the receipts it produced.

## Set it up

**1. An agent and its key.** With an admin key for the gateway (see
[OPERATIONS.md](OPERATIONS.md#keys-and-access)):

```bash
curl -sS https://genkai.example.com/v1/agents -H "authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' -d '{"id":"treasury-bot","label":"Treasury agent"}'
curl -sS https://genkai.example.com/v1/agents/treasury-bot/keys -H "authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' -d '{"label":"mcp"}'
```

The second call returns the agent key once. Save it to a file only you can read, for example
`~/.genkai/treasury-bot.key` with mode 600.

**2. Add the server to your client.**

Claude Code, from a clone of this repository (Node 22 or later):

```bash
claude mcp add genkai \
  -e GENKAI_GATEWAY_URL=https://genkai.example.com \
  -e GENKAI_AGENT_KEY_FILE=$HOME/.genkai/treasury-bot.key \
  -e GENKAI_AGENT_ID=treasury-bot \
  -- node --experimental-strip-types --no-warnings /path/to/clawshield/src/cli/main.ts mcp
```

Claude Desktop and other clients that take a JSON config can run the published image, so no
clone is needed. In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "genkai": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/Users/me/.genkai/treasury-bot.key:/run/secrets/agent.key:ro",
        "-e", "GENKAI_AGENT_KEY_FILE=/run/secrets/agent.key",
        "-e", "GENKAI_GATEWAY_URL=https://genkai.example.com",
        "-e", "GENKAI_AGENT_ID=treasury-bot",
        "ghcr.io/let-the-dreamers-rise/genkai-gateway:0.1.0", "mcp"
      ]
    }
  }
}
```

The image runs as uid 1000. On Linux, if your uid differs, add `"--user", "<your uid>"` so the
process can read the key file. From inside the container a gateway on your own machine is
`host.docker.internal`, which is not loopback, so plain http to it also needs
`GENKAI_ALLOW_HTTP=true`.

### Configuration

| Variable | Meaning | Default |
|---|---|---|
| `GENKAI_GATEWAY_URL` | The gateway. Must be https unless it is on this machine (`localhost`, `127.0.0.1`, `[::1]`) | required |
| `GENKAI_AGENT_KEY_FILE` | File holding the agent key, `gk_...` | required, or `GENKAI_AGENT_KEY` |
| `GENKAI_AGENT_KEY` | The agent key itself, when a file is not practical | |
| `GENKAI_AGENT_ID` | The agent the key belongs to | required |
| `GENKAI_ALLOW_HTTP` | `true` allows plain http to another host, for a private network you trust | `false` |

A missing or malformed setting stops the server before it speaks MCP, with every problem listed
on stderr (your client's MCP log) and exit code 2. The key is never repeated in those messages.

## The tools

### `request_transfer`

| Argument | |
|---|---|
| `to` | The recipient's Solana address |
| `amount` | Whole tokens as a decimal string: `"0.015"` is 0.015 SOL. Never lamports, never a JSON number |
| `token` | An SPL mint address. Leave it out to pay SOL |
| `decimals` | The mint's decimal places, required with `token`. SOL is always 9 |
| `reason` | What the payment is for, up to 2000 characters. Recorded in the receipt; the policy never reads it |
| `request_id` | The model's own name for this payment, such as an invoice number. Sent as the `Idempotency-Key` |

The amount is converted to minor units with integer arithmetic, so `"0.015"` is exactly
15000000 lamports, never 14999999. Input a model gets wrong comes back as an error that starts
with the argument's name and says what was expected, and reaches no one: `to: not a Solana
address...`, `amount: 0.0000000001 has more than 9 decimal places...`, `unknown argument: memo...`.

The answer is a sentence the model can act on, and the same answer as structured content:

```
ALLOWED. 0.01 SOL to 7VHU...4BmE was signed and sent as transaction 5axn...3wc (https://explorer.solana.com/tx/...?cluster=devnet). Receipt 4974...6254.
DENIED by the spending policy (counterparty_not_allowed). Nothing was signed. This is final for this request: do not retry it, split it into smaller payments or send it another way. Tell the user what was refused and why. Receipt 7477...f25b.
ESCALATED (human_approval_required): this payment needs a person's approval before it can be made. Nothing was signed or paid. Tell the user; do not retry it or split it into smaller payments. Receipt e93a...6b00.
```

```json
{
  "verdict": "allow",
  "rules": ["all_checks_passed"],
  "reasons": ["No rule objected"],
  "receiptId": "497482373ce9fc6a451945edeca56254",
  "seq": 1,
  "replayed": false,
  "transaction": { "signature": "5axn...", "submitted": true },
  "explorer": "https://explorer.solana.com/tx/5axn...?cluster=devnet"
}
```

A gateway in sign mode does not broadcast. Its answer says so, and carries the signed
transaction as `signedTransaction` for whoever submits it.

### `get_spending_status`

No arguments. What the agent has spent and how many requests it has made in the current
window, when the window started, how many receipts it has, and whether it is revoked. The
policy's limits are not shown: under a sealed policy nobody outside the MPC cluster can see
them, and the model has no use for them beyond probing.

### `get_receipt`

`receipt_id` in, the signed receipt out as JSON, ready to hand to anyone who wants to check it:
the [verifier site](https://genkai-inky.vercel.app), `POST /v1/receipts/verify`, or
`genkai verify`.

## Retries cannot pay twice

Every `request_transfer` sends its `request_id` as the gateway's `Idempotency-Key` (see
[API.md](API.md#post-v1decisions)). A failure that says nothing about the request (no answer, a
timeout, 409, 429 or a 5xx) is retried twice, with backoff or the gateway's `Retry-After`,
under the same key. When the first attempt was recorded after all, the retry gets that decision
back, marked as a replay, and the ledger is charged once. If every attempt fails, the model is
told that calling again with the same `request_id` is safe. Reusing a `request_id` for a
different transfer is refused.

A sealed decision takes 5 to 38 seconds on devnet while the MPC cluster evaluates. Each attempt
waits up to two minutes, and a client that asks for progress (`_meta.progressToken`) gets a
notification every five seconds while it waits, which keeps clients that reset their timeout on
progress from giving up.

## What this does and does not protect against

A prompt injection can make a model ask for a payment. It cannot make the policy allow one:
the verdict comes from the gateway's policy, not from anything the model says, and `reason` is
recorded for auditors but never read by the policy. The worst an attacker who controls the
model can do is spend inside the limits the operator set, and every attempt, refused or not,
leaves a signed receipt. Set the limits with that in mind.

- The MCP server never holds a signing key. Compromising it yields an agent key, which can be
  revoked with one admin call and is only as strong as the policy behind it.
- Plain http to a remote gateway is refused, because it would send the agent key in the clear.
- Stdout carries protocol messages only; diagnostics go to stderr and never include the key.
- `reason` ends up in the receipt. With public receipts (the default) anyone can read it, so it
  should not contain secrets.

## Protocol

MCP over stdio, one JSON-RPC 2.0 message per line. The server speaks protocol version
`2025-06-18` and answers clients of `2025-03-26` and `2024-11-05`. It implements `initialize`,
`ping`, `tools/list` and `tools/call` with progress notifications, and declares tool annotations:
`request_transfer` is destructive and idempotent, the two readers are read-only. It is written on
Node built-ins, in keeping with the project's rule of no runtime dependencies (`src/mcp/`), and
is checked against the official TypeScript SDK's client.
