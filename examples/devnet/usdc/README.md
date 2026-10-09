# The USDC run on devnet

An agent paid USDC under a sealed policy, and spoke to the GENKAI gateway only through
`genkai mcp`, as Claude Code or Claude Desktop would. It asked for five payments in Circle's
devnet USDC (mint `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`, 6 decimals), then retried the
first. The gateway ran from the released image, `ghcr.io/let-the-dreamers-rise/genkai-gateway:0.1.0`,
in sealed mode against its own PolicyRecord, so the Arcium cluster decided each request against
the encrypted policy, and in broadcast mode, so it sent what it signed.

| # | Request | Verdict | Rules | Decision |
|---|---|---|---|---|
| 1 | 1.25 USDC to vendor A, invoice A-1042 | allow | `all_checks_passed` | 7.8 s, [landed](https://explorer.solana.com/tx/3gJkMZdqaP8RsKBEED9vuqztHnjMvUm49DcbxWJuGrNxnDdVqe3Hy711ufnfYEMAGd8ypDYz7LfayLSeR5uQZXSr?cluster=devnet) |
| 2 | 0.5 USDC to an unknown address, a tip asked for in a support chat | deny | `counterparty_not_allowed` | 5.3 s |
| 3 | 4 USDC to vendor B, a quarter paid ahead | escalate | `human_approval_required` | 5.2 s |
| 4 | 12 USDC to vendor A, a year's renewal up front | deny | `mint_cap_exceeded`, `amount_exceeds_window` | 5.1 s |
| 5 | 2.5 USDC to vendor B, invoice B-2201 | allow | `all_checks_passed` | 5.9 s, [landed](https://explorer.solana.com/tx/4VfRF8bRzjNupn72nmQQhYH7ejcZ45JdSEdtfMdBJ8BWV2gfvk2SuiB4cAkvxqDWwiYCY7Ad7LFMBAX5gRYNzqvi?cluster=devnet) |
| retry | request 1 again, same `request_id` | the recorded allow | | 15 ms, nothing sent |

The times are the agent's full `tools/call` round trip, the MPC evaluation included. Every
decision took the cluster more than five seconds, and the agent's client got a progress
notification while it waited.

The policy, sealed into PolicyRecord
[`3iBdFt2rSE66nJhpagxniYZrYLbPXcF5QyT3rcUtVEYo`](https://explorer.solana.com/address/3iBdFt2rSE66nJhpagxniYZrYLbPXcF5QyT3rcUtVEYo?cluster=devnet),
pays only vendors A and B, only devnet USDC through the Token program, at most 5 USDC a payment
and 8 USDC a day, and asks for a person above 3 USDC. It is published here as
[`policy.json`](policy.json) so you can see why each verdict came out as it did; a real
deployment publishes only the commitment. Nothing ties the file to the record, because the salt
behind the commitment stays secret. `test/usdc-run.test.ts` replays it against the receipts and
reaches every verdict the cluster reached.

- `receipts.json`: the agent's receipt chain, as `GET /v1/agents/desk-alpha/receipts` served it
- `trust.json`: the trust anchor, the public facts of
  [`deployments/devnet-usdc.json`](../../../arcium/genkai/deployments/devnet-usdc.json): the same
  program as the SOL runs, its own PolicyRecord and commitment
- `mcp-transcript.jsonl`: the agent's whole MCP session, every message both ways, timed. No key
  appears in it: the agent key stays in the server's environment
- `run.json`: what the receipts do not carry: the image digest, the vault and its token account,
  the funding transactions, the operator key, each decision's latency, the slot each transfer
  finalized in, the retry, and the spending status the agent read at the end
- `policy.json`: the policy that was sealed

Check it from files and RPC alone:

```bash
npm run genkai -- verify-chain examples/devnet/usdc/receipts.json \
  --trust examples/devnet/usdc/trust.json --rpc https://api.devnet.solana.com
# VALID (sealed)
```

or in a browser: [genkai-inky.vercel.app/?sample=usdc](https://genkai-inky.vercel.app/?sample=usdc).
`verify-execution` on either allow then confirms that the transaction on chain is, byte for byte,
the one its receipt binds.

The vault held 0.05 SOL for fees and 10 USDC from Circle's faucet. After the run its remaining
6.25 USDC and its SOL went back to the authority, its token account was closed, and the vault
key was destroyed.
