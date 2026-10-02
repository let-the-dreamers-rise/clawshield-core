# The gateway run on devnet

One agent of the GENKAI gateway asked for five transfers. The gateway ran from its published
container image in sealed mode, so the Arcium cluster decided each request against the
encrypted policy, and in broadcast mode, so it sent what it signed.

| # | Request | Verdict | Rules | Decision |
|---|---|---|---|---|
| 1 | 0.01 SOL to vendor A | allow | `all_checks_passed` | 9.3 s, [landed](https://explorer.solana.com/tx/5axning5vhZ6PTx7Nhw3WyPpBAYjPgNQetaCT7Fq5D9kdW2xTspMMpxvQ8sEj47uGYFrGH5ANWyHEhqJW5oYU3wc?cluster=devnet) |
| 2 | 0.005 SOL to an unknown address | deny | `counterparty_not_allowed` | 38.4 s |
| 3 | 0.03 SOL to vendor B | escalate | `human_approval_required` | 5.1 s |
| 4 | 0.2 SOL to vendor A | deny | `mint_cap_exceeded`, `amount_exceeds_window` | 6.1 s |
| 5 | 0.015 SOL to vendor B | allow | `all_checks_passed` | 7.6 s, [landed](https://explorer.solana.com/tx/2NJoEc4CmAy5MyDWkFmwigVZ7hWKPUCZFspYHazhb18SC7A2QNwFA7m414zVwYsma7GSpghBSznfJPtH3NouULgA?cluster=devnet) |

The times are the agent's full HTTP round trip, the MPC evaluation included.

- `receipts.json`: the agent's receipt chain, as `GET /v1/agents/desk-alpha/receipts` served it
- `run.json`: what the receipts do not carry: the image digest, the vault, the operator key,
  each decision's latency and the slot each transfer finalized in
- the trust anchor is the deployment's, [`../trust.json`](../trust.json)

Check it from files and RPC alone:

```bash
npm run genkai -- verify-chain examples/devnet/gateway/receipts.json \
  --trust examples/devnet/trust.json --rpc https://api.devnet.solana.com
# VALID (sealed)
```

`verify-execution` on either allow then confirms that the transaction on chain is, byte for
byte, the one its receipt binds.
