# genkai

A confidential Solana app built with Arcium: an Anchor program queues computations, and Arcis instructions define the confidential logic.

## Quickstart

```bash
./scripts/test-localnet.sh
```

The script runs `arcium build`, which compiles the circuit and IDL, and then
rebuilds the program with `cargo-build-sbf` for the default SBF arch (v0).
The Anchor 1.2 CLI builds for `--arch v3`. Under v3, the callback's
`verify_output` overflows the BPF call depth on localnet.

The localnet suite runs the following checks against the program:

- It stages a policy encrypted under `Enc<Shared>` and activates it.
- It runs 7 fixture requests through the MXE (allow, deny and escalate).
- It asserts that each callback's DecisionRecord matches the TypeScript
  circuit model in `tests/fixtures.json`.
- It checks that only the policy authority can evaluate, so the policy cannot
  be probed as an oracle.

## Layout

| Path | Purpose |
|------|---------|
| `programs/genkai/` | Anchor program: queues computations, handles callbacks |
| `encrypted-ixs/` | Arcis confidential instructions |
| `tests/genkai.ts` | TypeScript integration tests |
| `Arcium.toml` | Localnet and cluster configuration |

## Docs

<https://docs.arcium.com/developers>
