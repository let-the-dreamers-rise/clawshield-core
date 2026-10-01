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

## Devnet

```bash
./scripts/deploy-devnet.sh ../../sealed-secret-devnet.json
```

This builds with `--features offchain-circuit`. The computation definition then
points at `circuits/evaluate_policy.arcis` through a tag-pinned URL, and Arx
nodes check the download against the hash compiled into the program. The script
then runs `arcium deploy` on cluster 456, registers the circuit, and stages and
activates the encrypted policy. Finally it writes `deployments/devnet.json`,
which `genkai demo --live` and the verifiers read.

## Layout

| Path | Purpose |
|------|---------|
| `programs/genkai/` | Anchor program: queues computations, handles callbacks |
| `encrypted-ixs/` | Arcis confidential instructions |
| `tests/genkai.ts` | TypeScript integration tests |
| `Arcium.toml` | Localnet and cluster configuration |

## Docs

<https://docs.arcium.com/developers>
