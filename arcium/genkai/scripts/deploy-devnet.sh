#!/usr/bin/env bash
# Deploy GENKAI to Solana devnet against Arcium cluster 456, and seal a policy into it.
#
#   ./scripts/deploy-devnet.sh <seal.json>
#
# <seal.json> comes from `node --experimental-strip-types scripts/seal-for-chain.ts --demo <out>`
# in the repository root. The deployer key (~/.config/solana/id.json, or $KEYPAIR) becomes the
# program's upgrade authority, the MXE authority and the policy authority, and needs about
# 7 devnet SOL: deploying the 485 KB program holds its rent twice while the buffer is written.
#
# Re-runnable: if `arcium deploy` was interrupted, rerun with RESUME=1.
set -euo pipefail

SEAL="${1:?usage: deploy-devnet.sh <seal.json>}"
SEAL="$(cd "$(dirname "$SEAL")" && pwd)/$(basename "$SEAL")"
RPC_URL="${RPC_URL:-https://api.devnet.solana.com}"
CLUSTER_OFFSET="${CLUSTER_OFFSET:-456}"
KEYPAIR="${KEYPAIR:-$HOME/.config/solana/id.json}"
TOOLS_VERSION="${TOOLS_VERSION:-v1.57}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CIRCUIT_URL="https://raw.githubusercontent.com/let-the-dreamers-rise/clawshield-core/circuit-evaluate-policy-v2/arcium/genkai/circuits/evaluate_policy.arcis"
cd "$ROOT"

balance=$(solana balance --url "$RPC_URL" --keypair "$KEYPAIR" | cut -d' ' -f1)
echo "deployer $(solana address --keypair "$KEYPAIR") holds $balance SOL on $RPC_URL"

# 1. Circuit and IDL, then the program for SBF v0 with the off-chain circuit source.
#    See scripts/test-localnet.sh for why the arch is v0.
arcium build
(cd programs/genkai && cargo-build-sbf --tools-version "$TOOLS_VERSION" --skip-tools-install --features offchain-circuit --sbf-out-dir ../../target/deploy)

# 2. The hosted circuit must be byte-identical to the one circuit_hash! compiled in, or the
#    Arx nodes will refuse it. Check before spending anything.
built=$(sha256sum build/evaluate_policy.arcis | cut -d' ' -f1)
committed=$(sha256sum circuits/evaluate_policy.arcis | cut -d' ' -f1)
hosted=$(curl -fsSL "$CIRCUIT_URL" | sha256sum | cut -d' ' -f1)
if [ "$built" != "$committed" ] || [ "$built" != "$hosted" ]; then
  echo "circuit mismatch: built $built, committed $committed, hosted $hosted" >&2
  exit 1
fi
echo "circuit $built is hosted at $CIRCUIT_URL"

# 3. Program and MXE account.
arcium deploy --cluster-offset "$CLUSTER_OFFSET" --recovery-set-size 4 --keypair-path "$KEYPAIR" \
  --program-keypair target/deploy/genkai-keypair.json --program-name genkai --rpc-url "$RPC_URL" \
  ${RESUME:+--resume}

# 4. Computation definition, sealed policy, manifest.
mkdir -p deployments
ANCHOR_PROVIDER_URL="$RPC_URL" ANCHOR_WALLET="$KEYPAIR" \
  npx ts-node -T -P tsconfig.json scripts/devnet-setup.ts "$SEAL" "$CLUSTER_OFFSET" deployments/devnet.json
