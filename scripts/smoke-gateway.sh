#!/usr/bin/env bash
# Boot the gateway image with a throwaway vault key and the example policy, then drive it the
# way an operator and an agent would: readiness, the first admin key, an agent and its key, a
# decision, the agent's receipts, and those receipts verifying against the published policy.
#
#   scripts/smoke-gateway.sh [image]          default image: genkai-gateway:test
#
# Needs docker, curl and jq. Nothing leaves the machine: execution is "sign", never broadcast.
set -euo pipefail

IMAGE="${1:-genkai-gateway:test}"
NAME="genkai-smoke-$$"
PORT="${SMOKE_PORT:-18788}"
BASE="http://127.0.0.1:${PORT}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() {
  echo "smoke: $*" >&2
  docker logs "$NAME" 2>&1 | tail -20 >&2 || true
  exit 1
}

chmod 777 "$WORK"
docker run --rm -v "$WORK:/work" "$IMAGE" keygen /work/vault.json >/dev/null
cp "$ROOT/examples/devnet/policy.json" "$WORK/policy.json"

docker run -d --name "$NAME" -p "127.0.0.1:${PORT}:8788" \
  --read-only --tmpfs /tmp --mount type=tmpfs,destination=/data,tmpfs-mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  -e GENKAI_VAULT_KEY_FILE=/work/vault.json -e GENKAI_POLICY_FILE=/work/policy.json \
  -e GENKAI_WINDOW_SECONDS=86400 \
  -v "$WORK:/work:ro" "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  curl -fsS "$BASE/readyz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$BASE/readyz" | jq -e '.success and .data.database == "ok"' >/dev/null || fail "not ready"
echo "ready: $(curl -fsS "$BASE/v1/trust" | jq -c '{mode: .data.mode, vault: .data.vault, execution: .data.execution}')"

ADMIN="$(docker exec "$NAME" node --experimental-strip-types --no-warnings src/cli/main.ts gateway-admin create-admin-key --db /data/genkai.db | tail -1)"
[[ "$ADMIN" =~ ^gk_[0-9a-f]{12}_ ]] || fail "no admin key issued"

api() {
  local method="$1" path="$2" token="$3" body="${4:-}"
  if [[ -n "$body" ]]; then
    curl -sS -X "$method" "$BASE$path" -H "authorization: Bearer $token" -H 'content-type: application/json' -d "$body"
  else
    curl -sS -X "$method" "$BASE$path" -H "authorization: Bearer $token"
  fi
}

api POST /v1/agents "$ADMIN" '{"id":"smoke-bot","label":"Smoke test agent"}' | jq -e '.success' >/dev/null || fail "agent not created"
AGENT="$(api POST /v1/agents/smoke-bot/keys "$ADMIN" '{"label":"smoke"}' | jq -r '.data.token')"
[[ "$AGENT" =~ ^gk_[0-9a-f]{12}_ ]] || fail "no agent key issued"

[[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/decisions" -H 'content-type: application/json' -d '{}')" == "401" ]] || fail "decisions accepted without a key"
[[ "$(api POST /v1/decisions "$ADMIN" '{}' | jq -r '.error')" != "null" ]] || fail "an admin key was allowed to decide"

decide() {
  api POST /v1/decisions "$AGENT" "{\"transfer\":{\"kind\":\"sol\",\"to\":\"$1\",\"amount\":\"$2\",\"decimals\":9},\"modelReasoning\":\"smoke test\"}" | jq -r '.data.decision.verdict'
}
[[ "$(decide 7VHUFJHWu2CuExkJcJrzhQPJ2oygupTWkL2A2For4BmE 10000000)" == "allow" ]] || fail "expected allow"
[[ "$(decide GsbwXfJraMomNxBcjYLcG3mxkBUiyWXAB32fGbSMQRdW 5000000)" == "deny" ]] || fail "expected deny for a counterparty off the allowlist"
[[ "$(decide 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM 30000000)" == "escalate" ]] || fail "expected escalate above the threshold"

RECEIPTS="$(curl -fsS "$BASE/v1/agents/smoke-bot/receipts" | jq -c '.data')"
[[ "$(jq 'length' <<<"$RECEIPTS")" == "3" ]] || fail "expected three receipts"
jq -n --argjson r "$RECEIPTS" --slurpfile p "$WORK/policy.json" '{receipts: $r, policy: $p[0]}' |
  curl -fsS "$BASE/v1/chains/verify" -H 'content-type: application/json' -d @- |
  jq -e '.data.valid == true and .data.mode == "plaintext"' >/dev/null || fail "the gateway's receipts do not verify"

echo "smoke: ok - allow, deny and escalate decided, receipted and verified as a chain"
