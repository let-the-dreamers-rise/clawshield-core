#!/usr/bin/env bash
# Build the GENKAI program for the default SBF arch (v0) and run the localnet suite.
#
# `arcium build` drives the Anchor 1.2 CLI, which passes `--arch v3` to
# cargo-build-sbf. With that build, every evaluate_policy_callback aborts with
# "exceeded max BPF to BPF call depth" inside the BLS check of verify_output.
# The v0 build runs the same callback within limits.
set -euo pipefail

TOOLS_VERSION="${TOOLS_VERSION:-v1.57}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

(cd "$ROOT" && arcium build)
(cd "$ROOT/programs/genkai" &&
  cargo-build-sbf --tools-version "$TOOLS_VERSION" --sbf-out-dir ../../target/deploy)
(cd "$ROOT" && arcium test --skip-build)
