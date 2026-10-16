#!/usr/bin/env bash
# The shipping build of the three release binaries (CLI, evaluator, control
# plane, with OpenFHE). The `binaries` job of .github/workflows/release.yml
# runs exactly this, and so does the shipping configuration of the diagnostic
# (scripts/release/diag-openfhe-order.sh), so the two cannot drift apart.
#
#   scripts/release/build-release-binaries.sh [TARGET_DIR]
#
# OPENFHE_ROOT, when set, is the install to build against and is used as
# given; unset, it is <repo>/.deps/openfhe. Either way it is resolved and
# validated BEFORE scripts/release/env.sh is sourced (env.sh computes the
# OpenFHE path remap from it), and the build stops if the remap is absent.
# The output is TARGET_DIR/release/{encompute,encompute-evaluator,encompute-control}.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TARGET="${1:-$ROOT/target}"

: "${OPENFHE_ROOT:=$ROOT/.deps/openfhe}"
export OPENFHE_ROOT
if [ ! -d "$OPENFHE_ROOT" ]; then
  echo "build-release-binaries: OpenFHE not found at $OPENFHE_ROOT (scripts/install-openfhe.sh, or set OPENFHE_ROOT)" >&2
  exit 1
fi

# shellcheck source=scripts/release/env.sh
. scripts/release/env.sh "$TARGET"

# Fail closed: the three flag sets name the OpenFHE root.
for v in RUSTFLAGS CFLAGS CXXFLAGS; do
  case "${!v}" in
    *"=$OPENFHE_ROOT=/openfhe"*|*"=$OPENFHE_ROOT=/openfhe "*) ;;
    *) echo "build-release-binaries: $v does not remap $OPENFHE_ROOT to /openfhe: $v=${!v}" >&2; exit 1 ;;
  esac
done
echo "OPENFHE_ROOT=$OPENFHE_ROOT"
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"

cargo build --release --locked -p encompute-cli -p encompute-evaluator -p encompute-control \
  --features encompute-cli/openfhe,encompute-evaluator/openfhe
