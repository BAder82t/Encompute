#!/usr/bin/env bash
# Measurement only: builds and runs crates/encompute-openfhe/bench/lut_measure.cc
# (OpenFHE BinFHE LUT evaluation against the production Boolean gate) against
# the static OpenFHE at $OPENFHE_ROOT (default .deps/openfhe).
# Usage: scripts/lut-measure.sh [gate|lut4|lut8|lut16|sign]...
# lut16 needs about 20 GB of memory (its key-switching key alone is ~9 GiB).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OPENFHE_ROOT="${OPENFHE_ROOT:-$ROOT/.deps/openfhe}"
INC="$OPENFHE_ROOT/include/openfhe"
OUT="$ROOT/target/lut_measure"

OMP_FLAGS=(-fopenmp)
OMP_LIBS=(-lgomp)
if [ "$(uname)" = Darwin ]; then
  OMP="$(brew --prefix libomp)"
  OMP_FLAGS=(-Xpreprocessor -fopenmp -I"$OMP/include")
  OMP_LIBS=(-L"$OMP/lib" -lomp)
fi

mkdir -p "$ROOT/target"
"${CXX:-c++}" -std=c++17 -O3 -DNDEBUG -DMATHBACKEND=4 "${OMP_FLAGS[@]}" \
  -isystem "$INC" -isystem "$INC/core" -isystem "$INC/binfhe" -isystem "$INC/cereal" \
  "$ROOT/crates/encompute-openfhe/bench/lut_measure.cc" -o "$OUT" \
  -L"$OPENFHE_ROOT/lib" -lOPENFHEbinfhe_static -lOPENFHEcore_static "${OMP_LIBS[@]}"

exec "$OUT" "$@"
