#!/usr/bin/env bash
# Build and install the pinned OpenFHE release into .deps/openfhe (or $1).
set -euo pipefail

OPENFHE_VERSION="v1.5.1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${1:-$ROOT/.deps/openfhe}"
SRC="$ROOT/.deps/src/openfhe-development"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

if [ -f "$PREFIX/.veil-openfhe-version" ] && [ "$(cat "$PREFIX/.veil-openfhe-version")" = "$OPENFHE_VERSION" ]; then
  echo "OpenFHE $OPENFHE_VERSION already installed at $PREFIX"
  exit 0
fi

rm -rf "$SRC"
git clone --depth 1 --branch "$OPENFHE_VERSION" https://github.com/openfheorg/openfhe-development.git "$SRC"

CMAKE_ARGS=(
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_INSTALL_PREFIX="$PREFIX"
  -DBUILD_UNITTESTS=OFF
  -DBUILD_EXAMPLES=OFF
  -DBUILD_BENCHMARKS=OFF
  -DBUILD_STATIC=OFF
  -DWITH_OPENMP=ON
)
if [ "$(uname)" = "Darwin" ]; then
  OMP="$(brew --prefix libomp)"
  CMAKE_ARGS+=(
    -DOpenMP_CXX_FLAGS="-Xpreprocessor -fopenmp -I$OMP/include"
    -DOpenMP_CXX_LIB_NAMES=omp
    -DOpenMP_omp_LIBRARY="$OMP/lib/libomp.dylib"
  )
fi

cmake -S "$SRC" -B "$SRC/build" "${CMAKE_ARGS[@]}"
cmake --build "$SRC/build" -j "$JOBS"
cmake --install "$SRC/build"
echo "$OPENFHE_VERSION" > "$PREFIX/.veil-openfhe-version"
echo "OpenFHE $OPENFHE_VERSION installed at $PREFIX"
