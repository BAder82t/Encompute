#!/usr/bin/env bash
# Build and install the pinned OpenFHE release into .deps/openfhe (or $1).
set -euo pipefail

OPENFHE_VERSION="v1.5.1"
# Static libraries: binaries and the Python extension need no rpath setup.
BUILD_ID="$OPENFHE_VERSION-static-3"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${1:-$ROOT/.deps/openfhe}"
SRC="$ROOT/.deps/src/openfhe-development"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"

if [ -f "$PREFIX/.encompute-openfhe-version" ] && [ "$(cat "$PREFIX/.encompute-openfhe-version")" = "$BUILD_ID" ]; then
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
  -DBUILD_STATIC=ON
  -DBUILD_SHARED=OFF
  -DWITH_OPENMP=ON
  # The Python extension is a shared object; static OpenFHE must be PIC on Linux.
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
)
if [ "$(uname)" = "Darwin" ]; then
  OMP="$(brew --prefix libomp)"
  CMAKE_ARGS+=(
    -DCMAKE_OSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
    -DOpenMP_CXX_FLAGS="-Xpreprocessor -fopenmp -I$OMP/include"
    -DOpenMP_CXX_LIB_NAMES=omp
    -DOpenMP_omp_LIBRARY="$OMP/lib/libomp.dylib"
  )
fi

cmake -S "$SRC" -B "$SRC/build" "${CMAKE_ARGS[@]}"
cmake --build "$SRC/build" -j "$JOBS"
cmake --install "$SRC/build"
echo "$BUILD_ID" > "$PREFIX/.encompute-openfhe-version"
echo "OpenFHE $OPENFHE_VERSION installed at $PREFIX"
