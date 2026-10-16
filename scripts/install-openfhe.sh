#!/usr/bin/env bash
# Build and install the pinned OpenFHE release into .deps/openfhe (or $1).
set -euo pipefail

OPENFHE_VERSION="v1.5.1"
# The commit the tag must resolve to: a moved tag fails the install.
OPENFHE_COMMIT="1306d14f8c26bb6150d3e6ad54f28dfe1007689e"
# Static libraries: binaries and the Python extension need no rpath setup.
# static-4: OpenFHE's own objects no longer embed the source or install path
# (-ffile-prefix-map below), so every binary that links them changes.
BUILD_ID="$OPENFHE_VERSION-static-4"
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
got="$(git -C "$SRC" rev-parse HEAD)"
if [ "$got" != "$OPENFHE_COMMIT" ]; then
  echo "OpenFHE $OPENFHE_VERSION resolved to $got, expected $OPENFHE_COMMIT: refusing to build" >&2
  exit 1
fi

# OpenFHE's own .cpp objects embed __FILE__ (OPENFHE_THROW, assertions) and the
# source-tree header paths of the checkout they were built in. Map them to
# fixed names so the library, and the binaries that link it, do not depend on
# where OpenFHE was built. Merged with any CFLAGS/CXXFLAGS already set.
PREFIX_MAP="-ffile-prefix-map=$SRC=/openfhe-src -ffile-prefix-map=$PREFIX=/openfhe"

CMAKE_ARGS=(
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_C_FLAGS="${CFLAGS:+$CFLAGS }$PREFIX_MAP"
  -DCMAKE_CXX_FLAGS="${CXXFLAGS:+$CXXFLAGS }$PREFIX_MAP"
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
