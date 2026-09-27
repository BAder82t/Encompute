# Build environment of a release, sourced by the release scripts and by
# .github/workflows/release.yml:
#
#   . scripts/release/env.sh [TARGET_DIR]
#
# Sets what makes two builds of the same commit produce the same bytes:
# a fixed timestamp (the commit's), no local paths in the binaries, one
# codegen unit, no incremental state. Symbols are kept: the commercial and
# evaluator audits read them (scripts/audit-*.sh).

_encompute_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/../.." && pwd)"
_encompute_target="${1:-${CARGO_TARGET_DIR:-$_encompute_root/target}}"

# The commit time, not the build time: embedded by anything that stamps a
# date (tar, zip, wheels, C/C++ __DATE__ through the compiler, macOS ar).
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$_encompute_root" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH
export ZERO_AR_DATE=1          # macOS ar/libtool: no member timestamps
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_INCREMENTAL=false
export CARGO_TARGET_DIR="$_encompute_target"

# Local paths become fixed prefixes: the checkout, the target directory,
# cargo's registry and rustup's toolchain (panic messages and debug strings
# otherwise name them).
_cargo_home="${CARGO_HOME:-$HOME/.cargo}"
_rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
_remap="--remap-path-prefix=$_encompute_target=/target"
_remap="$_remap --remap-path-prefix=$_encompute_root=/encompute"
_remap="$_remap --remap-path-prefix=$_cargo_home=/cargo"
_remap="$_remap --remap-path-prefix=$_rustup_home=/rustup"
_cmap="-ffile-prefix-map=$_encompute_root=/encompute -ffile-prefix-map=$_encompute_target=/target"
if [ -n "${OPENFHE_ROOT:-}" ]; then
  _remap="$_remap --remap-path-prefix=$OPENFHE_ROOT=/openfhe"
  _cmap="$_cmap -ffile-prefix-map=$OPENFHE_ROOT=/openfhe"
fi
export RUSTFLAGS="${ENCOMPUTE_EXTRA_RUSTFLAGS:-} $_remap"
# C and C++ code built by build scripts (cxx bridges, OpenFHE wrappers).
export CFLAGS="${CFLAGS:-} $_cmap"
export CXXFLAGS="${CXXFLAGS:-} $_cmap"
unset _cmap
unset _encompute_root _encompute_target _cargo_home _rustup_home _remap
