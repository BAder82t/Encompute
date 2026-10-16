#!/usr/bin/env bash
# Selftest of scripts/release/build-release-binaries.sh. A stub `cargo` records
# its arguments and the build environment, so no compiler and no OpenFHE are
# needed. Exit 0 only when every case behaves as stated.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0

# A fake checkout holding the two scripts, and a stub cargo.
mkdir -p "$W/repo/scripts/release" "$W/bin"
cp "$ROOT/scripts/release/env.sh" "$ROOT/scripts/release/build-release-binaries.sh" "$W/repo/scripts/release/"
cat > "$W/bin/cargo" <<EOF
#!/usr/bin/env bash
{ echo "ARGS=\$*"; echo "RUSTFLAGS=\$RUSTFLAGS"; echo "CFLAGS=\$CFLAGS"; echo "CXXFLAGS=\$CXXFLAGS"
  echo "ROOT=\$OPENFHE_ROOT"; echo "TARGET=\$CARGO_TARGET_DIR"; } > "$W/cargo.out"
EOF
chmod +x "$W/bin/cargo"
fake_install() {
  mkdir -p "$1/include/openfhe/pke" "$1/lib"; : > "$1/include/openfhe/pke/openfhe.h"
  for l in pke binfhe core; do : > "$1/lib/libOPENFHE${l}_static.a"; done
}
fake_install "$W/repo/.deps/openfhe"; fake_install "$W/explicit"
B="$W/repo/scripts/release/build-release-binaries.sh"

run() {  # run [VAR=VALUE...] TARGET ; sets $out and $rc
  rm -f "$W/cargo.out"
  out="$(env -i HOME="$HOME" PATH="$W/bin:$PATH" "${@:1:$#-1}" "$B" "${@: -1}" 2>&1)"; rc=$?
}
ok() { echo "PASS  $1"; }
no() { echo "FAIL  $1"; sed 's/^/    | /' <<<"$2"; fails=$((fails + 1)); }

# 1. unset: the default install, the exact shipping command, the remap in all flag sets.
run "$W/t1"
D="$W/repo/.deps/openfhe"
if [ "$rc" = 0 ] && grep -qx "ARGS=build --release --locked -p encompute-cli -p encompute-evaluator -p encompute-control --features encompute-cli/openfhe,encompute-evaluator/openfhe" "$W/cargo.out" &&
   grep -qx "ROOT=$D" "$W/cargo.out" && grep -qx "TARGET=$W/t1" "$W/cargo.out" &&
   grep -q "^RUSTFLAGS=.*--remap-path-prefix=$D=/openfhe" "$W/cargo.out" &&
   grep -q "^CFLAGS=.*-ffile-prefix-map=$D=/openfhe" "$W/cargo.out" &&
   grep -q "^CXXFLAGS=.*-ffile-prefix-map=$D=/openfhe" "$W/cargo.out"; then
  ok "unset root: default install, the shipping cargo command, remap in RUSTFLAGS, CFLAGS and CXXFLAGS"
else no "unset root" "$out"; fi

# 2. an explicit root is used as given.
run OPENFHE_ROOT="$W/explicit" "$W/t2"
if [ "$rc" = 0 ] && grep -qx "ROOT=$W/explicit" "$W/cargo.out" && grep -q "^RUSTFLAGS=.*=$W/explicit=/openfhe" "$W/cargo.out"; then
  ok "explicit root is used as given and remapped"
else no "explicit root" "$out"; fi

# 3. an invalid explicit root stops the build before cargo runs.
mkdir -p "$W/bad"
run OPENFHE_ROOT="$W/bad" "$W/t3"
if [ "$rc" != 0 ] && [ ! -e "$W/cargo.out" ]; then ok "invalid explicit root: fails, cargo not run"
else no "invalid explicit root" "$out"; fi
run OPENFHE_ROOT="$W/missing" "$W/t3"
if [ "$rc" != 0 ] && [ ! -e "$W/cargo.out" ]; then ok "missing explicit root: fails, cargo not run"
else no "missing explicit root" "$out"; fi

[ "$fails" = 0 ] && { echo "test-build-release-binaries: all cases passed"; exit 0; }
echo "test-build-release-binaries: $fails case(s) failed"
exit 1
