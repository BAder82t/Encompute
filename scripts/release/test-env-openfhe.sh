#!/usr/bin/env bash
# Selftest of the OPENFHE_ROOT contract of scripts/release/env.sh. It runs the
# script from a copy in a temporary fake checkout with a fake OpenFHE install
# (empty files), so it needs no compiler and no OpenFHE. Exit 0 only when
# every case behaves as stated.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0

mkdir -p "$W/repo/scripts/release"
cp "$ROOT/scripts/release/env.sh" "$W/repo/scripts/release/env.sh"
ENV="$W/repo/scripts/release/env.sh"

fake_install() {  # fake_install DIR
  mkdir -p "$1/include/openfhe/pke" "$1/lib"
  : > "$1/include/openfhe/pke/openfhe.h"
  for l in pke binfhe core; do : > "$1/lib/libOPENFHE${l}_static.a"; done
}
fake_install "$W/other"                 # an explicit, valid root
fake_install "$W/repo/.deps/openfhe"    # the default location
mkdir -p "$W/empty-dir"                 # a directory that is not an install
fake_install "$W/nolib"; rm "$W/nolib/lib/libOPENFHEcore_static.a"
fake_install "$W/nohdr"; rm "$W/nohdr/include/openfhe/pke/openfhe.h"

# run NAME... : run a snippet in a clean shell; prints "key=value" lines.
probe() {  # probe PRE_COMMAND  (executed before sourcing; env.sh is sourced from the fake checkout)
  env -i HOME="$HOME" PATH="$PATH" bash -c "$1"'
    echo "rc=$?"
    echo "ROOT=${OPENFHE_ROOT-<unset>}"
    echo "RUSTFLAGS=${RUSTFLAGS-}"
    echo "CFLAGS=${CFLAGS-}"
    echo "CXXFLAGS=${CXXFLAGS-}"' 2>"$W/stderr"
}
val() { sed -n "s/^$2=//p" <<<"$1" | head -n 1; }
ok() { echo "PASS  $1"; }
no() { echo "FAIL  $1"; [ -z "${2:-}" ] || sed 's/^/    | /' <<<"$2"; fails=$((fails + 1)); }

remap_in_all() {  # remap_in_all OUTPUT ROOT
  local o="$1" r="$2"
  grep -qF -- "--remap-path-prefix=$r=/openfhe" <<<"$(val "$o" RUSTFLAGS)" &&
  grep -qF -- "-ffile-prefix-map=$r=/openfhe" <<<"$(val "$o" CFLAGS)" &&
  grep -qF -- "-ffile-prefix-map=$r=/openfhe" <<<"$(val "$o" CXXFLAGS)"
}

# 1. unset and the default directory exists: the default is used and remapped.
out="$(probe ". '$ENV' '$W/t1'")"
D="$W/repo/.deps/openfhe"
if [ "$(val "$out" rc)" = 0 ] && [ "$(val "$out" ROOT)" = "$D" ] && remap_in_all "$out" "$D"; then
  ok "unset, default directory exists: default root and the remap in RUSTFLAGS, CFLAGS and CXXFLAGS"
else no "unset, default directory exists" "$out"; fi

# 2. set and valid: unchanged, remapped (even though a default exists).
out="$(probe "export OPENFHE_ROOT='$W/other'; . '$ENV' '$W/t2'")"
if [ "$(val "$out" rc)" = 0 ] && [ "$(val "$out" ROOT)" = "$W/other" ] && remap_in_all "$out" "$W/other" &&
   ! grep -qF -- "$D=/openfhe" <<<"$(val "$out" RUSTFLAGS)"; then
  ok "set and valid: used as given (not replaced by the default) and remapped in all three flag sets"
else no "set and valid" "$out"; fi

# 3. set and invalid: sourcing fails with a message naming the path, nothing is exported.
check_invalid() {  # check_invalid NAME VALUE EXPECT_TEXT
  out="$(probe "export OPENFHE_ROOT='$2'; . '$ENV' '$W/t3'")"
  if [ "$(val "$out" rc)" = 1 ] && grep -qF -- "OPENFHE_ROOT=$2" "$W/stderr" && grep -qF -- "$3" "$W/stderr" &&
     [ -z "$(val "$out" RUSTFLAGS)" ]; then ok "set and invalid ($1): sourcing fails and names the problem"
  else no "set and invalid ($1)" "$out
$(cat "$W/stderr")"; fi
}
check_invalid "missing directory" "$W/does-not-exist" "include/openfhe/pke/openfhe.h"
check_invalid "directory that is no install" "$W/empty-dir" "include/openfhe/pke/openfhe.h"
check_invalid "a static library is missing" "$W/nolib" "libOPENFHEcore_static.a"
check_invalid "the headers are missing" "$W/nohdr" "include/openfhe/pke/openfhe.h"
check_invalid "relative path" "relative/openfhe" "not an absolute path"
check_invalid "trailing slash" "$W/other/" "trailing slash"

# 4. an invalid explicit root is never replaced by the valid default.
out="$(probe "export OPENFHE_ROOT='$W/does-not-exist'; . '$ENV' '$W/t4'")"
if [ "$(val "$out" rc)" = 1 ] && [ "$(val "$out" ROOT)" = "$W/does-not-exist" ]; then
  ok "an invalid explicit root is not silently replaced by the default"
else no "invalid root replaced" "$out"; fi

# 5. a caller that holds an inherited root (the Azure vmenv.sh case) must export
#    the intended one BEFORE sourcing; env.sh then remaps exactly that one.
out="$(probe "export OPENFHE_ROOT='$W/other'; export OPENFHE_ROOT='$D'; . '$ENV' '$W/t5'")"
if [ "$(val "$out" rc)" = 0 ] && [ "$(val "$out" ROOT)" = "$D" ] && remap_in_all "$out" "$D"; then
  ok "the intended root exported before sourcing is the one remapped"
else no "intended root before sourcing" "$out"; fi

# 6. empty counts as unset.
out="$(probe "export OPENFHE_ROOT=''; . '$ENV' '$W/t6'")"
if [ "$(val "$out" rc)" = 0 ] && [ "$(val "$out" ROOT)" = "$D" ] && remap_in_all "$out" "$D"; then
  ok "empty OPENFHE_ROOT is treated as unset"
else no "empty root" "$out"; fi

# 7. order independence for the default location: exporting the default root
#    before sourcing and leaving it unset give the same flags.
a="$(probe ". '$ENV' '$W/t7'")"
b="$(probe "export OPENFHE_ROOT='$D'; . '$ENV' '$W/t7'")"
if [ "$(val "$a" RUSTFLAGS)" = "$(val "$b" RUSTFLAGS)" ] && [ "$(val "$a" CFLAGS)" = "$(val "$b" CFLAGS)" ] &&
   [ "$(val "$a" CXXFLAGS)" = "$(val "$b" CXXFLAGS)" ]; then
  ok "the default root and the same root exported explicitly give identical flags"
else no "default vs explicit flags differ" "$a
---
$b"; fi

# 8. no root and no default directory: nothing to remap, and no error.
out="$(probe "unset OPENFHE_ROOT; mv '$D' '$D.hidden'; . '$ENV' '$W/t8'; mv '$D.hidden' '$D'")"
if [ "$(val "$out" rc)" = 0 ] && ! grep -qF -- "=/openfhe" <<<"$(val "$out" RUSTFLAGS)"; then
  ok "no root and no default: no OpenFHE remap (builds without OpenFHE)"
else no "no root, no default" "$out"; fi

[ "$fails" = 0 ] && { echo "test-env-openfhe: all cases passed"; exit 0; }
echo "test-env-openfhe: $fails case(s) failed"
exit 1
