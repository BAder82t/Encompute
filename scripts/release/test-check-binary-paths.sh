#!/usr/bin/env bash
# Selftest of scripts/release/check-binary-paths.sh on tiny binary-like files.
# Exit 0 only when every case behaves as stated.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
G=scripts/release/check-binary-paths.sh
: > "$W/none.allow"

# A binary-like file: NUL separated strings around some bytes.
mk() {  # mk FILE STRING...
  local f="$1"; shift
  { printf '\177ELF\001\002\000\000'; local s; for s in "$@"; do printf '\000%s\000\001\002' "$s"; done; } > "$f"
}
case_() {  # case_ NAME EXPECT_EXIT PATTERN ARGS...
  local name="$1" want="$2" pat="$3" out code
  shift 3
  out="$("$G" "$@" 2>&1)"; code=$?
  if [ "$code" = "$want" ] && grep -q -- "$pat" <<<"$out"; then echo "PASS  $name"
  else echo "FAIL  $name (exit $code, want $want)"; sed 's/^/    | /' <<<"$out"; fails=$((fails + 1)); fi
}

mk "$W/clean" "/target/release/build/x/out/y.rs" "/encompute/crates/a/src/lib.rs" \
  "/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/num-integer-0.1.47/src/roots.rs" \
  "/rustup/toolchains/1.98.1/lib/rustlib/src/rust/library/core/src/fmt/mod.rs" \
  "/openfhe/include/openfhe/pke/ciphertext.h" "/openfhe-src/src/pke/lib/ciphertext-impl.cpp"
case_ "a clean binary passes" 0 "BINARY PATH CHECK PASSED" "$W/clean"

mk "$W/ofhe-src" "/openfhe/include/openfhe/x.h" "/home/runner/work/Encompute/Encompute/.deps/src/openfhe-development/src/pke/lib/a.cpp"
case_ "OpenFHE source path fails and is listed" 1 "openfhe-development/src/pke/lib/a.cpp" "$W/ofhe-src"

mk "$W/old-order" "/encompute/.deps/openfhe/include/openfhe/pke/ciphertext.h"
case_ "the v0.3.1 unremapped OpenFHE header path fails" 1 "/encompute/.deps/openfhe/include" "$W/old-order"

mk "$W/runner" "/home/runner/work/x/y.rs"
case_ "/home/runner fails" 1 "/home/runner/work/x/y.rs" "$W/runner"
mk "$W/home" "/home/alice/src/z.rs"
case_ "another user's home fails" 1 "/home/alice/src/z.rs" "$W/home"
mk "$W/users" "/Users/bob/dev/z.rs"
case_ "/Users fails" 1 "/Users/bob/dev/z.rs" "$W/users"
mk "$W/root" "/root/.cargo/registry/z.rs"
case_ "/root fails" 1 "/root/.cargo/registry/z.rs" "$W/root"
mk "$W/tmp" "/tmp/tmp.AbC123/release/build/z.rs"
case_ "a /tmp build directory fails" 1 "/tmp/tmp.AbC123" "$W/tmp"
mk "$W/var" "/var/folders/ab/T/build/z.rs"
case_ "/var fails" 1 "/var/folders" "$W/var"
mk "$W/builds" "/builds/group/project/z.rs"
case_ "/builds fails" 1 "/builds/group" "$W/builds"
mk "$W/runnerdir" "/runner/work/z.rs"
case_ "/runner fails" 1 "/runner/work" "$W/runnerdir"

# A path concatenated to other data (Rust keeps string literals back to back).
mk "$W/glued" "src/lib.rs/home/runner/work/z.rscalled Option::unwrap()"
case_ "a path glued to other strings still fails" 1 "BINARY PATH CHECK FAILED" "$W/glued"

# Several binaries: one bad one fails the call, and the clean one is reported.
case_ "one bad binary among several fails" 1 "PASS  $W/clean" "$W/clean" "$W/runner"

# Missing and empty files fail.
: > "$W/empty"
case_ "an empty file fails" 1 "missing or empty" "$W/empty"
case_ "a missing file fails" 1 "missing or empty" "$W/does-not-exist"

# Report only: same report, exit 0.
case_ "report-only prints the failure and exits 0" 0 "report only" --report-only "$W/runner"

# The allowlist.
printf '/home/runner/work/x/y.rs\tself-test: a runner path excused on purpose\n' > "$W/ok.allow"
case_ "an allowlisted string is excused" 0 "BINARY PATH CHECK PASSED" --allowlist "$W/ok.allow" "$W/runner"
case_ "an allowlist does not excuse other strings" 1 "/home/alice/src/z.rs" --allowlist "$W/ok.allow" "$W/home"
printf '# comment\n\n/home/runner/work/x/y.rs\n' > "$W/nojust.allow"
case_ "an allowlist line without a justification is an error" 2 "needs 'string<TAB>justification'" --allowlist "$W/nojust.allow" "$W/runner"
printf '/home/runner/work/x/y.rs\t   \n' > "$W/blank.allow"
case_ "an allowlist line with a blank justification is an error" 2 "needs" --allowlist "$W/blank.allow" "$W/runner"
case_ "a missing allowlist is an error" 2 "not found" --allowlist "$W/nope.allow" "$W/clean"
case_ "no arguments is a usage error" 2 "usage"

# The shipped allowlist has no exception (an exception needs a justification in review).
if grep -qvE '^[[:space:]]*(#|$)' scripts/release/binary-paths.allow; then
  echo "NOTE  scripts/release/binary-paths.allow holds exceptions:"; grep -vE '^[[:space:]]*(#|$)' scripts/release/binary-paths.allow | sed 's/^/    | /'
else echo "PASS  the shipped allowlist holds no exception"; fi
case_ "the shipped allowlist is valid" 0 "PASSED" "$W/clean"

# Without `strings` the python scan gives the same verdicts.
mkdir -p "$W/nostrings"
for t in python3 grep sed cut head sort wc tr mktemp rm cat dirname; do
  p="$(command -v "$t")" && ln -sf "$p" "$W/nostrings/$t"
done
nsout="$(PATH="$W/nostrings" /bin/bash "$G" --allowlist "$W/none.allow" "$W/runner" "$W/clean" 2>&1)"; nscode=$?
if [ "$nscode" = 1 ] && grep -q "/home/runner/work/x/y.rs" <<<"$nsout" && grep -q "PASS  $W/clean" <<<"$nsout"; then
  echo "PASS  the python scan replaces a missing strings"
else echo "FAIL  python fallback (exit $nscode)"; sed 's/^/    | /' <<<"$nsout"; fails=$((fails + 1)); fi

[ "$fails" = 0 ] && { echo "test-check-binary-paths: all cases passed"; exit 0; }
echo "test-check-binary-paths: $fails case(s) failed"
exit 1
