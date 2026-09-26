#!/usr/bin/env bash
# The commercial dependency boundary: production artifacts contain no TFHE-rs
# (commercial use of Zama's technology needs a separate patent license) and
# no other research-only dependency. Checks, for the production feature set:
#   1. the Rust dependency graph (cargo tree) and a CycloneDX SBOM;
#   2. the CLI and evaluator binaries (symbols, dynamic libraries);
#   3. the Python extension (and a wheel, with WHEEL=path);
#   4. the production container (with IMAGE=tag, if docker is available).
# Documentation strings naming TFHE-rs are allowed; code is not.
#
#   scripts/audit-commercial-build.sh [target/release]
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${1:-target/release}"
FEATURES="encompute-cli/openfhe,encompute-evaluator/openfhe,encompute-py/openfhe"
# Crates published by Zama for TFHE-rs, and its runtime.
BANNED='^(tfhe|tfhe-[a-z0-9-]+|concrete[a-z0-9-]*|zama[a-z0-9-]*)$'
SYMBOLS='_ZN4tfhe|_ZN[0-9]+tfhe_(fft|ntt|csprng|versionable|zk_pok|cuda)|[0-9]tfhe[0-9]'
status=0
row() { printf '%-32s%s\n' "$1" "$2"; }
fail() { row "$1" "FAIL: $2"; status=1; }

# 1. Dependency graph and SBOM.
crates="$(cargo tree -e normal --prefix none --format '{p}' \
  -p encompute-cli -p encompute-evaluator -p encompute-py --features "$FEATURES" 2>/dev/null |
  awk '{print $1}' | sort -u)"
if [ -z "$crates" ]; then fail "dependency graph" "cargo tree produced nothing"; fi
bad="$(echo "$crates" | grep -E "$BANNED" || true)"
if [ -n "$bad" ]; then fail "dependency graph" "research crates: $(echo "$bad" | tr '\n' ' ')";
else row "dependency graph" "PASS ($(echo "$crates" | wc -l | tr -d ' ') crates, no TFHE-rs)"; fi
mkdir -p target/sbom
if python3 scripts/sbom.py --features "$FEATURES" > target/sbom/encompute.cdx.json; then
  if python3 - target/sbom/encompute.cdx.json <<'PY'
import json, re, sys
bom = json.load(open(sys.argv[1]))
names = [c["name"] for c in bom["components"]]
banned = [n for n in names if re.match(r"^(tfhe|tfhe-[a-z0-9-]+|concrete[a-z0-9-]*|zama[a-z0-9-]*)$", n)]
assert "OpenFHE" in names and "encompute-openfhe-exact" in names, "OpenFHE missing from the SBOM"
assert not banned, f"research components in the SBOM: {banned}"
print(f"{len(names)} components")
PY
  then row "SBOM (CycloneDX)" "PASS (target/sbom/encompute.cdx.json: OpenFHE, no TFHE-rs)"
  else fail "SBOM (CycloneDX)" "see above"; fi
else fail "SBOM (CycloneDX)" "could not generate"; fi

# 2. Binaries.
scan() {  # scan NAME FILE
  local f="$2"
  if [ ! -f "$f" ]; then row "$1" "SKIPPED (no $f)"; return; fi
  local n
  n="$( (nm "$f" 2>/dev/null || true) | grep -cE "$SYMBOLS" || true)"
  local libs
  libs="$( (otool -L "$f" 2>/dev/null || ldd "$f" 2>/dev/null || true) | grep -ciE 'tfhe|zama' || true)"
  if [ "$n" != "0" ] || [ "$libs" != "0" ]; then fail "$1" "$n TFHE-rs symbols, $libs libraries"
  else row "$1" "PASS (no TFHE-rs symbols or libraries)"; fi
}
scan "encompute (CLI)" "$BIN/encompute"
scan "encompute-evaluator" "$BIN/encompute-evaluator"
EXT="$(python3 -c 'import encompute._native as n; print(n.__file__)' 2>/dev/null || true)"
scan "Python extension" "${EXT:-/nonexistent}"

# 3. A wheel.
if [ -n "${WHEEL:-}" ]; then
  if unzip -l "$WHEEL" | grep -qiE 'tfhe|zama'; then fail "Python wheel" "TFHE-rs files in $WHEEL"
  else row "Python wheel" "PASS ($(basename "$WHEEL"))"; fi
else
  row "Python wheel" "SKIPPED (set WHEEL=path to a built wheel)"
fi

# 4. The production container.
if [ -n "${IMAGE:-}" ] && command -v docker >/dev/null 2>&1; then
  if docker run --rm --entrypoint sh "$IMAGE" -c \
      "pip list 2>/dev/null | grep -iE 'tfhe|zama'; find / -xdev -iname '*tfhe*' -not -path '/proc/*' 2>/dev/null | grep -v encompute/ | head -5" | grep -q .; then
    fail "container $IMAGE" "TFHE-rs files or packages"
  else row "container $IMAGE" "PASS"; fi
else
  row "container" "SKIPPED (set IMAGE=tag)"
fi

echo
[ $status -eq 0 ] && echo "COMMERCIAL BUILD AUDIT PASSED: TFHE-rs contamination NONE" ||
  echo "COMMERCIAL BUILD AUDIT FAILED"
exit $status
