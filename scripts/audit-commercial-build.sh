#!/usr/bin/env bash
# The commercial dependency boundary: production artifacts contain no TFHE-rs
# (commercial use of Zama's technology needs a separate patent license) and
# no other research-only dependency. Checks, for the production feature set:
#   1. the Rust dependency graph (cargo tree) and a CycloneDX SBOM;
#   2. the CLI, evaluator and control-plane binaries (symbols, dynamic libraries);
#   3. the Python extension (and wheels, with WHEEL=path or WHEELS="a b"),
#      including the wheel's native symbols;
#   4. the production containers (IMAGE=tag or IMAGES="a b"; needs docker),
#      including the symbols of their binaries.
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
row() { printf '%-46s %s\n' "$1" "$2"; }
fail() { row "$1" "FAIL: $2"; status=1; }

# 1. Dependency graph and SBOM.
crates="$(cargo tree -e normal --prefix none --format '{p}' \
  -p encompute-cli -p encompute-evaluator -p encompute-control -p encompute-py --features "$FEATURES" 2>/dev/null |
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
  local n total
  total="$( (nm "$f" 2>/dev/null || true) | wc -l | tr -d ' ')"
  n="$( (nm "$f" 2>/dev/null || true) | grep -cE "$SYMBOLS" || true)"
  local libs
  libs="$( (otool -L "$f" 2>/dev/null || ldd "$f" 2>/dev/null || true) | grep -ciE 'tfhe|zama' || true)"
  if [ "$n" != "0" ] || [ "$libs" != "0" ]; then fail "$1" "$n TFHE-rs symbols, $libs libraries"
  elif [ "$total" = "0" ]; then row "$1" "PASS (libraries only: no symbols this nm can read)"
  else row "$1" "PASS (no TFHE-rs symbols or libraries)"; fi
}
scan "encompute (CLI)" "$BIN/encompute"
scan "encompute-evaluator" "$BIN/encompute-evaluator"
scan "encompute-control" "$BIN/encompute-control"
EXT="$(python3 -c 'import encompute._native as n; print(n.__file__)' 2>/dev/null || true)"
scan "Python extension" "${EXT:-/nonexistent}"

# 3. Wheels (WHEEL=path, or several in WHEELS="a b"): file names, then the
# native extension's symbols.
for w in ${WHEEL:-} ${WHEELS:-}; do
  if [ ! -f "$w" ]; then fail "Python wheel" "no such file: $w"; continue; fi
  if unzip -l "$w" | grep -qiE 'tfhe|zama'; then fail "Python wheel" "TFHE-rs files in $w"; continue; fi
  wd="$(mktemp -d)"
  unzip -q "$w" -d "$wd"
  so="$(find "$wd" -name '_native*' \( -name '*.so' -o -name '*.pyd' -o -name '*.dylib' \) | head -n 1)"
  if [ -n "$so" ]; then scan "wheel $(basename "$w")" "$so"
  else fail "Python wheel" "no native extension in $w"; fi
  rm -rf "$wd"
done
[ -n "${WHEEL:-}${WHEELS:-}" ] || row "Python wheel" "SKIPPED (set WHEEL=path to a built wheel)"

# 4. Production containers (IMAGE=tag, or several in IMAGES="a b"): Python
# packages and file names inside, then the symbols of every binary in
# /usr/local/bin.
for img in ${IMAGE:-} ${IMAGES:-}; do
  if ! command -v docker >/dev/null 2>&1; then fail "container $img" "docker unavailable"; continue; fi
  if docker run --rm --entrypoint sh "$img" -c \
      "pip list 2>/dev/null | grep -iE 'tfhe|zama'; find / -xdev -iname '*tfhe*' -not -path '/proc/*' 2>/dev/null | grep -v encompute/ | head -5" | grep -q .; then
    fail "container $img" "TFHE-rs files or packages"
    continue
  fi
  cd_="$(mktemp -d)"
  cid="$(docker create "$img" 2>/dev/null)"
  if [ -n "$cid" ] && docker cp "$cid:/usr/local/bin/." "$cd_/" >/dev/null 2>&1; then
    for b in "$cd_"/*; do [ -f "$b" ] && scan "container $img: $(basename "$b")" "$b"; done
  fi
  [ -z "$cid" ] || docker rm "$cid" >/dev/null 2>&1
  rm -rf "$cd_"
  row "container $img" "PASS (no TFHE-rs packages or files)"
done
[ -n "${IMAGE:-}${IMAGES:-}" ] || row "container" "SKIPPED (set IMAGE=tag or IMAGES=\"a b\")"

echo
[ $status -eq 0 ] && echo "COMMERCIAL BUILD AUDIT PASSED: TFHE-rs contamination NONE" ||
  echo "COMMERCIAL BUILD AUDIT FAILED"
exit $status
