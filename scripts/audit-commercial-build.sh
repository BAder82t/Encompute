#!/usr/bin/env bash
# The commercial dependency boundary: production artifacts contain no TFHE-rs
# (commercial use of Zama's technology needs a separate patent license) and
# no other research-only dependency. Checks, for the production feature set:
#   1. the Rust dependency graph (cargo tree) and a CycloneDX SBOM;
#   2. the CLI, evaluator and control-plane binaries (symbols, dynamic libraries);
#   3. the Python extension (and wheels, with WHEEL=path or WHEELS="a b"),
#      including the wheel's native symbols;
#   4. the production containers (IMAGE=tag or IMAGES="a b"; needs docker),
#      including the symbols of their binaries, and of the SDK's native
#      extension, which the images named in NATIVE_IMAGES (default:
#      encompute-training) must carry.
# Documentation strings naming TFHE-rs are allowed; code is not.
#
#   scripts/audit-commercial-build.sh [target/release]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
BIN="${1:-target/release}"
FEATURES="encompute-cli/openfhe,encompute-evaluator/openfhe,encompute-py/openfhe"
# Crates published by Zama for TFHE-rs, and its runtime.
BANNED='^(tfhe|tfhe-[a-z0-9-]+|concrete[a-z0-9-]*|zama[a-z0-9-]*)$'
NATIVE_IMAGES="${NATIVE_IMAGES:-encompute-training}"
SYMBOLS='_ZN4tfhe|_ZN[0-9]+tfhe_(fft|ntt|csprng|versionable|zk_pok|cuda)|[0-9]tfhe[0-9]'
status=0
audited=0  # binaries whose symbols were read
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

# 2. Binaries. A binary whose symbols cannot be read (stripped, or a format
# this nm does not know) fails: it would otherwise pass vacuously. Encompute's
# own binaries must show Encompute's symbols (proof that the Rust symbols, where
# TFHE-rs would appear, were read); other binaries (e.g. a container's Python)
# must show some symbols, dynamic ones included. With rust-audit-info
# installed, a binary built with cargo-auditable is also checked against its
# embedded dependency list.
symbols() {  # symbols FILE: every symbol nm can read, static then dynamic
  { nm "$1" 2>/dev/null; nm -D "$1" 2>/dev/null; } || true
}
is_object() {  # is_object FILE: ELF, Mach-O or PE (not a script or data file)
  local m
  m="$(head -c 4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
  case "$m" in
    7f454c46|cffaedfe|feedfacf|cefaedfe|feedface|cafebabe|bebafeca) return 0 ;;
    4d5a*) return 0 ;;
  esac
  return 1
}
scan() {  # scan NAME FILE [own]: "own" = an Encompute binary
  local f="$2" own="${3:-}"
  if [ ! -f "$f" ]; then row "$1" "SKIPPED (no $f)"; return; fi
  audited=$((audited + 1))
  local syms n total ours libs deps
  syms="$(symbols "$f")"
  total="$(printf '%s' "$syms" | grep -c . || true)"
  ours="$(printf '%s\n' "$syms" | grep -c 'encompute' || true)"
  n="$(printf '%s\n' "$syms" | grep -cE "$SYMBOLS" || true)"
  libs="$( (otool -L "$f" 2>/dev/null || ldd "$f" 2>/dev/null || true) | grep -ciE 'tfhe|zama' || true)"
  deps=""
  if command -v rust-audit-info >/dev/null 2>&1; then
    deps="$( (rust-audit-info "$f" 2>/dev/null || true) | python3 -c '
import json, re, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
print(" ".join(p["name"] for p in d.get("packages", []) if re.match(sys.argv[1], p["name"])))
' "$BANNED")"
  fi
  if [ "$n" != "0" ] || [ "$libs" != "0" ] || [ -n "$deps" ]; then
    fail "$1" "$n TFHE-rs symbols, $libs libraries${deps:+, embedded dependencies: $deps}"
  elif [ "$total" = "0" ]; then fail "$1" "no symbols this nm can read (stripped, or not a format it knows): cannot audit"
  elif [ -n "$own" ] && [ "$ours" = "0" ]; then
    fail "$1" "no Encompute symbols among $total (stripped of its Rust symbols?): cannot audit"
  else row "$1" "PASS (no TFHE-rs symbols or libraries in $total symbols)"; fi
}
scan "encompute (CLI)" "$BIN/encompute" own
scan "encompute-evaluator" "$BIN/encompute-evaluator" own
scan "encompute-control" "$BIN/encompute-control" own
EXT="$(python3 -c 'import encompute._native as n; print(n.__file__)' 2>/dev/null || true)"
scan "Python extension" "${EXT:-/nonexistent}" own

# 3. Wheels (WHEEL=path, or several in WHEELS="a b"): file names, then the
# native extension's symbols.
for w in ${WHEEL:-} ${WHEELS:-}; do
  if [ ! -f "$w" ]; then fail "Python wheel" "no such file: $w"; continue; fi
  if unzip -l "$w" | grep -qiE 'tfhe|zama'; then fail "Python wheel" "TFHE-rs files in $w"; continue; fi
  wd="$(mktemp -d)"
  unzip -q "$w" -d "$wd"
  so="$(find "$wd" -name '_native*' \( -name '*.so' -o -name '*.pyd' -o -name '*.dylib' \) | head -n 1)"
  if [ -n "$so" ]; then scan "wheel $(basename "$w")" "$so" own
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
  before=$status; status=0
  cid="$(docker create "$img" 2>/dev/null)"
  if [ -n "$cid" ] && docker cp "$cid:/usr/local/bin/." "$cd_/" >/dev/null 2>&1 &&
     [ -n "$(ls -A "$cd_")" ]; then
    # Executables only: scripts and data files have no symbols to read.
    for b in "$cd_"/*; do
      if [ ! -f "$b" ] || ! is_object "$b"; then continue; fi
      case "$(basename "$b")" in
        encompute*) scan "container $img: $(basename "$b")" "$b" own ;;
        *) scan "container $img: $(basename "$b")" "$b" ;;
      esac
    done
  else
    fail "container $img" "could not copy its binaries out of /usr/local/bin (docker create/cp)"
  fi
  # The SDK's native extension, where an image carries it (the training
  # worker): an Encompute binary like the others. The listing ends with a
  # marker, so a docker run that failed is told apart from an image without
  # the extension; an image that must carry it (by repository name: registry,
  # tag and digest aside) fails without one.
  name="${img%%@*}"; name="${name##*/}"; name="${name%%:*}"
  need_native=0
  for want in $NATIVE_IMAGES; do [ "$name" = "$want" ] && need_native=1; done
  listing="$(docker run --rm --entrypoint sh "$img" -c \
      "find / -xdev -path '*/encompute/_native*' \( -name '*.so' -o -name '*.dylib' \) 2>/dev/null; echo END-OF-LISTING" 2>/dev/null)"
  if [ "$(printf '%s\n' "$listing" | tail -n 1)" != "END-OF-LISTING" ]; then
    fail "container $img" "could not list its files for the SDK's native extension (docker run)"
  else
    sos="$(printf '%s\n' "$listing" | sed '$d' | grep . || true)"
    if [ -z "$sos" ] && [ $need_native = 1 ]; then
      fail "container $img" "no encompute/_native extension, which this image must carry: cannot audit"
    fi
    while IFS= read -r so; do
      [ -n "$so" ] || continue
      if [ -n "$cid" ] && docker cp "$cid:$so" "$cd_/native.so" >/dev/null 2>&1; then
        scan "container $img: $(basename "$so")" "$cd_/native.so" own
      else fail "container $img" "could not copy $so out"; fi
    done <<< "$sos"
  fi
  [ -z "$cid" ] || docker rm "$cid" >/dev/null 2>&1
  rm -rf "$cd_"
  [ $status -eq 0 ] && row "container $img" "PASS (no TFHE-rs packages, files or symbols)"
  [ $before -eq 0 ] || status=$before
done
[ -n "${IMAGE:-}${IMAGES:-}" ] || row "container" "SKIPPED (set IMAGE=tag or IMAGES=\"a b\")"

# Every binary skipped (a wrong directory, no extension, no wheel or image):
# nothing was audited, which is not a pass.
[ $audited -gt 0 ] || fail "binaries" "none found (not in $BIN, no extension, wheel or image): nothing audited"

echo
[ $status -eq 0 ] && echo "COMMERCIAL BUILD AUDIT PASSED: TFHE-rs contamination NONE" ||
  echo "COMMERCIAL BUILD AUDIT FAILED"
exit $status
