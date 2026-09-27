#!/usr/bin/env bash
# CycloneDX SBOMs for every release artifact, then checks them:
#
#   encompute.cdx.json             the CLI (BIN/encompute)
#   encompute-evaluator.cdx.json   the evaluator
#   encompute-control.cdx.json     the control plane
#   encompute-wheel.cdx.json       the Python wheel, with its extras' pinned deps
#   encompute-production.cdx.json  the whole production graph (as before)
#   image-<name>.cdx.json          each image in IMAGES (syft)
#
#   scripts/release/sbom-all.sh [OUT]      # default target/sbom
#   BIN=target/release WHEEL=dist/x.whl IMAGES="encompute-evaluator:rc" OPENFHE=1 ...
#
# OPENFHE=1 (the default when an OpenFHE install is found) records the
# OpenFHE builds of the CLI, evaluator and wheel; OPENFHE=0 the builds
# without it. A check fails when an SBOM is malformed, lacks OpenFHE where
# it was built in, or lists a TFHE-rs component.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OUT="${1:-target/sbom}"
BIN="${BIN:-target/release}"
mkdir -p "$OUT"
if [ -z "${OPENFHE:-}" ]; then
  if [ -d "${OPENFHE_ROOT:-.deps/openfhe}" ]; then OPENFHE=1; else OPENFHE=0; fi
fi
status=0
row() { printf '%-34s %s\n' "$1" "$2"; }

gen() {  # gen NAME ARTIFACT FEATURES FILE [extra args]
  local name="$1" art="$2" feat="$3" file="$4"
  shift 4
  local args=(--artifact "$art" --features "$feat" -o "$OUT/$name.cdx.json")
  [ -f "$file" ] && args+=(--file "$file")
  if python3 scripts/sbom.py "${args[@]}" "$@"; then :; else row "$name" "FAIL (sbom.py)"; status=1; fi
}
if [ "$OPENFHE" = 1 ]; then
  f_cli=encompute-cli/openfhe; f_eval=encompute-evaluator/openfhe; f_py=encompute-py/openfhe
else
  f_cli=""; f_eval=""; f_py=""
fi
gen encompute cli "$f_cli" "$BIN/encompute"
gen encompute-evaluator evaluator "$f_eval" "$BIN/encompute-evaluator"
gen encompute-control control "" "$BIN/encompute-control"
lic=()
[ -f target/release-scan/python-licenses.json ] && lic=(--python-licenses target/release-scan/python-licenses.json)
gen encompute-wheel wheel "$f_py" "${WHEEL:-/nonexistent}" \
  --python-lock scripts/release/python/constraints.txt "${lic[@]}"
python3 scripts/sbom.py -o "$OUT/encompute-production.cdx.json" || status=1

# Container images.
for img in ${IMAGES:-}; do
  n="image-$(echo "$img" | sed 's#.*/##; s/[:@]/-/g')"
  if command -v syft >/dev/null 2>&1; then
    if syft -q "$img" -o "cyclonedx-json=$OUT/$n.cdx.json"; then :; else row "$n" "FAIL (syft)"; status=1; fi
  else
    row "$n" "SKIPPED (install syft: https://github.com/anchore/syft)"
    [ -z "${REQUIRE_TOOLS:-}" ] || status=1
  fi
done

# Checks.
python3 - "$OUT" "$OPENFHE" <<'PY' || status=1
import glob, json, os, re, sys
out, openfhe = sys.argv[1], sys.argv[2] == "1"
banned = re.compile(r"^(tfhe|tfhe-[a-z0-9-]+|concrete[a-z0-9-]*|zama[a-z0-9-]*)$")
bad = 0
for f in sorted(glob.glob(os.path.join(out, "*.cdx.json"))):
    name = os.path.basename(f)
    try:
        bom = json.load(open(f))
        assert bom.get("bomFormat") == "CycloneDX", "not CycloneDX"
        comps = bom.get("components") or []
        assert comps, "no components"
        names = {c.get("name", "") for c in comps}
        tf = sorted(n for n in names if banned.match(n))
        assert not tf, f"TFHE-rs components: {tf}"
        if not name.startswith("image-"):
            want = openfhe and not name.startswith("encompute-control")
            if name.startswith("encompute-production"):
                want = True
            if want:
                assert "OpenFHE" in names, "OpenFHE missing"
            unlicensed = sorted(c["name"] for c in comps if not c.get("licenses")
                                and c.get("scope") != "optional")
            assert not unlicensed, f"components without a license: {unlicensed[:5]}"
        h = (bom.get("metadata", {}).get("component", {}).get("hashes") or [{}])[0].get("content", "")
        print(f"{name:34} PASS ({len(comps)} components{', OpenFHE' if 'OpenFHE' in names else ''}"
              f"{', sha256 ' + h[:12] if h else ''})")
    except (AssertionError, ValueError) as e:
        print(f"{name:34} FAIL ({e})")
        bad += 1
sys.exit(1 if bad else 0)
PY
echo
[ $status -eq 0 ] && echo "SBOMS PASSED ($OUT)" || echo "SBOMS FAILED"
exit $status
