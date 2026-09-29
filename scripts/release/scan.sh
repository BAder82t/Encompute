#!/usr/bin/env bash
# The vulnerability and license gate of a release (docs/release-process.md):
#
#   1. cargo-deny: advisories, bans (TFHE-rs), licenses, sources, on the
#      production feature graph (deny.toml);
#   2. cargo-audit on Cargo.lock, pip-audit on the Python lock, and a
#      container scan (trivy, else grype) of each image in IMAGES;
#   3. Python licenses (PyPI metadata);
#   4. the OpenFHE manual review record (security/openfhe-review.toml);
#   5. the severity policy over every finding (vuln_policy.py with
#      security/exceptions.toml).
#
#   scripts/release/scan.sh
#   IMAGES="encompute-evaluator:rc encompute-control:rc" scripts/release/scan.sh
#   REQUIRE_TOOLS=1 ...   # a missing scanner fails instead of skipping (CI)
#   REQUIRE_IMAGES="encompute-training ..."  # fail unless each was in IMAGES
#
# A release scans every image, the Confidential Space workloads
# (encompute-confidential-space, encompute-training) included: signing,
# pinning and attestation say which image ran, not that it has no known
# vulnerabilities.
#
# Reports go to target/release-scan/ (OUT=...). Exit 0 only when every
# step passed.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OUT="${OUT:-target/release-scan}"
mkdir -p "$OUT"
status=0
row() { printf '%-30s %s\n' "$1" "$2"; }
fail() { row "$1" "FAIL: $2"; status=1; }
skip() {
  if [ -n "${REQUIRE_TOOLS:-}" ]; then fail "$1" "$2 (REQUIRE_TOOLS is set)"
  else row "$1" "SKIPPED ($2)"; fi
}
policy_args=()

# 1. cargo-deny.
if cargo deny --version >/dev/null 2>&1; then
  if cargo deny --log-level error check advisories bans licenses sources > "$OUT/cargo-deny.txt" 2>&1; then
    row "cargo-deny" "PASS (advisories, bans, licenses, sources)"
  else fail "cargo-deny" "$(tail -n 1 "$OUT/cargo-deny.txt") (see $OUT/cargo-deny.txt)"; fi
else skip "cargo-deny" "cargo install cargo-deny --locked"; fi

# 2a. cargo-audit (the whole Cargo.lock, research crates included).
if cargo audit --version >/dev/null 2>&1; then
  cargo audit --json > "$OUT/cargo-audit.json" 2>/dev/null
  if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT/cargo-audit.json" 2>/dev/null; then
    row "cargo-audit" "RAN ($(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["vulnerabilities"]["count"])' "$OUT/cargo-audit.json") vulnerabilities; policy below)"
    policy_args+=(--cargo-audit "$OUT/cargo-audit.json")
  else fail "cargo-audit" "no JSON report"; fi
else skip "cargo-audit" "cargo install cargo-audit --locked"; fi

# 2b. pip-audit on the pinned Python dependencies. PyTorch's CPU wheels
# carry a local version (+cpu) PyPI's advisory data does not list: audit
# the public version.
lock=scripts/release/python/constraints.txt
PIP_AUDIT="${PIP_AUDIT:-pip-audit}"
if command -v "$PIP_AUDIT" >/dev/null 2>&1; then
  grep -E '^[A-Za-z0-9]' "$lock" | sed -E 's/ *\\$//; s/\+[A-Za-z0-9.]+$//' > "$OUT/pip-audit-input.txt"
  "$PIP_AUDIT" -r "$OUT/pip-audit-input.txt" --no-deps --disable-pip --progress-spinner off \
    --format json -o "$OUT/pip-audit.json" > "$OUT/pip-audit.log" 2>&1
  if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT/pip-audit.json" 2>/dev/null; then
    row "pip-audit" "RAN ($(grep -cE '^[a-z]' "$OUT/pip-audit-input.txt") packages; policy below)"
    policy_args+=(--pip-audit "$OUT/pip-audit.json")
  else fail "pip-audit" "no JSON report (see $OUT/pip-audit.log)"; fi
else skip "pip-audit" "pip install pip-audit"; fi

# 2c. Containers.
if [ -n "${IMAGES:-}" ]; then
  for img in $IMAGES; do
    safe="$(echo "$img" | tr '/:@' '___')"
    if command -v trivy >/dev/null 2>&1; then
      if trivy image --quiet --format json -o "$OUT/trivy-$safe.json" "$img" > "$OUT/trivy-$safe.log" 2>&1; then
        row "trivy $img" "RAN (policy below)"
        policy_args+=(--trivy "$OUT/trivy-$safe.json")
      else fail "trivy $img" "scan failed (see $OUT/trivy-$safe.log)"; fi
    elif command -v grype >/dev/null 2>&1; then
      if grype -q -o json --file "$OUT/grype-$safe.json" "$img" > "$OUT/grype-$safe.log" 2>&1; then
        row "grype $img" "RAN (policy below)"
        policy_args+=(--grype "$OUT/grype-$safe.json")
      else fail "grype $img" "scan failed (see $OUT/grype-$safe.log)"; fi
    else skip "container scan $img" "install trivy or grype"; fi
  done
else
  skip "container scan" "set IMAGES=\"image:tag ...\""
fi
# Every required image was scanned (by repository name: registry, tag and
# digest aside).
for want in ${REQUIRE_IMAGES:-}; do
  found=0
  for img in ${IMAGES:-}; do
    name="${img%%@*}"; name="${name##*/}"; name="${name%%:*}"
    [ "$name" = "$want" ] && found=1
  done
  [ $found = 1 ] || fail "container scan $want" "not in IMAGES (REQUIRE_IMAGES)"
done

# 3. Python licenses.
if python3 scripts/release/python_licenses.py "$lock" --json "$OUT/python-licenses.json" > "$OUT/python-licenses.txt" 2>&1; then
  row "Python licenses" "PASS ($(tail -n 1 "$OUT/python-licenses.txt"))"
else fail "Python licenses" "$(tail -n 1 "$OUT/python-licenses.txt") (see $OUT/python-licenses.txt)"; fi

# 4. OpenFHE: pinned version and a current manual review.
if python3 - <<'PY' > "$OUT/openfhe-review.txt" 2>&1
import datetime, re, sys, tomllib
r = tomllib.load(open("security/openfhe-review.toml", "rb"))
pin = re.search(r'^OPENFHE_VERSION="(.*)"', open("scripts/install-openfhe.sh").read(), re.M).group(1)
problems = []
if r.get("version") != pin:
    problems.append(f"review is for {r.get('version')}, the pin is {pin}")
if not r.get("reviewed_by") or not r.get("reviewed_on"):
    problems.append("not signed (reviewed_by, reviewed_on)")
else:
    d = r["reviewed_on"]
    d = d if isinstance(d, datetime.date) else datetime.date.fromisoformat(str(d))
    if (datetime.date.today() - d).days > 90:
        problems.append(f"reviewed {d}, more than 90 days ago")
affected = [c["id"] for c in r.get("cve", []) if c.get("affected")]
if affected:
    problems.append("affected by " + ", ".join(affected))
print("; ".join(problems) if problems else
      f"{pin} reviewed by {r['reviewed_by']} on {r['reviewed_on']}, {len(r.get('cve', []))} CVEs checked")
sys.exit(1 if problems else 0)
PY
then row "OpenFHE review" "PASS ($(cat "$OUT/openfhe-review.txt"))"
else fail "OpenFHE review" "$(tail -n 1 "$OUT/openfhe-review.txt") (security/openfhe-review.toml)"; fi

# 5. The severity policy. Its own tests first (exceptions must be exact,
# complete, approved and current), then the controls the exceptions rely
# on: the shipped Python package never calls the PyTorch and Transformers
# entry points the torch and transformers exceptions declare unused
# (security/exceptions.toml, compensating_controls).
if python3 -m unittest discover -s scripts/release -p 'test_vuln_policy.py' > "$OUT/policy-tests.txt" 2>&1; then
  row "severity policy tests" "PASS ($(grep -E '^Ran ' "$OUT/policy-tests.txt"))"
else fail "severity policy tests" "see $OUT/policy-tests.txt"; fi
unused='torch\.(load|jit|compile|export|distributed|_inductor)\b|from torch(\.[a-z_]+)* import [^#]*\b(load|jit|compile|export|distributed)\b|\bTrainer\b|load_checkpoint_(in_model|and_dispatch)|trust_remote_code *= *True|weights_only'
if grep -rnE "$unused" python/encompute --include='*.py' > "$OUT/exception-controls.txt" 2>&1; then
  fail "exception controls" "python/encompute calls an entry point an exception declares unused (see $OUT/exception-controls.txt)"
else row "exception controls" "PASS (no torch.load/jit/compile/export/distributed, Trainer, load_checkpoint, trust_remote_code)"; fi
if [ ${#policy_args[@]} -gt 0 ]; then
  if python3 scripts/release/vuln_policy.py "${policy_args[@]}" --exceptions security/exceptions.toml \
      --osv-cache "$OUT/osv-cache.json" --report "$OUT/vulnerabilities.md" > "$OUT/policy.txt" 2>&1; then
    row "severity policy" "PASS ($(tail -n 1 "$OUT/policy.txt"))"
  else
    fail "severity policy" "$(tail -n 1 "$OUT/policy.txt")"
    grep -E 'BLOCKING|STALE' "$OUT/policy.txt" | head -n 25 | sed 's/^/    | /'
  fi
else skip "severity policy" "no scanner ran"; fi

echo
echo "reports: $OUT/ (vulnerabilities.md, policy.txt, cargo-deny.txt, python-licenses.txt)"
[ $status -eq 0 ] && echo "SECURITY SCANS PASSED" || echo "SECURITY SCANS FAILED"
exit $status
