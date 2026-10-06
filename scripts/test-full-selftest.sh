#!/usr/bin/env bash
# Proves scripts/test-full.sh fails when it must: against fixture manifests
# whose commands print canned cargo output, and against the real manifest with
# a dead PostgreSQL or OpenBao. No test suite runs and nothing is started or
# stopped; every case asserts a non-zero exit, the checklist line that names
# the cause, a final FULL TEST FAILED, and never a bare "passed". Run it
# whenever the runner or the manifest format changes (CI does).
#
#   scripts/test-full-selftest.sh
set -uo pipefail
cd "$(dirname "$0")/.."
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
fails=0

# canned cargo output: section NAME PASSED [FAILED] [IGNORED] [extra line]
section() {
  local name="$1" passed="$2" failed="${3:-0}" ignored="${4:-0}" extra="${5:-}"
  echo "     Running tests/$name.rs (target/debug/deps/$name-0123456789abcdef)"
  echo "running $((passed + failed + ignored)) tests"
  [ -z "$extra" ] || echo "$extra"
  echo "test result: $([ "$failed" = 0 ] && echo ok || echo FAILED). $passed passed; $failed failed; $ignored ignored; 0 measured; 0 filtered out"
}
# manifest FILE RUN_EXTRA_JSON SUITES_JSON RUN_MIN TOTAL_MIN
manifest() {
  cat > "$1" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "r", "command": ["bash", "-c", "cat $W/out.txt"], "min_tests": $4 $2}],
 "suites": [$3]}
JSON
}
suite() {  # suite NAME TARGET MIN [EXTRA]
  echo "{\"name\": \"$1\", \"run\": \"r\", \"target\": \"?/$2\", \"required\": true, \"min_tests\": $3 ${4:-}}"
}
# expect NAME EXPECTED_EXIT_IS_FAIL(1|0) PATTERN... : runs the runner on $W/m.json
expect() {
  local name="$1" want="$2"; shift 2
  local out code
  out="$(scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
  local ok=1
  if [ "$want" = 1 ]; then
    [ $code -ne 0 ] || ok=0
    echo "$out" | tail -n 3 | grep -qx "FULL TEST FAILED" || echo "$out" | grep -qx "FULL TEST FAILED" || ok=0
    echo "$out" | grep -qE '^[0-9]+ passed|FULL TEST PASSED' && ok=0
  else
    [ $code -eq 0 ] || ok=0
    echo "$out" | grep -qx "FULL TEST PASSED" || ok=0
  fi
  for pat in "$@"; do echo "$out" | grep -qE -- "$pat" || { ok=0; echo "    missing: $pat"; }; done
  if [ $ok = 1 ]; then echo "PASS  $name"; else echo "FAIL  $name (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi
}

# A good run, to show the fixtures can pass.
{ section a 5; section b 3; } > "$W/out.txt"
manifest "$W/m.json" "" "$(suite s/a a 5), $(suite s/b b 3)" 8
expect "a good run passes" 0 "PASS +s/a" "Unexpected skips: 0" "Failures: 0"

# Negative 1: a required suite reports zero tests.
{ section a 5; section b 0; } > "$W/out.txt"
manifest "$W/m.json" "" "$(suite s/a a 5), $(suite s/b b 3)" 5
expect "a zero-test required suite fails" 1 "FAIL +s/b" "zero tests"

# Negative 2: a suite below its recorded minimum (and the run below its own).
{ section a 5; section b 2; } > "$W/out.txt"
manifest "$W/m.json" "" "$(suite s/a a 5), $(suite s/b b 3)" 8
expect "a suite below its minimum fails" 1 "FAIL +s/b" "2 tests, minimum 3" "ran 7 tests, the manifest's minimum is 8"

# Negative 3: the total falls (a whole suite gone from the output).
section a 5 > "$W/out.txt"
manifest "$W/m.json" "" "$(suite s/a a 5), $(suite s/b b 3)" 8
expect "a missing suite and a smaller total fail" 1 "FAIL +s/b" "did not run" "Total tests: 5 \(minimum 8\)"

# Unexpected skips: a harness skip message, and an ignored test.
{ section a 5 0 0 "SKIPPED: set ENCOMPUTE_TEST_DATABASE_URL"; section b 3; } > "$W/out.txt"
manifest "$W/m.json" "" "$(suite s/a a 5), $(suite s/b b 3)" 8
expect "a skipped test fails" 1 "FAIL +s/a" "Unexpected skips: 1" "unexpected skip: SKIPPED"
{ section a 5; section b 3 0 1 "test slow ... ignored, takes long"; } > "$W/out.txt"
manifest "$W/m.json" "" "$(suite s/a a 5), $(suite s/b b 3)" 8
expect "an ignored test fails" 1 "FAIL +s/b" "Unexpected skips: 1"

# The allow-list: the same skip, named in the manifest with its reason.
{ section a 5 0 0 "SKIPPED: live Confidential Space is not available"; section b 3; } > "$W/out.txt"
manifest "$W/m.json" "" "$(suite s/a a 5 ', "allowed_skips": [{"match": "live Confidential Space", "reason": "no GCP in this run"}]'), $(suite s/b b 3)" 8
expect "an allow-listed skip passes" 0 "PASS +s/a" "1 allowed skip"

# A failing test, and a run whose command fails.
{ section a 5 1; section b 3; } > "$W/out.txt"
manifest "$W/m.json" "" "$(suite s/a a 5), $(suite s/b b 3)" 8
expect "a failed test fails" 1 "FAIL +s/a" "1 failed"
{ section a 5; section b 3; } > "$W/body.txt"
printf 'cat %s/body.txt; exit 3\n' "$W" > "$W/cmd.sh"
cat > "$W/m.json" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "r", "command": ["bash", "$W/cmd.sh"], "min_tests": 8}],
 "suites": [$(suite s/a a 5), $(suite s/b b 3)]}
JSON
expect "a run that exits non-zero fails" 1 "exited 3"

# Dependencies: unset, a dead PostgreSQL, a dead OpenBao.
{ section a 5; section b 3; } > "$W/out.txt"
manifest "$W/m.json" ', "needs": ["postgres"]' "$(suite s/a a 5), $(suite s/b b 3)" 8
out="$(env -u ENCOMPUTE_TEST_DATABASE_URL scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -qE "PostgreSQL \.+ +FAIL" && echo "$out" | grep -qx "Required suites cannot run." &&
   echo "$out" | tail -n 3 | grep -qx "FULL TEST FAILED" && ! echo "$out" | grep -q "FULL TEST PASSED"; then
  echo "PASS  no PostgreSQL URL fails before any suite runs"
else echo "FAIL  no PostgreSQL URL (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi
out="$(ENCOMPUTE_TEST_DATABASE_URL=postgres://encompute:x@127.0.0.1:1/encompute scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -qE "PostgreSQL \.+ +FAIL +cannot reach" && echo "$out" | grep -qx "Required suites cannot run." &&
   echo "$out" | tail -n 3 | grep -qx "FULL TEST FAILED"; then
  echo "PASS  a dead PostgreSQL fails before any suite runs"
else echo "FAIL  dead PostgreSQL (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi
manifest "$W/m.json" ', "needs": ["openbao"]' "$(suite s/a a 5), $(suite s/b b 3)" 8
out="$(ENCOMPUTE_TEST_BAO_ADDR=http://127.0.0.1:1 ENCOMPUTE_TEST_BAO_TOKEN=x scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -qE "OpenBao \.+ +FAIL" && echo "$out" | grep -qx "Required suites cannot run." &&
   echo "$out" | tail -n 3 | grep -qx "FULL TEST FAILED"; then
  echo "PASS  a dead OpenBao fails before any suite runs"
else echo "FAIL  dead OpenBao (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi
manifest "$W/m.json" ', "needs": ["openfhe"]' "$(suite s/a a 5), $(suite s/b b 3)" 8
out="$(OPENFHE_ROOT=$W/none scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -qE "OpenFHE \.+ +FAIL" && echo "$out" | tail -n 3 | grep -qx "FULL TEST FAILED"; then
  echo "PASS  a missing OpenFHE fails before any suite runs"
else echo "FAIL  missing OpenFHE (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi

# The real manifest with a dead PostgreSQL: the control-plane run must not start.
out="$(ENCOMPUTE_TEST_DATABASE_URL=postgres://encompute:x@127.0.0.1:1/encompute scripts/test-full.sh --runs control-plane --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -qE "PostgreSQL \.+ +FAIL" && echo "$out" | tail -n 3 | grep -qx "FULL TEST FAILED" &&
   ! echo "$out" | grep -q "^running "; then
  echo "PASS  the real manifest with a dead PostgreSQL fails and starts no run"
else echo "FAIL  real manifest, dead PostgreSQL (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi
out="$(ENCOMPUTE_TEST_BAO_ADDR=http://127.0.0.1:1 scripts/test-full.sh --runs control-plane --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -qE "OpenBao \.+ +FAIL" && echo "$out" | tail -n 3 | grep -qx "FULL TEST FAILED" &&
   ! echo "$out" | grep -q "^running "; then
  echo "PASS  the real manifest with a dead OpenBao fails and starts no run"
else echo "FAIL  real manifest, dead OpenBao (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi

# An optional run may be unavailable only when the manifest says so.
{ section a 5; } > "$W/out.txt"
cat > "$W/m.json" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "r", "command": ["bash", "-c", "cat $W/out.txt"], "min_tests": 5},
          {"id": "t", "command": ["bash", "-c", "exit 9"], "needs": ["tfhe"],
           "allow_unavailable": [{"dep": "tfhe", "reason": "research feature, never shipped"}]}],
 "suites": [$(suite s/a a 5), {"name": "t/x", "run": "t", "target": "?/x", "required": false, "min_tests": 0}]}
JSON
out="$(env -u ENCOMPUTE_TFHE scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -eq 0 ] && echo "$out" | grep -qE "SKIPPED-ALLOWED +t/x" && echo "$out" | grep -qx "FULL TEST PASSED" &&
   python3 -c "import json,sys; j=json.load(open('$W/s.json')); sys.exit(0 if j['skipped_suites'][0]['name']=='t/x' and j['result']=='PASSED' else 1)"; then
  echo "PASS  an allow-listed unavailable run is SKIPPED-ALLOWED"
else echo "FAIL  allow-listed skip (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi
# Without the allow-list the same unavailable run fails.
python3 - "$W/m.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); del m["runs"][1]["allow_unavailable"]; json.dump(m, open(sys.argv[1], "w"))
PY
out="$(env -u ENCOMPUTE_TFHE scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | tail -n 3 | grep -qx "FULL TEST FAILED" && echo "$out" | grep -q "cannot run"; then
  echo "PASS  an unavailable run that is not allow-listed fails"
else echo "FAIL  not allow-listed (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi

# A required suite may not hide behind an allow-list; template mode is not a release.
cat > "$W/m.json" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "r", "command": ["true"], "allow_unavailable": [{"dep": "tfhe", "reason": "x"}]}],
 "suites": [$(suite s/a a 5)]}
JSON
out="$(scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -q "MANIFEST INVALID"; then echo "PASS  a required suite cannot be in a skippable run"
else echo "FAIL  manifest lint (exit $code)"; fails=$((fails + 1)); fi
out="$(scripts/test-full.sh --release --mode template 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | tail -n 1 | grep -qx "FULL TEST FAILED"; then echo "PASS  --release refuses template databases"
else echo "FAIL  --release with template (exit $code)"; fails=$((fails + 1)); fi

# A command that is not `cargo test` (parser "lines"): its suite declares a marker
# line that must appear and a pattern whose matches are the passing checks.
lines_manifest() {  # lines_manifest MIN [SUITE_EXTRA]
  cat > "$W/m.json" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "l", "command": ["bash", "-c", "cat $W/out.txt"], "parser": "lines", "min_tests": $1}],
 "suites": [{"name": "l/report", "run": "l", "required": true, "min_tests": $1,
             "marker": "^All checks satisfied", "count": "^ok ", "fail": "^FAILED ", "skip": "^SKIPPED " ${2:-}}]}
JSON
}
{ printf 'ok   one\nok   two\nok   three\n'; echo "All checks satisfied."; } > "$W/out.txt"
lines_manifest 3
expect "a lines-parsed suite with its marker and count passes" 0 "PASS +l/report +3 tests"
{ printf 'ok   one\nok   two\nok   three\n'; } > "$W/out.txt"
lines_manifest 3
expect "a lines-parsed suite without its marker line fails" 1 "FAIL +l/report" "marker line was not found"
{ printf 'ok   one\nok   two\n'; echo "All checks satisfied."; } > "$W/out.txt"
lines_manifest 3
expect "a lines-parsed suite below its count fails" 1 "FAIL +l/report" "2 tests, minimum 3"
{ echo "All checks satisfied."; } > "$W/out.txt"
lines_manifest 3
expect "a lines-parsed suite with no checks fails" 1 "FAIL +l/report" "zero tests"
{ printf 'ok   one\nok   two\nok   three\nFAILED four\n'; echo "All checks satisfied."; } > "$W/out.txt"
lines_manifest 3
expect "a lines-parsed failing check fails" 1 "FAIL +l/report" "1 failed"
{ printf 'ok   one\nok   two\nok   three\nSKIPPED four\n'; echo "All checks satisfied."; } > "$W/out.txt"
lines_manifest 3
expect "a lines-parsed skipped check fails" 1 "FAIL +l/report" "unexpected skip: SKIPPED four"
lines_manifest 3 ', "allowed_skips": [{"match": "SKIPPED four", "reason": "needs a live service"}]'
expect "a lines-parsed skip on the allow-list passes" 0 "PASS +l/report" "1 allowed skip"
{ printf 'ok   one\nok   two\nok   three\n'; echo "All checks satisfied."; echo "(and then it died)"; } > "$W/body.txt"
printf 'cat %s/body.txt; exit 1\n' "$W" > "$W/cmd.sh"
cat > "$W/m.json" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "l", "command": ["bash", "$W/cmd.sh"], "parser": "lines", "min_tests": 3}],
 "suites": [{"name": "l/report", "run": "l", "required": true, "min_tests": 3, "marker": "^All checks", "count": "^ok "}]}
JSON
expect "a lines-parsed command that exits non-zero fails whatever it printed" 1 "exited 1"
cat > "$W/m.json" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "l", "command": ["true"], "parser": "lines"}],
 "suites": [{"name": "l/report", "run": "l", "required": true, "min_tests": 1}]}
JSON
out="$(scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -q "MANIFEST INVALID" && echo "$out" | grep -q "needs a marker pattern"; then
  echo "PASS  a lines suite must declare its marker and count"
else echo "FAIL  lines suite lint (exit $code)"; fails=$((fails + 1)); fi

# A manifest that extends another: it raises a minimum and adds a run, and can
# never lower a minimum or leave the base's runs out.
{ section a 5; section b 3; } > "$W/out.txt"
manifest "$W/base.json" "" "$(suite s/a a 5), $(suite s/b b 3)" 8
cat > "$W/m.json" <<JSON
{"manifest_version": 1, "extends": "base.json",
 "runs": [{"id": "r", "min_tests": 8}],
 "suites": [{"name": "s/a", "min_tests": 5}, {"name": "s/c", "run": "r", "target": "?/c", "required": true, "min_tests": 1}]}
JSON
{ section a 5; section b 3; section c 1; } > "$W/out.txt"
expect "an extending manifest merges the base's runs and suites" 0 "PASS +s/a" "PASS +s/b" "PASS +s/c"
{ section a 5; section b 3; } > "$W/out.txt"
expect "an extending manifest's added suite must run" 1 "FAIL +s/c" "did not run"
{ section a 5; section b 3; section c 1; } > "$W/out.txt"
cat > "$W/m.json" <<JSON
{"manifest_version": 1, "extends": "base.json",
 "suites": [{"name": "s/a", "min_tests": 6}]}
JSON
expect "an extending manifest can raise a suite's minimum" 1 "FAIL +s/a" "5 tests, minimum 6"
cat > "$W/m.json" <<JSON
{"manifest_version": 1, "extends": "base.json",
 "suites": [{"name": "s/a", "min_tests": 4}]}
JSON
out="$(scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -q "MANIFEST INVALID" && echo "$out" | grep -q "lowers min_tests from 5 to 4"; then
  echo "PASS  an extending manifest cannot lower a minimum"
else echo "FAIL  lowering a minimum (exit $code)"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi
cat > "$W/m.json" <<JSON
{"manifest_version": 1, "extends": "m.json"}
JSON
out="$(scripts/test-full.sh --manifest "$W/m.json" --json "$W/s.json" 2>&1)"; code=$?
if [ $code -ne 0 ] && echo "$out" | grep -q "extends loops back"; then echo "PASS  a manifest cannot extend itself"
else echo "FAIL  extends loop (exit $code)"; fails=$((fails + 1)); fi

# Provenance: the summary records the exact commit and tree the run started on,
# and a release run refuses a dirty or unreadable checkout before any suite.
# Real runner, throwaway repository, fixture suites.
R="$W/repo"; mkdir -p "$R"
git -C "$R" init -q && git -C "$R" config user.email selftest@example.invalid && git -C "$R" config user.name selftest
echo one > "$R/tracked.txt"; git -C "$R" add tracked.txt && git -C "$R" commit -q -m selftest
jget() { python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print("null" if v is None else str(v).lower() if isinstance(v,bool) else v)' "$1" "$2"; }
{ section a 5; } > "$W/out.txt"
cat > "$W/pm.json" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "r", "command": ["bash", "-c", "touch $W/ran; cat $W/out.txt"], "min_tests": 5}],
 "suites": [$(suite s/a a 5)]}
JSON
prov_case() {  # prov_case NAME WANT_EXIT(0|1) EXPECT_RAN(yes|no) PATTERN... -- RUNNER_ARGS...
  local name="$1" want="$2" ran="$3"; shift 3
  local pats=(); while [ "$1" != "--" ]; do pats+=("$1"); shift; done; shift
  rm -f "$W/ran" "$W/s.json"
  local out code ok=1
  out="$(scripts/test-full.sh --manifest "$W/pm.json" --json "$W/s.json" "$@" 2>&1)"; code=$?
  if [ "$want" = 1 ]; then [ $code -ne 0 ] || ok=0; echo "$out" | grep -qx "FULL TEST FAILED" || ok=0
  else [ $code -eq 0 ] || ok=0; echo "$out" | grep -qx "FULL TEST PASSED" || ok=0; fi
  if [ "$ran" = yes ]; then [ -f "$W/ran" ] || ok=0; else [ ! -f "$W/ran" ] || ok=0; fi
  for pat in "${pats[@]}"; do echo "$out" | grep -qE -- "$pat" || { ok=0; echo "    missing: $pat"; }; done
  if [ $ok = 1 ]; then echo "PASS  $name"; else echo "FAIL  $name (exit $code, suites ran: $([ -f "$W/ran" ] && echo yes || echo no))"; echo "$out" | sed 's/^/    | /'; fails=$((fails + 1)); fi
}
json_is() {  # json_is NAME KEY VALUE
  local got; got="$(jget "$W/s.json" "$2" 2>&1)"
  if [ "$got" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: $2 is '$got', wanted '$3'"; fails=$((fails + 1)); fi
}

prov_case "a clean checkout is recorded and the run passes" 0 yes "commit [0-9a-f]{40}  tree [0-9a-f]{40}  clean" -- --repo "$R"
json_is "the summary records the commit Git reports" git_commit "$(git -C "$R" rev-parse HEAD)"
json_is "the summary records the tree Git reports" git_tree "$(git -C "$R" rev-parse 'HEAD^{tree}')"
json_is "a clean start is recorded as clean" git_clean_start true
json_is "a clean end is recorded as clean" git_clean_end true

echo two >> "$R/tracked.txt"
prov_case "a modified tracked file is recorded as not clean (development run)" 0 yes "WARNING: the checkout is not clean" -- --repo "$R"
json_is "a tracked modification gives git_clean_start false" git_clean_start false
git -C "$R" checkout -q -- tracked.txt

echo x > "$R/untracked.txt"
prov_case "an untracked file is recorded as not clean (development run)" 0 yes "WARNING: the checkout is not clean" -- --repo "$R"
json_is "an untracked file gives git_clean_start false" git_clean_start false
prov_case "a release run refuses a dirty start before any suite runs" 1 no "DIRTY CHECKOUT" "untracked.txt" -- --release --repo "$R"
rm -f "$R/untracked.txt"

mkdir -p "$W/notgit"
prov_case "a release run refuses unavailable git metadata before any suite runs" 1 no "PROVENANCE UNAVAILABLE" -- --release --repo "$W/notgit"
prov_case "a development run without git metadata records none and says so" 0 yes "WARNING: no git provenance" -- --repo "$W/notgit"
json_is "unavailable metadata is recorded as null, never guessed" git_commit null

cat > "$W/pm.json" <<JSON
{"manifest_version": 1,
 "runs": [{"id": "r", "command": ["bash", "-c", "touch $W/ran; echo changed >> $R/tracked.txt; cat $W/out.txt"], "min_tests": 5}],
 "suites": [$(suite s/a a 5)]}
JSON
prov_case "a release run that leaves the checkout dirty fails" 1 yes "left the checkout dirty" -- --release --repo "$R"
json_is "the dirty end is recorded" git_clean_end false
git -C "$R" checkout -q -- tracked.txt


echo
if [ $fails -eq 0 ]; then echo "SELFTEST PASSED"; else echo "SELFTEST FAILED: $fails case(s)"; fi
exit $((fails > 0))
