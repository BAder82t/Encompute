#!/usr/bin/env bash
# Selftest of scripts/release/compare-shipped-digests.sh and of the
# `--digests` option of scripts/release/repro-check.sh. It builds two tiny
# tarballs of fake binaries, so it needs no compiler and no OpenFHE. Exit 0
# only when every case behaves as stated.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
fails=0
BINS=(encompute encompute-evaluator encompute-control)
CMP=scripts/release/compare-shipped-digests.sh
mkdir -p "$W/bin"
for b in "${BINS[@]}"; do echo "binary $b" > "$W/bin/$b"; chmod +x "$W/bin/$b"; done
echo extra > "$W/bin/encompute-extra"; chmod +x "$W/bin/encompute-extra"
echo licence > "$W/LICENSE"
pack() {  # pack OUT FILE...
  local out="$1"; shift
  SOURCE_DATE_EPOCH=0 python3 scripts/release/pack.py "$out" encompute-1-linux-x86_64 "$@"
}
B="$W/bin"
pack "$W/ok.tar.gz" "$B/encompute" "$B/encompute-evaluator" "$B/encompute-control" "$W/LICENSE"
: > "$W/good.txt"
for b in "${BINS[@]}"; do printf '%s  %s\n' "$(shasum -a 256 "$B/$b" | cut -d' ' -f1)" "$b" >> "$W/good.txt"; done

case_() {  # case_ NAME EXPECT_EXIT PATTERN DIGESTS TARBALL
  local out code
  out="$("$CMP" "$4" "$5" 2>&1)"; code=$?
  if [ "$code" = "$2" ] && grep -q -- "$3" <<<"$out"; then echo "PASS  $1"
  else echo "FAIL  $1 (exit $code)"; sed 's/^/    | /' <<<"$out"; fails=$((fails + 1)); fi
}

case_ "a tarball of the gate's binaries passes" 0 "SHIPPED DIGESTS MATCH" "$W/good.txt" "$W/ok.tar.gz"

# A changed byte in one shipped binary.
cp -R "$B" "$W/bin2"; printf 'x' >> "$W/bin2/encompute-evaluator"
pack "$W/changed.tar.gz" "$W/bin2/encompute" "$W/bin2/encompute-evaluator" "$W/bin2/encompute-control" "$W/LICENSE"
case_ "a changed byte in a shipped binary fails" 1 "encompute-evaluator: gate build" "$W/good.txt" "$W/changed.tar.gz"

# A missing binary.
pack "$W/missing.tar.gz" "$B/encompute" "$B/encompute-evaluator" "$W/LICENSE"
case_ "a binary missing from the tarball fails" 1 "encompute-control: not in" "$W/good.txt" "$W/missing.tar.gz"

# An extra binary.
pack "$W/extra.tar.gz" "$B/encompute" "$B/encompute-evaluator" "$B/encompute-control" "$B/encompute-extra" "$W/LICENSE"
case_ "an extra binary in the tarball fails" 1 "encompute-extra: not a binary the gate reproduced" "$W/good.txt" "$W/extra.tar.gz"

# An empty digest file, one with the digest of empty input, one for another name, a truncated line.
: > "$W/empty.txt"
case_ "an empty digest file fails" 1 "the gate recorded no digest" "$W/empty.txt" "$W/ok.tar.gz"
printf 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  encompute\n' > "$W/emptysha.txt"
case_ "the digest of empty input fails" 1 "digest of empty input" "$W/emptysha.txt" "$W/ok.tar.gz"
sed 's/  encompute-control$/  encompute-other/' "$W/good.txt" > "$W/othername.txt"
case_ "a digest recorded for another name fails" 1 "encompute-control: the gate recorded no digest" "$W/othername.txt" "$W/ok.tar.gz"
{ cat "$W/good.txt"; printf '%s  encompute-extra\n' "$(shasum -a 256 "$B/encompute-extra" | cut -d' ' -f1)"; } > "$W/moredigests.txt"
case_ "a digest for a file that is not a release binary fails" 1 "encompute-extra: the gate recorded a digest" "$W/moredigests.txt" "$W/ok.tar.gz"
head -c 100 "$W/good.txt" > "$W/trunc.txt"
case_ "a truncated digest line fails" 1 "truncated line\|is not 'sha256  name'" "$W/trunc.txt" "$W/ok.tar.gz"
sed '$ s/.$//' "$W/good.txt" > "$W/short.txt"
case_ "a digest line missing its last character fails" 1 "encompute-control: the gate recorded no digest" "$W/short.txt" "$W/ok.tar.gz"
case_ "an absent digest file fails" 1 "no gate digests" "$W/absent.txt" "$W/ok.tar.gz"
case_ "an absent tarball fails" 1 "no tarball" "$W/good.txt" "$W/absent.tar.gz"

# repro-check.sh --digests: a fake cargo stands in for the two builds.
RC="$W/rc"; mkdir -p "$RC/scripts/release" "$RC/bin"
cp scripts/release/repro-check.sh scripts/release/env.sh scripts/release/check-binary-paths.sh \
  scripts/release/binary-paths.allow "$RC/scripts/release/"
cat > "$RC/bin/cargo" <<'CARGO'
#!/usr/bin/env bash
case "$1" in
  metadata) empty='{"packages":[]}'; printf '%s\n' "${FAKE_META_JSON:-$empty}" ;;
  build) mkdir -p "$CARGO_TARGET_DIR/release"; [ -z "${FAKE_BIN:-}" ] || echo "${FAKE_CONTENT:-same}" > "$CARGO_TARGET_DIR/release/$FAKE_BIN" ;;
esac
CARGO
chmod +x "$RC/bin/cargo"
META='{"packages":[{"name":"encompute-cli","targets":[{"kind":["bin"],"name":"fakebin"}]}]}'
out="$(env FAKE_META_JSON="$META" FAKE_BIN=fakebin PATH="$RC/bin:$PATH" bash "$RC/scripts/release/repro-check.sh" --digests "$W/rec/d.txt" 2>&1)"; code=$?
if [ $code -eq 0 ] && [ "$(wc -l < "$W/rec/d.txt" | tr -d ' ')" = 1 ] && grep -qE '^[0-9a-f]{64}  fakebin$' "$W/rec/d.txt"; then
  echo "PASS  repro-check --digests records one digest per matching binary"
else echo "FAIL  repro-check --digests records one digest per matching binary (exit $code)"; sed 's/^/    | /' <<<"$out"; fails=$((fails + 1)); fi
out="$(env FAKE_META_JSON="$META" PATH="$RC/bin:$PATH" bash "$RC/scripts/release/repro-check.sh" --digests "$W/rec/missing.txt" 2>&1)"; code=$?
if [ $code -ne 0 ] && grep -q "MISSING" <<<"$out" && [ ! -e "$W/rec/missing.txt" ]; then echo "PASS  repro-check --digests writes nothing when a binary is missing"
else echo "FAIL  repro-check --digests writes nothing when a binary is missing (exit $code)"; sed 's/^/    | /' <<<"$out"; fails=$((fails + 1)); fi
out="$(env FAKE_META_JSON='{"packages":[]}' PATH="$RC/bin:$PATH" bash "$RC/scripts/release/repro-check.sh" --digests "$W/rec/none.txt" 2>&1)"; code=$?
if [ $code -ne 0 ] && [ ! -e "$W/rec/none.txt" ]; then echo "PASS  repro-check --digests fails when there is no binary to compare"
else echo "FAIL  repro-check --digests fails when there is no binary to compare (exit $code)"; sed 's/^/    | /' <<<"$out"; fails=$((fails + 1)); fi

# On Linux repro-check.sh also runs the binary path guard: matching binaries that
# name a build path fail the check and no digest is recorded.
if [ "$(uname -s)" = Linux ]; then
  out="$(cd "$RC" && env FAKE_META_JSON="$META" FAKE_BIN=fakebin FAKE_CONTENT=/home/runner/work/x.rs PATH="$RC/bin:$PATH" bash scripts/release/repro-check.sh --digests "$W/rec/path.txt" 2>&1)"; code=$?
  if [ $code -ne 0 ] && grep -q "BINARY PATH CHECK FAILED" <<<"$out" && [ ! -e "$W/rec/path.txt" ]; then echo "PASS  repro-check fails and records nothing when a binary names a build path"
  else echo "FAIL  repro-check path guard (exit $code)"; sed 's/^/    | /' <<<"$out"; fails=$((fails + 1)); fi
else echo "SKIP  repro-check path guard case (Linux only)"; fi

[ "$fails" = 0 ] && echo "ALL CASES PASSED" || { echo "$fails CASE(S) FAILED"; exit 1; }
