#!/usr/bin/env bash
# 19: exact programs encrypted on OpenFHE exact (BinFHE), the commercial
# exact backend: Boolean logic, a lookup, and the eligibility rule on a
# remote evaluator with a verified receipt; then attacks on every binding.
source "$(dirname "$0")/../lib.sh"
need_cli
need_evaluator
need_python
has openfhe-exact || skip "OpenFHE exact unavailable (build with --features openfhe)"
cd "$W"
forge() { "$PYTHON" "$HERE/forge.py" "$@"; }
header() {
  "$PYTHON" -c 'import json,struct,sys; b=open(sys.argv[1],"rb").read(); n=struct.unpack("<I",b[6:10])[0]; print(json.loads(b[10:10+n])[sys.argv[2]])' "$@"
}
ELIG="$ROOT/examples/02_exact_private_logic/eligibility.py"

step "Boolean logic and a lookup, encrypted (clear == mock == OpenFHE exact)"
"$E" compile "$HERE/rules.py:screen" -o screen.encompute >/dev/null
"$E" compile "$HERE/rules.py:tier" -o tier.encompute >/dev/null
"$E" explain tier.encompute | grep -E "scheme|backend|parameter profile|bootstrapped gates|failure probability"
out() { "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["out"])'; }
check() {
  local model="$1" label="$2"
  shift 2
  local args=() c m x
  for kv in "$@"; do args+=(--input "$kv"); done
  c="$("$E" run "$model" --mode clear "${args[@]}" | out)"
  m="$("$E" run "$model" --mode mock "${args[@]}" | out)"
  x="$("$E" run "$model" --mode encrypted "${args[@]}" | out)"
  [ "$c" = "$m" ] && [ "$c" = "$x" ] || { echo "MISMATCH $label: clear=$c mock=$m encrypted=$x" >&2; exit 1; }
  printf '%-40s clear=%-5s mock=%-5s encrypted=%-5s MATCH\n' "$label" "$c" "$m" "$x"
}
check screen.encompute "screen(member, consent, not flagged)" member=true consent=true flagged=false
check tier.encompute "tier(score=200)" score=200

step "client: compile the eligibility rule, generate keys (two clients)"
"$E" compile "$ELIG:eligibility" -o el.encompute >/dev/null
"$E" keys generate el.encompute -o alice >/dev/null
"$E" keys generate el.encompute -o bob >/dev/null
printf 'secret.key  %s bytes, mode %s (stays here)\n' "$(wc -c <alice/secret.key | tr -d ' ')" "$(stat -f %Lp alice/secret.key 2>/dev/null || stat -c %a alice/secret.key)"
printf 'eval.keys   %s MiB (bootstrapping and key-switching keys; the evaluator gets these)\n' "$(( $(wc -c <alice/eval.keys) / 1048576 ))"

step "evaluator: a separate process with the OpenFHE exact backend (no keys)"
PORT="$(free_port)"
URL="http://127.0.0.1:$PORT"
mkdir evaluator
(cd evaluator && exec "$EVAL" serve --listen "127.0.0.1:$PORT" --backend openfhe-exact 2>log) &
ready "$URL/v1/info"
curl -s "$URL/v1/info" | "$PYTHON" -c 'import json,sys; i=json.load(sys.stdin)["backends"]["exact"]; print("exact backend", i["backend"], i["backend_version"], i["scheme"])'

step "client -> evaluator: eligibility on ciphertexts, receipt saved"
remote() {
  local keys="$1" dir="$2"
  shift 2
  "$E" run el.encompute --remote "$URL" --keys "$keys" --save-receipt "$dir.receipt.json" \
    --save-envelopes "$dir" --input age="$1" --input income="$2" --input debt="$3" --input risk="$4" \
    2>"$dir.log" | out
}
yes="$(remote alice alice-run 31 120000 21000 400)"
no="$(remote bob bob-run 17 120000 21000 400)"
cy="$("$E" run el.encompute --mode clear --input age=31 --input income=120000 --input debt=21000 --input risk=400 | out)"
cn="$("$E" run el.encompute --mode clear --input age=17 --input income=120000 --input debt=21000 --input risk=400 | out)"
[ "$yes" = "$cy" ] && [ "$no" = "$cn" ] || { echo "encrypted != clear" >&2; exit 1; }
echo "alice (age 31): encrypted=$yes clear=$cy MATCH"
echo "bob   (age 17): encrypted=$no clear=$cn MATCH"
grep -E "^Evaluator receipt|^Execution proof" alice-run.log

step "anyone with the files: verify alice's receipt"
TRUST="$(cat alice/evaluator.pub)"
verify() { "$E" verify "$1" --model el.encompute --trust-evaluator "$TRUST" --request "$2" --response "$3"; }
verify alice-run.receipt.json alice-run/request.bin alice-run/response.bin | grep -E "^RECEIPT|^EXECUTION"
n="$(find evaluator -name secret.key | wc -l | tr -d ' ')"
echo "secret.key files in the evaluator's directory: $n"
[ "$n" = 0 ] || exit 1

step "Try breaking it"
PID="$(header alice-run/request.bin program_id)"
JOBS="/v1/programs/$PID/jobs"
refused() {
  local what="$1" out
  shift
  if out="$("$@" 2>&1)"; then
    echo "$out"
    echo "ATTACK SUCCEEDED (this is a bug): $what" >&2
    exit 1
  fi
  # A refusal must name the check that fired: a crash or a typo is not one.
  local why
  why="$(echo "$out" | grep -E 'ENC[0-9]{4}|INVALID|UNAVAILABLE' | head -n 1)"
  if [ -z "$why" ]; then
    echo "$out"
    echo "ATTACK FAILED FOR AN UNEXPECTED REASON: $what" >&2
    exit 1
  fi
  printf 'ATTACK   %s\nREFUSED  %s\n' "$what" "$why"
}
forge swap alice-run/request.bin swap.bin bob-run/request.bin age
refused "a ciphertext under another client's key (bob's age in alice's request)" \
  forge post "$URL" "$JOBS" swap.bin
forge header alice-run/request.bin wrongkey.bin key_id="$(header bob-run/request.bin key_id)"
refused "evaluate alice's ciphertexts with bob's evaluation keys" \
  forge post "$URL" "$JOBS" wrongkey.bin
forge params alice-run/request.bin params.bin age
refused "a ciphertext claiming another parameter set" \
  forge post "$URL" "$JOBS" params.bin
forge header alice-run/request.bin backend.bin backend=tfhe-rs scheme=TFHE
refused "relabel the request for another backend (tfhe-rs)" \
  forge post "$URL" "$JOBS" backend.bin
forge corrupt alice-run/request.bin corrupt.bin age
refused "flip one ciphertext bit (outer checksum recomputed)" \
  forge post "$URL" "$JOBS" corrupt.bin
sed 's/const \[18.0\]/const [16.0]/' el.encompute/program.eir >lowered.eir
LOWERED="$(curl -s -X POST --data-binary @lowered.eir "$URL/v1/programs" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["program_id"])')"
refused "evaluator runs a modified plan (age >= 16) on alice's request" \
  forge post "$URL" "/v1/programs/$LOWERED/jobs" alice-run/request.bin
cp -r el.encompute edited.encompute
cp lowered.eir edited.encompute/program.eir
refused "client runs an edited artifact (age >= 16)" \
  "$E" run edited.encompute --remote "$URL" --keys alice \
  --input age=17 --input income=120000 --input debt=21000 --input risk=400
refused "replay alice's receipt as evidence for bob's result" \
  verify alice-run.receipt.json alice-run/request.bin bob-run/response.bin
refused "decrypt with only what the evaluator holds (eval.keys)" \
  sh -c 'mkdir -p stolen && cp alice/eval.keys stolen/ && "$0" run el.encompute --remote "$1" --keys stolen --input age=31 --input income=120000 --input debt=21000 --input risk=400' "$E" "$URL"
refused "income * 1_000_000 in a u32 program (overflow)" \
  "$E" compile "$ROOT/examples/02_exact_private_logic/unsafe.py:scaled" -o unsafe.encompute
refused "a 1001-entry lookup (outside the capability matrix)" \
  "$E" compile "$HERE/wide.py:wide" -o wide.encompute
refused "select TFHE-rs in a production build" \
  env ENCOMPUTE_RESEARCH_EXACT_BACKEND=tfhe-rs "$E" compile "$ELIG:eligibility" -o research.encompute
refused "serve exact programs on TFHE-rs in a production build" \
  "$EVAL" serve --listen 127.0.0.1:1 --backend tfhe-rs
