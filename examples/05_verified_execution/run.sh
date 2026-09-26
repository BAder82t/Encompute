#!/usr/bin/env bash
# 05: verified execution. The compile-time checks run in every build; the
# proven remote run needs the research build (OpenFHE BGV + vfhe-research).
source "$(dirname "$0")/../lib.sh"
need_cli
need_evaluator
need_python
export PYTHON PYTHONDONTWRITEBYTECODE=1  # `encompute compile file.py:fn` runs this Python
cd "$W"

# Tamper with something; the command must fail.
reject() {
  local what="$1" out rc
  shift
  out="$("$@" 2>&1)" && rc=0 || rc=$?
  if [ "$rc" = 0 ]; then
    echo "$out"
    echo "ATTACK SUCCEEDED (this is a bug): $what" >&2
    exit 1
  fi
  printf 'ATTACK   %s\nREFUSED  exit %s: %s\n' "$what" "$rc" \
    "$(echo "$out" | grep -E 'INVALID|ENC[0-9]{4}|FAILED' | head -n 1)"
}

step "Compile a program that requires verified execution"
"$E" compile "$HERE/precheck.py:precheck" -o precheck.encompute >/dev/null
"$E" explain precheck.encompute | grep -E "scheme|verification|proof backend|proof coverage|execution proof"

step "The transcript a proof must follow (operations only, never values)"
"$E" transcript precheck.encompute --backend openfhe | sed -n '/^Instructions/,/^Transcript/p' | grep -Ev '^─|^Transcript|^$'

step "Try breaking it: checks that hold in every build"
reject "require verification for a comparison (outside the proven subset)" \
  "$E" compile "$HERE/uncovered.py:adult" -o uncovered.encompute

if ! has verified-execution; then
  step "This build cannot verify execution, and says so"
  reject "plan a verified run without OpenFHE BGV" "$E" plan precheck.encompute
  "$E" plan precheck.encompute | grep -E "^No execution plan" || true
  has openfhe || reject "generate BGV keys without OpenFHE" \
    "$E" keys generate precheck.encompute -o keys

  step "What a receipt alone gives you (mock evaluator: never reported as verified)"
  "$E" keys generate precheck.encompute -o mockkeys --mode mock >/dev/null
  PORT="$(free_port)"
  "$EVAL" serve --listen "127.0.0.1:$PORT" --backend mock 2>/dev/null &
  ready "http://127.0.0.1:$PORT/v1/info"
  "$E" run precheck.encompute --remote "http://127.0.0.1:$PORT" --keys mockkeys \
    --input income=1000 --input member=true --input flagged=false \
    --save-receipt mock.receipt.json --save-envelopes mock 2>run.log >/dev/null
  grep -E "^(Evaluator receipt|Execution proof|Encrypted result)" run.log
  "$E" verify mock.receipt.json --model precheck.encompute --request mock/request.bin \
    --response mock/response.bin --trust-evaluator "$(cat mockkeys/evaluator.pub)" |
    grep -E "^(RECEIPT|EXECUTION|TRANSCRIPT)"
fi

need verified-execution

# The research build: OpenFHE BGV with re-execution proofs.
step "client: BGV keys; evaluator: OpenFHE BGV (attaches an execution proof)"
"$E" keys generate precheck.encompute -o keys >/dev/null
PORT="$(free_port)"
"$EVAL" serve --listen "127.0.0.1:$PORT" --backend openfhe 2>/dev/null &
ready "http://127.0.0.1:$PORT/v1/info"
URL="http://127.0.0.1:$PORT"

step "client: run remotely; decrypt only after the proof verifies"
run() {
  "$E" run precheck.encompute --remote "$URL" --keys keys \
    --input income="$1" --input member=true --input flagged=false \
    --save-receipt "$2.receipt.json" --save-envelopes "$2"
}
run 1000 honest 2>run.log
grep -E "^(Evaluator receipt|Execution proof|Encrypted result|VERIFIED)" run.log
grep -q "^VERIFIED PRIVATE EXECUTION" run.log || { echo "the run was not verified" >&2; exit 1; }
run 4000 other 2>/dev/null >/dev/null

step "anyone with the files: re-check the proof offline"
TRUST="$(cat keys/evaluator.pub)"
check() {
  "$E" verify "$1" --model precheck.encompute --request "$2" --response "$3" \
    --proof "$4" --evaluation-keys keys/eval.keys --trust-evaluator "$TRUST"
}
check honest.receipt.json honest/request.bin honest/response.bin honest/proof.bin >verify.out
grep -E "^(RECEIPT|EXECUTION|VERIFIED)" verify.out
grep -q "^EXECUTION VERIFIED" verify.out || { echo "the proof did not verify" >&2; exit 1; }

step "Try breaking it: tampered proof and replayed output"
cp honest/proof.bin proof.bin
"$PYTHON" -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[len(b)//2]^=1; open(p,"wb").write(b)' proof.bin
reject "flip one bit of the execution proof" \
  check honest.receipt.json honest/request.bin honest/response.bin proof.bin
reject "replay the output of another run (caught by the receipt binding)" \
  check honest.receipt.json honest/request.bin other/response.bin honest/proof.bin
