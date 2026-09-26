#!/usr/bin/env bash
# 04: execution receipts. A remote run saves the evaluator's signed receipt
# and the exchanged envelopes; `encompute verify` checks them later.
source "$(dirname "$0")/../lib.sh"
need_cli
need_evaluator
cd "$W"

# Tamper with something, then require `encompute verify` to reject it.
reject() {
  local what="$1" out rc
  shift
  out="$("$@" 2>&1)" && rc=0 || rc=$?
  if [ "$rc" = 0 ]; then
    echo "$out"
    echo "ATTACK SUCCEEDED (this is a bug): $what" >&2
    exit 1
  fi
  printf 'ATTACK   %s\nREFUSED  exit %s: %s\n' "$what" "$rc" "$(echo "$out" | grep -E 'INVALID|ENC[0-9]{4}|some bindings not checked' | head -n 1)"
}

step "client: compile an exact program and generate keys"
"$E" compile "$HERE/adult.eir" -o adult.encompute >/dev/null
"$E" keys generate adult.encompute -o keys --mode mock >/dev/null
echo "adult(age) = age >= 18"

step "evaluator: start (mock backend; it signs a receipt for every job)"
PORT="$(free_port)"
"$EVAL" serve --listen "127.0.0.1:$PORT" --backend mock 2>evaluator.log &
ready "http://127.0.0.1:$PORT/v1/info"

step "client: run remotely, save the receipt and the envelopes"
"$E" run adult.encompute --remote "http://127.0.0.1:$PORT" --keys keys --input age=30 \
  --save-receipt receipt.json --save-envelopes exchange 2>run.log
grep -E "on first use|receipt|proof|result" run.log | sed -E 's/enc-eval:[0-9a-f]+/enc-eval:<id>/'
ls exchange

step "anyone with the files: verify the receipt and every binding"
TRUST="$(cat keys/evaluator.pub)"
verify() { "$E" verify "$@" --model adult.encompute --trust-evaluator "$TRUST"; }
verify receipt.json --request exchange/request.bin --response exchange/response.bin |
  sed -n '/^Evaluator/,$p' | grep -Ev '^─|^  ID'

step "Try breaking it"
cp exchange/response.bin response.bin
"$PYTHON" -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[len(b)//2]^=1; open(p,"wb").write(b)' response.bin
reject "flip one bit of the response" \
  verify receipt.json --request exchange/request.bin --response response.bin
cp exchange/request.bin request.bin
"$PYTHON" -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[len(b)//2]^=1; open(p,"wb").write(b)' request.bin
reject "flip one bit of the request" \
  verify receipt.json --request request.bin --response exchange/response.bin
sed 's/"scheme":"TFHE"/"scheme":"CKKS"/' receipt.json >edited.json
reject "edit a receipt field (scheme TFHE -> CKKS)" \
  verify edited.json --request exchange/request.bin --response exchange/response.bin
reject "claim a different backend than the one requested" \
  verify receipt.json --request exchange/request.bin --response exchange/response.bin --backend tfhe-rs
reject "trust a different evaluator key" \
  "$E" verify receipt.json --model adult.encompute --request exchange/request.bin \
  --response exchange/response.bin --trust-evaluator "$(printf '11%.0s' $(seq 32))"
reject "check only the signature (bindings not checked is not success)" \
  "$E" verify receipt.json
PORT2="$(free_port)"
"$EVAL" serve --listen "127.0.0.1:$PORT2" --backend mock 2>/dev/null &
ready "http://127.0.0.1:$PORT2/v1/info"
reject "swap in another evaluator (a new signing key)" \
  "$E" run adult.encompute --remote "http://127.0.0.1:$PORT2" --keys keys --input age=30
