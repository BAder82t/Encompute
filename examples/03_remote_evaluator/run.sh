#!/usr/bin/env bash
# 03: a remote evaluator in a separate process. It computes on ciphertexts
# and never receives the secret key. Mock backend; OpenFHE when built.
source "$(dirname "$0")/../lib.sh"
need_cli
need_evaluator
need_python

BACKEND=mock KEYMODE=mock
if has openfhe; then
  BACKEND=openfhe KEYMODE=encrypted
elif [ "$MODE" = crypto ]; then
  skip "OpenFHE unavailable (build with --features openfhe)"
fi
CLIENT="$W/client" SERVER="$W/evaluator"
mkdir -p "$CLIENT" "$SERVER"

step "client: compile the model and generate keys"
"$PYTHON" "$HERE/search_model.py" "$CLIENT" >/dev/null
"$E" keys generate "$CLIENT/search.encompute" -o "$CLIENT/keys" --mode "$KEYMODE" >/dev/null
keyinfo() {
  "$PYTHON" - "$@" <<'PY'
import json, os, stat, sys
for path in sys.argv[1:]:
    raw = open(path, "rb").read()
    kind = json.JSONDecoder().raw_decode(raw[raw.index(b"{"):].decode("latin-1"))[0]["kind"]
    mode = stat.S_IMODE(os.stat(path).st_mode)
    print(f"  {os.path.basename(path):<10} {kind:<16} {len(raw):>9} bytes  mode {mode:o}")
PY
}
keyinfo "$CLIENT/keys/secret.key" "$CLIENT/keys/eval.keys"

step "evaluator: a separate process, in its own empty directory ($BACKEND backend)"
PORT="$(free_port)"
URL="http://127.0.0.1:$PORT"
(cd "$SERVER" && exec "$EVAL" serve --listen "127.0.0.1:$PORT" --backend "$BACKEND" 2>"$SERVER/log") &
ready "$URL/v1/info"
curl -s "$URL/v1/info" | "$PYTHON" -c 'import json,sys; i=json.load(sys.stdin); print("role", i["role"], "| holds_secret_keys", str(i["holds_secret_keys"]).lower())'

step "client -> evaluator: upload program and eval.keys, send an encrypted query, decrypt here"
"$E" run "$CLIENT/search.encompute" --remote "$URL" --keys "$CLIENT/keys" \
  --inputs-file "$CLIENT/query.json" >"$CLIENT/result.json" 2>"$CLIENT/run.log"
grep -E "receipt|proof|result" "$CLIENT/run.log"
"$PYTHON" - "$CLIENT/result.json" "$CLIENT/expected.json" <<'PY'
import json, sys
got = json.load(open(sys.argv[1]))["out"]; want = json.load(open(sys.argv[2]))["out"]
err = max(abs(a - b) for a, b in zip(got, want))
top = lambda v: sorted(range(len(v)), key=lambda i: -v[i])[:5]
assert err <= 1e-3 and top(got) == top(want), "mismatch"
print(f"top-5 documents   {top(got)} (plaintext: {top(want)})")
print("Result            MATCH (within 1e-3)")
PY

step "evaluator: what it received, and what it holds"
echo "requests it served (from its log):"
grep -E "POST " "$SERVER/log" | sed -E 's/^req=[0-9]+ //; s#/v1/programs/[0-9a-f]+#/v1/programs/<id>#; s/ status=([0-9]+) in=([0-9]+)B.*/  status \1  received \2 bytes/'
keys_in="$(grep -E "POST /v1/programs/[0-9a-f]+/keys " "$SERVER/log" | sed -E 's/.* in=([0-9]+)B.*/\1/')"
eval_size="$(wc -c <"$CLIENT/keys/eval.keys" | tr -d ' ')"
[ "$keys_in" = "$eval_size" ] || { echo "key upload is $keys_in bytes, eval.keys is $eval_size" >&2; exit 1; }
echo "key upload = eval.keys ($eval_size bytes); secret.key was never sent"
n="$(find "$SERVER" -name 'secret.key' | wc -l | tr -d ' ')"
[ "$n" = 0 ] || exit 1
echo "secret.key files in the evaluator's directory: $n"
"$E" audit "$CLIENT/search.encompute" --keys "$CLIENT/keys" --evaluator "$EVAL" |
  grep -E "keys.secret_permissions|evaluator.no_client_crypto|artifact.no_key_material" |
  sed "s#$W/##"

step "Try breaking it"
cd "$W"
mkdir -p stolen
cp client/keys/eval.keys stolen/
attack "decrypt with only what the evaluator holds (eval.keys)" \
  "$E" run "$CLIENT/search.encompute" --remote "$URL" --keys stolen --inputs-file client/query.json
