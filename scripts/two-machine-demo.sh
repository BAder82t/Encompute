#!/usr/bin/env bash
# Encompute 0.2 demo: the client (this machine) encrypts a 384-d query; the
# evaluator (a container: separate filesystem, network namespace and user)
# computes encrypted similarity scores and returns ciphertexts; only the
# client decrypts.
#
#   scripts/two-machine-demo.sh [EVALUATOR_URL]
#
# Without a URL, the evaluator image is built and started locally. With a
# URL, an evaluator already running on another machine is used.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
ENCOMPUTE="${ENCOMPUTE:-$ROOT/target/release/encompute}"
PYTHON="${PYTHON:-python3}"
URL="${1:-}"
CONTAINER=""
cleanup() { [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "client: compile the model"
"$PYTHON" "$ROOT/examples/03_remote_evaluator/search_model.py" "$WORK"

step "client: generate keys (secret.key never leaves this machine)"
"$ENCOMPUTE" keys generate "$WORK/search.encompute" -o "$WORK/client.keys"
ls -l "$WORK/client.keys"

if [ -z "$URL" ]; then
  step "evaluator: build and start the container (no keys, no model inside)"
  docker build -q -f "$ROOT/Dockerfile.evaluator" -t encompute-evaluator "$ROOT" >/dev/null
  CONTAINER="$(docker run -d -p 127.0.0.1:18750:8750 encompute-evaluator)"
  URL="http://127.0.0.1:18750"
  for _ in $(seq 1 60); do curl -fs "$URL/v1/info" >/dev/null && break; sleep 1; done
fi
curl -fs "$URL/v1/info"; echo

step "client → evaluator: upload program and evaluation keys, send encrypted query, decrypt result"
"$ENCOMPUTE" run "$WORK/search.encompute" --remote "$URL" --keys "$WORK/client.keys" \
  --inputs-file "$WORK/query.json" > "$WORK/result.json"

step "client: compare with plaintext"
"$PYTHON" - "$WORK/result.json" "$WORK/expected.json" <<'PY'
import json, sys
got = json.load(open(sys.argv[1]))["out"]; want = json.load(open(sys.argv[2]))["out"]
err = max(abs(a - b) for a, b in zip(got, want))
top = lambda v: sorted(range(len(v)), key=lambda i: -v[i])[:5]
print(f"max abs error {err:.2e} (target 1e-3); top-5 encrypted {top(got)} plaintext {top(want)}")
assert err <= 1e-3 and top(got) == top(want), "mismatch"
PY

if [ -n "$CONTAINER" ]; then
  step "evaluator: holds no secret key and no client crypto"
  docker exec "$CONTAINER" sh -c 'find / -xdev -name "secret.key" 2>/dev/null | wc -l' | xargs -I{} echo "secret.key files in container: {}"
  docker cp "$CONTAINER:/usr/local/bin/encompute-evaluator" "$WORK/evaluator-bin" >/dev/null
  cp "$ROOT/scripts/audit-evaluator-binary.sh" "$WORK/"
  # Audit with Linux binutils: the host's nm may not read a Linux binary.
  docker run --rm -v "$WORK:/w" debian:bookworm-slim sh -c \
    'apt-get update -qq >/dev/null && apt-get install -y -qq binutils >/dev/null 2>&1 && /w/audit-evaluator-binary.sh /w/evaluator-bin'
fi

step "client: explain with measurements"
"$ENCOMPUTE" explain "$WORK/search.encompute" --measure 10 --mode encrypted | sed -n '/Data/,$p'
echo; echo "DEMO PASSED"
