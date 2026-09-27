#!/usr/bin/env bash
# 20: optimized exact execution. The compiler reports the optimized
# circuit; the evaluator runs it with parallel gates and must return exactly
# what the reference lowering returns; arithmetic-only programs are
# selected for BGV; evaluation keys are cached and counted.
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
cd "$W"
P="$HERE/programs.py"
out() { "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["out"])'; }

step "Compile the eligibility rule: reference lowering vs optimized circuit"
"$E" compile "$P:eligibility" -o el.encompute >/dev/null
"$E" explain el.encompute | grep -E "^  (scheme|bootstrapped gates|optimized circuit|parallelism)"

step "explain --deep: what the optimizer did"
"$E" explain --deep el.encompute | sed -n '/^Exact optimization/,/^  estimated time/p'

step "Arithmetic only: the whole program is selected for BGV"
"$E" compile "$P:score" -o score.encompute >/dev/null
"$E" explain score.encompute | grep -E "^  (scheme|candidate)"

step "Boundary inputs: clear == mock (the mock runs the same plan)"
for a in "0 0 0 0" "17 1000000 0 650" "18 1000000 399999 650" "120 1000000 400000 651" "120 0 500000 1000"; do
  set -- $a
  args=(--input age="$1" --input income="$2" --input debt="$3" --input risk="$4")
  c="$("$E" run el.encompute --mode clear "${args[@]}" | out)"
  m="$("$E" run el.encompute --mode mock "${args[@]}" | out)"
  [ "$c" = "$m" ] || { echo "MISMATCH $a: clear=$c mock=$m" >&2; exit 1; }
  printf 'age=%-3s income=%-7s debt=%-6s risk=%-4s clear=%-5s mock=%-5s MATCH\n' "$1" "$2" "$3" "$4" "$c" "$m"
done

step "Try breaking it"
attack "age 121: the optimizer drops bits the declared range [0, 120] rules out, so the client refuses it" \
  "$E" run el.encompute --mode mock --input age=121 --input income=1 --input debt=1 --input risk=1
attack "income * 1_000_000 in a u32 program: no circuit is built for a possible overflow" \
  "$E" compile "$ROOT/examples/02_exact_private_logic/unsafe.py:scaled" -o unsafe.encompute

if ! has openfhe-exact || [ ! -x "$EVAL" ]; then
  echo
  echo "OpenFHE exact is not in this build: the encrypted comparison below is skipped."
  echo "(Build with --features openfhe; see README.)"
  exit 0
fi

step "Two evaluators: optimized (default) and reference lowering"
"$E" keys generate el.encompute -o alice >/dev/null
# One copy of the keys per evaluator: the client pins each evaluator's
# identity next to its keys on first use.
cp -r alice alice-ref
serve() {
  local port="$1" dir="$2"
  shift 2
  mkdir "$dir"
  (cd "$dir" && exec env "$@" "$EVAL" serve --listen "127.0.0.1:$port" --backend openfhe-exact 2>log) &
  ready "http://127.0.0.1:$port/v1/info"
}
OPT="$(free_port)"; serve "$OPT" optimized ENCOMPUTE_EXACT_WORKERS=8
REF="$(free_port)"; serve "$REF" reference ENCOMPUTE_EXACT_EXECUTION=reference
remote() {
  local port="$1" keys="$2"
  local t0 t1 r
  t0="$("$PYTHON" -c 'import time; print(time.time())')"
  r="$("$E" run el.encompute --remote "http://127.0.0.1:$port" --keys "$keys" \
    --input age=31 --input income=120000 --input debt=21000 --input risk=400 2>/dev/null | out)"
  t1="$("$PYTHON" -c 'import time; print(time.time())')"
  echo "$r $("$PYTHON" -c "print(round($t1 - $t0, 1))")"
}
read -r ro rt <<<"$(remote "$REF" alice-ref)"
read -r oo ot <<<"$(remote "$OPT" alice)"
c="$("$E" run el.encompute --mode clear --input age=31 --input income=120000 --input debt=21000 --input risk=400 | out)"
[ "$oo" = "$c" ] && [ "$ro" = "$c" ] || { echo "MISMATCH clear=$c reference=$ro optimized=$oo" >&2; exit 1; }
echo "clear=$c reference=$ro optimized=$oo MATCH"
echo "reference lowering: ${rt} s   optimized circuit: ${ot} s (includes key upload)"

step "Evaluation keys are cached: a second job does not reload them"
read -r oo2 ot2 <<<"$(remote "$OPT" alice)"
[ "$oo2" = "$c" ] || exit 1
echo "second optimized run: ${ot2} s"
curl -s "http://127.0.0.1:$OPT/metrics" | grep -E "^encompute_key_cache_(loads_total|hits_total|entries) "
