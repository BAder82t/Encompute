#!/usr/bin/env bash
# 02: exact private logic. Clear and mock always; OpenFHE exact when built.
source "$(dirname "$0")/../lib.sh"
need_cli
need_python
export PYTHON PYTHONDONTWRITEBYTECODE=1  # `encompute compile file.py:fn` runs this Python

step "Run an eligibility rule in clear and mock modes (and encrypted when built)"
"$PYTHON" "$HERE/eligible.py"

step "Compile it: overflow is checked for every input in range"
"$E" compile "$HERE/eligible.py:eligible" -o "$W/eligible.encompute" >/dev/null
"$E" explain "$W/eligible.encompute" | grep -E "semantics|comparisons|Boolean|overflow|scheme|bootstrapped gates|result semantics"
"$E" run "$W/eligible.encompute" --mode mock --input age=31 --input income=52000 --input risk=410

# eligibility.py (with a debt ratio) is the program scripts/exact-demo.sh runs.
"$E" compile "$HERE/eligibility.py:eligibility" -o "$W/eligibility.encompute" >/dev/null
echo "eligibility.py:eligibility compiles"

step "Try breaking it"
m="$W/eligible.encompute"
attack "age outside its declared range [0, 120]" \
  "$E" run "$m" --mode mock --input age=130 --input income=52000 --input risk=410
attack "negative income" \
  "$E" run "$m" --mode mock --input age=31 --input income=-1 --input risk=410
attack "a fractional age in an integer program" \
  "$E" run "$m" --mode mock --input age=31.5 --input income=52000 --input risk=410
attack "income * 1_000_000 in a u32 program" \
  "$E" compile "$HERE/unsafe.py:scaled" -o "$W/unsafe.encompute"
