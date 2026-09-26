#!/usr/bin/env bash
# 06: confidentiality policy. Illegal flows are compile errors.
source "$(dirname "$0")/../lib.sh"
need_cli
need_python

step "Compile the training step and explain its confidentiality graph"
"$E" compile "$HERE/training.eir" -o "$W/training.encompute" > /dev/null
# The trailing note of `privacy explain` points at design docs; not needed here.
"$E" privacy explain "$W/training.encompute" | sed '/^This is the policy/,$d'

step "The same graph for Graphviz"
"$E" privacy graph "$W/training.encompute" > "$W/graph.dot"
grep -- '->' "$W/graph.dot"

step "Try breaking it: each program below must fail to compile"
attack "return patient data publicly" \
  "$E" compile "$HERE/leak_patient_data.eir" -o "$W/x.encompute"
attack "send the gradient straight to the coordinator (no aggregation)" \
  "$E" compile "$HERE/gradient_to_coordinator.eir" -o "$W/x.encompute"
attack "use the datasets for another purpose (marketing)" \
  "$E" compile "$HERE/wrong_purpose.eir" -o "$W/x.encompute"

step "The same rules from Python"
"$PYTHON" "$HERE/confidential_training.py" | grep -E '^leak rejected'
