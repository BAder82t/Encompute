#!/usr/bin/env bash
# 14: the Python Project API. Declare policies; Encompute plans or refuses.
source "$(dirname "$0")/../lib.sh"
need_python

step "Plan, train, and fail closed"
"$PYTHON" "$HERE/project_api.py"
