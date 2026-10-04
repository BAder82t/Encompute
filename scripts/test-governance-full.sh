#!/usr/bin/env bash
# The governance branch's full test run: scripts/test-full.sh on
# scripts/test-manifest-governance.json (main's manifest plus the governance
# suites, attack suite, assurance report, backup drill and public-sector
# examples), always in release mode: cold databases only. Extra arguments go
# to the runner (--runs, --json, --list).
#
#   scripts/test-governance-full.sh
#   scripts/test-governance-full.sh --runs governance-attacks --json out.json
set -uo pipefail
cd "$(dirname "$0")/.."
exec scripts/test-full.sh --manifest scripts/test-manifest-governance.json --release "$@"
