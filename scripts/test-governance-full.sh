#!/usr/bin/env bash
# The governance branch's full test run: scripts/test-full.sh on
# scripts/test-manifest-governance.json (main's manifest plus the governance
# suites, attack suite, assurance report, backup drill and public-sector
# examples), always in release mode: cold databases only. Extra arguments go
# to the runner (--runs, --json, --list).
#
# The control-plane run needs the TLS PostgreSQL of scripts/tls-test-db.sh
# (the database-TLS tests). Give it with ENCOMPUTE_TEST_TLS_DATABASE,
# ENCOMPUTE_TEST_TLS_DATABASE_PASSWORD and ENCOMPUTE_TEST_TLS_PKI
# (eval "$(scripts/tls-test-db.sh env DIR)"); without them this script starts
# a throwaway one and removes it afterwards. The runner fails closed if the
# server is missing.
#
#   scripts/test-governance-full.sh
#   scripts/test-governance-full.sh --runs governance-attacks --json out.json
set -uo pipefail
cd "$(dirname "$0")/.."

listing=0
for a in "$@"; do [ "$a" = --list ] && listing=1; done
if [ "$listing" = 0 ] && [ -z "${ENCOMPUTE_TEST_TLS_DATABASE:-}" ]; then
  TLS_PKI="$(mktemp -d)"
  trap 'scripts/tls-test-db.sh down "$TLS_PKI" >/dev/null 2>&1; rm -rf "$TLS_PKI"' EXIT
  if scripts/tls-test-db.sh up "$TLS_PKI" >/dev/null; then
    eval "$(scripts/tls-test-db.sh env "$TLS_PKI")"
  fi
fi
scripts/test-full.sh --manifest scripts/test-manifest-governance.json --release "$@"
