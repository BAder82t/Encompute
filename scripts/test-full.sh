#!/usr/bin/env bash
# The full test run: a precheck of every service the integration suites need,
# then the suites the manifest lists, verified to have really run. It fails
# (never "N passed" with hidden skips) when a dependency is missing, a
# required suite runs zero tests, skips, fails, or falls below its recorded
# minimum, or the total falls below the manifest's.
#
#   scripts/test-full.sh                       every default run, cold databases
#   scripts/test-full.sh --release             the same, refusing anything but cold
#   scripts/test-full.sh --mode template       fast development databases (never a release)
#   scripts/test-full.sh --runs control-plane,cli   a subset of the manifest's runs
#   scripts/test-full.sh --list                the runs, suites and minimums
#   scripts/test-full.sh --json FILE           where the machine-readable summary goes
#
# Needs ENCOMPUTE_TEST_DATABASE_URL, ENCOMPUTE_TEST_BAO_ADDR and
# ENCOMPUTE_TEST_BAO_TOKEN (PostgreSQL and OpenBao dev servers), the TLS
# PostgreSQL of scripts/tls-test-db.sh (eval "$(scripts/tls-test-db.sh env)")
# for the database-TLS tests, and OpenFHE
# (OPENFHE_ROOT or .deps/openfhe) for the runs that list them. The manifest is
# scripts/test-manifest.json: reviewed whenever a minimum changes.
# scripts/test-full-selftest.sh proves this runner fails when it should.
set -uo pipefail
cd "$(dirname "$0")/.."
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found"
  echo "FULL TEST FAILED"
  exit 1
fi
exec python3 scripts/test_full.py "$@"
