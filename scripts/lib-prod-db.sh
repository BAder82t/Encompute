# shellcheck shell=bash
# The production-mode database connection for scripts that start a
# production-mode control plane (enterprise-e2e.sh, release/soak.sh).
#
# Production mode requires sslmode=verify-full, so these scripts run against
# the TLS-enabled PostgreSQL of scripts/tls-test-db.sh:
#
#   scripts/tls-test-db.sh up && eval "$(scripts/tls-test-db.sh env)"
#
# (ENCOMPUTE_TEST_TLS_DATABASE, ENCOMPUTE_TEST_TLS_DATABASE_PASSWORD,
# ENCOMPUTE_TEST_TLS_PKI). That server's certificate is for the name
# `postgres`, so the URL names that host and dials 127.0.0.1 with hostaddr.
#
# In a TEST ENVIRONMENT ONLY, a plaintext database can be used by setting
# <PREFIX>_ALLOW_PLAINTEXT_DATABASE=true: the script then passes the named
# opt-out ENCOMPUTE_ALLOW_PLAINTEXT_DATABASE=true to the control plane. It is
# insecure and never a production setting.

# tls_db_url USER PASSWORD DATABASE -> a verify-full URL with a client certificate
tls_db_url() {
  local port="${ENCOMPUTE_TEST_TLS_DATABASE##*:}" pki="$ENCOMPUTE_TEST_TLS_PKI"
  printf 'postgres://%s:%s@postgres:%s/%s?hostaddr=127.0.0.1&sslmode=verify-full&sslrootcert=%s/internal-ca.crt&sslcert=%s/pg-client.crt&sslkey=%s/pg-client.key' \
    "$1" "$2" "$port" "$3" "$pki" "$pki" "$pki"
}

# prod_db_mode PREFIX -> tls | plaintext (exit 1 with a message if neither is configured)
prod_db_mode() {
  if [ -n "${ENCOMPUTE_TEST_TLS_DATABASE:-}" ]; then
    : "${ENCOMPUTE_TEST_TLS_DATABASE_PASSWORD:?set ENCOMPUTE_TEST_TLS_DATABASE_PASSWORD (scripts/tls-test-db.sh env)}"
    : "${ENCOMPUTE_TEST_TLS_PKI:?set ENCOMPUTE_TEST_TLS_PKI (scripts/tls-test-db.sh env)}"
    echo tls
  elif [ "$(eval "echo \${${1}_ALLOW_PLAINTEXT_DATABASE:-}")" = true ]; then
    echo plaintext
  else
    echo "production mode needs a TLS database (sslmode=verify-full): run scripts/tls-test-db.sh up and eval \"\$(scripts/tls-test-db.sh env)\"; or, in a test environment only, set ${1}_ALLOW_PLAINTEXT_DATABASE=true" >&2
    return 1
  fi
}
