# shellcheck shell=bash
# Shared helpers for the production topology's scripts (sourced, not run).

# docker, with a deadline: Docker Desktop can hang.
d() { perl -e 'alarm('"${DOCKER_TIMEOUT:-60}"'); exec @ARGV' docker "$@"; }

# The project's container for a service (PROJECT: default encompute-prod).
cid() {
  d ps -q --filter "label=com.docker.compose.project=${PROJECT:-encompute-prod}" \
    --filter "label=com.docker.compose.service=$1" | head -n 1
}

# OpenBao/Vault HTTP API over verified TLS, from the host.
#   bao_api METHOD PATH [JSON]
# Needs BAO_ADDR and BAO_CACERT; the token is $BAO_TOKEN_VALUE (may be unset).
# The token goes in a header file read from a pipe, never on a command line.
bao_api() {
  local method="$1" body="${3:-}" url="${BAO_ADDR:?set BAO_ADDR}/v1/$2"
  : "${BAO_CACERT:?set BAO_CACERT}"
  if [ -n "$body" ]; then
    curl -sS --fail-with-body --max-time 20 --cacert "$BAO_CACERT" -X "$method" \
      -H @<(printf 'X-Vault-Token: %s\nContent-Type: application/json\n' "${BAO_TOKEN_VALUE:-}") \
      --data-binary @- "$url" <<<"$body"
  else
    curl -sS --fail-with-body --max-time 20 --cacert "$BAO_CACERT" -X "$method" \
      -H @<(printf 'X-Vault-Token: %s\n' "${BAO_TOKEN_VALUE:-}") "$url"
  fi
}
