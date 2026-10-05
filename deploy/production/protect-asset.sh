#!/usr/bin/env bash
# Protects an asset key in the key broker (creating the broker's state, and
# the root-wrapped KEK in OpenBao, on first use):
#
#   ./protect-asset.sh ASSET POLICY.json
#
# POLICY.json comes from `encompute attest policy MODEL --image sha256:...
# --tee intel_tdx`. The key broker must have its token file (bao-token.sh)
# and the root-key provider must be reachable on the `bao` network; the broker
# itself may be stopped, and must be (re)started afterwards: it refuses to
# start without its state.
set -euo pipefail
cd "$(dirname "$0")"
ASSET="${1:?usage: protect-asset.sh ASSET POLICY.json}"
POLICY="$(cd "$(dirname "${2:?usage: protect-asset.sh ASSET POLICY.json}")" && pwd)/$(basename "$2")"
ORG="${KEYBROKER_ORG:-modelco}"
PROJECT="${COMPOSE_PROJECT_NAME:-encompute-prod}"
dc() { docker compose -p "$PROJECT" "$@"; }
dc run --rm -T --no-deps -v "$POLICY:/tmp/policy.json:ro" keybroker \
  keys protect --asset "$ASSET" --policy /tmp/policy.json \
  --broker-id "keybroker-$ORG" --root-key "openbao:transit/$ORG" --organization "$ORG" \
  --broker /var/lib/encompute/broker.json --wrapped-kek /var/lib/encompute/kek.wrapped.json
