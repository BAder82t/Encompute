#!/bin/sh
# Inside Confidential Space: attest to each broker, receive the keys, then
# serve with receipts bound to the attested session. Keys are never written
# or printed; if any broker refuses, the workload stops.
#
# BROKER_URLS (set by the operator) says only where each broker is. Which
# grant-signing key each asset's grant must carry comes from
# /app/broker-keys, part of the attested image ("ASSET KEY" lines): the
# operator cannot pin a broker of its own, or leave one unpinned.
set -eu
: "${BROKER_URLS:?set BROKER_URLS to ASSET@URL[,ASSET@URL...]}"
KEYS=/app/broker-keys
echo "encompute workload: variant $(cat /app/variant)"
if [ ! -s "$KEYS" ]; then
  echo "encompute workload: REFUSED: the image names no broker keys ($KEYS)" >&2
  exit 3
fi
set --
for k in $(echo "$BROKER_URLS" | tr ',' ' '); do
  case "$k" in
    *'#'*)
      echo "encompute workload: REFUSED: BROKER_URLS may not carry a broker key; the image pins it" >&2
      exit 3 ;;
  esac
  asset="${k%%@*}"
  key="$(awk -v a="$asset" '$1 == a { print $2 }' "$KEYS")"
  if [ -z "$key" ]; then
    echo "encompute workload: REFUSED: the image names no broker key for $asset" >&2
    exit 3
  fi
  set -- "$@" --key "$k#$key"
done
encompute workload keys /app/model.encompute --backend mock \
  --identity /tmp/evaluator.id --attester confidential-space \
  --record /tmp/attestation.json "$@"
exec encompute-evaluator serve /app/model.encompute --backend mock \
  --listen 0.0.0.0:8750 --identity /tmp/evaluator.id --attestation /tmp/attestation.json
