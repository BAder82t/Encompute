#!/bin/sh
# Inside Confidential Space: attest to each broker, receive the keys, then
# serve with receipts bound to the attested session. Keys are never written
# or printed; if any broker refuses, the workload stops.
set -eu
: "${BROKER_URLS:?set BROKER_URLS to ASSET@URL[,ASSET@URL...]}"
echo "encompute workload: variant $(cat /app/variant)"
set --
for k in $(echo "$BROKER_URLS" | tr ',' ' '); do set -- "$@" --key "$k"; done
encompute workload keys /app/model.encompute --backend mock \
  --identity /tmp/evaluator.id --attester confidential-space \
  --record /tmp/attestation.json "$@"
exec encompute-evaluator serve /app/model.encompute --backend mock \
  --listen 0.0.0.0:8750 --identity /tmp/evaluator.id --attestation /tmp/attestation.json
