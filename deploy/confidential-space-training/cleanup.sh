#!/bin/sh
# Removes what deploy.sh created for a run: the VMs and the run's objects.
# Keeps the broker state and its key-encryption key (the owner's keys),
# the buckets, the service account and the image unless asked.
#
#   PROJECT=my-project deploy/confidential-space-training/cleanup.sh [approved|tampered|debug|all]
#   DELETE_IMAGES=1 DELETE_BUCKETS=1 ... to remove those too.
set -eu
: "${PROJECT:?set PROJECT}"
VARIANT="${1:-all}"
ZONE="${ZONE:-us-central1-a}"
REGION="${REGION:-us-central1}"
REPO="${REPO:-encompute}"
IN_BUCKET="${IN_BUCKET:-${PROJECT}-encompute-training-in}"
OUT_BUCKET="${OUT_BUCKET:-${PROJECT}-encompute-training-out}"
WORK="${WORK:-$PWD/cs-training-work}"
RUN="$(cat "$WORK/run-id" 2>/dev/null || true)"
gcloud config set project "$PROJECT" >/dev/null
filter="name~^enc-train-"
[ "$VARIANT" != all ] && filter="name~^enc-train-${VARIANT}-"
for vm in $(gcloud compute instances list --filter "$filter" --format 'value(name)'); do
  gcloud compute instances delete "$vm" --zone "$ZONE" --quiet
done
if [ -n "$RUN" ]; then
  gcloud storage rm --recursive --quiet "gs://${IN_BUCKET}/${RUN}" "gs://${OUT_BUCKET}/${RUN}" 2>/dev/null || true
fi
if [ "${DELETE_BUCKETS:-}" = 1 ]; then
  gcloud storage buckets delete "gs://${IN_BUCKET}" "gs://${OUT_BUCKET}" --quiet || true
fi
if [ "${DELETE_IMAGES:-}" = 1 ]; then
  gcloud artifacts docker images delete "${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/training-worker" \
    --delete-tags --quiet || true
fi
echo "Cleaned up ${VARIANT}. The broker state and key-encryption key in $WORK were kept."
