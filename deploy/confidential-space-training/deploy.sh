#!/bin/sh
# Real Confidential Space training: one Hugging Face + PEFT step per
# participant, in production Confidential Space VMs (Intel TDX), with
# hardware attestation gating the model, dataset and output keys.
#
#   PROJECT=my-project BROKER_URL=http://10.128.0.5:8760 \
#     deploy/confidential-space-training/deploy.sh [prepare-only|approved|tampered|debug]
#
# prepare-only  builds, prepares and stages the approved job, then stops:
#               start the broker (printed below), then run `approved`.
# approved  builds the image, prepares the job for its digest, stages the
#           sealed assets, runs the workers, and verifies their evidence.
# tampered  runs a rebuilt image (another digest) against the approved job:
#           ATTESTATION VALID, IMAGE NOT APPROVED, KEY RELEASE DENIED.
# debug     runs the approved image on a confidential-space-debug VM:
#           KEY RELEASE DENIED.
#
# Needs: gcloud (logged in), python with encompute[huggingface], and a
# built `encompute` (cargo build --bins). No secret is passed to any script
# or VM: keys stay in the broker, sealed assets are all the cloud sees.
set -eu
: "${PROJECT:?set PROJECT}" "${BROKER_URL:?set BROKER_URL (reachable from the VMs; also the broker ID)}"
VARIANT="${1:-approved}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
REPO="${REPO:-encompute}"
IN_BUCKET="${IN_BUCKET:-${PROJECT}-encompute-training-in}"
OUT_BUCKET="${OUT_BUCKET:-${PROJECT}-encompute-training-out}"
WORK="${WORK:-$PWD/cs-training-work}"
RUN="${RUN:-$(cat "$WORK/run-id" 2>/dev/null || date +run-%Y%m%d-%H%M%S)}"
MACHINE="${MACHINE:-c3-standard-4}"
SA_NAME=encompute-training-worker
SA="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PY="${PYTHON:-python3}"
JOB="$ROOT/examples/18_confidential_space_hf/job.py"
T0=$(date +%s)
mkdir -p "$WORK"
echo "$RUN" > "$WORK/run-id"
log() { printf '%-28s%s\n' "$1" "$2"; }

gcloud config set project "$PROJECT" >/dev/null
gcloud services enable compute.googleapis.com confidentialcomputing.googleapis.com \
  artifactregistry.googleapis.com logging.googleapis.com cloudbuild.googleapis.com \
  storage.googleapis.com >/dev/null
gcloud artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 ||
  gcloud artifacts repositories create "$REPO" --repository-format docker --location "$REGION"

# 1. The worker image, built on Cloud Build; its digest is what attests.
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/training-worker"
BUILD_VARIANT="$VARIANT"
case "$VARIANT" in debug|prepare-only) BUILD_VARIANT=approved ;; esac
if ! gcloud artifacts docker images describe "${IMAGE}:${BUILD_VARIANT}" >/dev/null 2>&1 ||
   [ "${REBUILD:-}" = 1 ]; then
  gcloud builds submit "$ROOT" --config "$HERE/cloudbuild.yaml" \
    --substitutions "_IMAGE=${IMAGE}:${BUILD_VARIANT},_VARIANT=${BUILD_VARIANT}"
fi
DIGEST="$(gcloud artifacts docker images describe "${IMAGE}:${BUILD_VARIANT}" \
  --format 'value(image_summary.digest)')"
log "Worker image" "${IMAGE}@${DIGEST}"
T_BUILD=$(date +%s)

# 2. The job, prepared for the APPROVED image only (tampered and debug runs
#    reuse it: that is the point).
if [ "$BUILD_VARIANT" = approved ] && [ "$VARIANT" != debug ] && [ ! -f "$WORK/run/prepared.json" ]; then
  "$PY" "$JOB" prepare "$WORK" --image "$DIGEST" --broker-id "$BROKER_URL" \
    --gcs "gs://${IN_BUCKET}/${RUN}" --gcs-output "gs://${OUT_BUCKET}/${RUN}"
  for b in "$IN_BUCKET" "$OUT_BUCKET"; do
    gcloud storage buckets describe "gs://$b" >/dev/null 2>&1 ||
      gcloud storage buckets create "gs://$b" --location "$REGION" --uniform-bucket-level-access
  done
  # Sealed assets and job descriptors only: never a key, never plaintext.
  "$PY" - "$WORK/uploads.json" <<'PYEOF'
import json, subprocess, sys
for src, dst in json.load(open(sys.argv[1])).items():
    subprocess.run(["gcloud", "storage", "cp", "--quiet", src, dst], check=True)
PYEOF
fi
[ -f "$WORK/run/prepared.json" ] || { echo "run the approved variant first" >&2; exit 2; }
T_STAGE=$(date +%s)

# 3. The worker's identity: attestation, its own image, read the inputs,
#    write the outputs. Nothing else (no key: keys come only from the
#    broker, and only after attestation).
gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 ||
  gcloud iam service-accounts create "$SA_NAME" --display-name "Encompute training worker"
for role in confidentialcomputing.workloadUser logging.logWriter artifactregistry.reader; do
  gcloud projects add-iam-policy-binding "$PROJECT" --condition=None --quiet \
    --member "serviceAccount:${SA}" --role "roles/${role}" >/dev/null
done
gcloud storage buckets add-iam-policy-binding "gs://${IN_BUCKET}" --quiet \
  --member "serviceAccount:${SA}" --role roles/storage.objectViewer >/dev/null
gcloud storage buckets add-iam-policy-binding "gs://${OUT_BUCKET}" --quiet \
  --member "serviceAccount:${SA}" --role roles/storage.objectCreator >/dev/null

cat <<EOM

The broker must be running where the VMs reach ${BROKER_URL}, in production
mode with Google's keys:
  cd $WORK/run/modelco && encompute keys serve --broker broker.json \\
    --kek $WORK/broker.kek --jwks google --listen 0.0.0.0:${BROKER_URL##*:}
EOM
[ "$VARIANT" = prepare-only ] && exit 0

# 4. One production Confidential Space VM per participant (TDX).
FAMILY=confidential-space; [ "$VARIANT" = debug ] && FAMILY=confidential-space-debug
PARTIES="$("$PY" -c "import json;print(' '.join(json.load(open('$WORK/run/prepared.json'))['jobs']))")"
for party in $PARTIES; do
  name="enc-train-${VARIANT}-${party}"
  gcloud compute instances create "$name" --zone "$ZONE" --machine-type "$MACHINE" \
    --confidential-compute-type TDX --maintenance-policy TERMINATE --shielded-secure-boot \
    --image-project confidential-space-images --image-family "$FAMILY" \
    --service-account "$SA" --scopes cloud-platform \
    --metadata "^~^tee-image-reference=${IMAGE}@${DIGEST}~tee-container-log-redirect=true~tee-restart-policy=Never~tee-env-JOB_URL=gs://${IN_BUCKET}/${RUN}/jobs/${party}.json" \
    >/dev/null
  log "Confidential Space VM" "$name ($FAMILY, $MACHINE, TDX)"
done
T_LAUNCH=$(date +%s)

# 5. Wait for each worker's evidence (or its refusal in the serial log).
mkdir -p "$WORK/outputs"
for party in $PARTIES; do
  name="enc-train-${VARIANT}-${party}"
  i=0
  while [ $i -lt 120 ]; do
    if gcloud storage ls "gs://${OUT_BUCKET}/${RUN}/${party}/evidence.json" >/dev/null 2>&1; then
      break
    fi
    if gcloud compute instances get-serial-port-output "$name" --zone "$ZONE" 2>/dev/null |
       grep -q "REFUSED"; then
      break
    fi
    sleep 15; i=$((i + 1))
  done
  gcloud compute instances get-serial-port-output "$name" --zone "$ZONE" 2>/dev/null |
    sed -n '/CONFIDENTIAL TRAINING JOB/,/Evidence\|REFUSED/p' | sed 's/^.*\] //' > "$WORK/$name.log" || true
  cat "$WORK/$name.log"
done
T_DONE=$(date +%s)

# 6. Verify from here: public evidence, Google's JWKS, our own policy.
STATUS=0
if [ "$VARIANT" = approved ]; then
  OUTS=""
  for party in $PARTIES; do
    gcloud storage cp --recursive "gs://${OUT_BUCKET}/${RUN}/${party}" "$WORK/outputs/" >/dev/null
    OUTS="$OUTS $WORK/outputs/$party"
  done
  # shellcheck disable=SC2086
  "$PY" "$JOB" verify "$WORK" --jwks google --outputs $OUTS || STATUS=1
else
  if grep -q "KEY RELEASE DENIED" "$WORK"/enc-train-"${VARIANT}"-*.log; then
    echo "RESULT: KEY RELEASE DENIED (as required for the ${VARIANT} variant)"
  else
    echo "RESULT: the ${VARIANT} workload was not refused (a bug)"; STATUS=1
  fi
fi
T_END=$(date +%s)
cat > "$WORK/deploy-timings-${VARIANT}.json" <<EOM
{"variant": "${VARIANT}", "machine": "${MACHINE}", "zone": "${ZONE}",
 "image_build_s": $((T_BUILD - T0)), "stage_s": $((T_STAGE - T_BUILD)),
 "vm_launch_s": $((T_LAUNCH - T_STAGE)), "until_evidence_s": $((T_DONE - T_LAUNCH)),
 "verify_s": $((T_END - T_DONE))}
EOM
log "Timings" "$WORK/deploy-timings-${VARIANT}.json (per-stage worker timings: outputs/*/timings.json)"
[ "${CLEANUP:-}" = 1 ] && "$HERE/cleanup.sh" "$VARIANT"
exit $STATUS
