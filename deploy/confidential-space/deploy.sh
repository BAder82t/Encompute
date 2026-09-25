#!/bin/sh
# Runs the attested key-release demo on Google Cloud Confidential Space.
#
#   PROJECT=my-project BROKER_URL=https://broker.example:8760 \
#     deploy/confidential-space/deploy.sh [approved|tampered]
#
# Needs gcloud (logged in), docker (to read the policy out of the image) and
# a built `encompute` on PATH. The broker must be reachable from the VM at
# BROKER_URL; see README.md. TEE=tdx (default, c3-standard-4) or TEE=sev
# (n2d-standard-2; cheaper, but SEV has no memory integrity protection).
set -eu
: "${PROJECT:?}" "${BROKER_URL:?}"
VARIANT="${1:-approved}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
REPO="${REPO:-encompute}"
TEE="${TEE:-tdx}"
case "$TEE" in
  tdx) MACHINE=c3-standard-4 CC=TDX MAINT=TERMINATE POLICY_TEE=intel_tdx ;;
  sev) MACHINE=n2d-standard-2 CC=SEV MAINT=MIGRATE POLICY_TEE=amd_sev ;;
  *) echo "TEE must be tdx or sev" >&2; exit 2 ;;
esac
SA="encompute-workload@${PROJECT}.iam.gserviceaccount.com"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/workload:${VARIANT}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

gcloud config set project "$PROJECT" >/dev/null
gcloud services enable compute.googleapis.com confidentialcomputing.googleapis.com \
  artifactregistry.googleapis.com logging.googleapis.com cloudbuild.googleapis.com
gcloud artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 ||
  gcloud artifacts repositories create "$REPO" --repository-format docker --location "$REGION"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet

gcloud builds submit "$ROOT" --config "$HERE/cloudbuild.yaml" \
  --substitutions "_IMAGE=${IMAGE},_VARIANT=${VARIANT}"
DIGEST="$(gcloud artifacts docker images describe "$IMAGE" --format 'value(image_summary.digest)')"
echo "image digest: $DIGEST"

if [ "$VARIANT" = approved ]; then
  # The owner's policy, computed from the artifact inside the image: this
  # execution spec, policy, artifact, and exactly this image digest, on a
  # production (non-debug) Confidential Space VM with a supported TCB.
  docker run --rm --platform linux/amd64 --entrypoint encompute "$IMAGE" \
    attest policy /app/model.encompute --backend mock --image "$DIGEST" \
    --tee "$POLICY_TEE" > attestation-policy.json
  if [ ! -f broker.json ]; then
    head -c 32 /dev/urandom > test.key
    encompute keys protect --asset test-key --policy attestation-policy.json \
      --key-file test.key --broker-id "$BROKER_URL" --broker broker.json
    rm test.key
  fi
  echo "Now run the broker where the VM can reach $BROKER_URL:"
  echo "  encompute keys serve --broker broker.json --jwks google --listen 0.0.0.0:8760"
fi

gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 ||
  gcloud iam service-accounts create encompute-workload
for role in confidentialcomputing.workloadUser artifactregistry.reader logging.logWriter; do
  gcloud projects add-iam-policy-binding "$PROJECT" --condition=None --quiet \
    --member "serviceAccount:${SA}" --role "roles/${role}" >/dev/null
done

gcloud compute instances create "encompute-${VARIANT}" --zone "$ZONE" \
  --machine-type "$MACHINE" --confidential-compute-type "$CC" \
  --maintenance-policy "$MAINT" --shielded-secure-boot \
  --image-project confidential-space-images --image-family confidential-space \
  --service-account "$SA" --scopes cloud-platform \
  --metadata "^~^tee-image-reference=${IMAGE}@${DIGEST}~tee-container-log-redirect=true~tee-restart-policy=OnFailure~tee-env-BROKER_URLS=test-key@${BROKER_URL}"

echo "Follow the workload:"
echo "  gcloud compute instances get-serial-port-output encompute-${VARIANT} --zone $ZONE | grep -A6 'encompute workload'"
echo "Clean up:"
echo "  gcloud compute instances delete encompute-${VARIANT} --zone $ZONE"
