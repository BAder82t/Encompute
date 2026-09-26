# Confidential training on Google Confidential Space

This runs one Hugging Face + PEFT training step per participant inside
production Confidential Space VMs (Intel TDX). Hardware attestation gates
the release of the model, dataset, adapter and output keys.

```text
MODEL OWNER (your machine)                   GOOGLE CLOUD
──────────────────────────                   ────────────
job.py prepare ─ sealed model ─────────────► gs://…-in/RUN/sealed/   (ciphertext only)
               ─ sealed datasets ──────────►
               ─ job descriptors ──────────► gs://…-in/RUN/jobs/     (commitments only)
encompute keys serve  ◄── challenge ──────── Confidential Space VM (TDX, production image)
  production broker,     token ───────────►   encompute training worker
  wrapped keys,        ── sealed keys ─────►    decrypts in memory, checks every digest
  --jwks google                                 Transformers + PEFT, per-patient DP-SGD
                                                seals its contribution ──► gs://…-out/RUN/
job.py verify  ◄── attestation record, signed evidence, sealed output ──┘
```

## What a live run establishes

- An approved, measured workload (this image digest) ran on approved
  confidential-computing hardware (Intel TDX, Confidential Space production
  image, debugging disabled since boot, a supported TCB).
- It received the model and dataset keys only after its attestation
  verified. The keys were sealed to its session, which lives in memory.
- It ran the training code the training spec binds, and its output left
  only sealed, under a key only attested workloads receive.

It does not prove:
- that Intel TDX, Google's infrastructure or the libraries have no
  vulnerabilities;
- that PyTorch or Transformers are correct;
- that the trained model resists inference attacks beyond what its
  differential privacy bounds.

## Prerequisites

- A GCP project with billing enabled, and `gcloud`, logged in as an
  operator.
- Python with `encompute[huggingface]`, and `encompute` built
  (`cargo build --bins`) and on your `PATH`.
- A broker address the VMs can reach (`BROKER_URL`), for example a small VM
  in the same VPC, or a self-hosted runner. It is also the broker's ID and
  the audience of the workload's token.

No secret is passed to any script, VM, metadata or bucket:
- The keys are generated on your machine and wrapped in the broker's
  state under a key-encryption key (`broker.kek`) that stays with you.
- The cloud receives only ciphertext and public commitments.

## Run

```sh
export PROJECT=my-project BROKER_URL=http://10.128.0.5:8760
deploy/confidential-space-training/deploy.sh prepare-only
# start the broker it prints, where BROKER_URL points:
#   cd cs-training-work/run/modelco && encompute keys serve --broker broker.json \
#     --kek ../../broker.kek --jwks google --listen 0.0.0.0:8760
deploy/confidential-space-training/deploy.sh approved
deploy/confidential-space-training/deploy.sh tampered   # must be refused
deploy/confidential-space-training/deploy.sh debug      # must be refused
deploy/confidential-space-training/cleanup.sh
```

`approved`:
1. builds the image on Cloud Build and resolves its digest;
2. prepares the job for that digest (the attestation policy fixes it);
3. stages the sealed assets;
4. starts one `c3-standard-4` TDX VM per participant;
5. waits for their evidence, downloads it, and verifies it here:
   `job.py verify --jwks google`.

`tampered` rebuilds the image with one changed file (another digest) and
runs it against the approved job. The attestation is valid, but the image is
not approved: KEY RELEASE DENIED.

`debug` runs the approved image on a `confidential-space-debug` VM: KEY
RELEASE DENIED.

The serial console shows the worker's lines. They carry no key and no
data.

## Identities and permissions

| Identity | May |
|---|---|
| operator (you, or a deploy service account) | build the image, create buckets, VMs and the worker service account |
| `encompute-training-worker` (the VMs) | `confidentialcomputing.workloadUser`, `logging.logWriter`, `artifactregistry.reader`; read the input bucket; create objects in the output bucket |
| the broker | nothing in GCP: it verifies tokens against Google's published keys |

Cloud IAM never grants a plaintext key. Keys come only from the broker,
only to an attested session. Each session attests as one participant, and
each participant's dataset and output keys are released only under its own
policy.

This deployment has a single operator: ModelCo's broker holds every
participant's keys. For a multi-party deployment, each hospital runs its
own broker and protects its own dataset key there.

## Network

The worker contacts only:
- the Confidential Space launcher (local socket) and the metadata server
  (for its storage token);
- the broker (`BROKER_URL`);
- `storage.googleapis.com` (the input and output buckets).

It downloads nothing else: no Hugging Face Hub, no PyPI, no GitHub. The
image sets `HF_HUB_OFFLINE=1`, and the model is a sealed package. The
launch policy lets the operator set only `JOB_URL`. The production image
holds only the worker and its libraries: no CLI, no broker, no launcher
simulator.

## Cost

A `c3-standard-4` TDX VM costs about $0.25 an hour in `us-central1`. One
run (two VMs for about 10 minutes, a Cloud Build, a few MB of storage)
costs well under a dollar. Delete the VMs with `cleanup.sh`, which keeps
the broker state and its key-encryption key.

## Local rehearsal

`examples/18_confidential_space_hf/run.sh --local` runs the same job on this
machine:
- the broker is the production broker;
- the tokens come from a simulated launcher, signed with a test key that
  only this broker trusts.

`job.py container` runs the built image the same way. CI runs both on every
pull request.
