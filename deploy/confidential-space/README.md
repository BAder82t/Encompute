# Attested key release on Google Confidential Space

This demo runs an Encompute workload in a Confidential Space VM. The workload
attests to a key broker and receives a protected test key sealed to its
session. A modified image receives nothing (ADR-011).

```text
owner machine                          Google Cloud
─────────────                          ────────────
encompute keys serve  ◄── challenge ── Confidential Space VM (TDX)
  broker.json            evidence ──►    encompute workload keys
  test-key (v1)       ── sealed key ──►  encompute-evaluator (attested receipts)
```

## Prerequisites

- A GCP project with billing enabled.
- `gcloud`, logged in.
- `docker`, used only to read the attestation policy out of the built image.
- `encompute`, built from this repository and on your `PATH`.
- A broker address the VM can reach: `BROKER_URL`. Either:
  - run the broker on a small VM in the same project (open port 8760 to the
    Confidential Space VM only); or
  - expose a local broker through a tunnel.

  `BROKER_URL` is also the broker's ID and the audience the workload's token
  must name.

## Run

```sh
export PROJECT=my-project BROKER_URL=http://10.128.0.5:8760
deploy/confidential-space/deploy.sh approved
```

The script does four things:

1. It builds the image on Cloud Build and pushes it.
2. It reads the attestation policy out of the image with `encompute attest
   policy`. The policy fixes:
   - the execution spec, policy ID and artifact digest;
   - the image digest;
   - Intel TDX;
   - debugging forbidden;
   - a supported TCB.
3. It protects a random `test-key` in `broker.json`.
4. It starts the VM from the production (non-debug) `confidential-space`
   image.

Once the script finishes, start the broker where `BROKER_URL` points:

```sh
encompute keys serve --broker broker.json --jwks google --listen 0.0.0.0:8760
```

The workload retries until the broker answers (`tee-restart-policy=OnFailure`).
It prints the following to the serial console:

```text
encompute workload: variant approved
Session       …
Execution     encspec1:…
Key           test-key v1 from http://…: RECEIVED (32 bytes, sealed to this session)
Record        /tmp/attestation.json (attestation …)
```

Then it serves on port 8750. Its receipts bind the attestation, and
`GET /v1/attestation` returns the record. To verify a receipt, use the policy
file the script wrote:

```sh
encompute verify result.receipt.json … --attestation attestation.json \
  --attestation-policy attestation-policy.json --jwks google --audience "$BROKER_URL"
```

## The modified workload gets no key

```sh
deploy/confidential-space/deploy.sh tampered
```

This builds the same code with a different `VARIANT`, so the image digest is
different. The broker refuses it with `ENC2002 workload image … is not
allowed`, and the workload stops without a key. Other variations are refused
the same way:

- a `confidential-space-debug` image (`dbgstat` enabled);
- another execution spec;
- a replayed token.

## Cost and cleanup

A `c3-standard-4` TDX VM costs a few dollars a day. With `TEE=sev` the script
uses an `n2d-standard-2` SEV VM instead. It is cheaper, but SEV has no memory
integrity protection. Delete the VMs when you are done:

```sh
gcloud compute instances delete encompute-approved encompute-tampered --zone us-central1-a
```

## Limits

- Evaluation in this demo uses the mock backend. The point here is key
  release.
- The workload tool opens the key, then exits. Decrypting asset-encrypted
  inputs inside the evaluator with the key is the next step.
- The broker keeps keys in a local file (mode 0600). In production it would
  front a KMS.
