"""A confidential training job: one participant's training step inside an
attested workload (Google Confidential Space in production).

    python -m encompute.torch.cs_worker JOB

``JOB`` is a job descriptor (a path, ``gs://`` or ``https://`` URL) with
public commitments only: the training spec, the model package ID, where
the sealed model, dataset and adapter are, the broker, and where the
output goes. It holds no key and no plaintext. The operator can change it,
but only to make the job fail: every commitment is checked, and the broker
releases keys only to a workload attesting to the approved training spec.

The worker:

1. checks the descriptor against the training spec it names (IDs, the
   model package, the participant's dataset);
2. creates a session identity in memory, attests (the Confidential Space
   launcher's token, bound to the session, the spec and the broker's
   challenge), and receives the model, dataset, adapter and output keys
   sealed to that session;
3. fetches and opens the sealed assets, checking every digest: the model
   weights, the package, the dataset, its patient grouping, its
   tokenization;
4. runs the bound training step, the same code as local runs (with
   DP-SGD: per-patient gradients, grouping, clipping, Poisson sampling);
5. seals its contribution (release ``aggregate_only``: only an attested
   workload can open it), and writes signed evidence and its attestation
   record.

Nothing in plaintext is written to disk; keys and plaintext live only in
this process's memory. The worker contacts only the broker, the storage
holding the sealed assets and the output location, and (in Confidential
Space) the local launcher and metadata server.

Environment:
- ``ENCOMPUTE_ATTESTER``: ``confidential-space`` (default) or ``mock``
  (development only).
- ``ENCOMPUTE_TEE_SOCKET``: the launcher socket (default: Confidential
  Space's). A simulated launcher is for development only.
- ``ENCOMPUTE_MOCK_SEED``, ``ENCOMPUTE_MOCK_IMAGE``: the mock attester's.
- ``JOB_URL``: the job descriptor, if no argument is given.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from typing import Dict

import torch

from .. import _native
from . import tensors
from .worker import Worker

JOB_KIND = "encompute.confidential-training-job.v1"
METADATA = "http://metadata.google.internal/computeMetadata/v1"


class JobRefused(RuntimeError):
    """The job does not match what was approved: nothing was trained."""


def _say(k: str, v: str) -> None:
    print(f"{k:<24}{v}", flush=True)


# --- storage: local paths, gs:// (metadata-server credentials), https:// -----


def _gcs_token() -> str:
    req = urllib.request.Request(f"{METADATA}/instance/service-accounts/default/token",
                                 headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["access_token"]


def fetch(location: str) -> bytes:
    if location.startswith("gs://"):
        bucket, _, name = location[5:].partition("/")
        url = (f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/"
               f"{urllib.parse.quote(name, safe='')}?alt=media")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {_gcs_token()}"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read()
    if location.startswith("https://") or location.startswith("http://"):
        with urllib.request.urlopen(location, timeout=120) as r:
            return r.read()
    with open(location.removeprefix("file://"), "rb") as f:
        return f.read()


def put(location: str, data: bytes) -> None:
    if location.startswith("gs://"):
        bucket, _, name = location[5:].partition("/")
        url = (f"https://storage.googleapis.com/upload/storage/v1/b/{bucket}/o"
               f"?uploadType=media&name={urllib.parse.quote(name, safe='')}")
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Authorization": f"Bearer {_gcs_token()}",
            "Content-Type": "application/octet-stream"})
        urllib.request.urlopen(req, timeout=120).read()
        return
    path = location.removeprefix("file://")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def join(prefix: str, name: str) -> str:
    return prefix.rstrip("/") + "/" + name


# --- the job ---------------------------------------------------------------------


def check_job(job: dict) -> dict:
    """The descriptor must name one approved training spec consistently;
    returns the spec. Anything the operator changed that the broker would
    not catch is caught here."""
    if job.get("kind") != JOB_KIND or job.get("version") != 1:
        raise JobRefused("not a confidential training job descriptor (version 1)")
    spec = job["training_spec"]
    sid = _native.training_spec_id(json.dumps(spec))
    if sid != job["training_spec_id"]:
        raise JobRefused("TRAINING SPEC MISMATCH: the descriptor's spec is not "
                         f"{job['training_spec_id'][:16]}")
    for k in ("plan_id", "policy_id", "privacy_policy_id"):
        if job.get(k) != spec.get(k):
            raise JobRefused(f"the descriptor's {k} is not the training spec's")
    base = spec["base_model"]
    if job["model"]["asset_id"] != base["asset_id"]:
        raise JobRefused("MODEL ASSET MISMATCH: the descriptor names another model")
    pkg = base.get("huggingface")
    if pkg is not None:
        if job.get("model_package_id") != _native.hf_package_id(json.dumps(pkg)):
            raise JobRefused("MODEL PACKAGE MISMATCH: the descriptor names another package")
    mine = [d for d in spec["datasets"] if d["owner"] == job["participant"]]
    if not mine or job["dataset"]["asset_id"] != mine[0]["asset_id"]:
        raise JobRefused("DATASET ASSET MISMATCH: not this participant's approved dataset")
    if not 1 <= int(job["round"]) <= spec["config"]["rounds"]:
        raise JobRefused("a round outside the training spec")
    return spec


def run(job: dict) -> dict:
    t: Dict[str, float] = {}
    t0 = time.perf_counter()
    spec = check_job(job)
    project, party, rnd = spec["project"], job["participant"], int(job["round"])
    model_id = spec["base_model"]["asset_id"]
    mine = next(d for d in spec["datasets"] if d["owner"] == party)
    attester = os.environ.get("ENCOMPUTE_ATTESTER", "confidential-space")
    _say("Training spec", "enctrain1:" + job["training_spec_id"][:16] + "...")
    if spec["base_model"].get("huggingface"):
        _say("Model package", "enchf1:" + job["model_package_id"][:16] + "...")
    _say("Participant", party)
    _say("Attester", {"confidential-space": "Google Confidential Space launcher",
                      "mock": "MOCK (development only)"}.get(attester, attester))

    # 1. Attest and receive the keys, sealed to this in-memory session.
    seed = os.urandom(32)
    dataset_key_id = f"dataset-{mine['asset_id']}"
    output_key_id = f"contribution-{party}"
    arg = (os.environ.get("ENCOMPUTE_TEE_SOCKET", "") if attester == "confidential-space"
           else os.environ.get("ENCOMPUTE_MOCK_SEED", ""))
    t1 = time.perf_counter()
    try:
        # The session attests as this participant: only its own dataset
        # and output keys are released to it.
        keys, record = _native.acquire_session_keys(
            json.dumps(spec), job["broker"],
            [f"{model_id}.{party}", dataset_key_id, f"adapters.{party}", output_key_id],
            seed, attester, arg, os.environ.get("ENCOMPUTE_MOCK_IMAGE", ""), party)
    except _native.NativeError as e:
        raise JobRefused(f"KEY RELEASE DENIED: {e.args[0]}: {e.args[1]}") from None
    keys = dict(keys)
    t["attestation_and_key_release_s"] = time.perf_counter() - t1
    _say("Attestation", "VERIFIED BY THE BROKER")
    _say("Model key", "RELEASED TO ATTESTED SESSION")
    _say("Dataset key", "RELEASED TO ATTESTED SESSION")

    # 2. Fetch and open the sealed assets; every digest is checked.
    t1 = time.perf_counter()
    sealed_model = fetch(job["model"]["ciphertext"])
    sealed_data = fetch(job["dataset"]["ciphertext"])
    sealed_adapter = fetch(job["adapter"]["ciphertext"])
    t["asset_download_s"] = time.perf_counter() - t1
    t1 = time.perf_counter()
    try:
        weights = _native.open_asset(keys[f"{model_id}.{party}"], sealed_model, project, model_id,
                                     spec["base_model"]["weights_digest"])
        blob = _native.open_asset(keys[dataset_key_id], sealed_data, project, mine["asset_id"],
                                  mine["digest"])
        a0 = _native.open_asset(keys[f"adapters.{party}"], sealed_adapter, project,
                                job["adapter"]["asset_id"], job["adapter"]["digest"])
    except _native.NativeError as e:
        raise JobRefused(f"ASSET MISMATCH: {e.args[1]}") from None
    del sealed_model, sealed_data
    t["decryption_s"] = time.perf_counter() - t1
    data = tensors.loads(bytes(blob))
    del blob
    unit_ids = data.pop("unit_ids", None)

    # 3. The bound model and adapter, the approved layout, the dataset's
    # grouping: the same checks as every worker.
    t1 = time.perf_counter()
    try:
        w = Worker.from_assets(spec, bytes(weights), data, unit_ids, mine["asset_id"],
                               job["lora"], int(job.get("microbatch", 64)))
    except (ValueError, RuntimeError, _native.NativeError) as e:
        raise JobRefused(f"TRAINING REFUSED: {e}") from None
    del weights
    t["model_loading_s"] = time.perf_counter() - t1
    if w.dp is not None:
        _say("Privacy unit", w.dp.unit)
        _say("Per-patient clipping", "ACTIVE (" + {"vmap": "vectorized per-example gradients",
                                                   "reference": "one patient at a time"}
             [w.grad_path] + ")")

    # 4. One training step: the contribution, in the codec's range.
    t1 = time.perf_counter()
    adapter = tensors.loads(bytes(a0))["adapter"]
    v, _, _ = w.contribution([float(x) for x in adapter], int(job.get("seed", 0)))
    canary = os.environ.get("ENCOMPUTE_CANARY_UPDATE")  # leakage tests only
    if canary:
        v[:4] = float(canary)
    t["training_step_s"] = time.perf_counter() - t1
    _say("Training", "COMPLETE")

    # 5. Seal the output (aggregate_only) and sign the evidence.
    t1 = time.perf_counter()
    salt = torch.tensor(list(os.urandom(16)), dtype=torch.int64)
    payload = tensors.dumps({"contribution": v.detach(), "salt": salt})
    out_asset = f"contribution-{party}-r{rnd}"
    sealed = bytes(_native.seal_asset(keys[output_key_id], "contribution", project, out_asset,
                                      payload))
    del keys, v, payload
    t["output_sealing_s"] = time.perf_counter() - t1
    ev = {
        "version": 1, "project": project, "training_spec_id": job["training_spec_id"],
        "run_id": job["run_id"], "plan_id": spec["plan_id"], "policy_id": spec["policy_id"],
        "privacy_policy_id": spec["privacy_policy_id"], "participant": party, "round": rnd,
        "model_asset": model_id, "model_package_id": job.get("model_package_id"),
        "weights_digest": spec["base_model"]["weights_digest"],
        "dataset_asset": mine["asset_id"], "dataset_digest": mine["digest"],
        "layout_digest": spec["layout_digest"], "image_digest": job["expected_image"],
        "attestation_record_id": "", "session_id": "",
        "output_asset": out_asset,
        "output_commitment": hashlib.sha256(sealed).hexdigest(),
        "step_commitment": _step_commitment(sealed, salt),
        "gradient_path": w.grad_path or "none", "libraries": _libraries(spec),
    }
    record_id, session_id = _record_ids(record)
    ev["attestation_record_id"], ev["session_id"] = record_id, session_id
    signed = _native.sign_worker_evidence(json.dumps(ev), seed)
    del seed
    out = job["output"]
    put(join(out, f"{out_asset}.sealed"), sealed)
    put(join(out, "attestation.json"), record.encode())
    put(join(out, "evidence.json"), signed.encode())
    t["total_s"] = time.perf_counter() - t0
    put(join(out, "timings.json"), json.dumps(t, indent=1).encode())
    _say("Output", f"SEALED ({out_asset}, {len(sealed)} bytes)")
    _say("Evidence", "SIGNED BY THE ATTESTED SESSION")
    return {"evidence": json.loads(signed), "timings": t}


def _step_commitment(sealed: bytes, salt: torch.Tensor) -> str:
    # A commitment the worker (or an attested aggregator, who can open the
    # output and read the salt) can check, and nobody else can guess.
    return hashlib.sha256(b"encompute.training-step.v1\0" + bytes(salt.tolist()) +
                          hashlib.sha256(sealed).digest()).hexdigest()


def _record_ids(record: str):
    """The attestation record's ID and session ID, as Rust computes them
    (the evidence verification recomputes and compares both)."""
    return _native.attestation_record_ids(record)


def _libraries(spec: dict) -> Dict[str, str]:
    if spec["base_model"].get("huggingface"):
        from . import hf
        return hf.exact_versions()
    return {"torch": torch.__version__}


def main() -> None:
    location = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("JOB_URL")
    if not location:
        print("usage: python -m encompute.torch.cs_worker JOB (or set JOB_URL)", file=sys.stderr)
        sys.exit(2)
    print("CONFIDENTIAL TRAINING JOB", flush=True)
    try:
        job = json.loads(fetch(location))
    except (OSError, ValueError) as e:
        print(f"UNREADABLE JOB          {type(e).__name__}: {e}", flush=True)
        sys.exit(2)
    try:
        run(job)
    except JobRefused as e:
        print(f"REFUSED                 {e}", flush=True)
        sys.exit(3)


if __name__ == "__main__":
    main()
