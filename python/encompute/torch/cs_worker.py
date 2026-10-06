"""A confidential training job: one participant's training step inside an
attested workload (Google Confidential Space in production).

    python -m encompute.torch.cs_worker JOB

``JOB`` is a job descriptor (a path, ``gs://`` or ``https://`` URL) with
public commitments only: the training spec, the model package ID, the
approved plan, where the sealed model, dataset and adapter are (and, after
round 1, the adapter's signed record), the broker's address, the round's
seed, and where the output goes. It holds no key and no plaintext. The
operator can change it, but only to make the job fail: every commitment
is checked against the training spec, the broker's grants are accepted
only under the grant-signing key the spec names, the training
configuration comes from the spec, and the broker releases keys only to a
workload attesting to the approved training spec.

The worker:

1. checks the descriptor against the training spec it names (IDs, the
   model package, the participant's dataset, the plan, the input adapter),
   and that its own training code is the code the spec binds;
2. creates a session identity in memory, attests (the Confidential Space
   launcher's token, bound to the session, the spec and the broker's
   challenge), and receives the model, dataset, adapter and output keys
   sealed to that session;
3. fetches and opens the sealed model and builds it (checking the
   weights, the package and the adapter layout), then opens the dataset and
   adapter, checking every digest: the dataset, its patient grouping, its
   tokenization, the adapter against the spec or its signed record;
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

Test hooks (``ENCOMPUTE_CANARY_UPDATE``) are honoured only under the mock
attester: never with Confidential Space evidence.
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
from .worker import Worker, check_code, codec_clip, development, split_dataset

JOB_KIND = "encompute.confidential-training-job.v1"
# 2: the plan and the input adapter's record; the configuration comes from
# the training spec.
JOB_VERSION = 2
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


# The LoRA settings a descriptor may repeat: each must equal the spec's.
LORA_FIELDS = ("rank", "alpha", "target_modules", "optimizer", "learning_rate", "update_clip",
               "local_steps", "batch_size", "rounds")


def check_job(job: dict) -> dict:
    """The descriptor must name one approved training spec consistently;
    returns the spec. Anything the operator changed that the broker would
    not catch is caught here: the training configuration comes from the
    spec, the input adapter must be the spec's or the coordinator's record
    of the previous round, the broker's key comes from the spec."""
    if job.get("kind") != JOB_KIND or job.get("version") != JOB_VERSION:
        raise JobRefused(f"not a confidential training job descriptor (version {JOB_VERSION})")
    spec = job["training_spec"]
    try:
        sid = _native.training_spec_id(json.dumps(spec))
    except _native.NativeError as e:
        raise JobRefused(f"TRAINING SPEC REFUSED: {e.args[1]}") from None
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
    rnd = job["round"]
    if not isinstance(rnd, int) or not 1 <= rnd <= spec["config"]["rounds"]:
        raise JobRefused("a round outside the training spec")
    # The training configuration is the spec's: a descriptor may repeat it,
    # never change it.
    given = job.get("lora") or {}
    c = spec["config"]
    for k in LORA_FIELDS:
        if k in given and _same(given[k], c[k]) is False:
            raise JobRefused(f"CONFIGURATION MISMATCH: the descriptor's {k} is not the training "
                             "spec's")
    seed, micro = job.get("seed", 0), job.get("microbatch", 64)
    if not isinstance(seed, int) or not 0 <= seed < 2 ** 63:
        raise JobRefused("the round's seed is a non-negative 63-bit integer")
    if not isinstance(micro, int) or not 1 <= micro <= 4096:
        raise JobRefused("the microbatch is between 1 and 4096 records")
    urls = job.get("broker_urls")
    if urls is not None and not (isinstance(urls, dict) and all(
            isinstance(b, str) and isinstance(u, str) for b, u in urls.items())):
        raise JobRefused("broker_urls maps key broker IDs to their addresses")
    if "#" in job["broker"] or any("#" in u for u in (urls or {}).values()):
        raise JobRefused("the broker's grant-signing key comes from the training spec, not the "
                         "descriptor")
    # The input adapter: the spec's initial one, or the one the coordinator
    # recorded for the previous round of this run.
    a = job["adapter"]
    record = a.get("record")
    try:
        _native.check_input_adapter(json.dumps(spec), job["run_id"], rnd, a["asset_id"],
                                    a["digest"], None if record is None else json.dumps(record))
    except _native.NativeError as e:
        raise JobRefused(e.args[1]) from None
    # This worker's own code must be the code the spec binds.
    try:
        check_code(spec)
    except ValueError as e:
        raise JobRefused(f"TRAINING CODE MISMATCH: {e}") from None
    return spec


def _same(given, bound) -> bool:
    """A descriptor's value equals the spec's (numbers bound as strings)."""
    if isinstance(bound, str) and isinstance(given, (int, float)):
        try:
            return float(bound) == float(given)
        except ValueError:
            return False
    if isinstance(bound, list):
        return list(given) == bound
    return given == bound


def attested_image(record: str) -> str:
    """The image digest this worker's own attestation measures (the token
    the launcher issued it, verified by the broker), never the image the
    descriptor expects (review finding KB-5)."""
    import base64
    ev = json.loads(record)["evidence"]
    if ev["provider"] == "mock":
        return json.loads(ev["evidence"])["claims"]["image_digest"]
    token = ev["evidence"].split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    return claims["submods"]["container"]["image_digest"]


def run(job: dict) -> dict:
    t: Dict[str, float] = {}
    t0 = time.perf_counter()
    spec = check_job(job)
    project, party, rnd = spec["project"], job["participant"], int(job["round"])
    model_id = spec["base_model"]["asset_id"]
    mine = next(d for d in spec["datasets"] if d["owner"] == party)
    attester = os.environ.get("ENCOMPUTE_ATTESTER", "confidential-space")
    clip = None
    if spec["config"].get("dp_sgd"):
        if "plan" not in job:
            raise JobRefused("a DP-SGD job carries its approved plan")
        try:
            clip = codec_clip(spec, json.dumps(job["plan"]))
        except ValueError as e:
            raise JobRefused(f"PLAN MISMATCH: {e}") from None
    _say("Training spec", "enctrain1:" + job["training_spec_id"][:16] + "...")
    if spec["base_model"].get("huggingface"):
        _say("Model package", "enchf1:" + job["model_package_id"][:16] + "...")
    _say("Participant", party)
    _say("Attester", {"confidential-space": "Google Confidential Space launcher",
                      "mock": "MOCK (development only)"}.get(attester, attester))

    # 1. Attest and receive the keys, sealed to this in-memory session. The
    # key IDs are the spec's (one definition, with the per-asset broker
    # binding's), never names this worker makes up.
    seed = os.urandom(32)
    ids = _native.training_participant_keys(json.dumps(spec), party)
    dataset_key_id, output_key_id = ids["dataset"], ids["contribution"]
    arg = (os.environ.get("ENCOMPUTE_TEE_SOCKET", "") if attester == "confidential-space"
           else os.environ.get("ENCOMPUTE_MOCK_SEED", ""))
    t1 = time.perf_counter()
    try:
        # The session attests as this participant: only its own dataset
        # and output keys are released to it. Grants are accepted only
        # under the broker keys the spec names.
        # With several brokers, each key goes to its own broker's address
        # (broker_urls); a bound broker without one fails closed.
        keys, record = _native.acquire_session_keys(
            json.dumps(spec), job["broker"],
            [ids["model"], dataset_key_id, ids["adapters"], output_key_id],
            seed, attester, arg, os.environ.get("ENCOMPUTE_MOCK_IMAGE", ""), party,
            broker_urls=job.get("broker_urls"))
    except _native.NativeError as e:
        raise JobRefused(f"KEY RELEASE DENIED: {e.args[0]}: {e.args[1]}") from None
    keys = dict(keys)
    hooks = development(record)
    image = attested_image(record)
    if job.get("expected_image") not in (None, image):
        raise JobRefused("IMAGE MISMATCH: this worker's attested image is not the one the "
                         "descriptor expects")
    t["attestation_and_key_release_s"] = time.perf_counter() - t1
    _say("Attestation", "VERIFIED BY THE BROKER")
    _say("Model key", "RELEASED TO ATTESTED SESSION")
    _say("Dataset key", "RELEASED TO ATTESTED SESSION")

    # 2. The model first: opened, built and its layout checked before any
    # data is opened.
    t1 = time.perf_counter()
    sealed_model = fetch(job["model"]["ciphertext"])
    try:
        weights = _native.open_asset(keys[f"{model_id}.{party}"], sealed_model, project, model_id,
                                     spec["base_model"]["weights_digest"])
    except _native.NativeError as e:
        raise JobRefused(f"ASSET MISMATCH: {e.args[1]}") from None
    del sealed_model
    try:
        w = Worker.for_model(spec, bytes(weights), int(job.get("seed", 0)), clip, hooks)
    except (ValueError, RuntimeError, _native.NativeError) as e:
        raise JobRefused(f"TRAINING REFUSED: {e}") from None
    del weights
    t["model_loading_s"] = time.perf_counter() - t1

    # 3. Fetch and open the dataset and adapter; every digest is checked.
    t1 = time.perf_counter()
    sealed_data = fetch(job["dataset"]["ciphertext"])
    sealed_adapter = fetch(job["adapter"]["ciphertext"])
    t["asset_download_s"] = time.perf_counter() - t1
    t1 = time.perf_counter()
    try:
        blob = _native.open_asset(keys[dataset_key_id], sealed_data, project, mine["asset_id"],
                                  mine["digest"])
        a0 = _native.open_asset(keys[f"adapters.{party}"], sealed_adapter, project,
                                job["adapter"]["asset_id"], job["adapter"]["digest"])
    except _native.NativeError as e:
        raise JobRefused(f"ASSET MISMATCH: {e.args[1]}") from None
    del sealed_data
    t["decryption_s"] = time.perf_counter() - t1
    data, unit_ids, salt = split_dataset(tensors.loads(bytes(blob)))
    del blob
    try:
        w.load(data, unit_ids, salt, mine["asset_id"], int(job.get("microbatch", 64)))
    except (ValueError, RuntimeError, _native.NativeError) as e:
        raise JobRefused("TRAINING REFUSED: the dataset does not match its commitments"
                         if spec["config"].get("dp_sgd") else f"TRAINING REFUSED: {e}") from None
    if w.dp is not None:
        _say("Privacy unit", w.dp.unit)
        _say("Per-patient clipping", "ACTIVE (" + {"vmap": "vectorized per-example gradients",
                                                   "reference": "one patient at a time"}
             [w.grad_path] + ")")

    # 4. One training step: the contribution, in the codec's range.
    t1 = time.perf_counter()
    adapter = tensors.loads(bytes(a0))["adapter"]
    try:
        v, _, _ = w.contribution([float(x) for x in adapter], int(job.get("seed", 0)))
    except Exception as e:
        if w.dp is not None:
            # A fixed error: a data-dependent one would leak outside the
            # privacy accounting (review finding DP-5).
            raise JobRefused("TRAINING FAILED: the DP-SGD step failed") from None
        raise JobRefused(f"TRAINING FAILED: {e}") from None
    w.canary(v)  # leakage tests only (development attestation)
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
        "version": 2, "project": project, "training_spec_id": job["training_spec_id"],
        "run_id": job["run_id"], "plan_id": spec["plan_id"], "policy_id": spec["policy_id"],
        "privacy_policy_id": spec["privacy_policy_id"], "participant": party, "round": rnd,
        "model_asset": model_id, "model_package_id": job.get("model_package_id"),
        "weights_digest": spec["base_model"]["weights_digest"],
        "dataset_asset": mine["asset_id"], "dataset_digest": mine["digest"],
        "layout_digest": spec["layout_digest"],
        "input_adapter": job["adapter"]["asset_id"],
        "input_adapter_digest": job["adapter"]["digest"],
        "config_digest": _native.training_config_digest(json.dumps(spec)),
        "seed": int(job.get("seed", 0)),
        "image_digest": image,
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
