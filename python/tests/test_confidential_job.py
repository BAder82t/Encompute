"""Confidential training jobs, rehearsed locally in production mode.

The broker is a production broker (keys wrapped under a KEK, no mock
evidence), verifying Confidential Space tokens. They come from a simulated
launcher signed with a test key, whose JWKS is the only one the broker
trusts. Everything but the hardware and Google's signature is real: the
attester, the claims (image, debug, TDX, nonce, audience), the policy,
session-bound key release, decryption, the Hugging Face + PEFT DP-SGD step,
output sealing, evidence and the trust report.
"""

import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("transformers")
pytest.importorskip("peft")

import encompute  # noqa: E402
import encompute.torch as et  # noqa: E402
from encompute.torch import finetune as ft, hf, job  # noqa: E402

try:
    CLI = ft._cli()
except encompute.EncomputeError:
    pytest.skip("the encompute CLI is not built", allow_module_level=True)

APPROVED = "sha256:" + "7" * 64
TAMPERED = "sha256:" + "8" * 64
WEIGHT_CANARY = 1234.5678
TOKEN_CANARY = [21, 22, 23, 24, 25, 26, 27, 21]
UPDATE_CANARY = 0.42424242


@pytest.fixture(scope="module")
def prep(tmp_path_factory):
    W = tmp_path_factory.mktemp("cs")
    repo = hf.write_tiny_model(str(W / "repository"), "bert", pretrain_steps=20)
    base = et.huggingface(str(repo))
    with torch.no_grad():
        base.classifier.weight[0, 0] = WEIGHT_CANARY
    tok = base.encompute_tokenizer
    p = encompute.Project("cs-training", parties=["hospital-a", "hospital-b", "modelco"],
                          purpose="disease-training")
    m = p.model("clinical-model", owner="modelco", module=base)
    data = []
    for i, owner in enumerate(("hospital-a", "hospital-b")):
        texts, labels = hf.synthetic_notes(i + 1, 200, hf.WORDS[13:])
        d = et.private_text_dataset(texts, labels, tokenizer=tok, max_length=8,
                                    unit_ids=[j // 2 for j in range(200)], public_units=100)
        d.tensors["input_ids"][5] = torch.tensor(TOKEN_CANARY)
        data.append(p.data(f"notes-{'ab'[i]}", owner=owner, dataset=d))
    port = job._port()
    return job.prepare(p, model=m, data=data, privacy="strong-patient",
                       config=et.LoRAConfig(rounds=2, batch_size=10), image=APPROVED,
                       broker_id=f"http://127.0.0.1:{port}", kek=str(W / "broker.kek"),
                       workdir=str(W / "run"), say=lambda *a: None)


@pytest.fixture(scope="module")
def local(prep):
    with job.Local(prep) as L:
        yield L


def job_file(prep, party="hospital-a", edit=None, name="edited"):
    j = json.loads(Path(prep["jobs"][party]["job"]).read_text())
    if edit:
        edit(j)
        path = Path(prep["workdir"]) / "jobs" / f"{name}.json"
        path.write_text(json.dumps(j))
        return str(path), j
    return prep["jobs"][party]["job"], j


def refused(r, *needles):
    out = r.stdout + r.stderr
    assert r.returncode == 3, out
    for n in needles:
        assert n in out, out
    return out


@pytest.fixture(scope="module")
def approved(prep, local):
    outs = []
    logs = ""
    for party, j in prep["jobs"].items():
        r = local.run_worker(j["job"], env={"ENCOMPUTE_CANARY_UPDATE": repr(UPDATE_CANARY)})
        assert r.returncode == 0, r.stdout + r.stderr
        outs.append(j["output"])
        logs += r.stdout + r.stderr
    return outs, logs


# --- the approved workload ---------------------------------------------------------


def test_the_approved_workload_trains_and_its_evidence_verifies(prep, approved):
    outs, logs = approved
    for line in ("Attestation             VERIFIED BY THE BROKER",
                 "Model key               RELEASED TO ATTESTED SESSION",
                 "Dataset key             RELEASED TO ATTESTED SESSION",
                 "Per-patient clipping    ACTIVE", "Training                COMPLETE",
                 "Output                  SEALED"):
        assert line in logs, logs
    for out in outs:
        ev = json.loads((Path(out) / "evidence.json").read_text())
        e = ev["evidence"]
        assert e["image_digest"] == APPROVED and e["gradient_path"] == "vmap"
        sealed = next(Path(out).glob("*.sealed")).read_bytes()
        import hashlib
        assert hashlib.sha256(sealed).hexdigest() == e["output_commitment"]
    report = job.verify(prep, outs, str(job.TEST_KEYS / "jwks.json"),
                        bundle=str(Path(prep["workdir"]) / "verify.json"))
    assert "Workload                ATTESTED" in report, report
    assert "Training                VERIFIED" in report, report


def test_the_evidence_binds_what_the_worker_trained_from_and_with(prep, approved):
    """Review findings TR-2 and KB-5 (ENC-SF-2026-050, ENC-SF-2026-062): the evidence commits to the input
    adapter, the training configuration and the seed, and its image is
    the one the worker's own attestation measures."""
    outs, _ = approved
    st = prep["state"]
    spec = json.loads(st["spec"])
    for out in outs:
        e = json.loads((Path(out) / "evidence.json").read_text())["evidence"]
        assert e["version"] == 2
        assert e["input_adapter"] == "adapter-0"
        assert e["input_adapter_digest"] == spec["initial_adapter_digest"]
        assert e["config_digest"] == encompute._native.training_config_digest(st["spec"])
        record = json.loads((Path(out) / "attestation.json").read_text())
        from encompute.torch import cs_worker
        assert e["image_digest"] == cs_worker.attested_image(json.dumps(record)) == APPROVED


def test_test_hooks_are_off_with_hardware_attestation(prep, local, approved):
    """Review finding SC-5 (ENC-SF-2026-082): the leakage tests' canary (it overwrites the
    contribution after clipping) is not honoured with Confidential Space
    evidence, whatever the environment says (the approved jobs ran with
    ENCOMPUTE_CANARY_UPDATE set)."""
    import os
    from encompute.torch import tensors
    outs, _ = approved
    st = prep["state"]
    keys, _ = encompute._native.acquire_session_keys(
        st["spec"], prep["broker_id"], ["contribution-hospital-a"], os.urandom(32),
        "confidential-space", str(local.socket), "", "hospital-a")
    sealed = next(Path(outs[0]).glob("*.sealed")).read_bytes()
    n = int.from_bytes(sealed[8:12], "little")
    digest = json.loads(sealed[12:12 + n])["digest"]
    plain = encompute._native.open_asset(dict(keys)["contribution-hospital-a"], sealed,
                                         st["project"], "contribution-hospital-a-r1", digest)
    v = tensors.loads(bytes(plain))["contribution"]
    assert not torch.isclose(v[:4], torch.full((4,), UPDATE_CANARY)).any()


def test_the_output_is_sealed_to_attested_workloads(prep, approved):
    outs, _ = approved
    st = prep["state"]
    sealed = next(Path(outs[0]).glob("*.sealed")).read_bytes()
    with pytest.raises(encompute._native.NativeError):
        encompute._native.open_asset(b"\0" * 32, sealed, st["project"],
                                     "contribution-hospital-a-r1", "0" * 64)


# --- the workload must be the approved one ---------------------------------------------


def test_a_genuine_tee_with_another_image_gets_no_keys(prep, local):
    try:
        local.start_launcher(TAMPERED)
        r = local.run_worker(prep["jobs"]["hospital-a"]["job"])
    finally:
        local.start_launcher(APPROVED)
    refused(r, "KEY RELEASE DENIED", "is not allowed")


def test_a_debug_workload_gets_no_keys(prep, local):
    try:
        local.start_launcher(APPROVED, debug=True)
        r = local.run_worker(prep["jobs"]["hospital-a"]["job"])
    finally:
        local.start_launcher(APPROVED)
    refused(r, "KEY RELEASE DENIED", "debug")


def test_mock_evidence_gets_no_production_keys(prep, local, tmp_path):
    seed = tmp_path / "hw.seed"
    subprocess.run([CLI, "attest", "mock-root", str(seed)], check=True, capture_output=True)
    r = local.run_worker(prep["jobs"]["hospital-a"]["job"],
                         env={"ENCOMPUTE_ATTESTER": "mock", "ENCOMPUTE_MOCK_SEED": str(seed),
                              "ENCOMPUTE_MOCK_IMAGE": APPROVED})
    refused(r, "KEY RELEASE DENIED")


def test_a_session_acts_for_one_participant_only(prep, local):
    """A session attests as one participant: another participant's dataset
    and output keys are never released to it, even running the approved
    image for the approved spec."""
    import os
    st = prep["state"]
    for asset in ("dataset-notes-b", "contribution-hospital-b"):
        with pytest.raises(encompute._native.NativeError) as e:
            encompute._native.acquire_session_keys(
                st["spec"], prep["broker_id"], [asset], os.urandom(32), "confidential-space",
                str(local.socket), "", "hospital-a")
        assert e.value.args[0] == "ENC2002", asset
    # A descriptor claiming to be hospital-b is attested as hospital-b: the
    # evidence's participant is what the attestation says.
    keys, record = encompute._native.acquire_session_keys(
        st["spec"], prep["broker_id"], ["dataset-notes-b"], os.urandom(32),
        "confidential-space", str(local.socket), "", "hospital-b")
    assert json.loads(record)["evidence"]["binding"]["execution_spec_id"] != \
        st["training_spec_id"]


# --- the job must be the approved one --------------------------------------------------


def test_another_training_spec_gets_no_keys(prep, local):
    def lower_rank(j):
        j["training_spec"]["config"]["rank"] = 8
        j["training_spec"]["config"]["peft"]["r"] = 8
        j["training_spec_id"] = encompute._native.training_spec_id(
            json.dumps(j["training_spec"]))
    path, _ = job_file(prep, edit=lower_rank, name="rank")
    refused(local.run_worker(path), "KEY RELEASE DENIED")

    def less_noise_unrenamed(j):
        j["training_spec"]["config"]["dp_sgd"]["noise_multiplier"] = "0.3"
    path, _ = job_file(prep, edit=less_noise_unrenamed, name="noise")
    refused(local.run_worker(path), "TRAINING SPEC MISMATCH")


def test_substituted_assets_are_refused(prep, local):
    W = Path(prep["workdir"])

    def other_model(j):
        j["model"]["ciphertext"] = str(W / "staged" / "notes-a.enc")
    refused(local.run_worker(job_file(prep, edit=other_model, name="model")[0]),
            "ASSET MISMATCH")

    def other_dataset(j):
        j["dataset"]["ciphertext"] = str(W / "staged" / "notes-b.enc")
    refused(local.run_worker(job_file(prep, edit=other_dataset, name="data")[0]),
            "ASSET MISMATCH")

    def other_participants_dataset(j):
        j["dataset"]["asset_id"] = "notes-b"
    refused(local.run_worker(job_file(prep, edit=other_participants_dataset, name="data2")[0]),
            "DATASET ASSET MISMATCH")

    def other_package(j):
        j["model_package_id"] = "0" * 64
    refused(local.run_worker(job_file(prep, edit=other_package, name="pkg")[0]),
            "MODEL PACKAGE MISMATCH")


def test_replayed_evidence_and_outputs_are_refused(prep, local, approved, tmp_path):
    outs, _ = approved
    st = prep["state"]
    mc = Path(prep["workdir"]) / st["model_owner"]
    # An old attestation token, presented again: its challenge is spent.
    record = json.loads((Path(outs[0]) / "attestation.json").read_text())
    (tmp_path / "old.json").write_text(json.dumps(record["evidence"]))
    state = tmp_path / "broker.json"
    shutil.copy(mc / "broker.json", state)
    r = subprocess.run([CLI, "keys", "release", "--asset", st["model_id"], "--attestation",
                        str(tmp_path / "old.json"), "--out", str(tmp_path / "grant.json"),
                        "--broker", str(state), "--kek", prep["kek"],
                        "--jwks", str(job.TEST_KEYS / "jwks.json")],
                       capture_output=True, text=True)
    assert r.returncode != 0 and not (tmp_path / "grant.json").exists(), r.stdout + r.stderr
    # A second output for the same participant and round (the job run
    # again): the report refuses it as a replay.
    first = tmp_path / "first"
    shutil.copytree(outs[0], first)
    again = local.run_worker(prep["jobs"]["hospital-a"]["job"])
    assert again.returncode == 0
    report = job.verify(prep, [str(first), outs[0]], str(job.TEST_KEYS / "jwks.json"),
                        bundle=str(tmp_path / "bundle.json"))
    assert "a replay" in report, report


def test_the_descriptor_cannot_change_the_training(prep, local):
    """Review finding TR-2 (ENC-SF-2026-050): the configuration comes from the spec, and the
    input adapter must be the spec's initial one (round 1) or the one the
    coordinator recorded for the previous round; a descriptor that says
    otherwise is refused before any key is requested."""
    def lr(j):
        j["lora"] = {"learning_rate": 1000.0}
    def steps(j):
        j["lora"] = {"local_steps": 10 ** 9}
    def replayed_adapter(j):
        j["adapter"]["digest"] = "0" * 64
    def later_round_without_record(j):
        j["round"] = 2
    def seed(j):
        j["seed"] = -1
    for edit, needle in ((lr, "CONFIGURATION MISMATCH"), (steps, "CONFIGURATION MISMATCH"),
                         (replayed_adapter, "INPUT ADAPTER MISMATCH"),
                         (later_round_without_record, "INPUT ADAPTER MISMATCH"),
                         (seed, "seed")):
        out = refused(local.run_worker(job_file(prep, edit=edit, name=edit.__name__)[0]),
                      needle)
        assert "Attestation" not in out, out


def test_only_the_specs_broker_key_is_trusted(prep, local, tmp_path):
    """Review finding KB-1 (ENC-SF-2026-036): the descriptor cannot pin a broker key, and a
    broker whose grant key the spec does not name (the operator's own,
    releasing keys it chose under the same public policies) gets nothing
    accepted."""
    def pinned(j):
        j["broker"] += "#" + "ab" * 32
    refused(local.run_worker(job_file(prep, edit=pinned, name="pinned")[0]),
            "comes from the training spec")
    # The operator's broker: the same asset names and participant policy,
    # its own keys and grant-signing key, trusting the same launcher keys.
    port = job._port()
    url = f"http://127.0.0.1:{port}"
    mc = Path(prep["workdir"]) / prep["state"]["model_owner"]
    for asset in ("clinical-model.hospital-a", "dataset-notes-a", "adapters.hospital-a",
                  "contribution-hospital-a"):
        subprocess.run([CLI, "keys", "protect", "--asset", asset, "--policy",
                        str(mc / "training-policy-hospital-a.json"), "--broker-id", url,
                        "--kek", str(tmp_path / "evil.kek"), "--broker",
                        str(tmp_path / "evil.json")], check=True, capture_output=True)
    evil = subprocess.Popen([CLI, "keys", "serve", "--listen", f"127.0.0.1:{port}", "--broker",
                             str(tmp_path / "evil.json"), "--kek", str(tmp_path / "evil.kek"),
                             "--jwks", str(job.TEST_KEYS / "jwks.json")],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        ft._wait_port(port, evil, "the operator's broker")

        def operators_broker(j):
            j["broker"] = url
        refused(local.run_worker(job_file(prep, edit=operators_broker, name="evil")[0]),
                "KEY RELEASE DENIED", "attested identity")
    finally:
        evil.kill()
        evil.wait()


def test_the_worker_refuses_other_code_before_any_key(prep, local):
    """Review finding TR-1 (ENC-SF-2026-037): a spec naming a factory the image does not ship
    is refused, and so is one whose code digest is not this worker's own
    code, before the worker attests or opens anything."""
    def factory(j):
        j["training_spec"]["base_model"]["architecture"] = json.dumps(
            {"factory": "timeit:timeit", "kwargs": {"stmt": "import os", "number": 1}})
    out = refused(local.run_worker(job_file(prep, edit=factory, name="factory")[0]),
                  "TRAINING SPEC REFUSED", "worker image")
    assert "Attestation" not in out

    def code(j):
        j["training_spec"]["code_digest"] = "0" * 64
        j["training_spec_id"] = encompute._native.training_spec_id(
            json.dumps(j["training_spec"]))
    out = refused(local.run_worker(job_file(prep, edit=code, name="code")[0]),
                  "TRAINING CODE MISMATCH")
    assert "Attestation" not in out


def test_the_plan_and_image_come_from_approved_sources(prep, local):
    """Review findings DP-3 and KB-5 (ENC-SF-2026-067, ENC-SF-2026-062): a DP-SGD job applies the approved
    plan's clip only if the plan is the spec's; and the image the evidence
    names is the attested one, so a descriptor expecting another is
    refused."""
    def other_plan(j):
        for step in j["plan"]["steps"]:
            for m in step["mechanisms"]:
                if m["mechanism"] == "differential_privacy":
                    m["clip_norm"] = "0.5"
    refused(local.run_worker(job_file(prep, edit=other_plan, name="plan")[0]),
            "PLAN MISMATCH")

    def no_plan(j):
        del j["plan"]
    refused(local.run_worker(job_file(prep, edit=no_plan, name="noplan")[0]),
            "approved plan")

    def other_image(j):
        j["expected_image"] = TAMPERED
    refused(local.run_worker(job_file(prep, edit=other_image, name="image")[0]),
            "IMAGE MISMATCH")


# --- nothing leaves the workload ------------------------------------------------------------


def test_no_plaintext_leaves_the_workload(prep, local, approved, tmp_path):
    """Everything the operator can see: job descriptors, sealed assets,
    outputs, the broker's state, and the workers' logs."""
    outs, logs = approved
    W = Path(prep["workdir"])
    st = prep["state"]
    # The keys, as an attested session receives them (to know what to
    # look for).
    import os
    keys, _ = encompute._native.acquire_session_keys(
        st["spec"], prep["broker_id"],
        [f"{st['model_id']}.hospital-a", "dataset-notes-a", "adapters.hospital-a",
         "contribution-hospital-a"],
        os.urandom(32), "confidential-space", str(local.socket), "", "hospital-a")
    needles = {"weights": [struct.pack("<f", WEIGHT_CANARY), repr(WEIGHT_CANARY).encode()],
               "patient tokens": [b"".join(struct.pack("<q", t) for t in TOKEN_CANARY),
                                  json.dumps(TOKEN_CANARY).encode()],
               "gradients": [struct.pack("<f", UPDATE_CANARY), struct.pack("<d", UPDATE_CANARY),
                             repr(UPDATE_CANARY).encode()]}
    needles["keys"] = [bytes(k) for _, k in keys] + [bytes(k).hex().encode() for _, k in keys]
    # The owners' own plaintext stays with them: each hospital's dataset
    # file, the model owner's key-encryption key.
    allowed = {"hospital-a/dataset.bin", "hospital-b/dataset.bin", "broker.kek"}
    hits = []
    for f in W.rglob("*"):
        rel = str(f.relative_to(W))
        if not f.is_file() or rel in allowed or rel.startswith("repository"):
            continue
        data = f.read_bytes()
        hits += [f"{rel}: {what}" for what, ns in needles.items() for n in ns if n in data]
    hits += [f"logs: {what}" for what, ns in needles.items() for n in ns if n in logs.encode()]
    assert hits == []
