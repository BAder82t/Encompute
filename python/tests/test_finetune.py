"""Confidential LoRA fine-tuning end to end: real PyTorch training in
attested workers, secure aggregation with DP, sealed checkpoints and
adapters, lineage, export control, inference, and the attacks, each
failing at its boundary. Needs PyTorch and the encompute CLI."""

import json
import shutil
import subprocess

import pytest

torch = pytest.importorskip("torch")

import encompute  # noqa: E402
import encompute.torch as et  # noqa: E402
from encompute import _native  # noqa: E402
from encompute.torch import finetune as ft, lora, tensors  # noqa: E402

try:
    CLI = ft._cli()
except encompute.EncomputeError:
    pytest.skip("the encompute CLI is not built", allow_module_level=True)


def dataset(seed, n=96):
    g = torch.Generator().manual_seed(seed)
    x = torch.randint(0, 64, (n, 8), generator=g)
    return et.private_dataset(x, (x[:, 0] < 32).long())


def project():
    p = encompute.Project("medical-lora", parties=["hospital-a", "hospital-b", "modelco"],
                          purpose="disease-training")
    torch.manual_seed(0)
    base = et.wrap_model("encompute.torch.models:tiny_classifier", vocab=64, dim=16)
    m = p.model("base-model", owner="modelco", module=base)
    a = p.data("patients-a", owner="hospital-a", dataset=dataset(1))
    b = p.data("patients-b", owner="hospital-b", dataset=dataset(2))
    return p, m, a, b


CFG = et.LoRAConfig(rounds=2, local_steps=10, learning_rate=0.1)


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    p, m, a, b = project()
    r = p.finetune(model=m, data=[a, b], privacy="standard", verification="required",
                   allow_development=True, config=CFG,
                   workdir=str(tmp_path_factory.mktemp("ft")), verbose=False)
    yield r
    r.close()


def report(r, bundle=None):
    c = r._ctx
    return subprocess.run([CLI, "trust", "report", "--bundle", str(bundle or c["bundle"]),
                           *c["anchors"], "--require", "Training"],
                          capture_output=True, text=True).stdout


def test_training_run_is_trusted_end_to_end(run):
    assert run.rounds == 2 and run.stopped is None
    assert run.satisfied, run.report
    for row in ("Plan", "Workload", "Private aggregation", "Privacy budget", "Training",
                "Lineage"):
        assert run.rows[row].split()[0] in ("SATISFIED", "ATTESTED", "VERIFIED", "COMPLETE"), row
    s = run.summary()
    assert "Adapter lineage         COMPLETE" in s and "TRUST REQUIREMENTS SATISFIED" in s
    for k in ("plain_pytorch_local_training_s", "attestation_startup_s",
              "secure_aggregation_s", "checkpoint_s", "trust_graph_s"):
        assert run.timings[k] >= 0


def test_adapter_is_usable_and_changed(run):
    x = dataset(9, 32)[0]
    before, after = run.infer(x, adapter="adapter-0"), run.infer(x)
    assert before.shape == after.shape == (32, 2)
    assert float((before - after).abs().max()) > 1e-3


def test_lineage_links_model_data_and_evidence(run):
    out = run.lineage()
    for want in ("base-model (modelco)", "patients-a (hospital-a)", "patients-b (hospital-b)",
                 "adapter-1 ← round 1", "adapter-2 ← round 2", "attestation      ATTESTED",
                 "training         VERIFIED"):
        assert want in out, out


def test_export_is_denied_by_inherited_policy(run):
    assert run.export.startswith("EXPORT DENIED")
    out = run.export_adapter()
    assert "EXPORT DENIED" in out and "base-model (never)" in out


def test_no_raw_update_is_ever_written(run):
    # A hospital's directory holds its key, dataset, config, round state and
    # attestation record: never an update, gradient or adapter.
    for h in ("hospital-a", "hospital-b"):
        files = sorted(f.name for f in (run.workdir / h).iterdir())
        assert files == ["attestation.json", "dataset.bin", "party.key", "round.state",
                         "worker.json"], files
    # ModelCo sees only aggregates: each released vector is the noised sum.
    for r in (1, 2):
        agg = json.loads((run.workdir / "modelco" / f"update-{r}.json").read_text())
        assert sorted(agg["contributors"]) == ["hospital-a", "hospital-b"]


def test_every_release_is_charged(run):
    for a in ("gradient-patients-a", "gradient-patients-b"):
        lines = (run.workdir / "modelco" / "ledgers" / f"{a}.ledger").read_text().splitlines()
        assert len(lines) == 1 + 2 * run.rounds  # genesis, then reserve+commit per round


def test_keys_only_for_the_approved_workload(run):
    c = run._ctx
    spec = json.loads(c["spec"])
    key = str(run.workdir / "hospital-a" / "party.key")
    seed = str(c["hw_seed"])
    # Another image (training outside the approved workload).
    with pytest.raises(_native.NativeError) as e:
        _native.acquire_training_keys(c["spec"], c["broker"], ["base-model"], key, seed,
                                      "sha256:" + "6" * 64)
    assert e.value.args[0] == "ENC2002"
    # Another training spec: changed code, LoRA rank, model, or plan.
    for field, value in (("code_digest", "0" * 64), ("plan_id", "1" * 64)):
        other = dict(spec, **{field: value})
        with pytest.raises(_native.NativeError) as e:
            _native.acquire_training_keys(json.dumps(other), c["broker"], ["base-model"], key,
                                          seed, ft.IMAGE)
        assert e.value.args[0] == "ENC2002", field
    other = dict(spec, config=dict(spec["config"], rank=16))
    with pytest.raises(_native.NativeError):
        _native.acquire_training_keys(json.dumps(other), c["broker"], ["base-model"], key, seed,
                                      ft.IMAGE)


def test_wrong_model_layout_or_dataset_is_refused(run):
    c = run._ctx
    spec = json.loads(c["spec"])
    keys, _ = _native.acquire_training_keys(c["spec"], c["broker"], ["base-model"],
                                            str(run.workdir / "hospital-a" / "party.key"),
                                            str(c["hw_seed"]), ft.IMAGE)
    key = dict(keys)["base-model"]
    sealed = (run.workdir / "modelco" / "base-model.enc").read_bytes()
    # Another model version.
    with pytest.raises(_native.NativeError) as e:
        _native.open_asset(key, sealed, "medical-lora", "base-model", "0" * 64)
    assert e.value.args[0] == "ENC2501"
    # A tampered sealed model.
    bad = bytearray(sealed)
    bad[-3] ^= 1
    with pytest.raises(_native.NativeError):
        _native.open_asset(key, bytes(bad), "medical-lora", "base-model",
                           spec["base_model"]["weights_digest"])
    # Another LoRA layout.
    m = et.wrap_model("encompute.torch.models:tiny_classifier", vocab=64, dim=16)
    et.apply_lora(m, et.LoRAConfig(rank=8))
    assert et.layout_digest(m) != spec["layout_digest"]
    # A dataset that is not the committed one: the worker refuses it.
    cfg = json.loads((run.workdir / "hospital-a" / "worker.json").read_text())
    cfg["dataset"] = str(run.workdir / "hospital-b" / "dataset.bin")
    with pytest.raises(ValueError):
        ft_worker_dataset(cfg)


def ft_worker_dataset(cfg):
    from encompute.torch import worker
    return worker.load_dataset(cfg)


def test_checkpoint_rollback_and_swap_are_refused(run, tmp_path):
    ck = run.workdir / "modelco" / "checkpoints"
    assert run.resume(str(ck / "round-2.enc"))["round"] == 2
    with pytest.raises(encompute.EncomputeError) as e:
        run.resume(str(ck / "round-1.enc"))
    assert e.value.code == "ENC2502" and "stale" in e.value.message
    bad = bytearray((ck / "round-2.enc").read_bytes())
    bad[-7] ^= 1
    (tmp_path / "t.enc").write_bytes(bytes(bad))
    with pytest.raises(encompute.EncomputeError):
        run.resume(str(tmp_path / "t.enc"))
    # The ledger rolled back to match the old checkpoint: the newer
    # checkpoint (and every owner's checkpoint) detects it.
    led = run.workdir / "modelco" / "ledgers" / "gradient-patients-a.ledger"
    text = led.read_text()
    led.write_text("\n".join(text.splitlines()[:3]) + "\n")
    try:
        with pytest.raises(encompute.EncomputeError) as e:
            run.resume(str(ck / "round-2.enc"))
        assert e.value.code == "ENC2202"
    finally:
        led.write_text(text)


def test_tampered_adapter_evidence_fails_the_report(run, tmp_path):
    b = json.loads(run._ctx["bundle"].read_text())
    node = b["nodes"]["adapter:adapter-2"]
    node["evidence"]["value"]["record"]["adapter_digest"] = "0" * 64
    t = tmp_path / "trust.json"
    t.write_text(json.dumps(b))
    out = report(run, t)
    assert "TRUST REQUIREMENTS NOT SATISFIED" in out
    assert "Training                FAILED" in out or "Evidence                FAILED" in out


def test_no_trusted_environment_fails_closed():
    p, m, a, b = project()
    with pytest.raises(encompute.PlanningFailed) as e:
        p.finetune(model=m, data=[a, b], allow_development=False, config=CFG, verbose=False)
    assert "not supported under FHE" in e.value.report


def test_budget_exhaustion_stops_training(tmp_path):
    p, m, a, b = project()
    # "standard" spends about epsilon 3.2 of 8 per organization-level round:
    # six rounds cannot fit.
    r = p.finetune(model=m, data=[a, b], privacy="standard", verification="required",
                   allow_development=True, config=et.LoRAConfig(rounds=6, local_steps=2),
                   workdir=str(tmp_path / "w"), verbose=False)
    try:
        assert r.stopped and "privacy budget exhausted" in r.stopped, r.stopped
        assert 1 <= r.rounds < 6
        # The denied round charged nothing, and training stopped cleanly with
        # a verified adapter from the rounds that were released.
        assert r.satisfied, r.report
    finally:
        r.close()
