"""Patient-level differential privacy (DP-SGD) for confidential fine-tuning.

- The vectorized per-example gradients equal a one-patient-at-a-time
  autograd reference, for any microbatch size.
- A patient's records are grouped, so one patient moves the sum by at most
  the clip, however many records they have (the canary patient).
- Poisson sampling uses the operating system's randomness: no seed chooses
  the sample.
- End to end: the run binds every DP-SGD setting, the preview and the
  ledgers agree, over-budget runs are denied before training, and a
  patient-level claim without per-example clipping is refused by the
  planner and by the trust report.
- Accuracy stays within a bound of non-private training.
"""

import json
import shutil
import subprocess

import pytest

torch = pytest.importorskip("torch")

import encompute  # noqa: E402
import encompute.torch as et  # noqa: E402
from encompute import _native  # noqa: E402
from encompute.torch import dpsgd, finetune as ft, lora, models, tasks  # noqa: E402

CL = tasks.CLASSIFIER


def model(seed=0):
    torch.manual_seed(seed)
    m = models.build("encompute.torch.models:tiny_classifier", {"vocab": 64})
    lora.apply_lora(m, lora.LoRAConfig())
    lora.set_flat(m, torch.randn(lora.get_flat(m).numel()) * 0.1)
    return m


def records(n, seed=1):
    g = torch.Generator().manual_seed(seed)
    x = torch.randint(0, 64, (n, 8), generator=g)
    return x, ((x < 32).float().mean(1) > 0.5).long()


# --- the per-example gradient engine -------------------------------------------


def test_vectorized_gradients_match_the_reference_for_any_microbatch():
    m = model()
    x, y = records(40)
    ids = torch.randint(500, 515, (40,), generator=torch.Generator().manual_seed(2))
    unit_of, n = dpsgd.unit_index(ids, len(x))
    sampled = dpsgd.poisson_sample(n, 0.6, torch.Generator().manual_seed(3))
    ref = dpsgd.reference_clipped_sum(m, CL, {"x": x, "y": y}, unit_of, sampled, 0.05)
    for mb in (1, 3, 7, 1000):
        got = dpsgd.clipped_sum(m, CL, {"x": x, "y": y}, unit_of, sampled, 0.05, microbatch=mb)
        assert torch.allclose(got, ref, atol=1e-6), mb
    # Only the adapter's parameters: the gradient has the layout's length.
    assert ref.numel() == sum(e["length"] for e in lora.layout(m))


def test_unit_index_groups_records_by_patient():
    ids = torch.tensor([7, 3, 7, 9, 3, 3])
    unit_of, n = dpsgd.unit_index(ids, 6)
    assert n == 3 and unit_of.tolist() == [1, 0, 1, 2, 0, 0]
    assert dpsgd.unit_index(None, 4)[1] == 4  # no grouping: one record, one unit


def test_one_patient_moves_the_sum_by_at_most_the_clip():
    """The canary patient has 30 records with extreme labels. With or
    without them (the same sample of everyone else), the clipped sum moves
    by at most the clip."""
    m = model()
    x, y = records(60)
    ids = torch.arange(30).repeat_interleave(2)
    cx = x[:1].repeat(30, 1)
    cy = 1 - y[:1].repeat(30)
    xc, yc = torch.cat([x, cx]), torch.cat([y, cy])
    idc = torch.cat([ids, torch.full((30,), 999)])
    clip = 0.05
    u0, n0 = dpsgd.unit_index(ids, len(x))
    u1, n1 = dpsgd.unit_index(idc, len(xc))
    assert n1 == n0 + 1
    others = dpsgd.poisson_sample(n0, 0.5, torch.Generator().manual_seed(4))
    without = dpsgd.clipped_sum(m, CL, {"x": x, "y": y}, u0, others, clip)
    with_canary = dpsgd.clipped_sum(m, CL, {"x": xc, "y": yc}, u1, torch.cat([others, torch.tensor([n0])]),
                                    clip)
    moved = float((with_canary - without).norm())
    assert 0 < moved <= clip * (1 + 1e-5)
    # Ungrouped, the same records would count 30 times over.
    u2, _ = dpsgd.unit_index(None, len(xc))
    ungrouped = dpsgd.clipped_sum(m, CL, {"x": xc, "y": yc}, u2, torch.arange(len(x), len(xc)), clip)
    assert float(ungrouped.norm()) > 5 * clip


def test_poisson_sampling_uses_os_randomness():
    torch.manual_seed(0)
    a = dpsgd.poisson_sample(10_000, 0.03)
    torch.manual_seed(0)
    b = dpsgd.poisson_sample(10_000, 0.03)
    assert not torch.equal(a, b), "the global seed must not choose the sample"
    # Each unit independently with probability q (binomial, ±6 sigma).
    sizes = [len(dpsgd.poisson_sample(10_000, 0.03)) for _ in range(20)]
    sd = (10_000 * 0.03 * 0.97) ** 0.5
    assert all(abs(s - 300) < 6 * sd for s in sizes)
    assert len(set(sizes)) > 1  # the batch size varies: Poisson, not fixed


def test_privacy_levels():
    assert encompute.Privacy.of("strong") == "strong"
    p = encompute.Privacy.of("strong-patient")
    assert isinstance(p, encompute.Privacy) and p.unit == "patient"
    assert p.resolve() == (3.0, 1e-6, 1.2)
    assert encompute.Privacy(level="standard-patient", epsilon=2.0).resolve()[0] == 2.0
    for bad in (lambda: encompute.Privacy.of("patient-ish"),
                lambda: encompute.Privacy(unit="organization").resolve(),
                lambda: encompute.Privacy(sampling_rate=1.0).resolve()):
        with pytest.raises(encompute.EncomputeError) as e:
            bad()
        assert e.value.code == "ENC2203"
    assert ft._exact(1e-6) == "1e-6" and ft._exact(0.05) == "0.05"


def test_organizations_cannot_be_sampled():
    with pytest.raises(_native.NativeError):
        _native.Model.compile(PROGRAM.replace("unit \"patient\"", "unit \"organization\""))


PROGRAM = """encompute 0.1
program t precision 0.001 purpose "p"
party "a" "a"
party "b" "b"
party "m" "m"
asset "ga" gradient owners ["a"] readers ["m"] purposes ["p"] release aggregate_only privacy unit "patient" epsilon 3.0 delta 1e-6
asset "gb" gradient owners ["b"] readers ["m"] purposes ["p"] release aggregate_only privacy unit "patient" epsilon 3.0 delta 1e-6
%0 = input "g_a" [-1.0, 1.0] asset "ga" : secret vector<4>
%1 = input "g_b" [-1.0, 1.0] asset "gb" : secret vector<4>
%2 = add %0, %1 : secret vector<4>
output "update" = %2 to "m"
aggregate "update" sum minimum 2 colluding 0 clip [-1.0, 1.0] scale 65536 modulus 40 dp discrete_gaussian clip_norm 0.015625 noise_multiplier 1.2 sampling_rate 0.01
"""


def test_the_preview_uses_the_sampled_accountant():
    rows, text = _native.privacy_preview(PROGRAM, 100)
    rows = json.loads(rows)
    assert {r["asset"] for r in rows} == {"ga", "gb"}
    r = rows[0]
    assert r["level"] == "example" and r["accountant"] == "rdp-poisson-zw2019"
    assert r["allowed"] and r["epsilon"] < 3.0 and r["affordable"] >= 100
    assert "DP-SGD, Poisson sampling 0.01" in text
    over = json.loads(_native.privacy_preview(PROGRAM, r["affordable"] + 1)[0])
    assert not over[0]["allowed"] and over[0]["epsilon"] > 3.0
    # Without sampling, the same noise affords far fewer releases.
    unsampled = json.loads(_native.privacy_preview(
        PROGRAM.replace(" sampling_rate 0.01", ""), 1)[0])[0]
    assert unsampled["accountant"] == "zcdp-cks2020"
    assert unsampled["affordable"] * 10 < r["affordable"]


# --- accuracy ------------------------------------------------------------------


def _train(noise: float, steps: int = 40, q: float = 0.032, clip: float = 1.0,
            lr: float = 2.0) -> float:
    """Simulated DP-SGD (the same clipping, sampling and noise as the
    protocol, in one process), and the held-out accuracy."""
    torch.manual_seed(0)
    m = models.build("encompute.torch.models:tiny_classifier", {"vocab": 64, "dim": 16})
    lora.apply_lora(m, lora.LoRAConfig())
    sets = []
    for s in (1, 2):
        x, y = records(2000, s)
        sets.append((x, y, *dpsgd.unit_index(torch.arange(1000).repeat_interleave(2), 2000)))
    xt, yt = records(500, 9)
    g = torch.Generator().manual_seed(5)
    for _ in range(steps):
        total = sum(dpsgd.clipped_sum(m, CL, {"x": x, "y": y}, u, dpsgd.poisson_sample(n, q, g), clip)
                    for x, y, u, n in sets)
        total = total + torch.randn(total.shape, generator=g) * noise * clip
        lora.set_flat(m, lora.get_flat(m) - lr * total / (q * 2000))
    with torch.no_grad():
        return float((m(xt).argmax(1) == yt).float().mean())


def test_accuracy_stays_within_bounds_of_non_private_training():
    base = _train(noise=0.0, steps=0)
    plain = _train(noise=0.0)
    private = _train(noise=1.2)  # strong-patient's noise
    assert plain > base + 0.2, (base, plain)
    assert private > base + 0.15, (base, private)
    assert plain - private < 0.1, (plain, private)


# --- end to end ----------------------------------------------------------------

try:
    CLI = ft._cli()
except encompute.EncomputeError:
    CLI = None
needs_cli = pytest.mark.skipif(CLI is None, reason="the encompute CLI is not built")


def project(tmp, patients=64, grouped=True):
    p = encompute.Project("dp-lora", parties=["hospital-a", "hospital-b", "modelco"],
                          purpose="disease-training")
    torch.manual_seed(0)
    base = et.wrap_model("encompute.torch.models:tiny_classifier", vocab=64, dim=16)
    m = p.model("base-model", owner="modelco", module=base)
    data = []
    for i, owner in enumerate(("hospital-a", "hospital-b")):
        x, y = records(patients * 2, i + 1)
        ids = torch.arange(patients).repeat_interleave(2) if grouped else None
        data.append(p.data(f"patients-{'ab'[i]}", owner=owner,
                           dataset=et.private_dataset(x, y, unit_ids=ids)))
    return p, m, data


@pytest.fixture(scope="module")
def patient_run(tmp_path_factory):
    if CLI is None:
        pytest.skip("the encompute CLI is not built")
    W = tmp_path_factory.mktemp("dp") / "run"
    p, m, data = project(W)
    r = p.finetune(model=m, data=data, privacy="strong-patient", allow_development=True,
                   config=et.LoRAConfig(rounds=3, batch_size=4, learning_rate=1.0),
                   workdir=str(W), verbose=False)
    yield r
    r.close()


@needs_cli
def test_patient_run_is_satisfied_and_binds_every_setting(patient_run):
    r = patient_run
    assert r.satisfied and r.rounds == 3 and r.privacy_unit == "patient"
    spec = json.loads(r._ctx["spec"])
    d = spec["config"]["dp_sgd"]
    assert spec["config"]["local_steps"] == 1
    assert d == {"privacy_unit": "patient", "per_example_clip": "1.0", "sampling": "poisson",
                 "sampling_rate": "0.0625", "noise_multiplier": "1.2", "delta": "1e-6",
                 "grouping": "unit_ids", "accountant": "rdp-poisson-zw2019",
                 "expected_batch": "8.0"}
    assert all(x["privacy_units"] == 64 and len(x["grouping_digest"]) == 64
               for x in spec["datasets"])
    assert "Privacy unit: patient" in r.summary()
    lineage = r.lineage()
    assert "patient (DP-SGD: per-patient clip 1.0, Poisson sampling 0.0625" in lineage


@needs_cli
def test_the_ledgers_charge_what_the_preview_projected(patient_run):
    r = patient_run
    projected = {row["asset"]: row["epsilon"] for row in r.privacy_preview}
    out = subprocess.run([CLI, "privacy", "budget", "--ledger", "ledgers"],
                         cwd=r._ctx["modelco"], capture_output=True, text=True).stdout
    for asset, eps in projected.items():
        assert asset in out
        assert f"{eps:.3f}"[:4] in out, (asset, eps, out)


@needs_cli
def test_workers_report_nothing_about_their_data(patient_run):
    # Organization mode reports each worker's local loss; DP-SGD reports no
    # loss, clipping or sampling statistics (they are not privatized).
    assert patient_run.losses == []


@needs_cli
def test_over_budget_runs_are_denied_before_training(tmp_path):
    p, m, data = project(tmp_path)
    W = tmp_path / "run"
    with pytest.raises(encompute.EncomputeError) as e:
        p.finetune(model=m, data=data, privacy="strong-patient", allow_development=True,
                   config=et.LoRAConfig(rounds=500, batch_size=4), workdir=str(W),
                   verbose=False)
    assert e.value.code == "ENC2201" and "DENIED BEFORE TRAINING" in str(e.value)
    # Nothing ran: no plan, no worker, no ledger.
    assert not list(W.rglob("worker.json")) and not list(W.rglob("*.ledger"))
    assert not (W / "modelco" / "plan.json").exists()


@needs_cli
def test_patient_privacy_needs_patient_ids(tmp_path):
    p, m, data = project(tmp_path, grouped=False)
    with pytest.raises(encompute.EncomputeError) as e:
        p.finetune(model=m, data=data, privacy="strong-patient", allow_development=True,
                   workdir=str(tmp_path / "run"), verbose=False)
    assert e.value.code == "ENC2501" and "unit_ids" in str(e.value)


@needs_cli
def test_the_planner_refuses_patient_claims_without_per_example_clipping(tmp_path):
    p, m, data = project(tmp_path)
    eir = p._aggregation_program(data, "modelco", m, privacy="strong", unit="patient",
                                 dim=16, colluding=None)
    infra = json.dumps({"tees": [{"tee": "mock", "provider": "mock", "cloud": True}],
                        "key_broker": True})
    prefs = json.dumps({"allow_development": True})

    def plan(unit, per_example):
        decl = json.dumps({"model": m.id, "data": [d.id for d in data], "verified": True,
                           "privacy_unit": unit, "per_example_clipping": per_example})
        return _native.plan(eir, "standard", infra, decl, prefs)

    # Patient-level budgets, whole-update clipping: refused however it is
    # declared.
    for unit, per_example in (("patient", False), ("patient", True), ("organization", False)):
        with pytest.raises(_native.NativeError) as e:
            plan(unit, per_example)
        assert e.value.args[0] == "ENC2401", (unit, per_example)
    with pytest.raises(_native.NativeError) as e:
        plan("patient", False)
    assert "per-example clipping" in e.value.args[1]


@needs_cli
def test_the_trust_report_refuses_patient_claims_from_organization_training(
        patient_run, tmp_path):
    """A training spec without DP-SGD under a program whose budgets protect
    patients: the Training row fails."""
    mc = tmp_path / "modelco"
    shutil.copytree(patient_run._ctx["modelco"], mc)
    spec = json.loads(patient_run._ctx["spec"])
    del spec["config"]["dp_sgd"]
    spec["config"]["local_steps"] = 5
    for d in spec["datasets"]:
        d.pop("privacy_units")
        d.pop("grouping_digest")
    (mc / "forged-spec.json").write_text(json.dumps(spec))
    subprocess.run([CLI, "trust", "add", "forged-spec.json", "--bundle", "trust.json"],
                   cwd=mc, check=True, capture_output=True)
    out = subprocess.run([CLI, "trust", "report", "--bundle", "trust.json",
                          *patient_run._ctx["anchors"]], cwd=mc, capture_output=True,
                         text=True).stdout
    assert "clips each organization's whole update" in out
    assert "TRUST REQUIREMENTS NOT SATISFIED" in out


@needs_cli
def test_changed_dp_settings_get_no_model_key(patient_run):
    """Less noise, a higher sampling rate, a larger clip or another unit is
    another training spec: the key broker refuses it."""
    c = patient_run._ctx
    for field, value in (("noise_multiplier", "0.5"), ("sampling_rate", "0.5"),
                         ("per_example_clip", "10.0"), ("privacy_unit", "record")):
        spec = json.loads(c["spec"])
        spec["config"]["dp_sgd"][field] = value
        with pytest.raises(_native.NativeError) as e:
            _native.acquire_training_keys(
                json.dumps(spec), patient_run._broker(), ["base-model"],
                str(c["modelco"] / "coord.key"), str(c["hw_seed"]), ft.IMAGE)
        assert e.value.args[0] == "ENC2002", field


@needs_cli
def test_contributions_bypassing_the_attested_worker_are_refused(patient_run, tmp_path):
    """No party-side clip bounds a DP-SGD contribution, so only attested
    workers (which clip each patient) may contribute: a coordinator without
    the contributor policy cannot open a round, and a raw vector sent
    without the worker's attestation is refused."""
    W = patient_run.workdir
    mc = W / "modelco"
    st = json.loads((W / "run.json").read_text())
    dim = json.loads(patient_run._ctx["spec"])["config"]["adapter_parameters"]
    (tmp_path / "big.json").write_text(json.dumps([1.0] * dim))
    base = [CLI, "aggregate", "serve", "training.encompute", "--parties",
            str(W / "parties.json"), "--plan", "plan.json", "--key", "coord.key",
            "--sequence", "90", "--ledger", str(tmp_path / "ledgers"), "--out",
            str(tmp_path / "x.json"), "--receipt", str(tmp_path / "r.json"),
            "--stage-timeout", "3"]
    port = ft._port()
    p = subprocess.run(base + ["--listen", f"127.0.0.1:{port}"], cwd=mc, capture_output=True,
                       text=True, timeout=30)
    assert p.returncode != 0 and "needs attested contributors" in p.stderr
    serve = subprocess.Popen(base + ["--listen", f"127.0.0.1:{port}", "--attestation-policy",
                                     st["contribution_policy"], "--mock-root", st["mock_root"]],
                             cwd=mc, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        ft._wait_port(port, serve, "the coordinator")
        j = subprocess.run(
            [CLI, "aggregate", "join", str(mc / "training.encompute"), "--parties",
             str(W / "parties.json"), "--plan", str(mc / "plan.json"),
             "--attestation-policy", st["contribution_policy"], "--coordinator",
             f"http://127.0.0.1:{port}", "--party", "hospital-a", "--key",
             str(W / "hospital-a" / "party.key"), "--values", str(tmp_path / "big.json"),
             "--state", str(tmp_path / "a.state"), "--timeout", "3"],
            capture_output=True, text=True, timeout=30)
        assert j.returncode != 0 and "requires an attested contribution workload" in j.stderr
    finally:
        serve.kill()
        serve.wait()
