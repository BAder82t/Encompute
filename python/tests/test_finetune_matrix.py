"""The fine-tuning commitments, case by case:
- model loading and digests;
- dataset commitments;
- adapter layouts;
- export governance;
- resume;
- determinism.

Every security-relevant change must be caught: by a different digest or
spec ID, or by a refusal."""

import json
import pickle
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

FACTORY = "encompute.torch.models:tiny_classifier"


def model(seed=0, **kw):
    torch.manual_seed(seed)
    return et.wrap_model(FACTORY, **({"vocab": 64, "dim": 16} | kw))


def digest(m):
    return _native.sha256_hex(tensors.dumps(m.state_dict()))


def dataset(seed, n=64):
    g = torch.Generator().manual_seed(seed)
    x = torch.randint(0, 64, (n, 8), generator=g)
    return x, (x[:, 0] < 32).long()


# --- model loading -------------------------------------------------------------


def test_pickles_are_refused_before_loading():
    blob = pickle.dumps({"weights": [1, 2, 3]})
    with pytest.raises(ValueError, match="never loaded from pickles"):
        tensors.loads(blob)
    blob = pickle.dumps(model().state_dict())
    with pytest.raises(ValueError):
        tensors.loads(blob)
    # A model object without a factory is refused by finetune itself.
    p = encompute.Project("x", parties=["a", "b", "m"])
    raw = torch.nn.Linear(4, 2)
    mm = p.model("base-model", owner="m", module=raw)
    a = p.data("da", owner="a", dataset=et.private_dataset(*dataset(1)))
    b = p.data("db", owner="b", dataset=et.private_dataset(*dataset(2)))
    with pytest.raises(encompute.EncomputeError, match="factory, not a pickle"):
        p.finetune(model=mm, data=[a, b], allow_development=True, verbose=False)


def test_model_digest_covers_weights_architecture_and_config():
    m = model()
    same = model()
    assert digest(m) == digest(same)
    changed = model()
    with torch.no_grad():
        changed.head.weight[0, 0] += 1e-6
    assert digest(changed) != digest(m)                  # modified weights
    assert digest(model(dim=8)) != digest(m)             # another architecture
    # Same weights under another factory or configuration: the architecture
    # string is in the training spec, so the spec (and the key release)
    # changes.
    spec = json.loads((ft.Path(__file__).resolve().parents[2] / "crates" /
                       "encompute-training" / "tests" / "fixtures" / "spec.json").read_text())
    base = _native.training_spec_id(json.dumps(spec))
    s = json.loads(json.dumps(spec))
    s["base_model"]["architecture"] = json.dumps({"factory": FACTORY, "kwargs": {"dim": 8}})
    assert _native.training_spec_id(json.dumps(s)) != base
    # Review finding TR-1 (ENC-SF-2026-037): a factory the worker image does not ship is not
    # a spec at all (no ID, so no key is ever released for it).
    for arch in ('{"factory":"other:f","kwargs":{}}',
                 '{"factory":"subprocess:run","kwargs":{"args":"true"}}'):
        s["base_model"]["architecture"] = arch
        with pytest.raises(_native.NativeError, match="worker image"):
            _native.training_spec_id(json.dumps(s))


# --- datasets ------------------------------------------------------------------


def test_dataset_commitment_covers_every_sample_label_and_order():
    x, y = dataset(1)
    d = _native.sha256_hex(tensors.dumps({"x": x, "y": y}))
    x2 = x.clone(); x2[3, 2] = (x2[3, 2] + 1) % 64
    y2 = y.clone(); y2[0] = 1 - y2[0]
    perm = torch.arange(len(x)).flip(0)
    for what, xs, ys in (("one sample", x2, y), ("labels", x, y2),
                         ("order", x[perm], y[perm]), ("another hospital's", *dataset(2))):
        assert _native.sha256_hex(tensors.dumps({"x": xs, "y": ys})) != d, what


# --- layouts -------------------------------------------------------------------


def layout_digest(cfg, **kw):
    m = model(**kw)
    lora.apply_lora(m, cfg)
    return lora.layout_digest(m)


def test_every_layout_change_changes_the_digest():
    base = layout_digest(et.LoRAConfig())
    for what, d in (("rank", layout_digest(et.LoRAConfig(rank=8))),
                    ("target module", layout_digest(et.LoRAConfig(target_modules=("k", "v")))),
                    ("more modules", layout_digest(et.LoRAConfig(target_modules=("k", "q", "v")))),
                    ("shape", layout_digest(et.LoRAConfig(), dim=32))):
        assert d != base, what
    m = model()
    lora.apply_lora(m, et.LoRAConfig())
    entries = lora.layout(m)
    # dtype
    e = json.loads(json.dumps(entries)); e[0]["dtype"] = "float64"
    assert _native.layout_digest(json.dumps({"version": 1, "entries": e})) != base
    # Reordered modules or parameters: refused, never reinterpreted.
    for swap in ((0, 2), (0, 1)):
        e = json.loads(json.dumps(entries))
        e[swap[0]], e[swap[1]] = e[swap[1]], e[swap[0]]
        with pytest.raises(_native.NativeError):
            _native.layout_digest(json.dumps({"version": 1, "entries": e}))
    with pytest.raises(_native.NativeError):
        _native.layout_digest(json.dumps({"version": 2, "entries": entries}))


# --- export --------------------------------------------------------------------


FIXTURES = ft.Path(__file__).resolve().parents[2] / "crates" / "encompute-training" / "tests" / "fixtures"


def export(permit):
    text = (FIXTURES / "program.eir").read_text()
    out = []
    for line in text.splitlines():
        out.append(line)
        for a in permit:
            if line.startswith(f'asset "{a}"'):
                out[-1] = line + " derive [adapter public to []]"
    try:
        _native.check_export("\n".join(out) + "\n", (FIXTURES / "spec.json").read_text(), "a-1")
        return "permitted"
    except _native.NativeError as e:
        return e.args[1]


def test_export_follows_every_parent():
    everything = ["base-model", "patients-a", "patients-b", "gradient-patients-a",
                  "gradient-patients-b"]
    assert export(everything) == "permitted"
    assert "base-model" in export(everything[1:])
    assert "patients-b" in export([a for a in everything if a != "patients-b"])
    assert "gradient-patients-a" in export([a for a in everything if a != "gradient-patients-a"])


# --- against a real run ------------------------------------------------------


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    p = encompute.Project("matrix-lora", parties=["hospital-a", "hospital-b", "modelco"],
                          purpose="disease-training")
    m = p.model("base-model", owner="modelco", module=model())
    a = p.data("patients-a", owner="hospital-a", dataset=et.private_dataset(*dataset(1)))
    b = p.data("patients-b", owner="hospital-b", dataset=et.private_dataset(*dataset(2)))
    r = p.finetune(model=m, data=[a, b], privacy="standard", allow_development=True,
                   config=et.LoRAConfig(rounds=2, local_steps=2),
                   workdir=str(tmp_path_factory.mktemp("m") / "run"), verbose=False)
    yield r
    r.close()


def cli_export(r, bundle):
    c = r._ctx
    return subprocess.run([CLI, "export", r.adapter_id, "--bundle", str(bundle), *c["anchors"]],
                          capture_output=True, text=True)


def test_export_denied_after_revocation_or_tampering(run, tmp_path):
    c = run._ctx
    t = tmp_path / "revoked.json"
    t.write_bytes(c["bundle"].read_bytes())
    subprocess.run([CLI, "trust", "revoke", "--party", "hospital-a", "--key",
                    str(run.workdir / "hospital-a" / "party.key"), "--asset", "patients-a",
                    "--reason", "consent withdrawn", "--bundle", str(t)], check=True,
                   capture_output=True)
    out = cli_export(run, t)
    assert out.returncode == 1 and "revoked assets: patients-a" in out.stdout, out.stdout
    b = json.loads(c["bundle"].read_text())
    b["nodes"][f"adapter:{run.adapter_id}"]["evidence"]["value"]["record"]["round"] += 7
    t2 = tmp_path / "tampered.json"
    t2.write_text(json.dumps(b))
    out = cli_export(run, t2)
    assert out.returncode == 1 and "EXPORT DENIED" in out.stdout, out.stdout
    # Review finding TR-5 (ENC-SF-2026-074): the owner's own bundle is enough; the run's
    # bundle, held by the model owner who benefits, need not carry it.
    assert "EXPORT DENIED" in run.export_adapter(revocations=[str(t)])
    assert "EXPORT PERMITTED" in run.export_adapter() or "EXPORT DENIED" in run.export_adapter()
    with pytest.raises(encompute.EncomputeError, match="revoked patients-a"):
        run.infer(dataset(3)[0][:2], revocations=[str(t)])
    with pytest.raises(encompute.EncomputeError, match="revoked patients-a"):
        run.resume(str(run.workdir / "modelco" / "checkpoints" / "round-2.enc"),
                   revocations=[str(t)])


def revocation_only(run, tmp_path, name, party, asset, owns=False):
    """A bundle holding nothing but ``party``'s signed revocation of ``asset``
    (no program, so no ownership). ``owns``: sign it through a scratch copy
    of the run's bundle that pretends ``party`` owns ``asset``, which is how
    a non-owner's validly signed revocation is made."""
    scratch = tmp_path / f"{name}-scratch.json"
    b = json.loads(run._ctx["bundle"].read_text())
    if owns:
        b["edges"].append({"from": f"party:{party}", "kind": "owns", "to": f"asset:{asset}"})
    scratch.write_text(json.dumps(b))
    subprocess.run([CLI, "trust", "revoke", "--party", party, "--key",
                    str(run.workdir / party / "party.key"), "--asset", asset,
                    "--reason", "consent withdrawn", "--bundle", str(scratch)], check=True,
                   capture_output=True)
    full = json.loads(scratch.read_text())
    nodes = {k: n for k, n in full["nodes"].items() if k.startswith("revocation:")}
    assert len(nodes) == 1
    out = tmp_path / f"{name}.json"
    out.write_text(json.dumps({"version": full["version"], "nodes": nodes,
                               "edges": [e for e in full["edges"]
                                         if e["from"] in nodes or e["to"] in nodes]}))
    return out, next(iter(nodes))


def report_json(run, bundle):
    c = run._ctx
    out = subprocess.run([CLI, "trust", "report", "--bundle", str(bundle), *c["anchors"],
                          "--json"], capture_output=True, text=True, cwd=c["modelco"])
    return json.loads(out.stdout)


def test_owner_revocation_alone_refuses_export_infer_and_resume(run, tmp_path):
    # ENC-SF-2026-074 follow-up: an owner hands over a bundle holding only its
    # signed revocation. Alone, it has no program and so no ownership: the
    # report ignores it (the gap). Judged against the run's program, it revokes.
    owner, _ = revocation_only(run, tmp_path, "owner", "hospital-a", "patients-a")
    assert "patients-a" not in report_json(run, owner).get("revoked", {})
    before = run._ctx["bundle"].read_bytes()
    decision = run.export_adapter(revocations=[str(owner)])
    assert "EXPORT DENIED" in decision and "revoked patients-a" in decision, decision
    with pytest.raises(encompute.EncomputeError, match="revoked patients-a"):
        run.infer(dataset(3)[0][:2], revocations=[str(owner)])
    with pytest.raises(encompute.EncomputeError, match="revoked patients-a"):
        run.resume(str(run.workdir / "modelco" / "checkpoints" / "round-2.enc"),
                   revocations=[str(owner)])
    with pytest.raises(encompute.EncomputeError, match="revoked patients-a"):
        ft.finetune(resume=str(run.workdir), revocations=[str(owner)], verbose=False)
    # The run's own bundle is untouched, and without the owner's bundle
    # nothing is refused for revocation.
    assert run._ctx["bundle"].read_bytes() == before
    assert "revoked" not in run.export_adapter()
    # A bundle that cannot be evaluated refuses rather than counting as
    # "nothing revoked".
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert "EXPORT DENIED" in run.export_adapter(revocations=[str(bad)])
    with pytest.raises(encompute.EncomputeError, match="could not be read"):
        run.infer(dataset(3)[0][:2], revocations=[str(bad)])
    with pytest.raises(encompute.EncomputeError, match="does not exist"):
        run.resume(str(run.workdir / "modelco" / "checkpoints" / "round-2.enc"),
                   revocations=[str(tmp_path / "missing.json")])


def test_non_owner_revocation_does_not_revoke_but_is_not_dropped(run, tmp_path):
    # Hospital-b validly signs a revocation of hospital-a's dataset.
    other, rid = revocation_only(run, tmp_path, "non-owner", "hospital-b", "patients-a",
                                 owns=True)
    # The trust report (TG-1): not honoured as a revocation, only noted.
    merged = json.loads(run._ctx["bundle"].read_text())
    theirs = json.loads(other.read_text())
    merged["nodes"].update(theirs["nodes"])
    merged["edges"] += theirs["edges"]
    m = tmp_path / "merged.json"
    m.write_text(json.dumps(merged))
    r = report_json(run, m)
    assert "patients-a" not in r.get("revoked", {})
    notes = [d for row in r["rows"] for d in row["details"]]
    assert any(rid in d and "hospital-b does not own patients-a" in d for d in notes), notes
    # The fine-tuning refusal path fails closed: an unhonoured revocation of
    # a parent stops export, inference and resume until it is resolved.
    decision = run.export_adapter(revocations=[str(other)])
    assert "EXPORT DENIED" in decision and "not honoured" in decision, decision
    assert "does not own patients-a" in decision, decision
    with pytest.raises(encompute.EncomputeError, match="not honoured"):
        run.infer(dataset(3)[0][:2], revocations=[str(other)])
    with pytest.raises(encompute.EncomputeError, match="not honoured"):
        run.resume(str(run.workdir / "modelco" / "checkpoints" / "round-2.enc"),
                   revocations=[str(other)])


def test_resume_matrix(run, tmp_path):
    ck = run.workdir / "modelco" / "checkpoints"
    latest, older = ck / "round-2.enc", ck / "round-1.enc"
    assert run.resume(str(latest))["round"] == 2              # normal
    with pytest.raises(encompute.EncomputeError, match="stale"):
        run.resume(str(older))                                 # older checkpoint
    real = run.run_id
    try:
        run.run_id = "0" * 64                                  # another run
        with pytest.raises(encompute.EncomputeError, match="another training run"):
            run.resume(str(latest))
    finally:
        run.run_id = real
    # A parent revoked: no resume.
    bundle = run._ctx["bundle"]
    saved = bundle.read_bytes()
    try:
        subprocess.run([CLI, "trust", "revoke", "--party", "hospital-b", "--key",
                        str(run.workdir / "hospital-b" / "party.key"), "--asset", "patients-b",
                        "--reason", "withdrawn", "--bundle", str(bundle)], check=True,
                       capture_output=True)
        with pytest.raises(encompute.EncomputeError, match="revoked patients-b"):
            run.resume(str(latest))
    finally:
        bundle.write_bytes(saved)


def test_determinism(run):
    # What is promised identical for identical inputs.
    m1, m2 = model(), model()
    assert digest(m1) == digest(m2)
    x, y = dataset(1)
    assert (_native.sha256_hex(tensors.dumps({"x": x, "y": y}))
            == _native.sha256_hex(tensors.dumps({"x": x.clone(), "y": y.clone()})))
    assert layout_digest(et.LoRAConfig()) == layout_digest(et.LoRAConfig())
    spec = run._ctx["spec"]
    assert _native.training_spec_id(spec) == run.training_spec_id
    # A new run of the same spec gets a new TrainingRunId.
    assert _native.training_run_id(spec, "a") != _native.training_run_id(spec, "b")
