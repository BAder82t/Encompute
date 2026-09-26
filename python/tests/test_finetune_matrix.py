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
    for arch in ('{"factory":"other:f","kwargs":{}}', '{"factory":"m:f","kwargs":{"dim":8}}'):
        s = json.loads(json.dumps(spec))
        s["base_model"]["architecture"] = arch
        assert _native.training_spec_id(json.dumps(s)) != base


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
