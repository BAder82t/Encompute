"""Hugging Face Transformers + PEFT for confidential fine-tuning.

- Import: packages are content-addressed; revisions are immutable; only
  safetensors, configuration and tokenizer files enter; remote code and
  pickles are refused; credentials are never stored.
- PEFT: the adapter layout is canonical and identical everywhere; every
  PEFT setting changes it or the training spec.
- Text datasets: tokenization and chunking keep each record's patient.
- Per-patient gradients: the fast (vmap) and reference paths agree with a
  one-record-at-a-time reference; a model with no per-unit gradients fails
  closed.
- End to end: a patient-level DP-SGD run of a PEFT model is trusted, binds
  the package, exports standard PEFT files only when permitted, and they
  load with plain Transformers and PEFT.
"""

import json
import shutil
import subprocess

import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("transformers")
pytest.importorskip("peft")

import encompute  # noqa: E402
import encompute.torch as et  # noqa: E402
from encompute import _native  # noqa: E402
from encompute.torch import dpsgd, finetune as ft, hf, lora, tasks, worker  # noqa: E402

SEQ = tasks.SEQUENCE_CLASSIFICATION
RISK = hf.WORDS[13:]


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    return hf.write_tiny_model(str(tmp_path_factory.mktemp("hf") / "tiny-bert"), "bert",
                               pretrain_steps=50)


@pytest.fixture(scope="module")
def distil(tmp_path_factory):
    return hf.write_tiny_model(str(tmp_path_factory.mktemp("hf") / "tiny-distilbert"),
                               "distilbert", pretrain_steps=0)


def refused(fn, match=None):
    with pytest.raises(encompute.EncomputeError) as e:
        fn()
    assert e.value.code == "ENC2504", e.value
    if match:
        assert match in str(e.value), str(e.value)


# --- import ---------------------------------------------------------------------


def test_packages_are_content_addressed(repo, tmp_path):
    a = hf.import_model(str(repo))
    b = hf.import_model(str(repo))
    assert a.id == b.id and a.manifest["revision"].startswith("sha256:")
    assert [f["path"] for f in a.manifest["files"]] == sorted(
        ["config.json", "model.safetensors", "special_tokens_map.json", "tokenizer.json",
         "tokenizer_config.json", "vocab.txt"])
    # One changed byte in a weight shard is another package.
    other = tmp_path / "changed"
    shutil.copytree(repo, other)
    w = bytearray((other / "model.safetensors").read_bytes())
    w[-1] ^= 1
    (other / "model.safetensors").write_bytes(bytes(w))
    c = hf.import_model(str(other))
    assert c.id != a.id and c.manifest["revision"] != a.manifest["revision"]
    # A stated revision must be the content.
    refused(lambda: hf.import_model(str(other), revision=a.manifest["revision"]),
            "is not revision")


def test_tokenizer_changes_change_the_package(repo, tmp_path):
    a = hf.import_model(str(repo))
    for f, edit in (("vocab.txt", lambda t: t + "extra\n"),
                    ("tokenizer_config.json",
                     lambda t: json.dumps(dict(json.loads(t), model_max_length=7)))):
        other = tmp_path / f.replace(".", "-")
        shutil.copytree(repo, other)
        (other / f).write_text(edit((other / f).read_text()))
        b = hf.import_model(str(other))
        assert b.manifest["tokenizer_digest"] != a.manifest["tokenizer_digest"], f
        assert b.id != a.id


def test_unsafe_repositories_are_refused(repo, tmp_path):
    refused(lambda: hf.import_model(str(repo), trust_remote_code=True), "trust_remote_code")
    cases = {
        "modeling_custom.py": ("write", "print('pwned')"),
        "pytorch_model.bin": ("write", "pickle"),
        "weights.pkl": ("write", "pickle"),
        "notes.txt": ("write", "hello"),
    }
    for name, (_, content) in cases.items():
        d = tmp_path / name.replace(".", "-")
        shutil.copytree(repo, d)
        (d / name).write_text(content)
        refused(lambda d=d: hf.import_model(str(d)))
    d = tmp_path / "auto-map"
    shutil.copytree(repo, d)
    cfg = json.loads((d / "config.json").read_text())
    cfg["auto_map"] = {"AutoModelForSequenceClassification": "custom.Model"}
    (d / "config.json").write_text(json.dumps(cfg))
    refused(lambda: hf.import_model(str(d)), "custom code")
    d = tmp_path / "pickle-only"
    shutil.copytree(repo, d)
    (d / "model.safetensors").unlink()
    refused(lambda: hf.import_model(str(d)), "safetensors")
    refused(lambda: hf.import_model(str(repo), task="causal-lm"))
    # A shard index may name only the package's own safetensors files.
    for target in ("../../../etc/passwd", "/etc/passwd", "pytorch_model.bin",
                   "missing.safetensors"):
        d = tmp_path / f"index-{abs(hash(target))}"
        shutil.copytree(repo, d)
        (d / "model.safetensors.index.json").write_text(json.dumps(
            {"metadata": {}, "weight_map": {"classifier.weight": "model.safetensors",
                                            "bert.pooler.dense.weight": target}}))
        refused(lambda d=d: hf.import_model(str(d)))
    d = tmp_path / "index-ok"
    shutil.copytree(repo, d)
    (d / "model.safetensors.index.json").write_text(json.dumps(
        {"metadata": {}, "weight_map": {"classifier.weight": "model.safetensors"}}))
    hf.import_model(str(d))
    # A mutable revision never validates.
    m = dict(hf.import_model(str(repo)).manifest, revision="main")
    with pytest.raises(_native.NativeError) as e:
        _native.hf_package_id(json.dumps(m))
    assert e.value.args[0] == "ENC2504"


def test_hub_revisions_resolve_and_credentials_are_never_stored(repo, monkeypatch):
    """The Hub path, offline: 'main' resolves to the commit, only allowed
    files are fetched, and the token is used for the download only."""
    import huggingface_hub
    commit = "a" * 40
    token = "hf_SECRET_token_0123456789"
    seen = {}

    class Sibling:
        def __init__(self, n):
            self.rfilename = n

    class Info:
        sha = commit
        card_data = {"license": "apache-2.0"}
        siblings = [Sibling(p.name) for p in repo.iterdir()] + [Sibling("README.md")]

    class Api:
        def model_info(self, repo_id, revision=None, token=None):
            seen["info"] = (repo_id, revision, token)
            return Info()

    def snapshot(repo_id, revision=None, allow_patterns=None, token=None, cache_dir=None):
        seen["snapshot"] = (revision, sorted(allow_patterns), token)
        return str(repo)

    monkeypatch.setattr(huggingface_hub, "HfApi", Api)
    monkeypatch.setattr(huggingface_hub, "snapshot_download", snapshot)
    pkg = hf.import_model("org/tiny-bert", token=token)
    assert seen["info"] == ("org/tiny-bert", "main", token)
    assert seen["snapshot"][0] == commit and "README.md" not in seen["snapshot"][1]
    assert pkg.manifest["revision"] == commit and pkg.manifest["license"] == "apache-2.0"
    blob = json.dumps(pkg.manifest) + "".join(p.read_bytes().decode("latin-1")
                                              for p in pkg.path.iterdir())
    assert token not in blob
    # A pinned commit that resolves to another is refused.
    refused(lambda: hf.import_model("org/tiny-bert", revision="b" * 40))


def test_library_versions_must_match_the_package(repo):
    pkg = hf.import_model(str(repo))
    hf.check_versions(pkg.manifest)
    installed = dict(hf.library_versions(), transformers="9.9")
    refused(lambda: hf.check_versions(pkg.manifest, installed), "transformers")


# --- PEFT and text --------------------------------------------------------------


def peft_model(repo, **kw):
    base = et.huggingface(str(repo))
    pc = hf.peft_config("bert", kw.get("rank", 4), 8, kw.get("targets", ("query", "value")))
    return hf.apply_peft(base, pc), pc


def test_the_peft_layout_is_canonical(repo):
    a, pc = peft_model(repo)
    b, _ = peft_model(repo)
    assert lora.layout_digest(a) == lora.layout_digest(b)
    names = [f"{e['module']}.{e['parameter']}" for e in lora.layout(a)]
    assert any("lora_A" in n for n in names) and any("modules_to_save" in n for n in names)
    assert all(not p.requires_grad for n, p in a.named_parameters()
               if n not in lora.adapter_parameters(a))
    # Rebuilt the way workers do, from the config and weights: the same.
    rebuilt = hf.from_config(et.huggingface(str(repo)).encompute_kwargs["config"])
    assert lora.layout_digest(hf.apply_peft(rebuilt, pc)) == lora.layout_digest(a)
    for kw in ({"rank": 8}, {"targets": ("query",)}, {"targets": ("key", "query", "value")}):
        assert lora.layout_digest(peft_model(repo, **kw)[0]) != lora.layout_digest(a), kw


def test_tokenization_keeps_each_patients_records_together(repo):
    tok = et.huggingface(str(repo)).encompute_tokenizer
    long_note = " ".join(hf.WORDS)  # longer than max_length: several chunks
    d = et.private_text_dataset(["fever cough", long_note, "calm"], [1, 1, 0], tokenizer=tok,
                                max_length=8, stride=2, unit_ids=[7, 7, 9])
    ids = d.tensors["unit_ids"].tolist()
    assert len(ids) > 3 and set(ids) == {7, 9} and ids.count(9) == 1
    assert d.preprocessing == {"tokenizer_digest": tok.digest, "max_length": 8,
                               "truncation": True, "padding": "max_length", "stride": 2}
    # Without unit IDs, a text's chunks are still one unit.
    d = et.private_text_dataset(["calm", long_note], [0, 1], tokenizer=tok, max_length=8,
                                stride=2)
    assert len(torch.unique(d.tensors["unit_ids"])) == 2 and len(d) > 2
    with pytest.raises(ValueError):
        et.private_text_dataset(["a"], [1], tokenizer=object())


def text_batch(repo, n=12):
    tok = et.huggingface(str(repo)).encompute_tokenizer
    texts, labels = hf.synthetic_notes(5, n, RISK)
    d = et.private_text_dataset(texts, labels, tokenizer=tok, max_length=16)
    return d.tensors


@pytest.mark.parametrize("which,attention,path", [
    ("bert", "eager", "vmap"), ("distilbert", "eager", "vmap"),
    # SDPA attention does not vectorize under vmap: the reference path.
    ("bert", "sdpa", "reference"), ("distilbert", "sdpa", "reference")])
def test_both_gradient_paths_match_the_reference(repo, distil, which, attention, path):
    from transformers import AutoModelForSequenceClassification
    model_dir = repo if which == "bert" else distil
    base = AutoModelForSequenceClassification.from_pretrained(str(model_dir),
                                                              attn_implementation=attention)
    m = hf.apply_peft(base, hf.peft_config(which, 4, 8, hf.TARGETS[which]))
    m.eval()
    batch = text_batch(model_dir)
    assert dpsgd.select_path(m, SEQ, batch) == path
    unit_of = torch.tensor([0, 0, 1, 1, 1, 2, 3, 3, 4, 5, 5, 5])
    sampled = torch.tensor([0, 1, 3, 5])
    ref = dpsgd.reference_clipped_sum(m, SEQ, batch, unit_of, sampled, 0.05)
    got = dpsgd.clipped_sum(m, SEQ, batch, unit_of, sampled, 0.05, microbatch=5, path=path)
    other = dpsgd.clipped_sum(m, SEQ, batch, unit_of, sampled, 0.05, path="reference")
    assert torch.allclose(got, ref, atol=1e-6) and torch.allclose(other, ref, atol=1e-6)


def test_no_per_unit_gradients_fails_closed(repo, monkeypatch):
    m, _ = peft_model(repo)

    def broken(*a, **k):
        raise RuntimeError("no gradient for you")
    monkeypatch.setattr(dpsgd, "unit_grad", broken)
    with pytest.raises(dpsgd.GradientsUnavailable, match="patient-level privacy cannot"):
        dpsgd.select_path(m, SEQ, text_batch(repo))


# --- end to end -------------------------------------------------------------------

try:
    CLI = ft._cli()
except encompute.EncomputeError:
    CLI = None


@pytest.fixture(scope="module")
def run(repo, tmp_path_factory):
    if CLI is None:
        pytest.skip("the encompute CLI is not built")
    base = et.huggingface(str(repo))
    tok = base.encompute_tokenizer
    p = encompute.Project("hf-lora", parties=["hospital-a", "hospital-b", "modelco"],
                          purpose="disease-training")
    m = p.model("clinical-model", owner="modelco", module=base, adapters="public")
    data = []
    for i, owner in enumerate(("hospital-a", "hospital-b")):
        texts, labels = hf.synthetic_notes(i + 1, 400, RISK)
        d = et.private_text_dataset(texts, labels, tokenizer=tok, max_length=16,
                                    unit_ids=[j // 2 for j in range(400)])
        data.append(p.data(f"notes-{'ab'[i]}", owner=owner, dataset=d, adapters="public"))
    W = tmp_path_factory.mktemp("hfrun") / "run"
    r = p.finetune(model=m, data=data, method="peft-lora", privacy="strong-patient",
                   allow_development=True, workdir=str(W), verbose=False,
                   config=et.LoRAConfig(rounds=2, batch_size=10, learning_rate=1.0))
    yield r, tok
    r.close()


def test_the_run_is_trusted_and_binds_the_package(run):
    r, tok = run
    assert r.satisfied and r.rounds == 2 and r.privacy_unit == "patient"
    spec = json.loads(r._ctx["spec"])
    pkg = spec["base_model"]["huggingface"]
    assert spec["config"]["method"] == "peft-lora"
    assert spec["config"]["peft"]["target_modules"] == ["query", "value"]
    assert spec["config"]["peft"]["modules_to_save"] == ["classifier"]
    assert all(d["preprocessing"]["tokenizer_digest"] == pkg["tokenizer_digest"]
               for d in spec["datasets"])
    lineage = r.lineage()
    assert "Hugging Face package" in lineage and pkg["revision"] in lineage
    assert "remote code      none" in lineage
    st = json.loads((r.workdir / "run.json").read_text())
    prov = st["provenance"][-1]
    assert prov["gradient_paths"] == {"hospital-a": "vmap", "hospital-b": "vmap"}
    assert prov["libraries"]["transformers"].startswith(pkg["libraries"]["transformers"])


def test_protected_inference_needs_no_export(run):
    r, tok = run
    texts, labels = hf.synthetic_notes(9, 20, RISK)
    logits = r.infer(et.private_text_dataset(texts, labels, tokenizer=tok, max_length=16))
    assert logits.shape == (20, 2)


def test_exported_adapters_load_with_standard_peft(run, repo, tmp_path):
    from peft import PeftModel
    from transformers import AutoModelForSequenceClassification
    r, tok = run
    out = tmp_path / "adapter"
    assert "EXPORT PERMITTED" in r.export_peft(str(out))
    assert {"adapter_config.json", "adapter_model.safetensors",
            "encompute-adapter.json"} <= {p.name for p in out.iterdir()}
    meta = json.loads((out / "encompute-adapter.json").read_text())
    assert meta["adapter_id"] == r.adapter_id and meta["training_spec_id"] == r.training_spec_id
    texts, labels = hf.synthetic_notes(10, 16, RISK)
    d = et.private_text_dataset(texts, labels, tokenizer=tok, max_length=16)
    plain = AutoModelForSequenceClassification.from_pretrained(str(repo))
    pm = PeftModel.from_pretrained(plain, str(out)).eval()
    with torch.no_grad():
        outside = pm(input_ids=d.tensors["input_ids"],
                     attention_mask=d.tensors["attention_mask"]).logits
    assert float((outside - r.infer(d)).abs().max()) < 1e-4


def test_export_after_revocation_writes_nothing(run, tmp_path):
    r, _ = run
    c = r._ctx
    real = c["bundle"]
    revoked = tmp_path / "revoked.json"
    revoked.write_bytes(real.read_bytes())
    subprocess.run([CLI, "trust", "revoke", "--party", "hospital-a", "--key",
                    str(r.workdir / "hospital-a" / "party.key"), "--asset", "notes-a",
                    "--reason", "consent withdrawn", "--bundle", str(revoked)], check=True,
                   capture_output=True)
    out = tmp_path / "adapter"
    try:
        c["bundle"] = revoked
        decision = r.export_peft(str(out))
    finally:
        c["bundle"] = real
    assert "revoked" in decision and not out.exists()


def test_private_adapters_are_never_exported(repo, tmp_path):
    """Without every owner's permission, the adapter stays protected."""
    fixtures = ft.Path(__file__).resolve().parents[2] / "crates" / "encompute-training" / \
        "tests" / "fixtures"
    with pytest.raises(_native.NativeError) as e:
        _native.check_export((fixtures / "program.eir").read_text(),
                             (fixtures / "spec.json").read_text(), "a-1")
    assert "EXPORT DENIED" in e.value.args[1]


def test_changed_settings_get_no_model_key(run):
    """Another revision, weight shard, tokenizer, PEFT configuration, rank or
    noise is another training spec: no model key."""
    r, _ = run
    c = r._ctx
    edits = {
        "revision": lambda s: s["base_model"]["huggingface"].__setitem__("revision", "c" * 40),
        "weights": lambda s: s["base_model"]["huggingface"]["files"][1].__setitem__(
            "sha256", "e" * 64),
        "targets": lambda s: (s["config"]["peft"].__setitem__("target_modules", ["query"]),
                              s["config"].__setitem__("target_modules", ["query"])),
        "rank": lambda s: (s["config"]["peft"].__setitem__("r", 8),
                           s["config"].__setitem__("rank", 8)),
        "noise": lambda s: s["config"]["dp_sgd"].__setitem__("noise_multiplier", "0.3"),
        "layout": lambda s: s.__setitem__("layout_digest", "0" * 64),
    }
    for what, edit in edits.items():
        s = json.loads(c["spec"])
        edit(s)
        with pytest.raises(_native.NativeError) as e:
            _native.acquire_training_keys(json.dumps(s), r._broker(), ["clinical-model"],
                                          str(c["modelco"] / "coord.key"), str(c["hw_seed"]),
                                          ft.IMAGE)
        assert e.value.args[0] in ("ENC2002", "ENC2504"), what


def test_workers_refuse_regrouped_or_ungrouped_text(run):
    r, _ = run
    cfg = json.loads((r.workdir / "hospital-a" / "worker.json").read_text())
    t = ft.tensors.loads((r.workdir / "hospital-a" / "dataset.bin").read_bytes())
    for name, edit in (("regrouped", lambda t: t.__setitem__(
                            "unit_ids", torch.arange(len(t["unit_ids"])))),
                       ("ungrouped", lambda t: t.pop("unit_ids"))):
        forged = dict(t)
        edit(forged)
        path = r.workdir / "hospital-a" / f"{name}.bin"
        path.write_bytes(ft.tensors.dumps(forged))
        with pytest.raises(ValueError, match="not the dataset"):
            worker.load_dataset(dict(cfg, dataset=str(path)))
