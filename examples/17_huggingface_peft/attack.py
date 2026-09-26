"""17: attacks on the confidential Hugging Face fine-tuning run in WORKDIR
(made by finetune.py). Each is attempted for real, and each must fail
closed at a documented boundary.

    python attack.py WORKDIR
"""

import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import torch

import encompute
from encompute import _native
from encompute.torch import finetune as ft, hf, tasks, tensors, worker

W = Path(sys.argv[1])
P = W / "run"
MC = P / "modelco"
REPO = W / "repository"
CLI = ft._cli()
SPEC = (MC / "training-spec.json").read_text()
spec = json.loads(SPEC)
run = json.loads((P / "run.json").read_text())
KEY_A = str(P / "hospital-a" / "party.key")
HW = str(P / "hw.seed")
MODEL = spec["base_model"]["asset_id"]
failed = []


def attack(what, boundary, fn):
    try:
        fn()
    except (encompute.EncomputeError, _native.NativeError, ValueError, RuntimeError) as e:
        msg = f"{e.args[0]}: {e.args[1]}" if isinstance(e, _native.NativeError) else str(e)
        print(f"ATTACK    {what}\nBOUNDARY  {boundary}\nREFUSED   {msg.splitlines()[0][:150]}\n")
        return
    failed.append(what)
    print(f"ATTACK SUCCEEDED (a bug): {what}\n")


s = socket.socket()
s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]
s.close()
broker = subprocess.Popen([CLI, "keys", "serve", "--listen", f"127.0.0.1:{port}",
                           "--mock-root", run["mock_root"], "--broker", "broker.json"], cwd=MC,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", port), 0.2).close()
        break
    except OSError:
        time.sleep(0.1)


def keys(spec_json=SPEC, image=ft.IMAGE, assets=(MODEL,)):
    return dict(_native.acquire_training_keys(spec_json, f"http://127.0.0.1:{port}",
                                              list(assets), KEY_A, HW, image)[0])


def variant(edit):
    s = json.loads(SPEC)
    edit(s)
    return json.dumps(s)


def copy_repo(name, edit):
    d = W / "attack-repos" / name
    shutil.rmtree(d, ignore_errors=True)
    shutil.copytree(REPO, d)
    edit(d)
    return d


try:
    keys()  # the approved workload gets the model key
    print("== The model package ==\n")
    attack("train on another model revision",
           "key broker: the training spec binds the resolved revision",
           lambda: keys(variant(lambda s: s["base_model"]["huggingface"].__setitem__(
               "revision", "c" * 40))))
    attack("swap one weight shard",
           "key broker: the training spec binds every file's digest",
           lambda: keys(variant(lambda s: s["base_model"]["huggingface"]["files"][1].__setitem__(
               "sha256", "e" * 64))))
    k = keys()[MODEL]
    sealed = bytearray((MC / f"{MODEL}.enc").read_bytes())
    sealed[-9] ^= 1
    attack("tamper with the sealed weights", "sealed model: authenticated encryption",
           lambda: _native.open_asset(k, bytes(sealed), spec["project"], MODEL,
                                      spec["base_model"]["weights_digest"]))

    def other_tokenizer():
        d = copy_repo("vocab", lambda d: (d / "vocab.txt").write_text(
            (d / "vocab.txt").read_text() + "injected\n"))
        tok = hf.import_model(str(d)).tokenizer()
        s = json.loads(SPEC)
        s["datasets"][0]["preprocessing"]["tokenizer_digest"] = tok.digest
        _native.training_spec_id(json.dumps(s))
    attack("tokenize a dataset with a changed vocabulary",
           "training spec: every dataset's tokenizer must be the package's", other_tokenizer)
    cfg_path = "tokenizer_config.json"
    attack("change the tokenizer configuration",
           "model package: the tokenizer digest covers its configuration",
           lambda: _native.training_spec_id(variant(
               lambda s: s["base_model"]["huggingface"]["files"][
                   [f["path"] for f in s["base_model"]["huggingface"]["files"]].index(cfg_path)
               ].__setitem__("sha256", "d" * 64))))
    attack("import with trust_remote_code=True",
           "import: remote code never runs in a confidential workload",
           lambda: hf.import_model(str(REPO), trust_remote_code=True))
    def auto_map(d):
        c = json.loads((d / "config.json").read_text())
        c["auto_map"] = {"AutoModel": "evil.Model"}
        (d / "config.json").write_text(json.dumps(c))
    attack("ship custom modeling code (auto_map)",
           "import: config.json may not name custom code",
           lambda: hf.import_model(str(copy_repo("auto-map", auto_map))))
    attack("supply pickled weights (pytorch_model.bin)",
           "import: only safetensors are accepted",
           lambda: hf.import_model(str(copy_repo("pickle", lambda d: (
               d / "pytorch_model.bin").write_bytes(b"\x80\x04 pickle")))))
    attack("point the shard index outside the package (../, absolute path)",
           "import: a shard index may name only the package's safetensors files",
           lambda: hf.import_model(str(copy_repo("index", lambda d: (
               d / "model.safetensors.index.json").write_text(json.dumps(
                   {"metadata": {}, "weight_map": {"classifier.weight": "../../../etc/passwd"}}
               ))))))
    attack("bind a mutable revision (main)",
           "model package: only a commit or a content digest",
           lambda: _native.hf_package_id(json.dumps(dict(
               spec["base_model"]["huggingface"], revision="main"))))

    print("== PEFT and the adapter ==\n")
    attack("change the PEFT target modules",
           "key broker: the training spec binds the PEFT configuration",
           lambda: keys(variant(lambda s: (s["config"]["peft"].__setitem__("target_modules",
                                                                            ["query"]),
                                           s["config"].__setitem__("target_modules",
                                                                   ["query"])))))
    attack("raise the LoRA rank", "key broker: the training spec binds the rank",
           lambda: keys(variant(lambda s: (s["config"]["peft"].__setitem__("r", 16),
                                           s["config"].__setitem__("rank", 16)))))

    def other_layout():
        s = json.loads(SPEC)
        s["config"]["peft"]["modules_to_save"] = []
        s["config"]["peft"]["target_modules"] = ["key", "query", "value"]
        s["config"]["target_modules"] = ["key", "query", "value"]
        weights = _native.open_asset(keys()[MODEL], (MC / f"{MODEL}.enc").read_bytes(),
                                     spec["project"], MODEL, spec["base_model"]["weights_digest"])
        tasks.build(s, weights, 0)
    attack("aggregate a different adapter layout",
           "worker: the layout digest is in the training spec", other_layout)
    attack("use the adapter with another base model",
           "key broker: the adapter's training spec names its base model",
           lambda: keys(variant(lambda s: s["base_model"].__setitem__("weights_digest",
                                                                      "a" * 64)),
                        assets=("adapters",)))
    ak = keys(assets=("adapters",))["adapters"]
    last = run.get("rounds") or max(int(p.stem.split("-")[1]) for p in MC.glob("adapter-*.enc"))
    attack("move the adapter into another project",
           "sealed adapter: bound to its project and adapter ID",
           lambda: _native.open_asset(ak, (MC / f"adapter-{last}.enc").read_bytes(),
                                      "another-project", f"adapter-{last}", "0" * 64))
    attack("take the private model without an approved workload",
           "key broker: only the attested training image receives keys",
           lambda: keys(image="sha256:" + "6" * 64))

    print("== Patient grouping and privacy ==\n")
    cfg = json.loads((P / "hospital-a" / "worker.json").read_text())
    data = tensors.loads((P / "hospital-a" / "dataset.bin").read_bytes())

    def forged(name, edit):
        t = dict(data)
        edit(t)
        path = P / "hospital-a" / f"{name}.bin"
        path.write_bytes(tensors.dumps(t))
        worker.load_dataset(dict(cfg, dataset=str(path)))
    attack("change patient IDs after tokenization (one per chunk)",
           "worker: the dataset digest covers the patient IDs",
           lambda: forged("regrouped", lambda t: t.__setitem__(
               "unit_ids", torch.arange(len(t["unit_ids"])))))
    attack("drop the patient grouping during chunking",
           "worker: the dataset digest covers the grouping",
           lambda: forged("ungrouped", lambda t: t.pop("unit_ids")))
    attack("reduce the DP noise", "key broker: the training spec binds the noise",
           lambda: keys(variant(lambda s: s["config"]["dp_sgd"].__setitem__(
               "noise_multiplier", "0.3"))))

    def no_per_example_clipping():
        project = encompute.Project("medical-text", parties=["hospital-a", "hospital-b",
                                                             "modelco"],
                                    purpose="disease-training")
        m = project.model("clinical-model", owner="modelco")
        d = [project.data("notes-a", owner="hospital-a"),
             project.data("notes-b", owner="hospital-b")]
        eir = project._aggregation_program(d, "modelco", m, privacy="strong", unit="patient",
                                           dim=16, colluding=None)
        plan, report, _ = _native.plan(
            eir, "standard", json.dumps({"tees": [{"tee": "mock", "provider": "mock",
                                                   "cloud": True}], "key_broker": True}),
            json.dumps({"model": "clinical-model", "data": ["notes-a", "notes-b"],
                        "verified": True, "privacy_unit": "patient",
                        "per_example_clipping": False,
                        "framework": "huggingface-sequence-classification"}),
            json.dumps({"allow_development": True}))
        if plan is None:
            raise RuntimeError(report.strip().splitlines()[-1])
    attack("fine-tune without per-patient clipping but claim patient privacy",
           "planner: patient-level privacy needs per-example clipping", no_per_example_clipping)
    attack("resume under another Transformers version",
           "worker: the package binds its library versions",
           lambda: hf.check_versions(spec["base_model"]["huggingface"],
                                     dict(hf.library_versions(), transformers="9.9")))

    print("== Export ==\n")

    def export_after_revocation():
        b = W / "revoked-trust.json"
        b.write_bytes((MC / "trust.json").read_bytes())
        subprocess.run([CLI, "trust", "revoke", "--party", "hospital-a", "--key", KEY_A,
                        "--asset", "notes-a", "--reason", "consent withdrawn", "--bundle",
                        str(b)], check=True, capture_output=True)
        out = subprocess.run(
            [CLI, "export", f"adapter-{last}", "--bundle", str(b), "--parties",
             str(P / "parties.json"), "--coordinator-key", run["coord_key"], "--mock-root",
             run["mock_root"], "--execution-policy", str(MC / "training-policy.json")],
            cwd=MC, capture_output=True, text=True)
        if out.returncode:
            raise RuntimeError((out.stdout + out.stderr).strip().splitlines()[0])
    attack("export the adapter after a hospital revokes its data",
           "export: no parent may be revoked", export_after_revocation)
finally:
    broker.terminate()
    broker.wait()

if failed:
    print("ATTACKS SUCCEEDED:", failed)
    sys.exit(1)
print("ALL ATTACKS FAILED CLOSED")
