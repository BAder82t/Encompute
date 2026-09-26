"""16: attacks on patient-level privacy, against the runs finetune.py made
in WORKDIR. Each is attempted for real, and each must fail closed.

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
from encompute.torch import finetune as ft, tensors, worker

W = Path(sys.argv[1])
P = W / "patient"
MC = P / "modelco"
CLI = ft._cli()
SPEC = (MC / "training-spec.json").read_text()
spec = json.loads(SPEC)
run = json.loads((P / "run.json").read_text())
KEY_A = str(P / "hospital-a" / "party.key")
HW = str(P / "hw.seed")
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


def keys(spec_json):
    return _native.acquire_training_keys(spec_json, f"http://127.0.0.1:{port}", ["base-model"],
                                         KEY_A, HW, ft.IMAGE)


def dp_variant(**changes):
    s = json.loads(SPEC)
    s["config"]["dp_sgd"].update(changes)
    return json.dumps(s)


try:
    keys(SPEC)  # the approved workload gets the key
    print("== Weaken DP-SGD inside the workload ==\n")
    for field, value, why in (
            ("noise_multiplier", "0.3", "less noise"),
            ("sampling_rate", "0.5", "a higher sampling rate (less amplification)"),
            ("per_example_clip", "100.0", "a larger per-patient clip"),
            ("privacy_unit", "record", "records as the unit instead of patients"),
            ("grouping", "none", "a patient's records left ungrouped")):
        attack(f"run DP-SGD with {why}",
               "key broker: every DP-SGD setting is in the TrainingSpecId",
               lambda f=field, v=value: keys(dp_variant(**{f: v})))

    def more_steps():
        s = json.loads(SPEC)
        s["config"]["local_steps"] = 10
        _native.training_spec_id(json.dumps(s))
    attack("take ten unaccounted local steps per round",
           "training spec: DP-SGD takes one accounted step per round", more_steps)

    def regroup():
        # Give every record its own patient ID: a patient with many records
        # would then be clipped once per record, not once.
        cfg = json.loads((P / "hospital-a" / "worker.json").read_text())
        t = tensors.loads((P / "hospital-a" / "dataset.bin").read_bytes())
        t["unit_ids"] = torch.arange(len(t["unit_ids"]))
        forged = P / "hospital-a" / "regrouped.bin"
        forged.write_bytes(tensors.dumps(t))
        worker.load_dataset(dict(cfg, dataset=str(forged)))
    attack("split each patient into one ID per record (escape per-patient clipping)",
           "worker: the dataset digest covers the patient IDs", regroup)

    def bypass_worker():
        # A hospital skips its attested worker and contributes an unclipped
        # vector with its own key: no attestation, so the round refuses it.
        big = P / "hospital-a" / "unclipped.json"
        big.write_text(json.dumps([1.0] * spec["config"]["adapter_parameters"]))
        j = subprocess.run(
            [CLI, "aggregate", "join", str(MC / "training.encompute"), "--parties",
             str(P / "parties.json"), "--plan", str(MC / "plan.json"),
             "--attestation-policy", run["contribution_policy"], "--coordinator",
             "http://127.0.0.1:9", "--party", "hospital-a", "--key", KEY_A,
             "--values", str(big), "--state", str(P / "attack.state"), "--timeout", "3"],
            capture_output=True, text=True)
        serve = subprocess.run(
            [CLI, "aggregate", "serve", "training.encompute", "--parties",
             str(P / "parties.json"), "--plan", "plan.json", "--key", "coord.key", "--listen",
             "127.0.0.1:0", "--sequence", "90", "--ledger", str(W / "evil-ledgers"), "--out",
             str(W / "evil.json"), "--receipt", str(W / "evil-r.json")],
            cwd=MC, capture_output=True, text=True)
        if serve.returncode:
            raise RuntimeError(serve.stderr.strip().splitlines()[-1])
        raise RuntimeError(j.stderr.strip().splitlines()[-1])
    attack("contribute an unclipped vector without the attested worker",
           "secure aggregation: DP-SGD rounds accept only attested contributors", bypass_worker)

    print("== Claim patient-level privacy without DP-SGD ==\n")
    project = encompute.Project("patient-private-lora",
                                parties=["hospital-a", "hospital-b", "modelco"],
                                purpose="disease-training")
    model = project.model("base-model", owner="modelco", policy="private-model")
    data = [project.data("patients-a", owner="hospital-a"),
            project.data("patients-b", owner="hospital-b")]
    eir = project._aggregation_program(data, "modelco", model, privacy="strong",
                                       unit="patient", dim=16, colluding=None)
    decl = json.dumps({"model": "base-model", "data": ["patients-a", "patients-b"],
                       "verified": True, "privacy_unit": "patient",
                       "per_example_clipping": False})
    infra = json.dumps({"tees": [{"tee": "mock", "provider": "mock", "cloud": True}],
                        "key_broker": True})

    def claim():
        plan, report, _ = _native.plan(eir, "standard", infra, decl,
                                       json.dumps({"allow_development": True}))
        if plan is None:
            raise RuntimeError(report.strip().splitlines()[-1])
    attack("label organization-level training as patient-level",
           "planner: patient-level privacy needs per-example clipping", claim)

    def sample_organizations():
        text = (MC / "training.eir").read_text().replace('unit "patient"',
                                                        'unit "organization"')
        _native.Model.compile(text)
    attack("Poisson-sample whole hospitals", "compiler: which parties contribute is public",
           sample_organizations)

    def forged_spec():
        mc = W / "forged"
        shutil.rmtree(mc, ignore_errors=True)
        shutil.copytree(MC, mc)
        s = json.loads(SPEC)
        del s["config"]["dp_sgd"]
        s["config"]["local_steps"] = 10
        for d in s["datasets"]:
            d.pop("privacy_units"), d.pop("grouping_digest")
        (mc / "forged.json").write_text(json.dumps(s))
        subprocess.run([CLI, "trust", "add", "forged.json", "--bundle", "trust.json"], cwd=mc,
                       check=True, capture_output=True)
        out = subprocess.run(
            [CLI, "trust", "report", "--bundle", "trust.json", "--parties",
             str(P / "parties.json"), "--coordinator-key", run["coord_key"], "--mock-root",
             run["mock_root"], "--execution-policy", str(mc / "training-policy.json")],
            cwd=mc, capture_output=True, text=True).stdout
        if "TRUST REQUIREMENTS NOT SATISFIED" in out:
            raise RuntimeError([x for x in out.splitlines() if "whole update" in x][0].strip())
    attack("record organization-level training under a patient-level program",
           "trust report: the Training row checks the privacy unit", forged_spec)

    print("== What stays true ==\n")
    print("  Poisson samples come from the worker's operating-system randomness: the model\n"
          "  owner's round seed does not choose them (test_poisson_sampling_uses_os_randomness).\n"
          "  Workers report no loss, sample size or clipping statistics.\n")
finally:
    broker.terminate()
    broker.wait()

if failed:
    print("ATTACKS SUCCEEDED:", failed)
    sys.exit(1)
print("ALL ATTACKS FAILED CLOSED")
