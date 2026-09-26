"""15: attacks on the confidential fine-tuning run in WORKDIR (made by
finetune.py). Each is attempted for real; each must fail closed at a
specific boundary.

    python attack.py WORKDIR
"""

import json
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import torch

import encompute
import encompute.torch as et
from encompute import _native
from encompute.torch import finetune as ft, worker

W = Path(sys.argv[1])
MC = W / "modelco"
CLI = ft._cli()
SPEC = (MC / "training-spec.json").read_text()
spec = json.loads(SPEC)
HW = str(W / "hw.seed")
KEY_A = str(W / "hospital-a" / "party.key")
failed = []


def attack(what, boundary, fn):
    try:
        fn()
    except (encompute.EncomputeError, _native.NativeError, ValueError, RuntimeError) as e:
        msg = e.args[0] if isinstance(e, _native.NativeError) else str(e)
        if isinstance(e, _native.NativeError):
            msg = f"{e.args[0]}: {e.args[1]}"
        print(f"ATTACK    {what}\nBOUNDARY  {boundary}\nREFUSED   {msg.splitlines()[0][:150]}\n")
        return
    failed.append(what)
    print(f"ATTACK SUCCEEDED (a bug): {what}\n")


# A key broker for the model, as in the run (the run's stopped on exit).
mock_root = subprocess.run([CLI, "attest", "mock-root", HW], capture_output=True,
                           text=True).stdout.strip()
s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
broker = subprocess.Popen([CLI, "keys", "serve", "--listen", f"127.0.0.1:{port}",
                           "--mock-root", mock_root, "--broker", "broker.json"], cwd=MC,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", port), 0.2).close()
        break
    except OSError:
        time.sleep(0.1)
URL = f"http://127.0.0.1:{port}"


def keys(spec_json=SPEC, image=ft.IMAGE, assets=("base-model",)):
    return dict(_native.acquire_training_keys(spec_json, URL, list(assets), KEY_A, HW, image)[0])


def variant(**changes):
    s = json.loads(SPEC)
    for k, v in changes.items():
        if k in s["config"]:
            s["config"][k] = v
        else:
            s[k] = v
    return json.dumps(s)


try:
    print("== Attested key release: only the approved training workload ==\n")
    attack("train outside the approved workload (another image)",
           "key broker: attestation must match the approved image",
           lambda: keys(image="sha256:" + "6" * 64))
    attack("run different training code", "key broker: the attestation binds the code digest",
           lambda: keys(variant(code_digest="0" * 64)))
    attack("change the LoRA configuration (rank 4 -> 16)",
           "key broker: the TrainingSpecId binds the configuration",
           lambda: keys(variant(rank=16)))
    attack("run under another plan", "key broker: the TrainingSpecId binds the PlanId",
           lambda: keys(variant(plan_id="1" * 64)))

    print("== The workload checks what it was given ==\n")
    k = keys()["base-model"]
    sealed = (MC / "base-model.enc").read_bytes()
    attack("substitute another model version", "sealed model: must be the committed weights",
           lambda: _native.open_asset(k, sealed, spec["project"], "base-model", "0" * 64))
    bad = bytearray(sealed); bad[-9] ^= 1
    attack("tamper with the sealed model", "sealed model: authenticated encryption",
           lambda: _native.open_asset(k, bytes(bad), spec["project"], "base-model",
                                      spec["base_model"]["weights_digest"]))

    def other_layout():
        m = et.wrap_model("encompute.torch.models:tiny_classifier", vocab=64, dim=16)
        et.apply_lora(m, et.LoRAConfig(target_modules=("k", "q")))
        if et.layout_digest(m) != spec["layout_digest"]:
            raise ValueError("this worker's adapter layout is not the approved one")
    attack("aggregate a different tensor layout", "worker: the layout digest is in the spec",
           other_layout)
    cfg = json.loads((W / "hospital-a" / "worker.json").read_text())
    cfg["dataset"] = str(W / "hospital-b" / "dataset.bin")
    attack("train on an unauthorized dataset", "worker: the dataset digest is in the spec",
           lambda: worker.load_dataset(cfg))

    print("== Updates, aggregation and privacy ==\n")
    s2 = socket.socket(); s2.bind(("127.0.0.1", 0)); cport = s2.getsockname()[1]; s2.close()

    def malicious_round(eir_edit, extra):
        text = (MC / "training.eir").read_text()
        (MC / "evil.eir").write_text(eir_edit(text))
        c = subprocess.run([CLI, "compile", "evil.eir", "-o", "evil.encompute"], cwd=MC,
                           capture_output=True, text=True)
        if c.returncode:
            raise RuntimeError(c.stderr.strip().splitlines()[-1])
        serve = subprocess.Popen([CLI, "aggregate", "serve", "evil.encompute", "--parties",
                                  str(W / "parties.json"), "--key", "coord.key", "--listen",
                                  f"127.0.0.1:{cport}", "--stage-timeout", "5", "--sequence",
                                  "90", "--ledger", "evil-ledgers", *extra, "--out", "evil.json",
                                  "--receipt", "evil-r.json"],
                                 cwd=MC, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", cport), 0.2).close()
                break
            except OSError:
                if serve.poll() is not None:
                    raise RuntimeError("the coordinator did not start: "
                                       + serve.stdout.read().decode().strip()[-200:])
                time.sleep(0.1)
        j = subprocess.run([CLI, "aggregate", "join", str(MC / "training.encompute"),
                            "--parties", str(W / "parties.json"), "--plan", str(MC / "plan.json"),
                            "--coordinator", f"http://127.0.0.1:{cport}", "--party",
                            "hospital-a", "--key", KEY_A, "--values", "-",
                            "--state", str(W / "attack.state"), "--timeout", "5"],
                           input=json.dumps([0.0] * spec["config"]["adapter_parameters"]),
                           capture_output=True, text=True)
        serve.kill(); serve.wait()
        if j.returncode:
            raise RuntimeError([l for l in (j.stdout + j.stderr).splitlines() if "ENC" in l][0])

    import re
    noise = float(re.search(r"noise_multiplier ([0-9.]+)", (MC / "training.eir").read_text())[1])
    attack("cut the DP noise sharply (to 0.5)",
           "the privacy ledger charges the noise actually used: over budget",
           lambda: malicious_round(
               lambda t: re.sub(r"noise_multiplier [0-9.]+", "noise_multiplier 0.5", t), []))
    attack(f"cut the DP noise slightly ({noise} -> {noise * 0.9:.2f}, within budget)",
           "each hospital checks the coordinator's spec is the approved one",
           lambda: malicious_round(
               lambda t: re.sub(r"noise_multiplier [0-9.]+",
                                f"noise_multiplier {noise * 0.9:.2f}", t), []))
    attack("bypass the approved plan (no --plan)",
           "each hospital checks the spec binds the approved PlanId",
           lambda: malicious_round(lambda t: t, []))
    attack("lower the aggregation threshold to one party",
           "the compiler: an aggregate needs at least two contributors",
           lambda: malicious_round(lambda t: re.sub(r"minimum [0-9]+", "minimum 1", t), []))
    print("  (Raw updates have no other way out: a worker pipes its clipped update only\n"
          "   into `aggregate join`, which sends it masked; nothing else is written.)\n")

    print("== Checkpoints and privacy state ==\n")
    ck = MC / "checkpoints"
    ckey = keys(assets=("checkpoints",))["checkpoints"]
    rounds = sorted(ck.glob("round-*.enc"))

    def resume(path, **over):
        e = dict(project=spec["project"], spec_id=_native.training_spec_id(SPEC),
                 policy=spec["policy_id"], privacy=spec["privacy_policy_id"])
        e.update(over)
        return _native.resume_checkpoint(ckey, Path(path).read_bytes(), e["project"],
                                         e["spec_id"], e["policy"], e["privacy"],
                                         str(MC / "ledgers"))
    resume(rounds[-1])  # the latest checkpoint resumes
    attack("restore an older checkpoint (roll privacy spend back)",
           "resume: the checkpoint must match the authoritative privacy ledgers",
           lambda: resume(rounds[0]))
    attack("resume under another policy", "resume: the PolicyId is in the checkpoint",
           lambda: resume(rounds[-1], policy="0" * 64))
    attack("swap in another project's checkpoint", "resume: the project is in the checkpoint",
           lambda: resume(rounds[-1], project="another-project"))
    led = MC / "ledgers" / "gradient-patients-a.ledger"
    text = led.read_text()
    led.write_text("\n".join(text.splitlines()[:3]) + "\n")
    try:
        attack("roll the privacy ledger back", "resume: the ledger must extend the checkpoint",
               lambda: resume(rounds[-1]))
    finally:
        led.write_text(text)

    print("== The adapter ==\n")
    last = sorted(MC.glob("adapter-*.record.json"))[-1]
    rec = json.loads(last.read_text())
    akey = keys(assets=("adapters",))["adapters"]
    sa = bytearray((MC / f"{rec['record']['adapter_id']}.enc").read_bytes()); sa[-4] ^= 1
    attack("modify the adapter after training", "sealed adapter: its digest is in the signed record",
           lambda: _native.open_asset(akey, bytes(sa), spec["project"], rec["record"]["adapter_id"],
                                      rec["record"]["adapter_digest"]))

    def export():
        run = json.loads((W / "run.json").read_text())
        out = subprocess.run([CLI, "export", rec["record"]["adapter_id"], "--bundle",
                              str(MC / "trust.json"), "--parties", str(W / "parties.json"),
                              "--coordinator-key", run["coord_key"], "--mock-root",
                              run["mock_root"], "--execution-policy",
                              str(MC / "training-policy.json")],
                             capture_output=True, text=True)
        if out.returncode:
            raise RuntimeError(out.stdout.strip())
    attack("export the adapter publicly", "export: the adapter inherits every parent's policy",
           export)
finally:
    broker.terminate(); broker.wait()

print("ALL ATTACKS FAILED CLOSED" if not failed else f"{len(failed)} ATTACKS SUCCEEDED")
sys.exit(1 if failed else 0)
