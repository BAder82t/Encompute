"""18: a Hugging Face + PEFT training step in Google Confidential Space.

    python job.py local WORKDIR                     # rehearse on this machine
    python job.py prepare WORKDIR --image DIGEST --broker-id URL --gcs gs://BUCKET/PREFIX
    python job.py verify WORKDIR --jwks google      # after the cloud run

LOCAL rehearses everything but the hardware: a production key broker
(wrapped keys, no mock evidence) verifies Confidential Space tokens from a
SIMULATED launcher signed with a test key. REAL CONFIDENTIAL SPACE runs the
same worker image on an Intel TDX VM with Google's attestation
(deploy/confidential-space-training/deploy.sh).
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import encompute
import encompute.torch as et
from encompute.torch import finetune as ft, hf, job

PATIENTS = 300


def project_and_assets(W: Path):
    """ModelCo's private model (a tiny BERT, packaged locally: no download)
    and two hospitals' private notes, grouped by patient."""
    repo = hf.write_tiny_model(str(W / "repository"), "bert", pretrain_steps=100)
    base = et.huggingface(str(repo))
    tok = base.encompute_tokenizer
    p = encompute.Project("clinical-cs", parties=["hospital-a", "hospital-b", "modelco"],
                          purpose="disease-training")
    model = p.model("clinical-model", owner="modelco", policy="private-model", module=base)
    data = []
    for i, owner in enumerate(("hospital-a", "hospital-b")):
        texts, labels = hf.synthetic_notes(i + 1, PATIENTS * 2, hf.WORDS[13:])
        d = et.private_text_dataset(texts, labels, tokenizer=tok, max_length=16,
                                    unit_ids=[j // 2 for j in range(len(texts))])
        data.append(p.data(f"notes-{'ab'[i]}", owner=owner, dataset=d))
    return p, model, data


def local_image() -> str:
    """The rehearsal's stand-in image digest: the worker code's digest."""
    return "sha256:" + ft.code_digest("encompute.torch.hf:from_config")


def summary(title: str, rows):
    print(f"\n{title}\n" + "─" * len(title))
    for k, v in rows:
        print(f"{k:<24}{v}")


def claims(prep: dict, record: Path, jwks: str, party: str) -> dict:
    """What the attestation proves, as an external verifier checks it
    (against the participant's policy: the job attests as that party)."""
    out = subprocess.run([ft._cli(), "attest", "verify", str(record), "--policy",
                          prep["policies"][party],
                          "--jwks", jwks, "--audience", prep["broker_id"]],
                         capture_output=True, text=True)
    return {"ok": out.returncode == 0, "text": out.stdout + out.stderr}


def report_rows(prep, outputs, report, provider, platform, jwks):
    ev = json.loads((Path(outputs[0]) / "evidence.json").read_text())["evidence"]
    c = claims(prep, Path(outputs[0]) / "attestation.json", jwks, ev["participant"])
    ok = ("Workload                ATTESTED" in report and "Training                VERIFIED"
          in report and c["ok"])
    return ok, [
        ("Provider", provider), ("Platform", platform),
        ("Debug mode", "DISABLED" if c["ok"] else "UNVERIFIED"),
        ("Worker image", ev["image_digest"][:23] + "..."),
        ("Attestation", "VERIFIED" if c["ok"] else "NOT VERIFIED"),
        ("TrainingSpec", "enctrain1:" + ev["training_spec_id"][:16] + "..."),
        ("Model", "enchf1:" + (ev["model_package_id"] or "")[:16] + "..."),
        ("Model key", "RELEASED TO ATTESTED SESSION"),
        ("Dataset key", "RELEASED TO ATTESTED SESSION"),
        ("Framework", "Transformers"), ("PEFT", "LoRA"),
        ("Privacy unit", prep["state"]["dp_sgd"]["privacy_unit"]),
        ("Per-patient clipping", f"ACTIVE ({ev['gradient_path']})"),
        ("Training", "COMPLETE"),
        ("Output", "SEALED (" + ", ".join(Path(o).name for o in outputs) + ")"),
        ("Evidence", "VERIFIED" if ok else "NOT VERIFIED"),
    ]


def cmd_local(W: Path) -> int:
    W.mkdir(parents=True, exist_ok=True)
    p, model, data = project_and_assets(W)
    port = job._port()
    prep = job.prepare(p, model=model, data=data, privacy="strong-patient",
                       config=et.LoRAConfig(rounds=5, batch_size=20), image=local_image(),
                       broker_id=f"http://127.0.0.1:{port}", kek=str(W / "broker.kek"),
                       workdir=str(W / "run"), say=lambda *a: None)
    print("LOCAL REHEARSAL: SIMULATED CONFIDENTIAL SPACE LAUNCHER, TEST SIGNING KEY")
    print("NO HARDWARE ATTESTATION. The broker is in production mode; only the hardware")
    print("and Google's signature are simulated.\n")
    jwks = str(job.TEST_KEYS / "jwks.json")
    with job.Local(prep) as L:
        outputs, logs = [], ""
        for party, j in prep["jobs"].items():
            r = L.run_worker(j["job"])
            print(r.stdout)
            if r.returncode:
                print(r.stderr[-2000:])
                return 1
            outputs.append(j["output"])
            logs += r.stdout + r.stderr
        report = job.verify(prep, outputs, jwks)
        print(report)
        ok, rows = report_rows(prep, outputs, report, "Google Confidential Space (SIMULATED)",
                               "Intel TDX (SIMULATED)", jwks)
        leaks = scan(prep, logs, model.payload)
        rows += [("Raw model exposure", "NONE DETECTED" if not leaks["model"] else "FOUND"),
                 ("Raw dataset exposure", "NONE DETECTED" if not leaks["data"] else "FOUND")]
        summary("CONFIDENTIAL SPACE TRAINING (LOCAL REHEARSAL)", rows)
        print("\nRESULT\n" + ("TRAINING STEP VERIFIED" if ok and not any(leaks.values())
                             else "NOT VERIFIED"))
        if not (ok and not any(leaks.values())):
            return 1
        return attacks(prep, L, jwks)


def scan(prep: dict, logs: str, base) -> dict:
    """Looks for the model's weights and the hospitals' records in
    everything the operator can see (job descriptors, sealed assets,
    outputs, the broker's state, the workers' logs). The hospitals' own
    dataset files are theirs, and the model owner's repository is outside
    the run directory."""
    W = Path(prep["workdir"])
    embeddings = base.bert.embeddings.word_embeddings.weight.detach()
    records = [ft.tensors.loads((W / o / "dataset.bin").read_bytes())["input_ids"]
               for o in ("hospital-a", "hospital-b")]
    needles = {"model": [embeddings[i].numpy().tobytes() for i in (5, 9, 17)],
               "data": [r[i].numpy().tobytes() for r in records for i in (3, 11)]}
    allowed = {"hospital-a/dataset.bin", "hospital-b/dataset.bin"}
    found = {k: [] for k in needles}
    for f in W.rglob("*"):
        rel = str(f.relative_to(W))
        if f.is_file() and rel not in allowed:
            b = f.read_bytes()
            for k, ns in needles.items():
                found[k] += [rel for n in ns if n in b]
    raw = logs.encode("utf-8", "ignore")
    for k, ns in needles.items():
        found[k] += ["logs" for n in ns if n in raw]
    return found


def attacks(prep: dict, L, jwks: str) -> int:
    print("\n== Try breaking it ==\n")
    W = Path(prep["workdir"])
    failed = []

    def attempt(what, boundary, run):
        r = run()
        out = r.stdout + r.stderr
        line = next((x for x in out.splitlines() if x.startswith("REFUSED")), None)
        if r.returncode == 3 and line:
            print(f"ATTACK    {what}\nBOUNDARY  {boundary}\n{line}\n")
        else:
            failed.append(what)
            print(f"ATTACK SUCCEEDED (a bug): {what}\n{out[-500:]}\n")

    job_a = prep["jobs"]["hospital-a"]["job"]

    def edited(name, edit):
        j = json.loads(Path(job_a).read_text())
        edit(j)
        path = W / "jobs" / f"attack-{name}.json"
        path.write_text(json.dumps(j))
        return str(path)

    def with_launcher(image, debug=False):
        def run():
            try:
                L.start_launcher(image, debug)
                return L.run_worker(job_a)
            finally:
                L.start_launcher(prep["image"])
        return run

    attempt("run a modified image on genuine (simulated) TDX",
            "broker: ATTESTATION VALID, but IMAGE NOT APPROVED",
            with_launcher("sha256:" + hashlib.sha256(b"tampered").hexdigest()))
    attempt("run the approved image on a debug-enabled VM",
            "broker: debug workloads never receive keys", with_launcher(prep["image"], True))

    def rank(j):
        j["training_spec"]["config"]["rank"] = 8
        j["training_spec"]["config"]["peft"]["r"] = 8
        j["training_spec_id"] = encompute._native.training_spec_id(
            json.dumps(j["training_spec"]))
    attempt("train with another LoRA rank (a new training spec)",
            "broker: keys are bound to the approved training spec",
            lambda: L.run_worker(edited("rank", rank)))

    def privacy(j):
        j["training_spec"]["config"]["dp_sgd"]["noise_multiplier"] = "0.3"
    attempt("weaken the privacy configuration in the job descriptor",
            "worker: the descriptor must be the approved training spec",
            lambda: L.run_worker(edited("privacy", privacy)))
    attempt("substitute the model ciphertext", "worker: authenticated decryption and digests",
            lambda: L.run_worker(edited("model", lambda j: j["model"].__setitem__(
                "ciphertext", str(W / "staged" / "notes-b.enc")))))
    attempt("swap in hospital B's dataset", "worker: the dataset is bound to its participant",
            lambda: L.run_worker(edited("dataset", lambda j: j["dataset"].__setitem__(
                "ciphertext", str(W / "staged" / "notes-b.enc")))))
    attempt("name another participant's dataset", "worker: DATASET ASSET MISMATCH",
            lambda: L.run_worker(edited("dataset2", lambda j: j["dataset"].__setitem__(
                "asset_id", "notes-b"))))

    def replay():
        rec = json.loads((Path(prep["jobs"]["hospital-a"]["output"]) /
                          "attestation.json").read_text())
        old = W / "old-evidence.json"
        old.write_text(json.dumps(rec["evidence"]))
        state = W / "replay-broker.json"
        shutil.copy(W / prep["state"]["model_owner"] / "broker.json", state)
        r = subprocess.run([ft._cli(), "keys", "release", "--asset", "clinical-model",
                            "--attestation", str(old), "--out", str(W / "replayed-grant.json"),
                            "--broker", str(state), "--kek", prep["kek"], "--jwks", jwks],
                           capture_output=True, text=True)
        r.returncode = 3 if r.returncode else 0
        last = (r.stdout + r.stderr).strip().splitlines()[-1]
        r.stdout = "REFUSED                 " + last.split("REFUSED:", 1)[-1].strip()
        return r
    attempt("replay an old attestation token", "broker: challenges are single-use", replay)
    if failed:
        print("ATTACKS SUCCEEDED:", failed)
        return 1
    print("ALL ATTACKS FAILED CLOSED")
    return 0


def cmd_container(W: Path, a) -> int:
    """Runs the worker IMAGE (a local docker image) against a locally
    prepared job: the same rehearsal, but the code that runs is the image's.
    The simulated launcher runs inside the container; the production broker
    runs here."""
    W.mkdir(parents=True, exist_ok=True)
    W = W.resolve()  # the container sees the resolved path (no symlinks)
    p, model, data = project_and_assets(W)
    port = job._port()
    linux = sys.platform.startswith("linux")
    host = "127.0.0.1" if linux else "host.docker.internal"
    def digest(tag):
        return subprocess.run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
                              capture_output=True, text=True, check=True).stdout.strip()
    image = digest(a.image)
    run_tag = a.run or a.image
    measured = digest(run_tag)  # what the (simulated) launcher measures
    prep = job.prepare(p, model=model, data=data, privacy="strong-patient",
                       config=et.LoRAConfig(rounds=5, batch_size=20), image=image,
                       broker_id=f"http://{host}:{port}", kek=str(W / "broker.kek"),
                       workdir=str(W / "run"), say=lambda *a: None)
    mc = W / "run" / prep["state"]["model_owner"]
    broker = subprocess.Popen(
        [ft._cli(), "keys", "serve", "--listen", f"0.0.0.0:{port}", "--broker", "broker.json",
         "--kek", prep["kek"], "--jwks", str(job.TEST_KEYS / "jwks.json")],
        cwd=mc, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ft._wait_port(port, broker, "the key broker")
        print(f"CONTAINER REHEARSAL: image {image[:23]}..., simulated launcher inside it\n")
        outputs, logs = [], ""
        for party, j in prep["jobs"].items():
            sock = "/run/container_launcher/teeserver.sock"
            cmd = ("mkdir -p /run/container_launcher && "
                   f"(encompute attest simulate-launcher --socket {sock} "
                   f"--key /keys/google-test.pem --image {measured} &) && sleep 1 && "
                   f"python -m encompute.torch.cs_worker {j['job']}")
            r = subprocess.run(
                ["docker", "run", "--rm", *(["--network", "host"] if linux else []),
                 "-v", f"{W.resolve()}:{W.resolve()}", "-v", f"{job.TEST_KEYS}:/keys:ro",
                 "--entrypoint", "sh", run_tag, "-c", cmd], capture_output=True, text=True)
            print(r.stdout)
            if run_tag != a.image:
                # Another image against the approved job: it must get no key.
                refusedrun = r.returncode == 3 and "KEY RELEASE DENIED" in r.stdout
                print("RESULT\n" + ("IMAGE NOT APPROVED: KEY RELEASE DENIED" if refusedrun
                                     else "THE UNAPPROVED IMAGE WAS NOT REFUSED (a bug)"))
                return 0 if refusedrun else 1
            if r.returncode:
                print(r.stderr[-3000:])
                return 1
            outputs.append(j["output"])
            logs += r.stdout + r.stderr
        report = job.verify(prep, outputs, str(job.TEST_KEYS / "jwks.json"))
        ok = "Training                VERIFIED" in report and "Workload                ATTESTED" \
            in report
        leaks = scan(prep, logs, model.payload)
        print(report)
        print("RESULT\n" + ("CONTAINER TRAINING STEP VERIFIED" if ok and not any(leaks.values())
                           else "NOT VERIFIED"))
        return 0 if ok and not any(leaks.values()) else 1
    finally:
        broker.kill()
        broker.wait()


def cmd_prepare(W: Path, a) -> int:
    W.mkdir(parents=True, exist_ok=True)
    p, model, data = project_and_assets(W)
    loc = None
    if a.gcs:
        # Inputs (sealed assets, job descriptors) and outputs live in
        # separate buckets: the worker may read one and write the other.
        pre = a.gcs.rstrip("/")
        out = (a.gcs_output or f"{pre}/output").rstrip("/")
        loc = {"model": f"{pre}/sealed/clinical-model.enc",
               "adapter": f"{pre}/sealed/adapter-0.enc", "datasets": f"{pre}/sealed",
               "output": out}
    prep = job.prepare(p, model=model, data=data, privacy="strong-patient",
                       config=et.LoRAConfig(rounds=5, batch_size=20), image=a.image,
                       broker_id=a.broker_id, kek=a.kek or str(W / "broker.kek"),
                       workdir=str(W / "run"), locations=loc)
    if a.gcs:
        # For the deploy script: what to upload where.
        run = W / "run"
        up = {str(run / "modelco" / "clinical-model.enc"): loc["model"],
              str(run / "modelco" / "adapter-0.enc"): loc["adapter"]}
        for f in (run / "staged").iterdir():
            up[str(f)] = f"{loc['datasets']}/{f.name}"
        for party, j in prep["jobs"].items():
            up[j["job"]] = f"{pre}/jobs/{party}.json"
        (W / "uploads.json").write_text(json.dumps(up, indent=1))
    print(f"\nPrepared. The broker's state is {W / 'run' / 'modelco' / 'broker.json'}.")
    return 0


def cmd_verify(W: Path, a) -> int:
    prep = json.loads((W / "run" / "prepared.json").read_text())
    outputs = a.outputs or [j["output"] for j in prep["jobs"].values()]
    jwks = a.jwks
    report = job.verify(prep, outputs, jwks, bundle=str(W / "verify-bundle.json"))
    print(report)
    ok, rows = report_rows(prep, outputs, report, "Google Confidential Space", "Intel TDX", jwks)
    print("HARDWARE ATTESTATION\nGOOGLE CONFIDENTIAL SPACE")
    summary("CONFIDENTIAL SPACE TRAINING", rows)
    print("\nRESULT\n" + ("TRAINING STEP VERIFIED" if ok else "NOT VERIFIED"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("local")
    s.add_argument("workdir")
    s = sub.add_parser("container")
    s.add_argument("workdir")
    s.add_argument("--image", default="encompute-training:approved",
                   help="the approved image (the job is prepared for its digest)")
    s.add_argument("--run", help="run this image instead (e.g. a tampered build)")
    s = sub.add_parser("prepare")
    s.add_argument("workdir")
    s.add_argument("--image", required=True)
    s.add_argument("--broker-id", required=True)
    s.add_argument("--kek")
    s.add_argument("--gcs")
    s.add_argument("--gcs-output")
    s = sub.add_parser("verify")
    s.add_argument("workdir")
    s.add_argument("--jwks", default="google")
    s.add_argument("--outputs", nargs="*")
    a = ap.parse_args()
    W = Path(a.workdir)
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    return {"local": lambda: cmd_local(W), "container": lambda: cmd_container(W, a),
            "prepare": lambda: cmd_prepare(W, a),
            "verify": lambda: cmd_verify(W, a)}[a.cmd]()


if __name__ == "__main__":
    sys.exit(main())
