"""Confidential training jobs on real confidential-computing hardware
(Google Confidential Space), and their local rehearsal.

    prep = job.prepare(project, model=m, data=[a, b], privacy="strong-patient",
                       image="sha256:...", broker_id="https://broker.example:8760",
                       kek="broker.kek", workdir="run")
    # stage prep["jobs"][party]["job"], the sealed assets and run the image in
    # Confidential Space (deploy/confidential-space-training), or rehearse:
    result = job.run_local(prep)

``prepare`` plans the run for an attested TEE (Intel TDX on Confidential
Space) and writes production artifacts:
- the training spec, and its attestation policy: this image digest, Intel
  TDX or AMD SEV-SNP, debugging forbidden, no mock evidence;
- a production key broker (keys wrapped under a key-encryption key)
  holding the model, dataset, adapter and output keys under that policy;
- the sealed model, adapter and datasets;
- one job descriptor per participant (public commitments only).

``run_local`` rehearses the job on this machine, in production mode except
for the hardware: the broker verifies Confidential Space tokens, but they
come from a simulated launcher signed with a test key (the broker trusts
only that key's JWKS). It proves the orchestration, not the hardware.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import finetune as ft, lora

ROOT = Path(__file__).resolve().parents[3]
TEST_KEYS = ROOT / "crates" / "encompute-attestation" / "tests" / "fixtures"


def _port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def prepare(project, *, model, data, privacy="strong-patient", config=None, image: str,
            broker_id: str, kek: str, workdir: str, round: int = 1,
            locations: Optional[Dict[str, str]] = None, say=print) -> Dict[str, Any]:
    """Prepares a confidential training job for ``image`` (the approved
    worker image digest). ``locations`` maps where the job reads and writes
    (``model``, ``adapter``, ``datasets`` prefix, ``output`` prefix);
    by default, paths under ``workdir``."""
    W = Path(workdir)
    W.mkdir(parents=True, exist_ok=True)
    cli = ft._cli()
    cfg = config or lora.LoRAConfig()
    target = {"image": image, "tee": "intel_tdx", "broker_id": broker_id, "kek": str(kek)}
    st = ft._setup(project, model, data, privacy, "required", cfg, None, False, W, cli, say,
                   target=target)
    spec = json.loads(st["spec"])
    mc = W / st["model_owner"]
    loc = dict(model=str(mc / f"{st['model_id']}.enc"), adapter=str(mc / "adapter-0.enc"),
               datasets=str(W / "staged"), output=str(W / "output"))
    loc.update(locations or {})
    jobs = {}
    for c in st["commitments"]:
        party = c["owner"]
        job = {
            "kind": "encompute.confidential-training-job.v1", "version": 1,
            "project": st["project"], "participant": party, "round": round,
            "training_spec": spec, "training_spec_id": st["training_spec_id"],
            "run_id": st["run_id"], "plan_id": spec["plan_id"], "policy_id": spec["policy_id"],
            "privacy_policy_id": spec["privacy_policy_id"],
            "model_package_id": st.get("package_id"),
            "model": {"asset_id": st["model_id"], "ciphertext": loc["model"]},
            "dataset": {"asset_id": c["asset_id"],
                        "ciphertext": f"{loc['datasets'].rstrip('/')}/{c['asset_id']}.enc"},
            "adapter": {"asset_id": "adapter-0", "digest": st["adapter0_digest"],
                        "ciphertext": loc["adapter"]},
            "broker": broker_id, "expected_image": image,
            "output": f"{loc['output'].rstrip('/')}/{party}",
            "lora": st["lora"], "seed": cfg.seed * 1000 + round * 10,
        }
        path = W / "jobs" / f"{party}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(job, indent=1))
        jobs[party] = {"job": str(path), "output": job["output"]}
    prep = {"workdir": str(W), "state": st, "jobs": jobs, "image": image, "broker_id": broker_id,
            "kek": str(kek), "policy": str(mc / "training-policy.json"),
            "policies": {c["owner"]: str(mc / f"training-policy-{c['owner']}.json")
                         for c in st["commitments"]}}
    (W / "prepared.json").write_text(json.dumps(prep, indent=1, default=str))
    return prep


class Local:
    """The rehearsal's services: the production broker and a simulated
    Confidential Space launcher (development only)."""

    def __init__(self, prep: dict, *, launcher_image: Optional[str] = None, debug: bool = False,
                 hwmodel: str = "GCP_INTEL_TDX"):
        self.prep = prep
        W = Path(prep["workdir"])
        self.mc = W / prep["state"]["model_owner"]
        self.cli = ft._cli()
        self.port = int(prep["broker_id"].rsplit(":", 1)[1].split("/")[0])
        self.broker = subprocess.Popen(
            [self.cli, "keys", "serve", "--listen", f"127.0.0.1:{self.port}", "--broker",
             "broker.json", "--kek", prep["kek"], "--jwks", str(TEST_KEYS / "jwks.json"),
             "--requests-per-minute", "1000"],
            cwd=self.mc, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ft._wait_port(self.port, self.broker, "the key broker")
        # Unix socket paths are short (104 bytes on macOS): a private
        # directory under /tmp when possible.
        base = "/tmp" if os.access("/tmp", os.W_OK) else None
        self.sockdir = Path(tempfile.mkdtemp(prefix="enc-", dir=base))
        self.socket = self.sockdir / "launcher.sock"
        self.launcher = None
        self.start_launcher(launcher_image or prep["image"], debug, hwmodel)

    def start_launcher(self, image: str, debug: bool = False, hwmodel: str = "GCP_INTEL_TDX"):
        if self.launcher:
            self.launcher.kill()
            self.launcher.wait()
        args = [self.cli, "attest", "simulate-launcher", "--socket", str(self.socket), "--key",
                str(TEST_KEYS / "google-test.pem"), "--image", image, "--hwmodel", hwmodel]
        if debug:
            args.append("--debug")
        self.launcher = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
        for _ in range(100):
            if self.socket.exists():
                return
            time.sleep(0.05)
        raise RuntimeError("the simulated launcher did not start")

    def run_worker(self, job_path: str, env: Optional[dict] = None) -> subprocess.CompletedProcess:
        e = dict(os.environ, ENCOMPUTE_ATTESTER="confidential-space",
                 ENCOMPUTE_TEE_SOCKET=str(self.socket), TOKENIZERS_PARALLELISM="false",
                 PYTHONDONTWRITEBYTECODE="1")
        e.update(env or {})
        return subprocess.run([sys.executable, "-m", "encompute.torch.cs_worker", job_path],
                              capture_output=True, text=True, env=e)

    def close(self) -> None:
        for p in (self.launcher, self.broker):
            if p and p.poll() is None:
                p.kill()
                p.wait()
        shutil.rmtree(self.sockdir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def verify(prep: dict, outputs: List[str], jwks: str, *, bundle: Optional[str] = None) -> str:
    """Adds each job's attestation record and evidence to the trust bundle
    and returns the trust report: what an external verifier runs, with
    only public evidence and its own trust anchors (the Confidential Space
    JWKS, the parties' keys, the training attestation policy)."""
    st = prep["state"]
    W = Path(prep["workdir"])
    mc = W / st["model_owner"]
    cli = ft._cli()
    b = bundle or str(mc / "trust.json")
    if not Path(b).exists():  # a separate verification bundle: start from the run's
        shutil.copy(mc / "trust.json", b)
    for out in outputs:
        for f in ("attestation.json", "evidence.json"):
            subprocess.run([cli, "trust", "add", str(Path(out) / f), "--bundle", b],
                           cwd=mc, check=True, capture_output=True)
    return subprocess.run(
        [cli, "trust", "report", "--bundle", b, "--parties", str(W / "parties.json"),
         "--jwks", jwks, "--audience", prep["broker_id"],
         "--execution-policy", prep["policy"], "--require", "Training",
         "--require", "Workload"], cwd=mc, capture_output=True, text=True).stdout
