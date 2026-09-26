"""Confidential LoRA fine-tuning: ``Project.finetune`` runs the plan.

Every party runs as a separate process with its own directory, on this
machine:
- each hospital's training worker;
- ModelCo's key broker;
- ModelCo's aggregation coordinator, one per round.

The orchestrator plays ModelCo. It holds the base model and the adapter,
and never sees a dataset or an individual update. In a deployment, each
party runs its part on its own machine; the checks are the same.

Attestation here is DEVELOPMENT (mock): it exercises every check, but
provides no hardware confidentiality.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import torch

from .. import _native
from .._frontend import EncomputeError
from . import lora, models, tensors

IMAGE = "sha256:" + "5" * 64  # the training worker image (development)
CODE = ["worker.py", "lora.py", "tensors.py", "models.py", "finetune.py", "infer.py"]


class TrainingFailed(EncomputeError):
    def __init__(self, message: str, log: str = ""):
        super().__init__("ENC2501", message)
        self.log = log


def _cli() -> str:
    for c in (os.environ.get("ENCOMPUTE_CLI"),
              str(Path(__file__).resolve().parents[3] / "target" / "debug" / "encompute"),
              shutil.which("encompute")):
        if c and os.path.exists(c):
            return c
    raise TrainingFailed("the encompute CLI was not found (cargo build --bins, or ENCOMPUTE_CLI)")


def _run(args: List[str], cwd: Path, check: bool = True, stdin: Optional[str] = None,
         both: bool = False) -> str:
    """Runs the CLI; returns its stdout (and stderr with ``both``)."""
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, input=stdin)
    if check and p.returncode != 0:
        raise TrainingFailed(f"{' '.join(args[1:3])} failed", p.stdout + p.stderr)
    return p.stdout + p.stderr if both else p.stdout


def _port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, proc: subprocess.Popen, what: str) -> None:
    for _ in range(300):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            if proc.poll() is not None:
                raise TrainingFailed(f"{what} exited", proc.stdout.read() if proc.stdout else "")
            time.sleep(0.1)
    raise TrainingFailed(f"{what} did not start")


def code_digest(factory: str) -> str:
    h = hashlib.sha256()
    here = Path(__file__).parent
    for f in CODE:
        h.update(f.encode() + b"\0" + (here / f).read_bytes())
    src = models.source_file(factory)
    h.update(b"factory\0" + Path(src).read_bytes())
    return h.hexdigest()


@dataclass
class FineTuneResult:
    """The outcome of a confidential fine-tuning run."""

    adapter_id: str
    plan_id: str
    training_spec_id: str
    run_id: str
    rounds: int
    stopped: Optional[str]
    report: str
    rows: Dict[str, str]
    satisfied: bool
    export: str
    timings: Dict[str, float]
    losses: List[float]
    workdir: Path
    _ctx: Dict[str, Any] = field(repr=False, default_factory=dict)

    def summary(self) -> str:
        r = self.rows
        ok = lambda *rows: all(r.get(x, "").split(" ")[0] in (
            "VERIFIED", "SATISFIED", "AUTHORIZED", "ATTESTED", "COMPLETE") for x in rows)
        lines = [
            "CONFIDENTIAL FINE-TUNING",
            "────────────────────────",
            f"{'Model protection':<24}{'SATISFIED' if ok('Workload', 'Owner authorization', 'Plan') else 'NOT SATISFIED'}",
            f"{'Dataset protection':<24}{'SATISFIED' if ok('Policy', 'Owner authorization', 'Plan') else 'NOT SATISFIED'}",
            f"{'Gradient protection':<24}{'SATISFIED' if ok('Private aggregation') else 'NOT SATISFIED'}",
            f"{'Privacy budget':<24}{r.get('Privacy budget', 'NOT PRESENT')}",
            f"{'Workload identity':<24}{'VERIFIED' if ok('Workload') else r.get('Workload')}",
            f"{'Aggregation':<24}{r.get('Private aggregation')}",
            f"{'Checkpoint lineage':<24}{'COMPLETE' if ok('Training') else r.get('Training')}",
            f"{'Adapter lineage':<24}{'COMPLETE' if ok('Training', 'Lineage') else r.get('Lineage')}",
            "",
            "Output",
            self.adapter_id,
            "",
            "RESULT",
            "TRUST REQUIREMENTS SATISFIED" if self.satisfied else "TRUST REQUIREMENTS NOT SATISFIED",
        ]
        return "\n".join(lines)

    def lineage(self) -> str:
        c = self._ctx
        return _run([c["cli"], "lineage", self.adapter_id, "--bundle", str(c["bundle"])]
                    + c["anchors"], c["modelco"], check=False)

    def export_adapter(self) -> str:
        """Asks to export the adapter publicly (denied unless every parent
        permits it)."""
        c = self._ctx
        return _run([c["cli"], "export", self.adapter_id, "--bundle", str(c["bundle"])],
                    c["modelco"], check=False)

    def infer(self, tokens: torch.Tensor, adapter: Optional[str] = None) -> torch.Tensor:
        """Runs the base model with an adapter (default: the final one) in
        an attested inference workload; returns the logits."""
        c = self._ctx
        which = adapter or self.adapter_id
        rec = c["modelco"] / f"{which}.record.json"
        digest = (json.loads(rec.read_text())["record"]["adapter_digest"] if rec.exists()
                  else c["adapter0_digest"])
        cfg = dict(c["infer"], adapter=which, adapter_digest=digest,
                   adapter_sealed=str(c["modelco"] / f"{which}.enc"),
                   inputs=tensors.dumps({"tokens": tokens}).hex())
        path = c["modelco"] / f"infer-{which}.json"
        path.write_text(json.dumps(cfg))
        p = subprocess.run([sys.executable, "-m", "encompute.torch.infer", str(path)],
                           capture_output=True, text=True, env=c["env"])
        path.unlink()
        out = json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {}
        if not out.get("ok"):
            raise TrainingFailed("inference refused", out.get("error", p.stderr))
        return tensors.loads(bytes.fromhex(out["logits"]))["logits"]

    def resume(self, checkpoint: str) -> dict:
        """Opens a checkpoint for resuming (an attested workload receives
        the checkpoint key); refuses a stale, foreign or rolled-back one."""
        c = self._ctx
        keys, _ = _native.acquire_training_keys(
            c["spec"], c["broker"], ["checkpoints"], str(c["modelco"] / "coord.key"),
            str(c["hw_seed"]), IMAGE)
        key = dict(keys)["checkpoints"]
        sealed = Path(checkpoint).read_bytes()
        s = json.loads(c["spec"])
        try:
            header, _ = _native.resume_checkpoint(
                key, sealed, s["project"], self.training_spec_id, s["policy_id"],
                s["privacy_policy_id"], str(c["modelco"] / "ledgers"))
        except _native.NativeError as e:
            code, message = e.args
            raise EncomputeError(code, message) from None
        return json.loads(header)

    def close(self) -> None:
        b = self._ctx.get("broker_proc")
        if b and b.poll() is None:
            b.terminate()
            b.wait()


def finetune(project, *, model, data, method="lora", privacy="strong",
             verification="required", config: Optional[lora.LoRAConfig] = None,
             infrastructure: Optional[dict] = None, allow_development: bool = False,
             workdir: Optional[str] = None, verbose: bool = True) -> FineTuneResult:
    from .._project import PlanningFailed

    if method != "lora":
        raise EncomputeError("ENC2501", "only method='lora' is supported")
    if verification not in ("receipt", "required"):
        raise EncomputeError("ENC1906", 'verification is "receipt" or "required"')
    module = model.payload
    if module is None or not hasattr(module, "encompute_factory"):
        raise EncomputeError("ENC2501", "the model needs a module built with "
                             "encompute.torch.wrap_model (a factory, not a pickle)")
    for d in data:
        if d.payload is None:
            raise EncomputeError("ENC2501", f"{d.id} needs a dataset (encompute.torch.private_dataset)")
    cfg = config or lora.LoRAConfig()
    say = print if verbose else (lambda *a, **k: None)
    t0 = time.perf_counter()
    timings: Dict[str, float] = {}
    cli = _cli()
    W = Path(workdir or tempfile.mkdtemp(prefix="encompute-finetune-"))
    W.mkdir(parents=True, exist_ok=True)
    mc = W / model.owner
    mc.mkdir(exist_ok=True)
    env = dict(os.environ, ENCOMPUTE_CLI=cli, PYTHONDONTWRITEBYTECODE="1")

    # ModelCo's view: the base model, LoRA added, its layout and adapter-0.
    base_state = {k: v.clone() for k, v in module.state_dict().items()}
    weights = tensors.dumps(base_state)
    ref = models.build(module.encompute_factory, module.encompute_kwargs)
    ref.load_state_dict(base_state)
    lora.apply_lora(ref, cfg)
    dim = lora.get_flat(ref).numel()
    adapter = lora.get_flat(ref).clone()

    # 1. Declarations and the plan.
    eir = project._aggregation_program(data, model.owner, model, privacy=privacy,
                                       unit="organization", dim=dim, colluding=None)
    (mc / "training.eir").write_text(eir)
    _run([cli, "compile", "training.eir", "-o", "training.encompute"], mc)
    infra = infrastructure
    if infra is None and allow_development:
        infra = {"tees": [{"tee": "mock", "provider": "mock", "cloud": True}], "key_broker": True}
    (mc / "infra.json").write_text(json.dumps(infra or {}))
    (mc / "training-decl.json").write_text(json.dumps(
        {"model": model.id, "data": [d.id for d in data], "verified": verification == "required"}))
    args = [cli, "plan", "training.encompute", "--profile", project.security,
            "--infrastructure", "infra.json", "--training", "training-decl.json", "-o", "plan.json"]
    if allow_development:
        args.append("--allow-development")
    out = _run(args, mc, check=False, both=True)
    if not (mc / "plan.json").exists():
        raise PlanningFailed(out)
    plan = json.loads((mc / "plan.json").read_text())
    plan_id = [l for l in out.splitlines() if l.startswith("encplan1:")][0]
    agg_step = next(s for s in plan["steps"] if s["kind"]["kind"] == "aggregate")
    attested_coord = any(m["mechanism"] == "attestation" for m in agg_step["mechanisms"])
    say(f"{'Plan':<24}{plan_id[:25]}...")
    if any(t.get("provider") == "mock" for t in (infra or {}).get("tees", [])):
        say("DEVELOPMENT ATTESTATION: NO HARDWARE CONFIDENTIALITY")

    # 2. Identities (public keys in parties.json, known to all out of band).
    ids = []
    for d in data:
        pd = W / d.owner
        pd.mkdir(exist_ok=True)
        ids.append(json.loads(_run([cli, "aggregate", "identity", "--party", d.owner,
                                    "--key", "party.key"], pd)))
    (W / "parties.json").write_text(json.dumps(ids))
    coord = json.loads(_run([cli, "aggregate", "identity", "--party", model.owner,
                             "--key", "coord.key"], mc))["public_key"]
    mock_root = _run([cli, "attest", "mock-root", str(W / "hw.seed")], W).strip()

    # 3. Owners approve; the trust bundle starts.
    parties = str(W / "parties.json")
    coord_policy = []
    if attested_coord:
        (mc / "coord-policy.json").write_text(_run(
            [cli, "aggregate", "coordinator-policy", "training.encompute", "--image", IMAGE,
             "--tee", "mock", "--development", "--plan", "plan.json"], mc))
        coord_policy = ["--coordinator-policy", str(mc / "coord-policy.json")]
    _run([cli, "trust", "init", "training.encompute", "--parties", parties, "--plan",
          "plan.json", *coord_policy, "--bundle", "trust.json"], mc)
    for d in data:
        _run([cli, "trust", "authorize", "--party", d.owner, "--key", str(W / d.owner / "party.key"),
              "--bundle", str(mc / "trust.json")], mc)
    bundle = json.loads((mc / "trust.json").read_text())
    spec_node = next(k for k in bundle["nodes"] if k.startswith("spec:"))
    agg_spec = bundle["nodes"][spec_node]["evidence"]["value"]

    # 4. Datasets stay with their owners; only digests are shared.
    commitments = []
    for d in data:
        x, y = d.payload
        blob = tensors.dumps({"x": x, "y": y})
        (W / d.owner / "dataset.bin").write_bytes(blob)
        commitments.append({"asset_id": d.id, "owner": d.owner,
                            "gradient_asset": f"gradient-{d.id}",
                            "digest": _native.sha256_hex(blob)})
    commitments.sort(key=lambda c: c["asset_id"])

    # 5. The training spec every worker attests to.
    spec = {
        "version": 1, "project": project.name, "purpose": project.purpose,
        "plan_id": plan_id.split(":", 1)[1],
        "program_id": agg_spec["plan"]["program_id"],
        "policy_id": agg_spec["plan"]["policy_id"],
        "privacy_policy_id": agg_spec["plan"].get("privacy_policy_id"),
        "aggregation_spec_id": spec_node.split(":", 1)[1],
        "base_model": {
            "asset_id": model.id, "owner": model.owner,
            "architecture": json.dumps({"factory": module.encompute_factory,
                                        "kwargs": module.encompute_kwargs}, sort_keys=True),
            "weights_digest": _native.sha256_hex(weights),
        },
        "datasets": commitments,
        "code_digest": code_digest(module.encompute_factory),
        "layout_digest": lora.layout_digest(ref),
        "config": {
            "method": "lora", "rank": cfg.rank, "alpha": cfg.alpha,
            "target_modules": sorted(cfg.target_modules), "optimizer": cfg.optimizer,
            "learning_rate": repr(float(cfg.learning_rate)),
            "update_clip": repr(float(cfg.update_clip)),
            "local_steps": cfg.local_steps, "batch_size": cfg.batch_size,
            "rounds": cfg.rounds, "adapter_parameters": dim,
        },
        "participants": agg_spec["parties"],
    }
    spec_json = json.dumps(spec)
    spec_id = _native.training_spec_id(spec_json)
    run_id = _native.training_run_id(spec_json, secrets.token_hex(16))
    (mc / "training-spec.json").write_text(spec_json)
    _run([cli, "trust", "add", "training-spec.json", "--bundle", "trust.json"], mc)
    say(f"{'Training':<24}LoRA (rank {cfg.rank}, {dim} adapter parameters)")
    say(f"{'Participants':<24}{len(data)}")

    # 6. ModelCo's key broker: the model, checkpoint and adapter keys,
    # released only to workloads attesting to this training spec.
    (mc / "training-policy.json").write_text(
        _native.training_attestation_policy(spec_json, IMAGE, True))
    model_key = secrets.token_bytes(32)
    (mc / f"{model.id}.enc").write_bytes(
        _native.seal_asset(model_key, "model", project.name, model.id, weights))
    for asset, key in ((model.id, model_key), ("checkpoints", secrets.token_bytes(32)),
                       ("adapters", secrets.token_bytes(32))):
        kf = mc / f"{asset}.key"
        kf.write_bytes(key)
        _run([cli, "keys", "protect", "--asset", asset, "--policy", "training-policy.json",
              "--key-file", kf.name, "--broker-id", model.owner, "--development",
              "--broker", "broker.json"], mc)
        kf.unlink()  # the broker holds it now
    del model_key
    bport = _port()
    broker = subprocess.Popen([cli, "keys", "serve", "--listen", f"127.0.0.1:{bport}",
                               "--mock-root", mock_root, "--broker", "broker.json"],
                              cwd=mc, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    _wait_port(bport, broker, "the key broker")
    broker_url = f"http://127.0.0.1:{bport}"
    say(f"{'Model protection':<24}ACTIVE (key released only to attested training workloads)")
    say(f"{'Dataset protection':<24}ACTIVE (datasets never leave their owners' workers)")
    say(f"{'Attestation':<24}{'REQUIRED' if verification == 'required' else 'PLANNED'}")
    say(f"{'Gradient protection':<24}SECURE AGGREGATION")
    say(f"{'Privacy':<24}ACTIVE ({privacy}, organization-level: each hospital's clipped update)")

    ctx: Dict[str, Any] = dict(cli=cli, bundle=mc / "trust.json", modelco=mc, spec=spec_json,
                               broker=broker_url, hw_seed=W / "hw.seed", env=env,
                               broker_proc=broker)
    ctx["anchors"] = ["--parties", parties, "--coordinator-key", coord, "--mock-root",
                      mock_root, "--execution-policy", str(mc / "training-policy.json")]

    # Plain PyTorch baseline: the same local steps, no Encompute.
    bl = models.build(module.encompute_factory, module.encompute_kwargs)
    bl.load_state_dict(base_state)
    lora.apply_lora(bl, cfg)
    t = time.perf_counter()
    x0, y0 = data[0].payload
    opt = torch.optim.SGD(list(lora.adapter_parameters(bl).values()), lr=cfg.learning_rate)
    for _ in range(cfg.local_steps):
        opt.zero_grad()
        torch.nn.functional.cross_entropy(bl(x0[:cfg.batch_size]), y0[:cfg.batch_size]).backward()
        opt.step()
    timings["plain_pytorch_local_training_s"] = time.perf_counter() - t

    # 7. Training workers: attest, receive the model key, build the model.
    workers = []
    t = time.perf_counter()
    try:
        for d in data:
            pd = W / d.owner
            wcfg = {
                "spec": spec_json, "broker": broker_url, "identity": str(pd / "party.key"),
                "mock_seed": str(W / "hw.seed"), "image": IMAGE,
                "model_sealed": str(mc / f"{model.id}.enc"),
                "dataset": str(pd / "dataset.bin"), "dataset_asset": d.id,
                "dataset_digest": next(c["digest"] for c in commitments if c["asset_id"] == d.id),
                "lora": {"rank": cfg.rank, "alpha": cfg.alpha,
                         "target_modules": list(cfg.target_modules), "optimizer": cfg.optimizer,
                         "learning_rate": cfg.learning_rate, "update_clip": cfg.update_clip,
                         "local_steps": cfg.local_steps, "batch_size": cfg.batch_size,
                         "rounds": cfg.rounds, "seed": cfg.seed},
                "cli": cli, "artifact": str(mc / "training.encompute"), "parties": parties,
                "plan": str(mc / "plan.json"),
                "coordinator_policy": str(mc / "coord-policy.json") if attested_coord else "",
                "mock_root": mock_root, "party": d.owner, "state": str(pd / "round.state"),
            }
            (pd / "worker.json").write_text(json.dumps(wcfg))
            p = subprocess.Popen([sys.executable, "-m", "encompute.torch.worker",
                                  str(pd / "worker.json")], cwd=pd, env=env, text=True,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            hello = json.loads(p.stdout.readline() or '{"ready": false, "error": "no reply"}')
            if not hello.get("ready"):
                raise TrainingFailed(f"{d.owner}'s training worker refused: {hello.get('error')}",
                                     p.stderr.read())
            (pd / "attestation.json").write_text(hello["record"])
            _run([cli, "trust", "add", str(pd / "attestation.json"), "--bundle", "trust.json"], mc)
            workers.append((d, p))
        timings["attestation_startup_s"] = time.perf_counter() - t
        say(f"{'Workers':<24}{len(workers)} attested, model key received")

        # 8. Rounds.
        ckpt = {k: v for k, v in dict(_native.acquire_training_keys(
            spec_json, broker_url, ["checkpoints", "adapters"], str(mc / "coord.key"),
            str(W / "hw.seed"), IMAGE)[0]).items()}
        (mc / "checkpoints").mkdir(exist_ok=True)
        ctx["infer"] = dict(spec=spec_json, broker=broker_url,
                            identity=str(mc / "coord.key"), mock_seed=str(W / "hw.seed"),
                            image=IMAGE, model_sealed=str(mc / f"{model.id}.enc"),
                            lora={"rank": cfg.rank, "alpha": cfg.alpha,
                                  "target_modules": list(cfg.target_modules), "seed": cfg.seed})
        a0 = tensors.dumps({"adapter": adapter})
        ctx["adapter0_digest"] = _native.sha256_hex(a0)
        (mc / "adapter-0.enc").write_bytes(_native.seal_asset(
            ckpt["adapters"], "adapter", project.name, "adapter-0", a0))
        adapter_id, previous, stopped, losses = "adapter-0", None, None, []
        timings["secure_aggregation_s"] = timings["checkpoint_s"] = timings["trust_graph_s"] = 0.0
        gradient_assets = [c["gradient_asset"] for c in commitments]
        done = 0
        for r in range(1, cfg.rounds + 1):
            t = time.perf_counter()
            port = _port()
            serve = [cli, "aggregate", "serve", "training.encompute", "--parties", parties,
                     "--plan", "plan.json", "--key", "coord.key", "--listen",
                     f"127.0.0.1:{port}", "--stage-timeout", "30", "--sequence", str(r),
                     "--ledger", "ledgers", "--out", f"update-{r}.json",
                     "--receipt", f"receipt-{r}.json", "--trust-bundle", "trust.json"]
            if attested_coord:
                serve += [*coord_policy, "--attester", "mock", "--mock-seed",
                          str(W / "hw.seed"), "--mock-image", IMAGE]
            cp = subprocess.Popen(serve, cwd=mc, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
            try:
                _wait_port(port, cp, "the coordinator")
            except TrainingFailed as e:
                if "ENC2201" in e.log:
                    stopped = f"round {r}: privacy budget exhausted (RELEASE DENIED)"
                    break
                raise
            for i, (d, p) in enumerate(workers):
                p.stdin.write(json.dumps({"adapter": [float(v) for v in adapter],
                                          "seed": cfg.seed * 1000 + r * 10 + i,
                                          "coordinator": f"http://127.0.0.1:{port}"}) + "\n")
                p.stdin.flush()
            replies = [json.loads(p.stdout.readline()) for _, p in workers]
            log = cp.communicate()[0]
            if cp.returncode != 0:
                if "ENC2201" in log:
                    stopped = f"round {r}: privacy budget exhausted (RELEASE DENIED)"
                    break
                raise TrainingFailed(f"round {r} failed", log + "".join(x["log"] for x in replies))
            timings["secure_aggregation_s"] += time.perf_counter() - t
            losses.append(sum(x["loss"] for x in replies) / len(replies))
            # The released (noised) sum of clipped, scaled updates: the mean
            # update, rescaled.
            agg = json.loads((mc / f"update-{r}.json").read_text())
            n = len(agg["contributors"])
            mean = torch.tensor(agg["values"], dtype=torch.float32) / n * cfg.update_clip
            adapter = adapter + mean
            new_id = f"adapter-{r}"
            t = time.perf_counter()
            payload = tensors.dumps({"adapter": adapter})
            (mc / f"{new_id}.enc").write_bytes(_native.seal_asset(
                ckpt["adapters"], "adapter", project.name, new_id, payload))
            header = {
                "version": 1, "project": project.name, "training_spec_id": spec_id,
                "run_id": run_id, "round": r, "adapter_id": new_id,
                "payload_digest": _native.sha256_hex(payload),
                "policy_id": spec["policy_id"], "privacy_policy_id": spec["privacy_policy_id"],
                "ledgers": json.loads(_native.ledger_checkpoints(str(mc / "ledgers"),
                                                                 gradient_assets)),
                "lineage_root": None,
            }
            (mc / "checkpoints" / f"round-{r}.enc").write_bytes(
                _native.seal_checkpoint(ckpt["checkpoints"], json.dumps(header), payload))
            timings["checkpoint_s"] += time.perf_counter() - t
            t = time.perf_counter()
            rec = _native.sign_adapter_record(
                spec_json, run_id, r, previous, (mc / f"receipt-{r}.json").read_text(),
                "update", _native.sha256_hex(payload), str(mc / "coord.key"))
            (mc / f"{new_id}.record.json").write_text(rec)
            _run([cli, "trust", "add", f"{new_id}.record.json", "--bundle", "trust.json"], mc)
            timings["trust_graph_s"] += time.perf_counter() - t
            previous, adapter_id, done = new_id, new_id, r
            say(f"{f'Round {r}/{cfg.rounds}':<24}COMPLETE (mean local loss {losses[-1]:.3f})")
        if stopped:
            say(f"{'Stopped':<24}{stopped}")
    finally:
        for _, p in workers:
            try:
                p.stdin.write('{"cmd": "exit"}\n')
                p.stdin.flush()
            except (BrokenPipeError, ValueError):
                pass
            p.wait(timeout=30)

    # 9. The trust report and the export decision.
    report = _run([cli, "trust", "report", "--bundle", "trust.json", *ctx["anchors"],
                   "--require", "Private aggregation", "--require", "Privacy budget",
                   "--require", "Plan", "--require", "Workload", "--require", "Training"],
                  mc, check=False)
    rows = {}
    for line in report.splitlines():
        for name in ("Evidence", "Program", "Policy", "Plan", "Owner authorization", "Workload",
                     "Private aggregation", "Privacy budget", "Execution", "Training", "Lineage"):
            if line.startswith(name + " ") and line[len(name):].startswith("  "):
                rows[name] = line[24:].strip()
    try:
        _native.check_export(eir, spec_json, adapter_id)
        export = "EXPORT PERMITTED"
    except _native.NativeError as e:
        export = e.args[1]
    timings["total_s"] = time.perf_counter() - t0
    result = FineTuneResult(
        adapter_id=adapter_id, plan_id=plan_id, training_spec_id=spec_id, run_id=run_id,
        rounds=done, stopped=stopped, report=report, rows=rows,
        satisfied="TRUST REQUIREMENTS SATISFIED" in report and done > 0,
        export=export, timings=timings, losses=losses, workdir=W, _ctx=ctx,
    )
    say("")
    say(result.summary())
    return result
