"""Confidential LoRA fine-tuning: ``Project.finetune`` runs the plan.

Every party runs as a separate process with its own directory, on this
machine:
- each hospital's training worker;
- ModelCo's key broker;
- ModelCo's aggregation coordinator, one per round.

The orchestrator plays ModelCo. It holds the base model and the adapter,
and never sees a dataset or an individual update. In a deployment, each
party runs its part on its own machine; the checks are the same.

A round becomes trusted at one commit point, in this order:
1. The aggregate is released with differential privacy; the coordinator
   commits the charge to the privacy ledgers.
2. The new adapter and its checkpoint are sealed into ``pending/``, and are
   provisional.
3. The coordinator-signed adapter record is added to the trust bundle. This
   is the commit point.
4. The pending files move into place.

After a crash, ``recover`` finalizes rounds that reached the commit point
and discards the rest. A released but uncommitted round stays charged: its
privacy is spent, only its progress is lost. ``finetune(resume=workdir)``
continues from the last accepted adapter.

Privacy unit: organization by default (each hospital's whole update is
clipped). With ``privacy="strong-patient"`` (or ``encompute.Privacy``), the
unit is the patient: DP-SGD with per-patient clipping and Poisson sampling
inside each attested worker, noise added by the coordinator, and Rényi DP
accounting. A run that would exceed the budget is denied before training.

Attestation here is DEVELOPMENT (mock): it exercises every check, but
provides no hardware confidentiality.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import torch

from .. import _native
from .._frontend import EncomputeError
from . import dpsgd, lora, models, tasks, tensors

IMAGE = "sha256:" + "5" * 64  # the training worker image (development)
CODE = ["worker.py", "lora.py", "tensors.py", "models.py", "finetune.py", "infer.py",
        "dpsgd.py", "tasks.py", "hf.py", "cs_worker.py"]
PRIVACY_UNIT = ("Privacy unit: organization. Patient-level DP requires per-example clipping "
                "(DP-SGD) and is not claimed.")


def _privacy_note(dp: Optional[dict]) -> str:
    if not dp:
        return PRIVACY_UNIT
    return (f"Privacy unit: {dp['privacy_unit']}. Each {dp['privacy_unit']}'s gradient is "
            f"clipped to {dp['per_example_clip']} (DP-SGD, Poisson sampling "
            f"{dp['sampling_rate']}), accounted with Rényi DP.")
FAILPOINTS = ("after-aggregate-release", "after-adapter-write", "before-checkpoint-write",
              "during-checkpoint-write", "before-trust-update", "after-trust-update",
              "kill-coordinator", "kill-broker")


class TrainingFailed(EncomputeError):
    def __init__(self, message: str, log: str = ""):
        super().__init__("ENC2501", message)
        self.log = log


def _failpoint(name: str) -> None:
    """Crash injection for the assurance tests: exits abruptly here when
    ENCOMPUTE_TRAINING_FAILPOINT names this point."""
    if os.environ.get("ENCOMPUTE_TRAINING_FAILPOINT") == name:
        os._exit(137)


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


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def code_digest(factory: str) -> str:
    h = hashlib.sha256()
    here = Path(__file__).parent
    for f in CODE:
        h.update(f.encode() + b"\0" + (here / f).read_bytes())
    src = models.source_file(factory)
    h.update(b"factory\0" + Path(src).read_bytes())
    return h.hexdigest()


# --- run state ----------------------------------------------------------------


def _bundle_state(mc: Path, spec_id: str) -> Tuple[Dict[int, dict], Dict[int, str]]:
    """Accepted adapters by round (their signed records), and every released
    round's aggregation round ID by sequence, from the trust bundle."""
    b = json.loads((mc / "trust.json").read_text())
    accepted, released = {}, {}
    for key, node in b["nodes"].items():
        ev = node.get("evidence") or {}
        if key.startswith("adapter:") and ev.get("type") == "adapter":
            rec = ev["value"]["record"]
            if rec["training_spec_id"] == spec_id:
                accepted[rec["round"]] = rec
        if key.startswith("round:") and ev.get("type") == "aggregation_receipt":
            m = ev["value"]["manifest"]
            released[m["round"]["sequence"]] = m["round_id"]
    return accepted, released


def _round_of(name: str) -> int:
    return int(name.split("-")[1].split(".")[0])


def recover(workdir: str) -> dict:
    """Brings a run directory to a consistent state after a crash, and says
    what happened.

    - A pending round that reached the commit point (its adapter record is
      in the trust bundle) is finalized.
    - Any other pending file is provisional and is discarded.
    - Rounds released but never accepted are reported as lost: their
      privacy stays spent.
    - Every privacy ledger must verify.
    """
    W = Path(workdir)
    st = json.loads((W / "run.json").read_text())
    mc = W / st["model_owner"]
    accepted, released = _bundle_state(mc, st["training_spec_id"])
    finalized, discarded = [], []
    pending = mc / "pending"
    if pending.exists():
        for f in sorted(pending.iterdir()):
            r = _round_of(f.name)
            target = (mc / "checkpoints" / f"round-{r}.enc" if f.name.endswith(".ckpt")
                      else mc / f"adapter-{r}.enc")
            if r in accepted and not f.name.endswith(".tmp"):
                os.replace(f, target)
                finalized.append(target.name)
            else:
                f.unlink()
                discarded.append(f.name)
    problems = []
    for r in accepted:
        if not (mc / f"adapter-{r}.enc").exists():
            problems.append(f"accepted adapter-{r} is missing")
        if not (mc / "checkpoints" / f"round-{r}.enc").exists():
            problems.append(f"accepted round {r} has no checkpoint")
    for f in mc.glob("adapter-*.enc"):
        r = _round_of(f.name)
        if r and r not in accepted:
            problems.append(f"{f.name} exists but was never accepted")
    # Reading every ledger verifies it (hash chain, reservations, commits).
    present = [a for a in st["gradient_assets"] if (mc / "ledgers" / f"{a}.ledger").exists()]
    ledgers = json.loads(_native.ledger_checkpoints(str(mc / "ledgers"), present))
    lost = sorted(set(released) - set(accepted))
    return {"accepted": sorted(accepted), "lost": lost,
            "lost_round_ids": [released[r] for r in lost],
            "finalized": finalized, "discarded": discarded, "problems": problems,
            "ledgers": {a: c["seq"] for a, c in ledgers.items()},
            "next_round": max(list(released) + list(accepted) + [0]) + 1}


def _refuse_revoked(cli: str, mc: Path, anchors: List[str], spec: dict) -> None:
    """Refuses to go on once an owner has revoked any parent asset."""
    out = _run([cli, "trust", "report", "--bundle", "trust.json", *anchors, "--json"], mc,
               check=False)
    try:
        revoked = set(json.loads(out).get("revoked", {}))
    except ValueError:
        raise TrainingFailed("the trust report could not be read", out) from None
    parents = {f"asset:{spec['base_model']['asset_id']}"}
    for d in spec["datasets"]:
        parents |= {f"asset:{d['asset_id']}", f"asset:{d['gradient_asset']}"}
    hit = sorted(p.split(":", 1)[1] for p in revoked & parents)
    if hit:
        raise EncomputeError("ENC2302", f"training cannot resume: its owners revoked {', '.join(hit)}")


def _start_broker(cli: str, mc: Path, mock_root: str) -> Tuple[subprocess.Popen, str]:
    port = _port()
    p = subprocess.Popen([cli, "keys", "serve", "--listen", f"127.0.0.1:{port}",
                          "--mock-root", mock_root, "--broker", "broker.json"],
                         cwd=mc, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    _wait_port(port, p, "the key broker")
    return p, f"http://127.0.0.1:{port}"


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
    recovery: Optional[dict] = None
    privacy_unit: str = "organization"
    privacy_preview: Optional[List[dict]] = None
    _ctx: Dict[str, Any] = field(repr=False, default_factory=dict)

    def summary(self) -> str:
        r = self.rows
        ok = lambda *rows: all(r.get(x, "").split(" ")[0] in (  # noqa: E731
            "VERIFIED", "SATISFIED", "AUTHORIZED", "ATTESTED", "COMPLETE") for x in rows)
        yes = lambda b: "SATISFIED" if b else "NOT SATISFIED"  # noqa: E731
        lines = [
            "CONFIDENTIAL FINE-TUNING",
            "────────────────────────",
            f"{'Model protection':<24}{yes(ok('Workload', 'Owner authorization', 'Plan'))}",
            f"{'Dataset protection':<24}{yes(ok('Policy', 'Owner authorization', 'Plan'))}",
            f"{'Gradient protection':<24}{yes(ok('Private aggregation'))}",
            f"{'Privacy budget':<24}{r.get('Privacy budget', 'NOT PRESENT')}",
            f"{'Workload identity':<24}{'VERIFIED' if ok('Workload') else r.get('Workload')}",
            f"{'Aggregation':<24}{r.get('Private aggregation')}",
            f"{'Checkpoint lineage':<24}{'COMPLETE' if ok('Training') else r.get('Training')}",
            f"{'Adapter lineage':<24}"
            f"{'COMPLETE' if ok('Training', 'Lineage') else r.get('Lineage')}",
            "",
            _privacy_note(self._ctx.get("dp_sgd")),
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
        """Asks to export the adapter publicly: denied unless every parent
        permits it and the run's trust report is satisfied."""
        c = self._ctx
        return _run([c["cli"], "export", self.adapter_id, "--bundle", str(c["bundle"])]
                    + c["anchors"], c["modelco"], check=False)

    def _broker(self) -> str:
        c = self._ctx
        b = c.get("broker_proc")
        if b is None or b.poll() is not None:
            c["broker_proc"], c["broker"] = _start_broker(c["cli"], c["modelco"], c["mock_root"])
        return c["broker"]

    def infer(self, inputs, adapter: Optional[str] = None) -> torch.Tensor:
        """Runs the base model with an adapter (default: the final one) in
        an attested inference workload; returns the logits. ``inputs`` is a
        token tensor (reference models), or a ``private_text_dataset`` or
        a dict of named tensors (Hugging Face models)."""
        c = self._ctx
        which = adapter or self.adapter_id
        rec = c["modelco"] / f"{which}.record.json"
        digest = (json.loads(rec.read_text())["record"]["adapter_digest"] if rec.exists()
                  else c["adapter0_digest"])
        cfg = dict(c["infer"], broker=self._broker(), adapter=which, adapter_digest=digest,
                   adapter_sealed=str(c["modelco"] / f"{which}.enc"),
                   inputs=tensors.dumps(_inputs(inputs)).hex())
        path = c["modelco"] / f"infer-{which}.json"
        path.write_text(json.dumps(cfg))
        p = subprocess.run([sys.executable, "-m", "encompute.torch.infer", str(path)],
                           capture_output=True, text=True, env=c["env"])
        path.unlink()
        out = json.loads(p.stdout.strip().splitlines()[-1]) if p.stdout.strip() else {}
        if not out.get("ok"):
            raise TrainingFailed("inference refused", out.get("error", p.stderr))
        return tensors.loads(bytes.fromhex(out["logits"]))["logits"]

    def resume(self, checkpoint: str, lost_rounds: Optional[List[str]] = None) -> dict:
        """Opens a checkpoint for resuming (an attested workload receives
        the checkpoint key). Refuses:
        - a stale, foreign or rolled-back checkpoint;
        - one from another run;
        - any resume once a parent asset has been revoked."""
        c = self._ctx
        _refuse_revoked(c["cli"], c["modelco"], c["anchors"], json.loads(c["spec"]))
        keys, _ = _native.acquire_training_keys(
            c["spec"], self._broker(), ["checkpoints"], str(c["modelco"] / "coord.key"),
            str(c["hw_seed"]), IMAGE)
        s = json.loads(c["spec"])
        try:
            header, _ = _native.resume_checkpoint(
                dict(keys)["checkpoints"], Path(checkpoint).read_bytes(), s["project"],
                self.training_spec_id, s["policy_id"], s["privacy_policy_id"],
                str(c["modelco"] / "ledgers"), lost_rounds or [], self.run_id)
        except _native.NativeError as e:
            code, message = e.args
            raise EncomputeError(code, message) from None
        return json.loads(header)

    def export_peft(self, path: str) -> str:
        """Exports the adapter as standard PEFT files
        (``adapter_config.json``, ``adapter_model.safetensors``), usable with
        ``PeftModel.from_pretrained``, plus ``encompute-adapter.json`` (its
        Encompute identity and lineage). Only if the export is permitted:
        every parent's policy allows a public adapter, no parent is revoked,
        and the trust report is satisfied. Otherwise nothing is written and
        the refusal is returned."""
        decision = self.export_adapter()
        if "EXPORT PERMITTED" not in decision:
            return decision.strip()
        c = self._ctx
        spec = json.loads(c["spec"])
        if spec["config"]["method"] != "peft-lora":
            raise TrainingFailed("PEFT export needs a Hugging Face (peft-lora) run")
        if c.get("base_module") is None or c.get("adapter") is None:
            raise TrainingFailed("export the adapter from the run that trained it")
        from . import hf
        import copy
        model = hf.apply_peft(copy.deepcopy(c["base_module"]), spec["config"]["peft"],
                              c["seed"])
        lora.set_flat(model, c["adapter"])
        out = Path(path)
        out.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(str(out), safe_serialization=True)
        hfp = spec["base_model"]["huggingface"]
        (out / "encompute-adapter.json").write_text(json.dumps({
            "adapter_id": self.adapter_id, "training_spec_id": self.training_spec_id,
            "run_id": self.run_id, "model_package_id": f"enchf1:{c['package_id']}",
            "base_model": {"repo_id": hfp["repo_id"], "revision": hfp["revision"],
                           "asset_id": spec["base_model"]["asset_id"]},
            "plan_id": self.plan_id}, indent=1))
        return decision.strip()

    def close(self) -> None:
        b = self._ctx.get("broker_proc")
        if b and b.poll() is None:
            b.terminate()
            b.wait()


def _inputs(inputs) -> Dict[str, torch.Tensor]:
    if isinstance(inputs, torch.Tensor):
        return {"x": inputs}
    t = dict(inputs.tensors) if hasattr(inputs, "tensors") else dict(inputs)
    for k in ("labels", "unit_ids", "y"):
        t.pop(k, None)
    return t


# --- setup --------------------------------------------------------------------

DP_SPEC_FIELDS = ("privacy_unit", "per_example_clip", "sampling", "sampling_rate",
                  "noise_multiplier", "delta", "grouping", "accountant", "expected_batch")


def _exact(x: float) -> str:
    """A float as Rust's ``{:?}`` prints it (``1e-6``, not ``1e-06``): the
    training spec's canonical number format."""
    m, _, e = repr(float(x)).partition("e")
    return f"{m}e{int(e)}" if e else m


def _dataset(payload) -> Tuple[Dict[str, torch.Tensor], Optional[dict]]:
    """A dataset's named tensors and, for text, its preprocessing."""
    if hasattr(payload, "preprocessing"):
        return dict(payload.tensors), payload.preprocessing
    t = {"x": payload[0], "y": payload[1]}
    if len(payload) == 3:
        t["unit_ids"] = payload[2]
    return t, None


def _dp_settings(pv, data, cfg: lora.LoRAConfig) -> dict:
    """A DP-SGD run's settings, from ``encompute.Privacy`` and the datasets.
    The sampling rate defaults to the batch size over the smallest
    dataset's number of units."""
    eps, delta, z = pv.resolve()
    units = {}
    sets = [_dataset(d.payload)[0] for d in data]
    grouped = ["unit_ids" in t for t in sets]
    if any(grouped) and not all(grouped):
        raise EncomputeError("ENC2501", "either every dataset has unit_ids, or none does")
    if pv.unit != "record" and not all(grouped):
        raise EncomputeError(
            "ENC2501", f"{pv.unit}-level privacy needs each record's {pv.unit}: pass unit_ids "
                       "to encompute.torch.private_dataset or private_text_dataset (one ID per "
                       "record), so a "
                       f"{pv.unit}'s records are clipped together")
    for d, t in zip(data, sets):
        units[d.id] = (len(torch.unique(t["unit_ids"])) if grouped[0]
                       else len(next(iter(t.values()))))
    q = pv.sampling_rate if pv.sampling_rate is not None else cfg.batch_size / min(units.values())
    if not 0 < q < 1:
        raise EncomputeError("ENC2501", f"sampling rate {q} is not below 1: a dataset has fewer "
                                        f"{pv.unit}s than the batch size")
    q = float(f"{q:.6g}")
    return {
        "privacy_unit": pv.unit, "per_example_clip": _exact(pv.per_example_clip),
        "sampling": "poisson", "sampling_rate": _exact(q), "noise_multiplier": _exact(z),
        "delta": _exact(delta), "grouping": "unit_ids" if grouped[0] else "none",
        "accountant": "rdp-poisson-zw2019",
        "expected_batch": _exact(float(f"{q * sum(units.values()):.6g}")),
        "epsilon": eps, "delta_f": delta, "noise_f": z, "q": q, "units": units,
    }



def _setup(project, model, data, privacy, verification, cfg, infrastructure,
           allow_development, W: Path, cli: str, say, target: Optional[dict] = None) -> dict:
    """Plans the run and prepares every party; writes the (non-secret) run
    state to run.json.

    ``target`` (confidential training jobs) names a real attestation
    target instead of development attestation: ``image`` (the worker image
    digest), ``tee`` (``intel_tdx``), ``broker_id`` and ``kek`` (a
    production broker's key-encryption key file). Policies are then
    production policies (no mock, no debug), and the broker is a
    production broker with wrapped keys."""
    from .._project import PlanningFailed

    from .._privacy import Privacy

    module = model.payload
    mc = W / model.owner
    mc.mkdir(parents=True, exist_ok=True)
    pv = Privacy.of(privacy)
    dp = None
    if isinstance(pv, Privacy):
        dp = _dp_settings(pv, data, cfg)
        cfg = replace(cfg, local_steps=1)  # one accounted step per round

    pkg = getattr(module, "encompute_hf", None)
    method = "peft-lora" if pkg is not None else "lora"
    peft = None
    if pkg is not None:
        from . import hf
        cfg = replace(cfg, target_modules=tuple(cfg.target_modules or hf.TARGETS[pkg.model_type]))
        peft = hf.peft_config(pkg.model_type, cfg.rank, cfg.alpha, cfg.target_modules,
                              dropout=cfg.dropout)
    else:
        cfg = replace(cfg, target_modules=tuple(cfg.target_modules or ("q", "v")))
    base_state = {k: v.detach().clone() for k, v in module.state_dict().items()}
    weights = tensors.dumps(base_state)
    ref = models.build(module.encompute_factory, module.encompute_kwargs)
    ref.load_state_dict(base_state)
    if peft is not None:
        ref = hf.apply_peft(ref, peft, cfg.seed)
    else:
        lora.apply_lora(ref, cfg)
    adapter0 = lora.get_flat(ref).clone()
    dim = adapter0.numel()

    # 1. Declarations and the plan.
    eir = project._aggregation_program(
        data, model.owner, model, privacy=privacy if dp is None else "",
        unit="organization" if dp is None else dp["privacy_unit"], dim=dim, colluding=None,
        dpsgd=None if dp is None else {
            "epsilon": dp["epsilon"], "delta": dp["delta_f"],
            "noise_multiplier": dp["noise_f"], "sampling_rate": dp["q"],
            "clip_norm": dpsgd.CODEC_CLIP, "scale": dpsgd.CODEC_SCALE})
    # The privacy preview: what the planned rounds cost each budget. A
    # DP-SGD run that would exceed it is denied before anything runs.
    rows_json, preview = _native.privacy_preview(eir, cfg.rounds)
    rows = json.loads(rows_json)
    if dp is not None:
        say(preview.rstrip())
        if not all(r["allowed"] for r in rows):
            r = min(rows, key=lambda r: r["affordable"])
            raise EncomputeError(
                "ENC2201", f"PRIVACY BUDGET EXCEEDED: DENIED BEFORE TRAINING. {cfg.rounds} rounds "
                f"would cost {r['asset']} epsilon {r['epsilon']:.3f} of {r['budget_epsilon']}; "
                f"its budget affords {r['affordable']} rounds")
    (mc / "training.eir").write_text(eir)
    _run([cli, "compile", "training.eir", "-o", "training.encompute"], mc)
    image = target["image"] if target else IMAGE
    dev = target is None
    infra = infrastructure
    if target is not None:
        infra = {"tees": [{"tee": target["tee"].replace("_", "-"),
                           "provider": "gcp-confidential-space", "cloud": True}],
                 "key_broker": True}
        allow_development = False
    elif infra is None and allow_development:
        infra = {"tees": [{"tee": "mock", "provider": "mock", "cloud": True}], "key_broker": True}
    (mc / "infra.json").write_text(json.dumps(infra or {}))
    (mc / "training-decl.json").write_text(json.dumps(
        {"model": model.id, "data": [d.id for d in data], "verified": verification == "required",
         "privacy_unit": "organization" if dp is None else dp["privacy_unit"],
         "per_example_clipping": dp is not None,
         "framework": ("huggingface-sequence-classification" if pkg is not None
                       else "pytorch-reference")}))
    args = [cli, "plan", "training.encompute", "--profile", project.security,
            "--infrastructure", "infra.json", "--training", "training-decl.json", "-o", "plan.json"]
    if allow_development:
        args.append("--allow-development")
    out = _run(args, mc, check=False, both=True)
    if not (mc / "plan.json").exists():
        raise PlanningFailed(out)
    plan = json.loads((mc / "plan.json").read_text())
    plan_id = [line for line in out.splitlines() if line.startswith("encplan1:")][0]
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
            [cli, "aggregate", "coordinator-policy", "training.encompute", "--image", image,
             "--tee", "mock" if dev else target["tee"], *(["--development"] if dev else []),
             "--plan", "plan.json"], mc))
        coord_policy = ["--coordinator-policy", str(mc / "coord-policy.json")]
    # DP-SGD: no party-side clip bounds a contribution (each patient is
    # clipped inside the worker), so contributions must come from attested
    # workers running the bound training code.
    contrib = []
    if dp is not None:
        (mc / "contribution-policy.json").write_text(_native.contribution_attestation_policy(
            plan_id.split(":", 1)[1], None, code_digest(module.encompute_factory), image, dev))
        contrib = ["--attestation-policy", str(mc / "contribution-policy.json")]
    _run([cli, "trust", "init", "training.encompute", "--parties", parties, "--plan",
          "plan.json", *coord_policy, *contrib, "--bundle", "trust.json"], mc)
    for d in data:
        _run([cli, "trust", "authorize", "--party", d.owner, "--key", str(W / d.owner / "party.key"),
              "--bundle", str(mc / "trust.json")], mc)
    bundle = json.loads((mc / "trust.json").read_text())
    spec_node = next(k for k in bundle["nodes"] if k.startswith("spec:"))
    agg_spec = bundle["nodes"][spec_node]["evidence"]["value"]

    # 4. Datasets stay with their owners; only digests are shared. The
    # digest covers every sample and label, in order.
    commitments = []
    for d in data:
        t, pre = _dataset(d.payload)
        blob = tensors.dumps(t)
        (W / d.owner / "dataset.bin").write_bytes(blob)
        c = {"asset_id": d.id, "owner": d.owner, "gradient_asset": f"gradient-{d.id}",
             "digest": _native.sha256_hex(blob)}
        if pre is not None:
            c["preprocessing"] = pre
        if dp is not None:
            c["privacy_units"] = dp["units"][d.id]
            if "unit_ids" in t:
                c["grouping_digest"] = _native.sha256_hex(
                    tensors.dumps({"unit_ids": t["unit_ids"]}))
        commitments.append(c)
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
            **({} if pkg is None else {"huggingface": pkg.manifest}),
        },
        "datasets": commitments,
        "code_digest": code_digest(module.encompute_factory),
        "layout_digest": lora.layout_digest(ref),
        "config": {
            "method": method, "rank": cfg.rank, "alpha": cfg.alpha,
            "target_modules": sorted(cfg.target_modules), "optimizer": cfg.optimizer,
            "learning_rate": repr(float(cfg.learning_rate)),
            "update_clip": repr(float(cfg.update_clip)),
            "local_steps": cfg.local_steps, "batch_size": cfg.batch_size,
            "rounds": cfg.rounds, "adapter_parameters": dim,
            **({} if dp is None else {"dp_sgd": {k: dp[k] for k in DP_SPEC_FIELDS}}),
            **({} if peft is None else {"peft": peft}),
        },
        "participants": agg_spec["parties"],
    }
    spec_json = json.dumps(spec)
    spec_id = _native.training_spec_id(spec_json)
    run_id = _native.training_run_id(spec_json, secrets.token_hex(16))
    (mc / "training-spec.json").write_text(spec_json)
    _run([cli, "trust", "add", "training-spec.json", "--bundle", "trust.json"], mc)

    # 6. ModelCo's key broker: the model, checkpoint and adapter keys,
    # released only to workloads attesting to this training spec.
    (mc / "training-policy.json").write_text(
        _native.training_attestation_policy(spec_json, image, dev))
    model_key = secrets.token_bytes(32)
    (mc / f"{model.id}.enc").write_bytes(
        _native.seal_asset(model_key, "model", project.name, model.id, weights))
    keys = {model.id: model_key, "checkpoints": secrets.token_bytes(32),
            "adapters": secrets.token_bytes(32)}
    staged = {}
    # Keys by asset, and the policy each is released under.
    scoped: Dict[str, Tuple[bytes, str]] = {a: (k, "training-policy.json") for a, k in keys.items()}
    if target is not None:
        # Confidential training jobs attest as one participant: each
        # participant's policy releases the model and adapter to its jobs,
        # and its own dataset and output keys only to its jobs. Each
        # dataset travels sealed, its key with the broker.
        for c in commitments:
            party = c["owner"]
            policy = f"training-policy-{party}.json"
            (mc / policy).write_text(_native.participant_attestation_policy(
                spec_json, party, image, dev))
            k = secrets.token_bytes(32)
            blob = (W / party / "dataset.bin").read_bytes()
            staged[c["asset_id"]] = _native.seal_asset(k, "dataset", project.name, c["asset_id"],
                                                       blob)
            scoped[f"dataset-{c['asset_id']}"] = (k, policy)
            scoped[f"contribution-{party}"] = (secrets.token_bytes(32), policy)
            scoped[f"{model.id}.{party}"] = (keys[model.id], policy)
            scoped[f"adapters.{party}"] = (keys["adapters"], policy)
    broker_args = (["--broker-id", model.owner, "--development"] if dev else
                   ["--broker-id", target["broker_id"], "--kek", str(target["kek"])])
    for asset, (key, policy) in scoped.items():
        kf = mc / f"{asset}.key"
        kf.write_bytes(key)
        _run([cli, "keys", "protect", "--asset", asset, "--policy", policy,
              "--key-file", kf.name, *broker_args, "--broker", "broker.json"], mc)
        kf.unlink()  # the broker holds it now
    del scoped
    if staged:
        (W / "staged").mkdir(exist_ok=True)
        for asset_id, blob in staged.items():
            (W / "staged" / f"{asset_id}.enc").write_bytes(bytes(blob))
    # adapter-0, sealed under the adapters key (accepted by definition).
    a0 = tensors.dumps({"adapter": adapter0})
    (mc / "adapter-0.enc").write_bytes(
        _native.seal_asset(keys["adapters"], "adapter", project.name, "adapter-0", a0))
    del keys, model_key
    (mc / "checkpoints").mkdir(exist_ok=True)

    state = {
        "version": 1, "project": project.name, "model_id": model.id,
        "model_owner": model.owner, "data": [{"id": d.id, "owner": d.owner} for d in data],
        "gradient_assets": [c["gradient_asset"] for c in commitments],
        "commitments": commitments, "plan_id": plan_id, "spec": spec_json,
        "training_spec_id": spec_id, "run_id": run_id, "attested_coord": attested_coord,
        "mock_root": mock_root, "coord_key": coord, "eir": eir, "dim": dim,
        "adapter0_digest": _native.sha256_hex(a0),
        "lora": {"rank": cfg.rank, "alpha": cfg.alpha, "target_modules": list(cfg.target_modules),
                 "optimizer": cfg.optimizer, "learning_rate": cfg.learning_rate,
                 "update_clip": cfg.update_clip, "local_steps": cfg.local_steps,
                 "batch_size": cfg.batch_size, "rounds": cfg.rounds, "seed": cfg.seed,
                 "dropout": cfg.dropout},
        "privacy": privacy if dp is None else pv.level,
        "dp_sgd": None if dp is None else {k: dp[k] for k in DP_SPEC_FIELDS},
        "contribution_policy": contrib[1] if contrib else "",
        "privacy_preview": rows,
        "package_id": None if pkg is None else pkg.id,
    }
    _write_atomic(W / "run.json", json.dumps(state, indent=1).encode())
    return state


# --- training -----------------------------------------------------------------


def finetune(project=None, *, model=None, data=None, method="lora", privacy="strong",
             verification="required", config: Optional[lora.LoRAConfig] = None,
             infrastructure: Optional[dict] = None, allow_development: bool = False,
             workdir: Optional[str] = None, resume: Optional[str] = None,
             verbose: bool = True) -> FineTuneResult:
    say = print if verbose else (lambda *a, **k: None)
    t0 = time.perf_counter()
    if not resume:
        from .._privacy import Privacy
        Privacy.of(privacy)  # refuse an unknown level before any work
    timings: Dict[str, float] = {}
    cli = _cli()
    env = dict(os.environ, ENCOMPUTE_CLI=cli, PYTHONDONTWRITEBYTECODE="1",
               TOKENIZERS_PARALLELISM="false")
    recovery = None
    if resume:
        W = Path(resume)
        recovery = recover(str(W))
        if recovery["problems"]:
            raise TrainingFailed("the run directory is inconsistent: "
                                 + "; ".join(recovery["problems"]))
        st = json.loads((W / "run.json").read_text())
        say(f"{'Resuming':<24}accepted rounds {recovery['accepted'] or 'none'}; "
            f"lost rounds {recovery['lost'] or 'none'} (their privacy stays spent)")
    else:
        hf_model = getattr(getattr(model, "payload", None), "encompute_hf", None) is not None
        if method not in ("lora", "peft-lora"):
            raise EncomputeError("ENC2501", "method is 'lora' or 'peft-lora'")
        if (method == "peft-lora") != hf_model:
            raise EncomputeError(
                "ENC2501", "method='peft-lora' fine-tunes a Hugging Face model "
                           "(encompute.torch.huggingface); method='lora' a reference model")
        if verification not in ("receipt", "required"):
            raise EncomputeError("ENC1906", 'verification is "receipt" or "required"')
        module = model.payload
        if module is None or not hasattr(module, "encompute_factory"):
            raise EncomputeError("ENC2501", "the model needs a module built with "
                                 "encompute.torch.wrap_model (a factory, not a pickle)")
        for d in data:
            if d.payload is None:
                raise EncomputeError("ENC2501",
                                     f"{d.id} needs a dataset (encompute.torch.private_dataset)")
        W = Path(workdir or tempfile.mkdtemp(prefix="encompute-finetune-"))
        W.mkdir(parents=True, exist_ok=True)
        st = _setup(project, model, data, privacy, verification, config or lora.LoRAConfig(),
                    infrastructure, allow_development, W, cli, say)
    dp = st.get("dp_sgd")
    c = st["lora"]
    cfg = lora.LoRAConfig(rank=c["rank"], alpha=c["alpha"],
                          target_modules=tuple(c["target_modules"]), optimizer=c["optimizer"],
                          learning_rate=c["learning_rate"], update_clip=c["update_clip"],
                          local_steps=c["local_steps"], batch_size=c["batch_size"],
                          rounds=c["rounds"], seed=c["seed"], dropout=c.get("dropout", 0.0))
    mc = W / st["model_owner"]
    spec_json, spec_id, run_id = st["spec"], st["training_spec_id"], st["run_id"]
    spec = json.loads(spec_json)
    parties = str(W / "parties.json")
    mock_root = st["mock_root"]
    coord_policy = (["--coordinator-policy", str(mc / "coord-policy.json")]
                    if st["attested_coord"] else [])
    hfp = spec["base_model"].get("huggingface")
    if hfp:
        say(f"{'Framework':<24}Transformers {hfp['libraries']['transformers']}, "
            f"PEFT {hfp['libraries']['peft']} (LoRA)")
        say(f"{'Base model':<24}{hfp['repo_id']} ({hfp['model_class']})")
        say(f"{'Resolved revision':<24}{hfp['revision']}")
        say(f"{'Model package':<24}enchf1:{st['package_id'][:16]}...")
        say(f"{'Weights':<24}SAFETENSORS VERIFIED "
            f"({sum(f['path'].endswith('.safetensors') for f in hfp['files'])} file(s))")
        say(f"{'Remote code':<24}DISABLED")
    say(f"{'Training':<24}LoRA (rank {cfg.rank}, {st['dim']} adapter parameters)")
    say(f"{'Participants':<24}{len(st['data'])}")

    broker, broker_url = _start_broker(cli, mc, mock_root)
    ctx: Dict[str, Any] = dict(cli=cli, bundle=mc / "trust.json", modelco=mc, spec=spec_json,
                               broker=broker_url, broker_proc=broker, hw_seed=W / "hw.seed",
                               env=env, mock_root=mock_root, adapter0_digest=st["adapter0_digest"],
                               dp_sgd=dp)
    ctx["anchors"] = ["--parties", parties, "--coordinator-key", st["coord_key"], "--mock-root",
                      mock_root, "--execution-policy", str(mc / "training-policy.json")]
    ctx.update(base_module=None if resume else model.payload, seed=cfg.seed,
               package_id=st.get("package_id"))
    ctx["infer"] = dict(spec=spec_json, identity=str(mc / "coord.key"),
                        mock_seed=str(W / "hw.seed"), image=IMAGE,
                        model_sealed=str(mc / f"{st['model_id']}.enc"),
                        lora={k: c[k] for k in ("rank", "alpha", "target_modules", "seed")})
    say(f"{'Model protection':<24}ACTIVE (key released only to attested training workloads)")
    say(f"{'Dataset protection':<24}ACTIVE (datasets never leave their owners' workers)")
    say(f"{'Attestation':<24}REQUIRED")
    say(f"{'Gradient protection':<24}SECURE AGGREGATION")
    if dp:
        say(f"{'Privacy':<24}ACTIVE ({st['privacy']}, {dp['privacy_unit']}-level: DP-SGD, "
            f"per-{dp['privacy_unit']} clip {dp['per_example_clip']}, Poisson sampling "
            f"{dp['sampling_rate']}, noise {dp['noise_multiplier']})")
    else:
        say(f"{'Privacy':<24}ACTIVE ({st['privacy']}, organization-level)")

    # Plain PyTorch baseline: the same local steps, no Encompute.
    if not resume:
        bl = models.build(model.payload.encompute_factory, model.payload.encompute_kwargs)
        bl.load_state_dict(model.payload.state_dict())
        if spec["config"]["method"] == "peft-lora":
            from . import hf
            bl = hf.apply_peft(bl, spec["config"]["peft"], cfg.seed)
        else:
            lora.apply_lora(bl, cfg)
        task = tasks.of_spec(spec)
        t = time.perf_counter()
        b0 = tasks.select(_dataset(data[0].payload)[0], torch.arange(cfg.batch_size))
        b0.pop("unit_ids", None)
        opt = torch.optim.SGD(list(lora.adapter_parameters(bl).values()), lr=cfg.learning_rate)
        for _ in range(cfg.local_steps):
            opt.zero_grad()
            task.losses(bl, b0).mean().backward()
            opt.step()
        timings["plain_pytorch_local_training_s"] = time.perf_counter() - t

    # Training workers: attest, receive the model key, build the model.
    workers = []
    grad_paths: Dict[str, str] = {}
    provenance: Dict[str, Any] = {}
    ctx["provenance"] = provenance
    losses: List[float] = []
    stopped = None
    done = 0
    adapter_id = "adapter-0"
    t = time.perf_counter()
    try:
        for d in st["data"]:
            pd = W / d["owner"]
            wcfg = {
                "spec": spec_json, "broker": broker_url, "identity": str(pd / "party.key"),
                "mock_seed": str(W / "hw.seed"), "image": IMAGE,
                "model_sealed": str(mc / f"{st['model_id']}.enc"),
                "dataset": str(pd / "dataset.bin"), "dataset_asset": d["id"],
                "dataset_digest": next(x["digest"] for x in st["commitments"]
                                       if x["asset_id"] == d["id"]),
                "lora": st["lora"], "cli": cli, "artifact": str(mc / "training.encompute"),
                "parties": parties, "plan": str(mc / "plan.json"),
                "coordinator_policy": (str(mc / "coord-policy.json")
                                       if st["attested_coord"] else ""),
                "mock_root": mock_root, "party": d["owner"], "state": str(pd / "round.state"),
                "contribution_policy": st.get("contribution_policy", ""),
            }
            (pd / "worker.json").write_text(json.dumps(wcfg))
            p = subprocess.Popen([sys.executable, "-m", "encompute.torch.worker",
                                  str(pd / "worker.json")], cwd=pd, env=env, text=True,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            hello = json.loads(p.stdout.readline() or '{"ready": false, "error": "no reply"}')
            if not hello.get("ready"):
                raise TrainingFailed(f"{d['owner']}'s training worker refused: {hello.get('error')}",
                                     p.stderr.read())
            workers.append((d, p))
            if hello.get("grad_path"):
                grad_paths[d["owner"]] = hello["grad_path"]
            if hello.get("versions"):
                provenance["libraries"] = hello["versions"]
            if not (pd / "attestation.json").exists():
                (pd / "attestation.json").write_text(hello["record"])
                _run([cli, "trust", "add", str(pd / "attestation.json"), "--bundle",
                      "trust.json"], mc)
            # DP-SGD: the worker's contribution attestation (fresh each start).
            contribution = pd / "contribution-attestation.json"
            if st.get("contribution_policy") and contribution.exists():
                _run([cli, "trust", "add", str(contribution), "--bundle", "trust.json"], mc)
        timings["attestation_startup_s"] = time.perf_counter() - t
        say(f"{'Workers':<24}{len(workers)} attested, model key received")
        if grad_paths:
            paths = sorted(set(grad_paths.values()))
            say(f"{'Per-patient gradients':<24}ACTIVE ("
                + ", ".join({"vmap": "vectorized per-example gradients",
                             "reference": "one patient at a time"}[x] for x in paths) + ")")

        keys = dict(_native.acquire_training_keys(
            spec_json, broker_url, ["checkpoints", "adapters"], str(mc / "coord.key"),
            str(W / "hw.seed"), IMAGE)[0])
        if os.environ.get("ENCOMPUTE_TRAINING_FAILPOINT") == "kill-broker":
            broker.kill()  # keys are already held: training must not need it now

        # Where to start: adapter-0, or the latest accepted adapter (its
        # checkpoint checked against the ledgers, allowing only lost rounds).
        adapter = tensors.loads(bytes(_native.open_asset(
            keys["adapters"], (mc / "adapter-0.enc").read_bytes(), st["project"], "adapter-0",
            st["adapter0_digest"])))["adapter"]
        previous, r = None, 1
        if recovery:
            _refuse_revoked(cli, mc, ctx["anchors"], spec)
            if recovery["accepted"]:
                last = recovery["accepted"][-1]
                _, payload = _native.resume_checkpoint(
                    keys["checkpoints"], (mc / "checkpoints" / f"round-{last}.enc").read_bytes(),
                    st["project"], spec_id, spec["policy_id"], spec["privacy_policy_id"],
                    str(mc / "ledgers"), recovery["lost_round_ids"], run_id)
                adapter = tensors.loads(bytes(payload))["adapter"]
                adapter_id = previous = f"adapter-{last}"
            r = recovery["next_round"]
            done = len(recovery["accepted"])
        timings.update(secure_aggregation_s=0.0, checkpoint_s=0.0, trust_graph_s=0.0)
        (mc / "pending").mkdir(exist_ok=True)
        while done < cfg.rounds:
            t = time.perf_counter()
            port = _port()
            serve = [cli, "aggregate", "serve", "training.encompute", "--parties", parties,
                     "--plan", "plan.json", "--key", "coord.key", "--listen",
                     f"127.0.0.1:{port}", "--stage-timeout", "30", "--sequence", str(r),
                     "--ledger", "ledgers", "--out", f"update-{r}.json",
                     "--receipt", f"receipt-{r}.json", "--trust-bundle", "trust.json"]
            if st["attested_coord"]:
                serve += [*coord_policy, "--attester", "mock", "--mock-seed",
                          str(W / "hw.seed"), "--mock-image", IMAGE]
            if st.get("contribution_policy"):
                serve += ["--attestation-policy", st["contribution_policy"], "--mock-root",
                          mock_root]
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
            if os.environ.get("ENCOMPUTE_TRAINING_FAILPOINT") == "kill-coordinator":
                time.sleep(0.3)
                cp.send_signal(signal.SIGKILL)
            replies = []
            for d, p in workers:
                line = p.stdout.readline()
                if not line:
                    # Abort the round: nothing from it is accepted.
                    cp.kill()
                    cp.wait()
                    raise TrainingFailed(f"{d['owner']}'s training worker died in round {r}",
                                         p.stderr.read())
                replies.append(json.loads(line))
            log = cp.communicate()[0]
            if cp.returncode != 0:
                if "ENC2201" in log:
                    stopped = f"round {r}: privacy budget exhausted (RELEASE DENIED)"
                    break
                raise TrainingFailed(f"round {r} failed", log + "".join(x["log"] for x in replies))
            _failpoint("after-aggregate-release")
            timings["secure_aggregation_s"] += time.perf_counter() - t
            agg = json.loads((mc / f"update-{r}.json").read_text())
            released = torch.tensor(agg["values"], dtype=torch.float32)
            if dp:
                # The released (noised) sum of every sampled patient's
                # clipped gradient: one SGD step on the mean over the
                # expected batch.
                grad = released * (float(dp["per_example_clip"]) / dpsgd.CODEC_CLIP)
                adapter = adapter - cfg.learning_rate * grad / float(dp["expected_batch"])
            else:
                losses.append(sum(x["loss"] for x in replies) / len(replies))
                # The released (noised) sum of clipped, scaled updates: the
                # mean update, rescaled.
                n = len(agg["contributors"])
                adapter = adapter + released / n * cfg.update_clip
            new_id = f"adapter-{r}"
            t = time.perf_counter()
            # Provisional: sealed into pending/.
            payload = tensors.dumps({"adapter": adapter})
            _write_atomic(mc / "pending" / f"adapter-{r}.enc", bytes(_native.seal_asset(
                keys["adapters"], "adapter", st["project"], new_id, payload)))
            _failpoint("after-adapter-write")
            header = {
                "version": 1, "project": st["project"], "training_spec_id": spec_id,
                "run_id": run_id, "round": r, "adapter_id": new_id,
                "payload_digest": _native.sha256_hex(payload),
                "policy_id": spec["policy_id"], "privacy_policy_id": spec["privacy_policy_id"],
                "ledgers": json.loads(_native.ledger_checkpoints(str(mc / "ledgers"),
                                                                 st["gradient_assets"])),
                "lineage_root": None,
            }
            _failpoint("before-checkpoint-write")
            ckpt = bytes(_native.seal_checkpoint(keys["checkpoints"], json.dumps(header), payload))
            if os.environ.get("ENCOMPUTE_TRAINING_FAILPOINT") == "during-checkpoint-write":
                (mc / "pending" / f"round-{r}.ckpt.tmp").write_bytes(ckpt[: len(ckpt) // 2])
                os._exit(137)
            _write_atomic(mc / "pending" / f"round-{r}.ckpt", ckpt)
            timings["checkpoint_s"] += time.perf_counter() - t
            t = time.perf_counter()
            rec = _native.sign_adapter_record(
                spec_json, run_id, r, previous, (mc / f"receipt-{r}.json").read_text(),
                "update", _native.sha256_hex(payload), str(mc / "coord.key"))
            (mc / f"{new_id}.record.json").write_text(rec)
            _failpoint("before-trust-update")
            # The commit point.
            _run([cli, "trust", "add", f"{new_id}.record.json", "--bundle", "trust.json"], mc)
            _failpoint("after-trust-update")
            os.replace(mc / "pending" / f"adapter-{r}.enc", mc / f"{new_id}.enc")
            os.replace(mc / "pending" / f"round-{r}.ckpt", mc / "checkpoints" / f"round-{r}.enc")
            timings["trust_graph_s"] += time.perf_counter() - t
            previous, adapter_id = new_id, new_id
            done += 1
            say(f"{f'Round {r}/{cfg.rounds}':<24}COMPLETE"
                + ("" if dp else f" (mean local loss {losses[-1]:.3f})"))
            r += 1
        if stopped:
            say(f"{'Stopped':<24}{stopped}")
    finally:
        for _, p in workers:
            try:
                p.stdin.write('{"cmd": "exit"}\n')
                p.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                pass
            try:
                p.wait(timeout=30)
            except subprocess.TimeoutExpired:
                p.kill()

    # The trust report and the export decision.
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
        _native.check_export(st["eir"], spec_json, adapter_id)
        export = "EXPORT PERMITTED"
    except _native.NativeError as e:
        export = e.args[1]
    timings["total_s"] = time.perf_counter() - t0
    ctx["adapter"] = adapter if done else None
    if provenance:
        provenance["gradient_paths"] = grad_paths
        st_path = W / "run.json"
        state = json.loads(st_path.read_text())
        state.setdefault("provenance", []).append(provenance)
        _write_atomic(st_path, json.dumps(state, indent=1).encode())
    result = FineTuneResult(
        adapter_id=adapter_id, plan_id=st["plan_id"], training_spec_id=spec_id, run_id=run_id,
        rounds=done, stopped=stopped, report=report, rows=rows,
        satisfied="TRUST REQUIREMENTS SATISFIED" in report and done > 0,
        export=export, timings=timings, losses=losses, workdir=W, recovery=recovery, _ctx=ctx,
        privacy_unit=dp["privacy_unit"] if dp else "organization",
        privacy_preview=st.get("privacy_preview"),
    )
    say("")
    say(result.summary())
    return result
