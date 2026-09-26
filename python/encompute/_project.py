"""Projects: declare who owns what and what may happen to it;
Encompute chooses the protection mechanisms.

    project = encompute.Project("medical-training",
                                parties=["hospital-a", "hospital-b", "modelco"])
    a = project.data("patients-a", owner="hospital-a")
    b = project.data("patients-b", owner="hospital-b")
    model = project.model("base-model", owner="modelco")
    run = project.train(model=model, data=[a, b], privacy="strong",
                        verification="required")
    print(run.explain())      # every requirement, mechanism, reason, evidence
    run.plan_id               # "encplan1:..."

Policies are named, and expand into visible declarations:

- ``private-training`` (data): only its owner reads it; used only for the
  project's purpose; only an aggregate of its gradients leaves, under a
  differential-privacy budget.
- ``private-model`` (model): only its owner reads it.
- ``shared-model`` (model): every data owner may read it (training can then
  run at each owner's premises).

No mechanism (secure aggregation, DP, TEEs, FHE) is named here: those are
the planner's choices, and it refuses to plan rather than weaken a
requirement.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from . import _native
from ._frontend import EncomputeError

DATA_POLICIES = ("private-training",)
MODEL_POLICIES = ("private-model", "shared-model")
SECURITY = ("standard", "strong", "maximum")


class PlanningFailed(EncomputeError):
    """No combination of available mechanisms satisfies the policy
    (ENC2401). ``report`` says why, per step and candidate."""

    def __init__(self, report: str):
        super().__init__("ENC2401", "PLANNING FAILED: no execution plan satisfies the policy")
        self.report = report


def _id(s: str, what: str) -> str:
    ok = s and len(s) <= 64 and s[0].isalnum() and all(
        c.isalnum() or c in "-_." for c in s
    )
    if not ok or s != s.lower():
        raise EncomputeError(
            "ENC1906",
            f"{what} {s!r}: use 1-64 lowercase letters, digits, '-', '_' or '.'",
        )
    return s


def _q(s: str) -> str:
    return json.dumps(s)


@dataclass(frozen=True)
class ProjectAsset:
    id: str
    owner: str
    kind: str
    policy: str
    # The PyTorch module or dataset, for fine-tuning (never serialized into
    # declarations, plans or the trust graph).
    payload: Any = field(default=None, compare=False, repr=False)


@dataclass
class Training:
    """A planned training run: the program, the approved plan and its ID."""

    eir: str
    plan: Optional[Dict[str, Any]]
    plan_json: Optional[str]
    plan_id: Optional[str]
    report: str
    model: Any

    def explain(self) -> str:
        """The plan: requirements, selected mechanisms, why, evidence."""
        return self.report

    def save_plan(self, path: str) -> None:
        """Write the plan for `encompute aggregate --plan` and the trust
        bundle."""
        if self.plan_json is None:
            raise PlanningFailed(self.report)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.plan_json)


class Project:
    """A collaboration: parties, their assets, and the security profile."""

    def __init__(
        self,
        name: str,
        parties: Sequence[str],
        *,
        purpose: Optional[str] = None,
        security: str = "standard",
    ):
        self.name = _id(name, "project")
        self.parties = [_id(p, "party") for p in parties]
        if len(set(self.parties)) != len(self.parties):
            raise EncomputeError("ENC1906", "parties must be distinct")
        self.purpose = purpose or self.name
        if security not in SECURITY:
            raise EncomputeError("ENC1906", f"security is one of {', '.join(SECURITY)}")
        self.security = security
        self._assets: Dict[str, ProjectAsset] = {}

    def _add(self, id: str, owner: str, kind: str, policy: str, payload: Any = None) -> ProjectAsset:
        _id(id, "asset")
        if owner not in self.parties:
            raise EncomputeError("ENC1906", f"{owner} is not a party of {self.name}")
        if id in self._assets:
            raise EncomputeError("ENC1906", f"asset {id} is declared twice")
        a = ProjectAsset(id, owner, kind, policy, payload)
        self._assets[id] = a
        return a

    def data(self, id: str, *, owner: str, policy: str = "private-training",
             dataset: Any = None) -> ProjectAsset:
        """A dataset owned by ``owner`` (for fine-tuning, pass
        ``dataset=encompute.torch.private_dataset(x, y)``)."""
        if policy not in DATA_POLICIES:
            raise EncomputeError("ENC1906", f"data policy is one of {', '.join(DATA_POLICIES)}")
        return self._add(id, owner, "dataset", policy, dataset)

    def model(self, id: str, *, owner: str, policy: str = "private-model",
              module: Any = None) -> ProjectAsset:
        """A model owned by ``owner`` (for fine-tuning, pass
        ``module=encompute.torch.wrap_model(...)``)."""
        if policy not in MODEL_POLICIES:
            raise EncomputeError("ENC1906", f"model policy is one of {', '.join(MODEL_POLICIES)}")
        return self._add(id, owner, "model", policy, module)

    def finetune(self, *, model: Optional[ProjectAsset] = None,
                 data: Optional[Sequence[ProjectAsset]] = None,
                 method: str = "lora", privacy: str = "strong",
                 verification: str = "required", **kwargs: Any):
        """Confidential LoRA fine-tuning of ``model`` on ``data``: planned,
        attested, securely aggregated, differentially private, checkpointed
        and verified. Returns an ``encompute.torch.finetune.FineTuneResult``.
        Raises :class:`PlanningFailed` if no available mechanism satisfies
        the policy. Needs PyTorch."""
        from .torch.finetune import finetune
        return finetune(self, model=model, data=data, method=method, privacy=privacy,
                        verification=verification, **kwargs)

    def train(
        self,
        *,
        model: ProjectAsset,
        data: Sequence[ProjectAsset],
        privacy: str = "strong",
        unit: str = "record",
        verification: str = "receipt",
        dim: int = 16,
        colluding: Optional[int] = None,
        infrastructure: Optional[Dict[str, Any]] = None,
        local_only: bool = False,
        region: Optional[str] = None,
        prefer: str = "latency",
        allow_development: bool = False,
    ) -> Training:
        """Plans federated training of ``model`` on ``data``: each data
        owner's gradient leaves only inside a noised aggregate delivered to
        the model's owner. Raises :class:`PlanningFailed` if no available
        mechanisms satisfy every requirement."""
        eir = self.training_program(model, data, privacy=privacy, unit=unit, dim=dim,
                                    colluding=colluding)
        if verification not in ("receipt", "required"):
            raise EncomputeError("ENC1906", 'verification is "receipt" or "required"')
        native = _call(_native.Model.compile, eir)
        training = json.dumps(
            {"model": model.id, "data": [d.id for d in data],
             "verified": verification == "required"}
        )
        prefs = json.dumps({"objective": prefer, "local_only": local_only,
                            "region": region, "allow_development": allow_development})
        plan_json, report, plan_id = _call(
            _native.plan, eir, self.security,
            json.dumps(infrastructure) if infrastructure is not None else None,
            training, prefs,
        )
        if plan_json is None:
            raise PlanningFailed(report)
        return Training(eir=eir, plan=json.loads(plan_json), plan_json=plan_json,
                        plan_id=plan_id, report=report, model=native)

    def plan(
        self,
        *,
        data: Sequence[ProjectAsset],
        privacy: str = "strong",
        unit: str = "record",
        to: Optional[str] = None,
        dim: int = 16,
        infrastructure: Optional[Dict[str, Any]] = None,
        local_only: bool = False,
        region: Optional[str] = None,
        prefer: str = "latency",
        allow_development: bool = False,
    ) -> Training:
        """Plans a private federated statistic over ``data``: each owner's
        contribution leaves only inside a noised aggregate delivered to
        ``to`` (default: the first party). No model is involved. Raises
        :class:`PlanningFailed` if nothing satisfies the policy."""
        recipient = to or self.parties[0]
        if recipient not in self.parties:
            raise EncomputeError("ENC1906", f"{recipient} is not a party of {self.name}")
        eir = self._aggregation_program(data, recipient, None, privacy=privacy, unit=unit,
                                        dim=dim, colluding=None)
        native = _call(_native.Model.compile, eir)
        prefs = json.dumps({"objective": prefer, "local_only": local_only,
                            "region": region, "allow_development": allow_development})
        plan_json, report, plan_id = _call(
            _native.plan, eir, self.security,
            json.dumps(infrastructure) if infrastructure is not None else None,
            None, prefs,
        )
        if plan_json is None:
            raise PlanningFailed(report)
        return Training(eir=eir, plan=json.loads(plan_json), plan_json=plan_json,
                        plan_id=plan_id, report=report, model=native)

    def training_program(
        self,
        model: ProjectAsset,
        data: Sequence[ProjectAsset],
        *,
        privacy: str = "strong",
        unit: str = "record",
        dim: int = 16,
        colluding: Optional[int] = None,
    ) -> str:
        """The declarations `train` plans: the project's parties and assets,
        a gradient per dataset (aggregate-only, budgeted) and their secure
        sum to the model's owner."""
        if model.kind != "model":
            raise EncomputeError("ENC1906", f"{model.id} is not a model")
        return self._aggregation_program(data, model.owner, model, privacy=privacy, unit=unit,
                                         dim=dim, colluding=colluding)

    def _aggregation_program(
        self,
        data: Sequence[ProjectAsset],
        recipient: str,
        model: Optional[ProjectAsset],
        *,
        privacy: str,
        unit: str,
        dim: int,
        colluding: Optional[int],
    ) -> str:
        if len(data) < 2:
            raise EncomputeError("ENC2106", "aggregation needs datasets from at least two parties")
        owners = [d.owner for d in data]
        if len(set(owners)) != len(owners):
            raise EncomputeError("ENC2106", "each dataset must belong to a different party")
        presets = {p[0]: p for p in _native.privacy_presets()}
        if privacy not in presets:
            raise EncomputeError("ENC2203", f"privacy is one of {', '.join(presets)}")
        _, eps, delta, noise = presets[privacy]
        n = len(data)
        c = max(0, n - 2) if colluding is None else colluding
        lines = [
            "encompute 0.1",
            f"program {self.name.replace('-', '_').replace('.', '_')} precision 0.001 "
            f"purpose {_q(self.purpose)}",
        ]
        lines += [f"party {_q(p)} {_q(p)}" for p in self.parties]
        if model is not None:
            readers = "[]"
            if model.policy == "shared-model":
                readers = "[" + ", ".join(_q(o) for o in owners) + "]"
            lines.append(
                f"asset {_q(model.id)} model owners [{_q(model.owner)}] readers {readers} "
                f"purposes [{_q(self.purpose)}] release never"
            )
        for d in data:
            lines.append(
                f"asset {_q(d.id)} dataset owners [{_q(d.owner)}] readers [] "
                f"purposes [{_q(self.purpose)}] release never"
            )
        for d in data:
            lines.append(
                f"asset {_q('gradient-' + d.id)} gradient owners [{_q(d.owner)}] "
                f"readers [{_q(recipient)}] purposes [{_q(self.purpose)}] release aggregate_only "
                f"privacy unit {_q(unit)} epsilon {eps!r} delta {delta!r}"
            )
        for i, d in enumerate(data):
            lines.append(
                f"%{i} = input {_q('g_' + d.id.replace('-', '_').replace('.', '_'))} [-1.0, 1.0] "
                f"asset {_q('gradient-' + d.id)} "
                f": secret vector<{dim}>"
            )
        acc = 0
        for i in range(1, n):
            lines.append(f"%{n + i - 1} = add %{acc}, %{i} : secret vector<{dim}>")
            acc = n + i - 1
        lines.append(f"output \"update\" = %{acc} to {_q(recipient)}")
        lines.append(
            f"aggregate \"update\" sum minimum {n} colluding {c} clip [-1.0, 1.0] scale 4096 "
            f"modulus 40 dp discrete_gaussian clip_norm 1.0 noise_multiplier {noise!r}"
        )
        return "\n".join(lines) + "\n"


def _call(f: Any, *args: Any) -> Any:
    try:
        return f(*args)
    except _native.NativeError as e:
        code, message = e.args
        raise EncomputeError(code, message) from None
