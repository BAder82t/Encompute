"""The Encompute control plane from Python (API v1).

    client = encompute.Client("https://encompute.company.example")
    project = client.project("medical-training")
    result = project.run(eligibility, dict(age=31, income=120_000, debt=21_000, risk=400),
                         purpose="credit-decision")
    result.outputs, result.job.state, result.trust["verdict"]

The CLI (``encompute jobs run``) and this client call the same API. The
control plane never sees inputs or outputs: they are encrypted here, sent
to the scheduled evaluator with the job's grant, and decrypted here; the
control plane gets the evaluator's signed receipt and this client's
commitments, and rebuilds the trust report from them.

Credentials: ``token=`` (an OIDC token from your identity provider),
``ENCOMPUTE_TOKEN``, or the login saved by ``encompute login``.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from ._frontend import EncomputeError

__all__ = ["Client", "Project", "Job", "RunResult", "ControlError"]


class ControlError(EncomputeError):
    """An error from the control plane: ``code`` (ENCnnnn) and message."""


def _saved_login() -> Dict[str, Any]:
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    p = base / "encompute" / "control.json"
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def _eir(program: Any) -> str:
    if isinstance(program, str):
        return program
    eir = getattr(program, "eir", None)
    if isinstance(eir, str):
        return eir
    raise TypeError("program must be a compiled Encompute function, a Model, or .eir text")


class Client:
    """A connection to an Encompute control plane."""

    def __init__(self, url: Optional[str] = None, token: Optional[str] = None, *, timeout: float = 60.0):
        saved = _saved_login()
        self.url = (url or os.environ.get("ENCOMPUTE_CONTROL_URL") or saved.get("url") or "").rstrip("/")
        if not self.url:
            raise ControlError("ENC2601", "no control plane URL: pass url= or run `encompute login`")
        self._token = token or os.environ.get("ENCOMPUTE_TOKEN") or saved.get("token")
        if not self._token:
            raise ControlError("ENC2601", "no credentials: pass token= or run `encompute login`")
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"<encompute.Client {self.url}>"

    # -- transport -----------------------------------------------------------

    def _call(self, method: str, path: str, body: Any = None, headers: Optional[Dict[str, str]] = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                err = json.loads(e.read())
            except ValueError:
                err = {}
            raise ControlError(err.get("code", "ENC1701"), err.get("message", f"HTTP {e.code}")) from None
        except urllib.error.URLError as e:
            raise ControlError("ENC1701", f"cannot reach the control plane: {e.reason}") from None

    def get(self, path: str) -> Any:
        return self._call("GET", path)

    def post(self, path: str, body: Any = None, headers: Optional[Dict[str, str]] = None) -> Any:
        return self._call("POST", path, body, headers)

    # -- resources -------------------------------------------------------------

    def whoami(self) -> Dict[str, Any]:
        return self.get("/v1/whoami")

    def projects(self) -> List[Dict[str, Any]]:
        return self.get("/v1/projects")

    def project(self, name_or_id: str) -> "Project":
        """A project by ID or name (among the projects you can see)."""
        for p in self.projects():
            if name_or_id in (p["id"], p["name"]):
                return Project(self, self.get(f"/v1/projects/{p['id']}"))
        raise ControlError("ENC2603", f"no project {name_or_id!r}")

    def create_project(self, organization: str, name: str) -> "Project":
        p = self.post("/v1/projects", {"organization": organization, "name": name})
        return Project(self, self.get(f"/v1/projects/{p['id']}"))

    def assets(self) -> List[Dict[str, Any]]:
        return self.get("/v1/assets")

    def register_asset(
        self,
        organization: str,
        kind: str,
        name: str,
        *,
        digest: Optional[str] = None,
        path: Optional[Union[str, Path]] = None,
        **metadata: Any,
    ) -> Dict[str, Any]:
        """Registers an asset's metadata: its digest (computed from ``path``
        if given), never its contents."""
        if digest is None:
            if path is None:
                raise ValueError("give digest= or path=")
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        return self.post("/v1/assets", {"organization": organization, "kind": kind, "name": name, "digest": digest, **metadata})

    def approve_asset(self, asset: str, project: str, purpose: str) -> Dict[str, Any]:
        return self.post(f"/v1/assets/{asset}/approvals", {"project": project, "purpose": purpose})

    def revoke_asset(self, asset: str) -> Dict[str, Any]:
        return self.post(f"/v1/assets/{asset}/revoke")

    def job(self, job_id: str) -> "Job":
        return Job(self, self.get(f"/v1/jobs/{job_id}"))

    def trust(self, job_id: str) -> Dict[str, Any]:
        """The job's trust report, rebuilt by the control plane from signed
        evidence."""
        return self.get(f"/v1/trust/{job_id}")

    def privacy(self, asset: str) -> Dict[str, Any]:
        return self.get(f"/v1/privacy/{asset}")

    def audit(self, organization: Optional[str] = None, after: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
        q = f"/v1/audit?after={after}&limit={limit}"
        if organization:
            q += f"&organization={organization}"
        return self.get(q)


class Job:
    def __init__(self, client: Client, data: Dict[str, Any]):
        self._client = client
        self.data = data

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def state(self) -> str:
        return self.data["state"]

    def refresh(self) -> "Job":
        self.data = self._client.get(f"/v1/jobs/{self.id}")
        return self

    def cancel(self) -> "Job":
        self._client.post(f"/v1/jobs/{self.id}/cancel")
        return self.refresh()

    def trust(self) -> Dict[str, Any]:
        return self._client.trust(self.id)

    def __repr__(self) -> str:
        return f"<Job {self.id} {self.state}>"


class RunResult:
    def __init__(self, outputs: Any, job: Job, trust: Dict[str, Any]):
        self.outputs = outputs
        self.job = job
        self.trust = trust

    def __repr__(self) -> str:
        return f"<RunResult {self.job.state} trust={self.trust.get('verdict')} outputs={self.outputs!r}>"


class Project:
    def __init__(self, client: Client, data: Dict[str, Any]):
        self._client = client
        self.data = data

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def name(self) -> str:
        return self.data["name"]

    def __repr__(self) -> str:
        return f"<Project {self.name} ({self.id}) members={self.data.get('members')}>"

    def add_member(self, organization: str) -> "Project":
        self._client.post(f"/v1/projects/{self.id}/members", {"organization": organization})
        self.data = self._client.get(f"/v1/projects/{self.id}")
        return self

    def plan(self, program: Any) -> Dict[str, Any]:
        return self._client.post("/v1/plans", {"project": self.id, "program": _eir(program)})

    def submit(
        self,
        program: Any,
        *,
        purpose: str,
        sources: Iterable[str] = (),
        output: str = "out",
        idempotency_key: Optional[str] = None,
    ) -> Job:
        """Plans and submits a job. Retrying with the same idempotency key
        returns the same job (never a second one)."""
        plan = self.plan(program)
        body = {"project": self.id, "plan": plan["id"], "purpose": purpose,
                "source_assets": list(sources), "requested_output": output}
        key = idempotency_key or hashlib.sha256(
            json.dumps([self.id, purpose, plan["program_id"], body["source_assets"]]).encode()
        ).hexdigest()[:32]
        return Job(self._client, self._client.post("/v1/jobs", body, {"Idempotency-Key": key}))

    def run(
        self,
        program: Any,
        inputs: Dict[str, Any],
        *,
        purpose: str,
        sources: Iterable[str] = (),
        keys_dir: Optional[Union[str, Path]] = None,
        idempotency_key: Optional[str] = None,
        timeout: float = 300.0,
    ) -> RunResult:
        """Submits, waits for a compatible evaluator, runs there encrypted
        with the job's grant, reports the receipt, and returns the
        decrypted outputs with the trust report."""
        from . import Model, _call  # noqa: F401  (avoid an import cycle)

        model = program if isinstance(program, Model) else None
        if model is None:
            from . import _native

            model = Model(_call(_native.Model.compile, _eir(program)), "dict")
        job = self.submit(model, purpose=purpose, sources=sources, idempotency_key=idempotency_key)
        deadline = time.monotonic() + timeout
        while job.state in ("created", "planning", "planned", "waiting_for_approval", "authorized"):
            if time.monotonic() > deadline:
                raise ControlError("ENC2606", f"job {job.id} was not scheduled within {timeout}s ({job.state})")
            time.sleep(1.0)
            job.refresh()
        if job.state != "queued":
            raise ControlError("ENC2604", f"job {job.id} is {job.state}: {job.data.get('error')}")
        d = job.data
        got = json.loads(
            _call(
                model._native.run_remote_json,
                d["evaluator_url"],
                model._encode((), dict(inputs)),
                json.dumps(d["grant"]),
                d["evaluator_receipt_key"],
                None if keys_dir is None else str(keys_dir),
            )
        )
        self._client.post(
            f"/v1/jobs/{job.id}/complete",
            {"receipt": got["receipt"], "request_commitment": got["request_commitment"],
             "output_commitment": got["output_commitment"], "key_id": got["key_id"]},
        )
        job.refresh()
        from . import _typed

        raw = got["raw_outputs"]
        outputs = {name: _typed(raw[name], s, e) for name, _, s, e in model._outputs}
        return RunResult(outputs, job, job.trust())
