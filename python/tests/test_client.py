"""The control-plane client pins evaluator keys: a compromised control
plane cannot choose which evaluator receipt key the client accepts."""

import pytest

import encompute
from encompute import Tensor, secret
from encompute.client import Client, ControlError, Project

TRUSTED = "ab" * 32
ROGUE = "cd" * 32


@encompute.compile(precision=1e-3)
def double(x: secret[Tensor[2], -1.0:1.0]):
    return x * 2.0


def scheduled(receipt_key):
    """A control plane that schedules the job on `receipt_key` at an
    unreachable evaluator (nothing is ever sent there in these tests)."""

    def call(method, path, body=None, headers=None):
        if path == "/v1/plans":
            return {"id": "pln_1", "program_id": "p" * 64}
        if path == "/v1/jobs":
            return {"id": "job_1", "state": "queued", "evaluator_url": "http://127.0.0.1:9",
                    "grant": {}, "evaluator_receipt_key": receipt_key}
        raise AssertionError(f"unexpected call {method} {path}")

    return call


def project(receipt_key, monkeypatch, **kw):
    monkeypatch.delenv("ENCOMPUTE_TRUSTED_EVALUATORS", raising=False)
    c = Client("http://control.invalid", token="t", **kw)
    c._call = scheduled(receipt_key)
    return Project(c, {"id": "prj_1", "name": "p"})


def run(p):
    return p.run(double, {"x": [0.1, 0.2]}, purpose="test", timeout=1.0)


def test_a_key_outside_the_pinned_set_is_refused(monkeypatch):
    p = project(ROGUE, monkeypatch, trusted_evaluators=[TRUSTED])
    with pytest.raises(ControlError) as e:
        run(p)
    assert e.value.code == "ENC2607"
    assert "not among the trusted evaluators" in str(e.value)


def test_the_pin_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("ENCOMPUTE_TRUSTED_EVALUATORS", f"{TRUSTED.upper()}, {'ef' * 32}")
    c = Client("http://control.invalid", token="t")
    assert TRUSTED in c.trusted_evaluators
    c.check_evaluator(TRUSTED)
    with pytest.raises(ControlError):
        c.check_evaluator(ROGUE)


def test_a_pinned_key_passes_and_unpinned_warns(monkeypatch):
    # Pinned and matching: no refusal; the run then fails only on the
    # unreachable evaluator.
    p = project(TRUSTED, monkeypatch, trusted_evaluators=[TRUSTED])
    with pytest.raises(encompute.EncomputeError) as e:
        run(p)
    assert "trusted evaluators" not in str(e.value)
    # No pin (backward compatible): accepted with a warning.
    p = project(ROGUE, monkeypatch)
    with pytest.warns(UserWarning, match="not pinned"):
        with pytest.raises(encompute.EncomputeError) as e:
            run(p)
    assert "trusted evaluators" not in str(e.value)
