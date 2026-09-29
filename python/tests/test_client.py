"""The control-plane client pins evaluator keys: a compromised control
plane cannot choose which evaluator receipt key the client accepts."""

import json

import pytest

import encompute
from encompute import Tensor, secret
from encompute import _call
from encompute.client import Client, ControlError, Project

TRUSTED = "ab" * 32
ROGUE = "cd" * 32
ENV = ("ENCOMPUTE_TRUSTED_EVALUATORS", "ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR", "ENCOMPUTE_ENV")


@encompute.compile(precision=1e-3)
def double(x: secret[Tensor[2], -1.0:1.0]):
    return x * 2.0


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ENV:
        monkeypatch.delenv(k, raising=False)


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


def project(receipt_key, **kw):
    c = Client("http://control.invalid", token="t", **kw)
    c._call = scheduled(receipt_key)
    return Project(c, {"id": "prj_1", "name": "p"})


def run(p):
    return p.run(double, {"x": [0.1, 0.2]}, purpose="test", timeout=1.0)


def test_a_key_outside_the_pinned_set_is_refused():
    p = project(ROGUE, trusted_evaluators=[TRUSTED])
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


def test_a_pinned_key_passes():
    # Pinned and matching: no refusal; the run then fails only on the
    # unreachable evaluator.
    p = project(TRUSTED, trusted_evaluators=[TRUSTED])
    with pytest.raises(encompute.EncomputeError) as e:
        run(p)
    assert "trusted evaluators" not in str(e.value)
    assert "pinned" not in str(e.value)


def test_an_empty_pin_set_refuses_every_evaluator(monkeypatch):
    """Review finding PY-1 (ENC-SF-2026-078): an explicit, empty pin set (``trusted_evaluators=[]``
    or ``ENCOMPUTE_TRUSTED_EVALUATORS`` set to nothing) used to mean "no pin":
    any key the control plane named was accepted with a warning. It now
    refuses every key."""
    c = Client("http://control.invalid", token="t", trusted_evaluators=[])
    for key in (TRUSTED, ROGUE):
        with pytest.raises(ControlError) as e:
            c.check_evaluator(key)
        assert e.value.code == "ENC2607"
    monkeypatch.setenv("ENCOMPUTE_TRUSTED_EVALUATORS", " , ")
    c = Client("http://control.invalid", token="t")
    assert c.trusted_evaluators == frozenset()
    with pytest.raises(ControlError) as e:
        c.check_evaluator(ROGUE)
    assert e.value.code == "ENC2607"


def test_without_a_pin_a_job_is_refused():
    """Review finding PY-1 (ENC-SF-2026-078): pinning was opt-in, so by default the control
    plane chose the evaluator key. Without a pin the job is now refused
    before any input leaves."""
    p = project(ROGUE)
    with pytest.raises(ControlError) as e:
        run(p)
    assert e.value.code == "ENC2605"
    assert "no trusted evaluator keys are pinned" in str(e.value)


def test_the_development_opt_out_warns_and_is_refused_in_production(monkeypatch):
    monkeypatch.setenv("ENCOMPUTE_ENV", "development")
    p = project(ROGUE, allow_unpinned_evaluator=True)
    with pytest.warns(UserWarning, match="not pinned"):
        with pytest.raises(encompute.EncomputeError) as e:
            run(p)
    # Accepted: the run fails only on the unreachable evaluator.
    assert "trusted evaluators" not in str(e.value) and "pinned" not in str(e.value)
    monkeypatch.setenv("ENCOMPUTE_ALLOW_UNPINNED_EVALUATOR", "1")
    c = Client("http://control.invalid", token="t")
    assert c.allow_unpinned_evaluator
    monkeypatch.setenv("ENCOMPUTE_ENV", "production")
    with pytest.raises(ControlError) as e:
        c.check_evaluator(ROGUE)
    assert e.value.code == "ENC2605"


@pytest.mark.parametrize("env", [None, "", "prod", "Development", "staging"])
def test_the_opt_out_fails_closed_unless_explicitly_in_development(monkeypatch, env):
    """The opt-out used to be refused only under ENCOMPUTE_ENV=production, so
    an unset or misspelt environment accepted the control plane's key. It is
    now honoured only under an explicit ENCOMPUTE_ENV=development, in the
    Python check and in the native run alike."""
    if env is not None:
        monkeypatch.setenv("ENCOMPUTE_ENV", env)
    c = Client("http://control.invalid", token="t", allow_unpinned_evaluator=True)
    with pytest.raises(ControlError) as e:
        c.check_evaluator(ROGUE)
    assert e.value.code == "ENC2605"
    assert "ENCOMPUTE_ENV=development" in str(e.value)
    with pytest.raises(encompute.EncomputeError) as e:
        _call(double._native.run_remote_json, "http://127.0.0.1:9", {"x": [0.1, 0.2]},
              json.dumps({}), ROGUE, None, None, True)
    assert e.value.code == "ENC2605"
    assert "ENCOMPUTE_ENV=development" in str(e.value)


def test_the_native_run_enforces_the_pin_before_sending_anything():
    """Review finding EV-4 (ENC-SF-2026-046): the pin was enforced only in the Python wrapper;
    ``run_remote_json`` trusted whatever receipt key it was given. It now
    checks the pin itself before contacting the evaluator (the URL here is
    unreachable, so any other error would mean it tried)."""
    native = double._native

    def remote(key, *pin):
        return _call(native.run_remote_json, "http://127.0.0.1:9", {"x": [0.1, 0.2]},
                     json.dumps({}), key, None, *pin)

    for pin, key, code in [
        ([TRUSTED], ROGUE, "ENC2607"),
        ([], TRUSTED, "ENC2607"),
        (None, ROGUE, "ENC2605"),
    ]:
        with pytest.raises(encompute.EncomputeError) as e:
            remote(key, pin, False)
        assert e.value.code == code, (pin, key, e.value)
