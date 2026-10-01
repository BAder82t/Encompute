"""Under ENCOMPUTE_ENV=production the SDK verifies every plan it returns
against the production floor, with facts it recomputes itself."""

import pytest

import encompute


def project():
    p = encompute.Project("demo", parties=["alice", "bob"])
    return p, [p.data("alice-data", owner="alice"), p.data("bob-data", owner="bob")]


def test_production_refuses_a_plan_accepting_development_attestation(monkeypatch):
    """Review finding TG-3 (ENC-SF-2026-077): the SDK checked only the plan's consistency
    with the context the plan declares about itself; a plan accepting
    development (mock) attestation was returned in production."""
    monkeypatch.delenv("ENCOMPUTE_ENV", raising=False)
    p, data = project()
    assert p.plan(data=data, privacy="strong", allow_development=True).plan_id
    monkeypatch.setenv("ENCOMPUTE_ENV", "production")
    with pytest.raises(encompute.EncomputeError) as e:
        p.plan(data=data, privacy="strong", allow_development=True)
    assert "development attestation" in str(e.value)
    # A production-grade plan still passes the floor.
    assert p.plan(data=data, privacy="strong").plan_id
