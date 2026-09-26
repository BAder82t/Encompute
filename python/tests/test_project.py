"""Projects (ADR-015): declare policies; Encompute plans the mechanisms,
or refuses without weakening anything."""

import json

import pytest

import encompute

TDX = {
    "tees": [{"tee": "intel-tdx", "provider": "gcp-confidential-space", "gpu": True, "cloud": True}],
    "key_broker": True,
}


def hospitals(security="standard", model_policy="private-model"):
    p = encompute.Project(
        "medical-training",
        parties=["hospital-a", "hospital-b", "hospital-c", "modelco"],
        security=security,
    )
    data = [p.data(f"patients-{x}", owner=f"hospital-{x}") for x in "abc"]
    model = p.model("base-model", owner="modelco", policy=model_policy)
    return p, model, data


def mechanisms(run, step):
    s = next(s for s in run.plan["steps"] if s["id"] == step)
    return [m["mechanism"] for m in s["mechanisms"]]


def test_private_model_training_is_attested_and_aggregated():
    p, model, data = hospitals()
    run = p.train(model=model, data=data, privacy="strong", infrastructure=TDX)
    assert run.plan_id.startswith("encplan1:")
    assert mechanisms(run, "train:patients-a") == [
        "confidential_compute", "attestation", "attested_key_release"]
    assert mechanisms(run, "aggregate:update") == [
        "secure_aggregation", "differential_privacy"]
    text = run.explain()
    assert "ALL TRUST REQUIREMENTS SATISFIED" in text
    assert "estimated" in text and "guaranteed" not in text.replace("not guarantees", "")
    # Deterministic.
    again = p.train(model=model, data=data, privacy="strong", infrastructure=TDX)
    assert again.plan_id == run.plan_id


def test_no_valid_mechanism_fails_closed():
    p, model, data = hospitals()
    with pytest.raises(encompute.PlanningFailed) as e:
        p.train(model=model, data=data)          # normal hardware only
    assert e.value.code == "ENC2401"
    assert "not supported under FHE" in e.value.report
    # A debug-only TEE is not a TEE.
    debug = {"tees": [dict(TDX["tees"][0], debug_only=True)], "key_broker": True}
    with pytest.raises(encompute.PlanningFailed):
        p.train(model=model, data=data, infrastructure=debug)


def test_shared_model_trains_at_each_owner():
    p, model, data = hospitals(model_policy="shared-model")
    run = p.train(model=model, data=data)
    s = next(s for s in run.plan["steps"] if s["id"] == "train:patients-b")
    assert s["placement"] == {"at": "party", "detail": "hospital-b"}
    # Verified training needs attested workloads: local training is refused.
    with pytest.raises(encompute.PlanningFailed):
        p.train(model=model, data=data, verification="required")


def test_presets_expand_visibly():
    p, model, data = hospitals(security="strong")
    run = p.train(model=model, data=data, infrastructure=TDX)
    reqs = run.plan["requirements"]
    assert {"requirement": "require_attestation", "step": "aggregate:update"} in reqs
    assert "attestation for every aggregation coordinator" in run.explain()
    assert "epsilon 3.0" in run.eir


def test_declarations_are_checked():
    p, model, data = hospitals()
    with pytest.raises(encompute.EncomputeError):
        p.data("x", owner="nobody")
    with pytest.raises(encompute.EncomputeError):
        p.model("m2", owner="modelco", policy="whatever")
    with pytest.raises(encompute.EncomputeError):
        p.train(model=model, data=data[:1], infrastructure=TDX)
    with pytest.raises(encompute.EncomputeError):
        encompute.Project("x", parties=["a"], security="paranoid")


def test_plan_is_saved_for_the_cli(tmp_path):
    p, model, data = hospitals()
    run = p.train(model=model, data=data, infrastructure=TDX)
    out = tmp_path / "plan.json"
    run.save_plan(str(out))
    assert json.loads(out.read_text())["program_id"] == run.plan["program_id"]


def test_plan_without_a_model():
    p = encompute.Project("demo", parties=["alice", "bob"])
    a = p.data("alice-data", owner="alice")
    b = p.data("bob-data", owner="bob")
    run = p.plan(data=[a, b], privacy="strong")
    assert [s["id"] for s in run.plan["steps"]] == ["aggregate:update"]
    assert "secure_aggregation" in [m["mechanism"] for m in run.plan["steps"][0]["mechanisms"]]
    with pytest.raises(encompute.EncomputeError):
        p.plan(data=[a, b], to="carol")
