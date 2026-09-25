"""Confidentiality declarations from Python (ADR-010)."""

import pytest

import encompute
from encompute import EncomputeError, Party, Tensor, asset, confidential, publish, reveal, secret, u16

hospital = Party("hospital-a", "Hospital A")
modelco = Party("modelco", "ModelCo")
coordinator = Party("coordinator")

patients = asset(
    "patients", owner=hospital, readers=[hospital], purposes=["disease-training"],
    derive={"gradient": ("aggregate_only", [coordinator])},
)
weights = asset(
    "weights", owner=modelco, readers=[modelco], purposes=["disease-training"], kind="model",
    derive={"gradient": ("aggregate_only", [coordinator])},
)


def code_of(fn):
    with pytest.raises(EncomputeError) as e:
        fn()
    return e.value.code


def step(x: secret[Tensor[4], -1.0:1.0, patients], w: secret[Tensor[4], -1.0:1.0, weights]):
    return {"g": confidential(x * w, kind="gradient", release="aggregate_only")}


def test_policy_graph_and_ids():
    m = encompute.compile(step, purpose="disease-training", precision=1e-2)
    eir = m.eir
    assert 'purpose "disease-training"' in eir and 'asset "patients"' in eir
    text = m.privacy()
    assert "gradient %" in text and "aggregate_only" in text and "coordinator" in text
    assert m.privacy(graph=True).startswith("digraph confidentiality")
    again = encompute.compile(step, purpose="disease-training", precision=1e-2)
    assert again.eir == eir, "deterministic"
    # The mock still runs (policies do not change execution).
    out = m([0.5, -0.5, 0.25, 1.0], [1.0, 1.0, -1.0, 0.5], mode="mock")
    assert out["g"] == pytest.approx([0.5, -0.5, -0.25, 0.5], abs=1e-2)


def test_illegal_flows():
    def leak(x: secret[Tensor[4], -1.0:1.0, patients], w: secret[Tensor[4], -1.0:1.0, weights]):
        return reveal(confidential(x * w, kind="gradient", release="aggregate_only"), to=coordinator)

    def public(x: secret[Tensor[4], -1.0:1.0, patients]):
        return publish(x * 2.0)

    def to_owner(x: secret[Tensor[4], -1.0:1.0, patients], w: secret[Tensor[4], -1.0:1.0, weights]):
        return reveal(encompute.dot(x, w), to=hospital)

    def weaker(x: secret[Tensor[4], -1.0:1.0, patients]):
        return confidential(x * 2.0, kind="gradient", release="public")

    def unbound(x: secret[Tensor[4], -1.0:1.0, patients], y: secret[Tensor[4], -1.0:1.0]):
        return x * y

    assert code_of(lambda: encompute.compile(leak, purpose="disease-training")) == "ENC1905"
    assert code_of(lambda: encompute.compile(public, purpose="disease-training")) == "ENC1901"
    assert code_of(lambda: encompute.compile(to_owner, purpose="disease-training")) == "ENC1902"
    assert code_of(lambda: encompute.compile(step, purpose="advertising")) == "ENC1903"
    assert code_of(lambda: encompute.compile(weaker, purpose="disease-training")) == "ENC1904"
    assert code_of(lambda: encompute.compile(unbound, purpose="disease-training")) == "ENC1906"
    with pytest.raises(EncomputeError):
        Party("Bad Name")
    with pytest.raises(EncomputeError):
        asset("a", owner=hospital, release="sometimes")


def test_exact_programs_carry_policies_too():
    scores = asset("scores", owner=hospital, readers=[hospital], release="allowed_parties",
                   purposes=["triage"])

    @encompute.compile(purpose="triage")
    def triage(s: secret[u16, 0:1000, scores]):
        return reveal(s >= 700, to=hospital)

    assert triage(750, mode="mock") is True
    assert "scores" in triage.privacy()


def test_unsafe_declarations_fail_fast():
    assert code_of(lambda: Party("p", 'Evil"')) == "ENC1906"
    assert code_of(lambda: asset("a", owner=hospital, purposes=['t"] release public'])) == "ENC1906"
    assert code_of(lambda: encompute.compile(step, purpose="x\n", precision=1e-2)) == "ENC1906"
    impostor = Party("hospital-a", "Someone Else")
    other = asset("other", owner=impostor, purposes=["disease-training"])

    def two_names(x: secret[Tensor[4], -1.0:1.0, patients], y: secret[Tensor[4], -1.0:1.0, other]):
        return x * y

    assert code_of(lambda: encompute.compile(two_names, purpose="disease-training", precision=1e-2)) == "ENC1906"


def test_raw_input_cannot_be_relabelled():
    data = asset("data", owner=hospital, purposes=["t"], derive={"model_update": ("public", [])})

    def launder(x: secret[Tensor[4], -1.0:1.0, data]):
        return {"u": publish(confidential(x, kind="model_update", release="public"))}

    assert code_of(lambda: encompute.compile(launder, purpose="t", precision=1e-2)) == "ENC1904"
