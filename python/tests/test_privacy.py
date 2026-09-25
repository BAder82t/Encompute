"""Differential-privacy declarations from Python (ADR-013)."""

import pytest

import encompute
from encompute import DP, DiscreteGaussian, EncomputeError, Party, Tensor, asset, secret, secure_aggregate

coordinator = Party("coordinator")
hospitals = [Party(f"hospital-{x}") for x in "abc"]


def grads(privacy="strong", unit="patient"):
    return [
        asset(f"gradient-{x}", owner=h, readers=[coordinator], purposes=["disease-training"],
              kind="gradient", release="aggregate_only", privacy=privacy, unit=unit)
        for x, h in zip("abc", hospitals)
    ]


def fedavg(assets, privacy="strong"):
    def step(ga: secret[Tensor[8], -1.0:1.0, assets[0]],
             gb: secret[Tensor[8], -1.0:1.0, assets[1]],
             gc: secret[Tensor[8], -1.0:1.0, assets[2]]):
        return {"global_gradient": secure_aggregate(
            ga + gb + gc, to=coordinator, minimum=3, colluding=2, clip=(-1.0, 1.0),
            scale=65536, modulus_bits=40, privacy=privacy)}
    return step


def code_of(fn):
    with pytest.raises(EncomputeError) as e:
        fn()
    return e.value.code


def test_presets_expand_and_explain():
    m = encompute.compile(fedavg(grads()), purpose="disease-training")
    assert 'privacy unit "patient" epsilon 3.0 delta 1e-6' in m.eir
    assert "dp discrete_gaussian clip_norm 1.0 noise_multiplier 6.0" in m.eir
    text = m.privacy()
    assert "Differential privacy" in text and "runtime enforcement" in text


def test_explicit_budget_and_mechanism():
    m = encompute.compile(fedavg(grads(DP(2.0, 1e-7)), privacy=DiscreteGaussian(0.5, 3.0)),
                          purpose="disease-training")
    assert "epsilon 2.0 delta 1e-7" in m.eir and "clip_norm 0.5 noise_multiplier 3.0" in m.eir


def test_budgeted_release_needs_noise():
    assert code_of(lambda: encompute.compile(fedavg(grads(), privacy=None), purpose="disease-training")) == "ENC2203"


def test_invalid_levels_and_parameters():
    assert code_of(lambda: grads("weak")) == "ENC2203"
    assert code_of(lambda: DP(0, 1e-6)) == "ENC2203"
    assert code_of(lambda: DP(1.0, 1.0)) == "ENC2203"
    assert code_of(lambda: DiscreteGaussian(1.0, 0.0)) == "ENC2203"


def test_dp_object_carries_unit_and_mechanism():
    dp = DP(2.0, 1e-7, unit="user", clip_norm=0.5, noise_multiplier=4.0)
    m = encompute.compile(fedavg(grads(dp, unit="record"), privacy=dp), purpose="disease-training")
    assert 'privacy unit "user" epsilon 2.0 delta 1e-7' in m.eir
    assert "clip_norm 0.5 noise_multiplier 4.0" in m.eir
    assert code_of(lambda: encompute.compile(fedavg(grads(), privacy=DP(3.0, 1e-6)), purpose="disease-training")) == "ENC2203"
