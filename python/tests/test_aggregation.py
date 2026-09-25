"""Secure-aggregation declarations from Python (ADR-012)."""

import pytest

import encompute
from encompute import EncomputeError, Party, Tensor, asset, secret, secure_aggregate

coordinator = Party("coordinator")
hospitals = [Party(f"hospital-{x}") for x in "abc"]
grads = [
    asset(f"gradient-{x}", owner=h, readers=[coordinator], purposes=["disease-training"],
          kind="gradient", release="aggregate_only")
    for x, h in zip("abc", hospitals)
]


def fedavg(scale=65536, modulus_bits=32, minimum=3):
    def step(ga: secret[Tensor[8], -1.0:1.0, grads[0]],
             gb: secret[Tensor[8], -1.0:1.0, grads[1]],
             gc: secret[Tensor[8], -1.0:1.0, grads[2]]):
        return {"global_gradient": secure_aggregate(
            ga + gb + gc, to=coordinator, minimum=minimum, colluding=1, clip=(-1.0, 1.0),
            scale=scale, modulus_bits=modulus_bits)}
    return step


def code_of(fn):
    with pytest.raises(EncomputeError) as e:
        fn()
    return e.value.code


def test_declaration_lowers_to_an_aggregation_boundary():
    m = encompute.compile(fedavg(), purpose="disease-training", precision=1e-3)
    assert 'aggregate "global_gradient" sum minimum 3 colluding 1 clip [-1.0, 1.0] scale 65536 modulus 32' in m.eir
    text = m.privacy()
    assert "MECHANISM     secure aggregation" in text and "STATUS        SATISFIED" in text


def test_overflow_and_bad_declarations_are_compile_errors():
    assert code_of(lambda: encompute.compile(fedavg(modulus_bits=12), purpose="disease-training")) == "ENC2105"
    assert code_of(lambda: encompute.compile(fedavg(minimum=4), purpose="disease-training")) == "ENC2106"

    def product(ga: secret[Tensor[8], -1.0:1.0, grads[0]], gb: secret[Tensor[8], -1.0:1.0, grads[1]]):
        return secure_aggregate(ga * gb, to=coordinator, minimum=2, colluding=0, clip=(-1, 1), scale=8, modulus_bits=16)

    assert code_of(lambda: encompute.compile(product, purpose="disease-training")) == "ENC2106"


def test_aggregate_only_still_needs_the_boundary():
    def leak(ga: secret[Tensor[8], -1.0:1.0, grads[0]], gb: secret[Tensor[8], -1.0:1.0, grads[1]]):
        return encompute.reveal(ga + gb, to=coordinator)

    assert code_of(lambda: encompute.compile(leak, purpose="disease-training")) == "ENC1905"
