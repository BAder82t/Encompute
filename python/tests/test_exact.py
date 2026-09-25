"""Exact (integer/Boolean) programs from Python: tracing, typing, privacy
diagnostics and execution on the mock backend (TFHE-rs when built)."""

import subprocess
import sys

import pytest

import encompute
from encompute import (
    EncomputeError,
    bool_,
    compile,
    i8,
    i16,
    i32,
    i64,
    secret,
    u8,
    u16,
    u32,
    u64,
)

tfhe = pytest.mark.skipif(not encompute.has_tfhe(), reason="built without TFHE-rs")


def code_of(fn):
    with pytest.raises(EncomputeError) as e:
        fn()
    return e.value.code


@compile()
def approve(
    age: secret[u8, 0:120],
    income: secret[u32, 0:1_000_000],
    debt: secret[u32, 0:500_000],
    risk: secret[u16, 0:1000],
):
    adult = age >= 18
    debt_ok = debt * 100 < income * 40
    risk_ok = risk <= 650
    return adult & debt_ok & risk_ok


def test_flagship_traces_to_exact_ir():
    eir = approve.eir
    assert '%0 = input "age" [0.0, 120.0] : secret u8' in eir
    assert "%4 = const [18.0] : public u8" in eir
    assert "%5 = ge %0, %4 : secret bool" in eir
    assert "and %13, %12 : secret bool" in eir
    assert approve.semantics == "exact"


def test_flagship_runs_exactly():
    yes = dict(age=35, income=100_000, debt=20_000, risk=400)
    for mode in ("clear", "mock"):
        assert approve(**yes, mode=mode) is True
        assert approve(**{**yes, "age": 17}, mode=mode) is False
        assert approve(**{**yes, "risk": 651}, mode=mode) is False
    rep = approve.test(cases=1000)
    assert rep.semantics == "exact" and rep.passed
    assert (rep.matches, rep.mismatches) == (1000, 0)
    assert rep.max_error is None, "no error metrics for exact programs"
    assert "mismatches" in str(rep)


def test_every_exact_type_round_trips():
    for t in (u8, u16, u32, u64, i8, i16, i32, i64):
        lo = max(t.min, -(2**53))
        hi = min(t.max, 2**53)

        def ident(x: secret[t, lo:hi]):  # noqa: B023
            return x + 0

        m = compile(ident)
        for v in (lo, hi, 0 if lo <= 0 else lo):
            assert m(v, mode="mock") == v, (t, v)
            assert isinstance(m(v, mode="mock"), int)


def test_bool_inputs_logic_and_select():
    @compile()
    def fee(vip: secret[bool_], risk: secret[u16, 0:1000]):
        high = risk > 700
        base = encompute.select(high, 25, 5)
        return {
            "fee": encompute.select(vip, 0, base),
            "flag": high ^ vip,
            "neither": ~(high | vip),
        }

    for vip in (True, False):
        for risk in (0, 700, 701, 1000):
            out = fee(vip, risk, mode="mock")
            high = risk > 700
            assert out == {
                "fee": 0 if vip else (25 if high else 5),
                "flag": high != vip,
                "neither": not (high or vip),
            }, (vip, risk)
    assert "select" in fee.eir


def test_signed_arithmetic_shifts_div_rem_lookup_cast_minmax():
    @compile()
    def f(a: secret[i16, -1000:1000], b: secret[i16, -1000:1000], k: secret[u8, 0:3]):
        return {
            "sum": a + b,
            "diff": a - b,
            "neg": -a,
            "div": a // 7,
            "rem": a % 7,
            "lo": encompute.minimum(a, b),
            "hi": encompute.maximum(a, 3),
            "shl": encompute.cast(k, u16) << 4,
            "shr": a >> 2,
            "look": encompute.lookup(k, [10, 20, 30, 40]),
        }

    def trunc_div(x, y):
        q = abs(x) // abs(y)
        return q if (x >= 0) == (y > 0) else -q

    for a, b, k in [(-1000, 1000, 0), (-1, 0, 1), (0, -1, 2), (999, -7, 3), (-7, 7, 3)]:
        out = f(a, b, k, mode="mock")
        assert out == {
            "sum": a + b,
            "diff": a - b,
            "neg": -a,
            "div": trunc_div(a, 7),
            "rem": a - 7 * trunc_div(a, 7),
            "lo": min(a, b),
            "hi": max(a, 3),
            "shl": k << 4,
            "shr": a >> 2,
            "look": [10, 20, 30, 40][k],
        }, (a, b, k)
    assert f.test(cases=300).passed


def test_overflow_is_a_compile_error():
    def over(x: secret[u8, 0:255]):
        return x + 1

    def over_mul(x: secret[u32, 0:100_000]):
        return x * x

    def unsigned_underflow(x: secret[u8, 0:10], y: secret[u8, 0:10]):
        return x - y

    for fn in (over, over_mul, unsigned_underflow):
        assert code_of(lambda: compile(fn)) == "ENC1303", fn.__name__

    def fits(x: secret[u8, 0:254]):
        return x + 1

    assert compile(fits)(254, mode="mock") == 255


def test_exact_diagnostics():
    def branch(x: secret[u8, 0:10]):
        if x > 3:
            return x
        return x + 1

    def python_and(x: secret[u8, 0:10]):
        return (x > 1) and (x < 5)

    def builtin_min(x: secret[u8, 0:10], y: secret[u8, 0:10]):
        return min(x, y)

    def mixed_types(x: secret[u8, 0:10], y: secret[u16, 0:10]):
        return x + y

    def mixed_schemes(x: secret[u8, 0:10], y: secret[float, 0:1]):
        return x + y

    def float_constant(x: secret[u8, 0:10]):
        return x + 0.5

    def constant_too_big(x: secret[u8, 0:10]):
        return x < 300

    def true_div(x: secret[u8, 0:10]):
        return x / 2

    def secret_divisor(x: secret[u8, 1:10], y: secret[u8, 1:10]):
        return x // y

    def printing(x: secret[u8, 0:10]):
        print(x)
        return x

    def to_int(x: secret[u8, 0:10]):
        return int(x)

    def unsigned_neg(x: secret[u8, 0:10]):
        return -x

    def bool_constant(x: secret[u8, 0:10]):
        return x + True

    def secret_shift(x: secret[u8, 0:3]):
        return 1 << x

    def exact_dot(x: secret[u8, 0:3], y: secret[u8, 0:3]):
        return encompute.dot(x, y)

    cases = {
        branch: "ENC1001",
        python_and: "ENC1001",
        builtin_min: "ENC1001",
        mixed_types: "ENC1301",
        mixed_schemes: "ENC1301",
        float_constant: "ENC1301",
        constant_too_big: "ENC1301",
        true_div: "ENC1301",
        secret_divisor: "ENC1002",
        printing: "ENC1004",
        to_int: "ENC1004",
        unsigned_neg: "ENC1301",
        bool_constant: "ENC1301",
        secret_shift: "ENC1301",
        exact_dot: "ENC1301",
    }
    for fn, code in cases.items():
        with pytest.raises(EncomputeError) as e:
            compile(fn)
        assert e.value.code == code, f"{fn.__name__}: {e.value}"
        assert "mixes" not in e.value.message or fn is mixed_schemes, e.value.message


def test_annotation_errors():
    with pytest.raises(EncomputeError):
        secret[u8, 0:256]
    with pytest.raises(EncomputeError):
        secret[u64, 0 : 2**60]
    with pytest.raises(EncomputeError):
        secret[i32, 0.5:10]
    with pytest.raises(TypeError):
        secret[bool_, 0:1]
    assert repr(secret[u8, 0:120]) == "secret[encompute.u8, 0:120]"
    assert repr(secret[bool_]) == "secret[encompute.bool_]"


def test_inputs_are_checked():
    with pytest.raises(TypeError):
        approve(35.5, 1, 1, 1, mode="mock")
    with pytest.raises(TypeError):
        approve(True, 1, 1, 1, mode="mock")
    assert code_of(lambda: approve(121, 1, 1, 1, mode="mock")) == "ENC1102"


def test_exact_artifact_round_trip_and_cli(tmp_path):
    art = tmp_path / "approve.encompute"
    approve.save(str(art))
    m = encompute.load(str(art))
    assert m.semantics == "exact"
    assert m.run(age=40, income=500_000, debt=1_000, risk=10, mode="mock") == {"out": True}
    assert m.security["result_semantics"] == "exact"
    assert m.security["evaluator_receives_secret_key"] is False

    src = tmp_path / "eligibility.py"
    src.write_text(
        "import encompute\n"
        "from encompute import secret, u8, u32\n\n"
        "@encompute.compile()\n"
        "def eligibility(age: secret[u8, 0:120], income: secret[u32, 0:1_000_000],\n"
        "                debt: secret[u32, 0:500_000]):\n"
        "    return (age >= 18) & (debt * 100 < income * 40)\n"
    )
    out = subprocess.run(
        [sys.executable, "-m", "encompute", "compile", f"{src}:eligibility"],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    loaded = encompute.load(str(tmp_path / "eligibility.encompute"))
    assert loaded.run(age=31, income=120_000, debt=21_000, mode="mock") == {"out": True}


def test_encrypted_mode_needs_tfhe():
    if encompute.has_tfhe():
        pytest.skip("built with TFHE-rs")
    assert code_of(lambda: approve(30, 1, 1, 1, mode="encrypted")) == "ENC1501"


@tfhe
def test_tfhe_rs_encrypted():
    yes = dict(age=35, income=100_000, debt=20_000, risk=400)
    assert approve(**yes, mode="encrypted") is True
    assert approve(**{**yes, "age": 17}, mode="encrypted") is False
