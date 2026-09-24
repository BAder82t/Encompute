import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

import veil
from veil import Tensor, VeilError, secret

W = [0.5, -0.25, 2.0]
encrypted = pytest.mark.skipif(not veil.has_openfhe(), reason="built without OpenFHE")


def code_of(fn):
    with pytest.raises(VeilError) as e:
        fn()
    return e.value.code


@veil.compile(precision=1e-3)
def score(x: secret[Tensor[3], -1.0:1.0]):
    return veil.sigmoid(veil.dot(W, x) + 0.1)


def test_trace_emits_documented_ir():
    assert score.vlir == (
        "veil 0.1\n"
        "program score precision 0.001\n"
        '%0 = input "x" [-1.0, 1.0] : secret vector<3>\n'
        "%1 = const [0.5, -0.25, 2.0] : public vector<3>\n"
        "%2 = dot %1, %0 : secret scalar\n"
        "%3 = const [0.1] : public scalar\n"
        "%4 = add %2, %3 : secret scalar\n"
        "%5 = sigmoid %4 : secret scalar\n"
        'output "out" = %5\n'
    )
    assert score.inputs == ["x"]


def test_modes_agree():
    x = [1.0, 0.0, -0.5]
    clear = score(x)
    assert clear == pytest.approx(1 / (1 + np.exp(-(0.5 - 1.0 + 0.1))), abs=1e-15)
    assert score(x, mode="mock") == pytest.approx(clear, abs=1e-3)


@encrypted
def test_encrypted_mode():
    x = np.array([0.2, -0.9, 0.7])
    assert score(x, mode="encrypted") == pytest.approx(score(x), abs=1e-3)
    rep = score.test(cases=20, mode="encrypted")
    assert rep.passed, str(rep)


def test_privacy_violations_have_codes():
    def branch(x: secret[float, 0:1]):
        if x:
            return x
        return -x

    def compare(x: secret[float, 0:1]):
        return x if x > 0.5 else -x

    def printing(x: secret[float, 0:1]):
        print(x)
        return x

    def formatting(x: secret[float, 0:1]):
        return f"{x}"

    def to_float(x: secret[float, 0:1]):
        return float(x)

    def divide(x: secret[float, 1:2]):
        return 1 / x

    def divide_secret(x: secret[float, 1:2], y: secret[float, 1:2]):
        return x / y

    def index(x: secret[Tensor[3], 0:1]):
        return x[0]

    def no_range(x: secret[float]):
        return x

    def public_out(x: secret[float, 0:1]):
        return 3.0

    def select(x: secret[float, 0:1]):
        return veil.select(x, 1.0, 0.0)

    cases = {
        branch: "VEIL1001",
        compare: "VEIL1003",
        printing: "VEIL1004",
        formatting: "VEIL1004",
        to_float: "VEIL1004",
        divide: "VEIL1002",
        divide_secret: "VEIL1002",
        index: "VEIL1005",
        no_range: "VEIL1101",
        public_out: "VEIL1301",
        select: "VEIL1005",
    }
    for fn, code in cases.items():
        assert code_of(lambda: veil.compile(fn)) == code, fn.__name__


def test_compiler_limits_have_codes():
    def deep(x: secret[float, -1:1]):
        for _ in range(60):
            x = x * x
        return x

    def too_precise(x: secret[float, -1:1]):
        return x * x

    assert code_of(lambda: veil.compile(deep)) == "VEIL1201"
    assert code_of(lambda: veil.compile(too_precise, precision=1e-15)) == "VEIL1202"
    assert code_of(lambda: score([2.0, 0.0, 0.0])) == "VEIL1102"
    assert code_of(lambda: score([0.0, 0.0])) == "VEIL1102"


def test_numpy_publics_and_operators():
    M = np.arange(6, dtype=float).reshape(2, 3) / 10
    b = np.array([0.1, -0.2])

    def layer(x: secret[Tensor[3], -1:1], M=M, b=b):
        h = M @ x + b
        return {"h": h, "total": veil.sum(h * h) / 2, "p": (x @ M.T) ** 3}

    m = veil.compile(layer)
    x = np.array([0.3, -0.6, 0.9])
    out = m(x, mode="mock")
    h = M @ x + b
    assert out["h"] == pytest.approx(h.tolist(), abs=1e-3)
    assert out["total"] == pytest.approx(float(h @ h / 2), abs=1e-3)
    assert out["p"] == pytest.approx((h - b).__pow__(3).tolist(), abs=1e-3)


def test_public_parameters_bound_at_compile():
    def f(x: secret[Tensor[2], -1:1], w):
        return veil.dot(w, x)

    m = veil.compile(f, w=[2.0, 3.0])
    assert m([1.0, -1.0]) == pytest.approx(-1.0)
    assert code_of(lambda: veil.compile(lambda x: x)) == "VEIL1301"


def test_explain_bench_and_manifest():
    text = score.explain(measure=20)
    assert "Chebyshev degree" in text and "PASS" in text
    b = score.bench(reps=2)
    assert b["backend"] == "mock" and b["evaluate_ms"] >= 0
    assert score.security["server_can_decrypt"] is False
    assert score.parameters["security"] == "128-bit classical"


def test_save_load_and_tamper(tmp_path):
    path = tmp_path / "score.veil"
    score.save(path)
    loaded = veil.load(path)
    assert loaded([0.1, 0.2, 0.3])["out"] == pytest.approx(score([0.1, 0.2, 0.3]))
    manifest = json.loads((path / "manifest.json").read_text())
    assert set(manifest["files"]) == {"program.vlir", "plan.json", "parameters.json", "security.json"}
    (path / "program.vlir").write_text(score.vlir.replace("0.5", "0.6"))
    assert code_of(lambda: veil.load(path)) == "VEIL1401"


def test_module_cli_compiles_python(tmp_path):
    src = tmp_path / "model.py"
    src.write_text(
        "import veil\nfrom veil import secret, Tensor\n"
        "@veil.compile\n"
        "def twice(x: secret[Tensor[4], -1:1]):\n    return 2 * x\n"
    )
    out = tmp_path / "twice.veil"
    r = subprocess.run([sys.executable, "-m", "veil", "compile", str(src), "-o", str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert (out / "manifest.json").exists()
