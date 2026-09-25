"""Encompute: compile ordinary Python functions into encrypted computation.

    import encompute
    from encompute import secret, Tensor, u8, u32

    @encompute.compile(precision=1e-3)
    def score(x: secret[Tensor[32], -1.0:1.0]):          # approximate: CKKS
        return encompute.sigmoid(encompute.dot(W, x) + b)

    @encompute.compile()
    def eligible(age: secret[u8, 0:120], income: secret[u32, 0:1_000_000]):
        return (age >= 18) & (income > 30_000)             # exact: integers/bools

    score(x_values)                      # plaintext reference
    score(x_values, mode="encrypted")    # CKKS on OpenFHE
    eligible(35, 100_000, mode="mock")   # True
    print(score.test(cases=1000, mode="encrypted"))
    print(score.explain())

The program's types choose the scheme; no backend needs naming.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from . import _native
from ._frontend import (
    ExactType,
    Secret,
    SecretSpec,
    Tensor,
    EncomputeError,
    bool_,
    cast,
    dot,
    i8,
    i16,
    i32,
    i64,
    lookup,
    maximum,
    minimum,
    u8,
    u16,
    u32,
    u64,
    matvec,
    poly,
    public,
    secret,
    select,
    sigmoid,
    square,
    sum,
    trace,
)

__all__ = [
    "ExactType",
    "Model",
    "Secret",
    "Tensor",
    "TestReport",
    "EncomputeError",
    "bool_",
    "cast",
    "compile",
    "dot",
    "has_openfhe",
    "has_tfhe",
    "i8",
    "i16",
    "i32",
    "i64",
    "load",
    "lookup",
    "matvec",
    "maximum",
    "minimum",
    "poly",
    "public",
    "secret",
    "select",
    "sigmoid",
    "square",
    "sum",
    "u8",
    "u16",
    "u32",
    "u64",
]
__version__ = _native.__version__


def _call(f: Callable[..., Any], *args: Any) -> Any:
    try:
        return f(*args)
    except _native.NativeError as e:
        code, message = e.args
        raise EncomputeError(code, message) from None


def has_openfhe() -> bool:
    """Whether mode="encrypted" is available for approximate programs."""
    return _native.has_openfhe()


def has_tfhe() -> bool:
    """Whether mode="encrypted" is available for exact programs (TFHE-rs,
    research use only)."""
    return _native.has_tfhe()


class TestReport:
    """Result of ``Model.test``: plaintext reference vs. mock or encrypted.

    Approximate programs report errors against the declared precision;
    exact programs report matches and mismatches (no tolerance)."""

    __test__ = False  # not a pytest class

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.semantics: str = data["semantics"]
        self.passed: bool = data["passed"]
        self.cases: int = data["cases"]
        self.backend: str = data["backend"]
        self.outputs: List[Dict[str, Any]] = data["outputs"]
        self.failing: Optional[Dict[str, Any]] = data.get("failing")
        # Approximate programs only.
        self.max_error: Optional[float] = data.get("max_error")
        self.precision: Optional[float] = data.get("precision")
        # Exact programs only.
        self.matches: Optional[int] = data.get("matches")
        self.mismatches: Optional[int] = data.get("mismatches")

    def __str__(self) -> str:
        if self.semantics == "exact":
            lines = [
                f"{self.cases} exact cases on {self.backend}",
                f"  matches     {self.matches:>8}",
                f"  mismatches  {self.mismatches:>8}",
            ]
        else:
            lines = [f"{self.cases} cases on {self.backend}, precision {self.precision:g}"]
            for o in self.outputs:
                lines.append(
                    f"  {o['name']:<12} max error {o['max_abs']:.3e}  mean {o['mean_abs']:.3e}"
                )
        lines.append("PASS" if self.passed else "FAIL")
        if self.failing:
            lines.append(f"failing case #{self.failing['case']}: {self.failing['inputs']}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        verdict = "PASS" if self.passed else "FAIL"
        if self.semantics == "exact":
            return f"<TestReport {verdict} exact {self.matches}/{self.cases} match>"
        return f"<TestReport {verdict} max_error={self.max_error:.3e}>"


def _typed(v: List[float], is_scalar: bool, elem: str) -> Any:
    if elem == "bool":
        return v[0] != 0.0
    if elem != "f64":
        return int(v[0])
    return v[0] if is_scalar else v


class Model:
    """A compiled Encompute program. Call it like the original function."""

    def __init__(self, native: Any, style: str = "single"):
        self._native = native
        self._inputs = native.inputs()  # (name, len, is_scalar, lo, hi, elem)
        self._outputs = native.outputs()  # (name, len, is_scalar, elem)
        self._style = style if len(self._outputs) == 1 or style != "single" else "dict"

    @property
    def name(self) -> str:
        return self._native.name()

    @property
    def eir(self) -> str:
        """The program in Encompute IR text form."""
        return self._native.eir()

    @property
    def inputs(self) -> List[str]:
        return [i[0] for i in self._inputs]

    @property
    def semantics(self) -> str:
        """"approximate" (CKKS) or "exact" (integers and Booleans)."""
        return self._native.semantics()

    @property
    def parameters(self) -> Dict[str, Any]:
        """CKKS parameters (ring dimension, scale, depth, security table...)
        or, for exact programs, the TFHE parameter profile."""
        return json.loads(self._native.artifact_files()["parameters.json"])

    @property
    def security(self) -> Dict[str, Any]:
        """The security manifest written into the artifact."""
        return json.loads(self._native.artifact_files()["security.json"])

    def _encode(self, args: Sequence[Any], kwargs: Dict[str, Any]) -> Dict[str, List[float]]:
        if len(args) > len(self._inputs):
            raise TypeError(f"{self.name}() takes {len(self._inputs)} inputs, got {len(args)}")
        values = dict(zip(self.inputs, args))
        for k, v in kwargs.items():
            if k in values:
                raise TypeError(f"{self.name}() got input {k!r} twice")
            values[k] = v
        out = {}
        for name, length, is_scalar, _, _, elem in self._inputs:
            if name not in values:
                raise TypeError(f"{self.name}() missing input {name!r}")
            v = values.pop(name)
            if hasattr(v, "tolist"):
                v = v.tolist()
            if elem != "f64":
                if not isinstance(v, int) or (elem != "bool" and isinstance(v, bool)):
                    want = "True or False" if elem == "bool" else f"an integer ({elem})"
                    raise TypeError(f"{self.name}() input {name!r} must be {want}, got {v!r}")
                if abs(v) > 2**53:
                    raise EncomputeError("ENC1102", f"input {name!r} = {v} exceeds ±2^53")
            out[name] = [float(v)] if is_scalar else [float(x) for x in v]
        if values:
            raise TypeError(f"{self.name}() got unknown inputs {sorted(values)}")
        return out

    def run(self, *args: Any, mode: str = "clear", **kwargs: Any) -> Any:
        """Run on inputs. mode: "clear" (plaintext), "mock", or "encrypted"
        (OpenFHE for approximate programs, TFHE-rs for exact ones)."""
        raw = _call(self._native.run, self._encode(args, kwargs), mode)
        vals = {name: _typed(raw[name], is_scalar, elem) for name, _, is_scalar, elem in self._outputs}
        if self._style == "single":
            return next(iter(vals.values()))
        if self._style == "tuple":
            return tuple(vals.values())
        return vals

    __call__ = run

    def test(self, cases: int = 100, seed: int = 42, mode: str = "mock") -> TestReport:
        """Differential test against the plaintext reference on sampled inputs
        (range endpoints first, then uniform samples; exact programs also
        sample boundary values and must match exactly)."""
        return TestReport(json.loads(_call(self._native.test_json, mode, cases, seed)))

    def explain(self, measure: Optional[int] = None, mode: str = "mock") -> str:
        """Execution plan, parameters and precision; optionally measure the error."""
        return _call(self._native.explain, measure, mode)

    def bench(self, reps: int = 5, mode: str = "mock") -> Dict[str, Any]:
        """Keygen, encrypt, evaluate and decrypt timings (ms) and ciphertext sizes."""
        return json.loads(_call(self._native.bench_json, mode, reps))

    def save(self, path: str) -> None:
        """Write the compiled artifact directory (never contains keys)."""
        _call(self._native.save, str(path))

    def __repr__(self) -> str:
        ins = ", ".join(self.inputs)
        return f"<encompute.Model {self.name}({ins})>"


def compile(
    fn: Optional[Callable[..., Any]] = None,
    *,
    precision: float = 1e-3,
    name: Optional[str] = None,
    **publics: Any,
) -> Any:
    """Compile a function whose secret parameters are annotated with
    ``secret[shape, lo:hi]`` (approximate) or ``secret[u8, lo:hi]`` /
    ``secret[bool_]`` (exact). Other parameters are public and bound here:
    ``encompute.compile(f, weights=W)``, or taken from their defaults.

    The types choose the scheme: approximate programs compile to CKKS,
    exact ones to an exact plan. ``precision`` is the maximum absolute error
    allowed on every approximate output. Usable as ``@encompute.compile``,
    ``@encompute.compile(precision=...)`` or a call.
    """

    def build(f: Callable[..., Any]) -> Model:
        text, (_, style) = trace(f, precision, name, publics)
        return Model(_call(_native.Model.compile, text), style)

    if fn is None:
        return build
    return build(fn)


def load(path: str) -> Model:
    """Load and verify a ``.encompute`` artifact."""
    return Model(_call(_native.Model.load, str(path)), "dict")
