"""Veil: compile ordinary Python functions into encrypted computation.

    import veil
    from veil import secret, Tensor

    @veil.compile(precision=1e-3)
    def score(x: secret[Tensor[32], -1.0:1.0]):
        return veil.sigmoid(veil.dot(W, x) + b)

    score(x_values)                      # plaintext reference
    score(x_values, mode="encrypted")    # CKKS on OpenFHE
    print(score.test(cases=1000, mode="encrypted"))
    print(score.explain())

"Veil" is an internal codename (ADR-003); the distribution is ``veilcompute``.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from . import _native
from ._frontend import (
    Secret,
    SecretSpec,
    Tensor,
    VeilError,
    dot,
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
    "Model",
    "Secret",
    "Tensor",
    "TestReport",
    "VeilError",
    "compile",
    "dot",
    "has_openfhe",
    "load",
    "matvec",
    "poly",
    "public",
    "secret",
    "select",
    "sigmoid",
    "square",
    "sum",
]
__version__ = _native.__version__


def _call(f: Callable[..., Any], *args: Any) -> Any:
    try:
        return f(*args)
    except _native.NativeError as e:
        code, message = e.args
        raise VeilError(code, message) from None


def has_openfhe() -> bool:
    """Whether mode="encrypted" is available in this build."""
    return _native.has_openfhe()


class TestReport:
    """Result of ``Model.test``: plaintext reference vs. mock or encrypted."""

    __test__ = False  # not a pytest class

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.passed: bool = data["passed"]
        self.max_error: float = data["max_error"]
        self.precision: float = data["precision"]
        self.cases: int = data["cases"]
        self.backend: str = data["backend"]
        self.outputs: List[Dict[str, Any]] = data["outputs"]
        self.failing: Optional[Dict[str, Any]] = data.get("failing")

    def __str__(self) -> str:
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
        return f"<TestReport {'PASS' if self.passed else 'FAIL'} max_error={self.max_error:.3e}>"


class Model:
    """A compiled Veil program. Call it like the original function."""

    def __init__(self, native: Any, style: str = "single"):
        self._native = native
        self._inputs = native.inputs()  # (name, len, is_scalar, lo, hi)
        self._outputs = native.outputs()  # (name, len, is_scalar)
        self._style = style if len(self._outputs) == 1 or style != "single" else "dict"

    @property
    def name(self) -> str:
        return self._native.name()

    @property
    def vlir(self) -> str:
        """The program in Veil IR text form."""
        return self._native.vlir()

    @property
    def inputs(self) -> List[str]:
        return [i[0] for i in self._inputs]

    @property
    def parameters(self) -> Dict[str, Any]:
        """CKKS parameters (ring dimension, scale, depth, security table...)."""
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
        for name, length, is_scalar, _, _ in self._inputs:
            if name not in values:
                raise TypeError(f"{self.name}() missing input {name!r}")
            v = values.pop(name)
            if hasattr(v, "tolist"):
                v = v.tolist()
            out[name] = [float(v)] if is_scalar else [float(x) for x in v]
        if values:
            raise TypeError(f"{self.name}() got unknown inputs {sorted(values)}")
        return out

    def run(self, *args: Any, mode: str = "clear", **kwargs: Any) -> Any:
        """Run on inputs. mode: "clear" (plaintext), "mock", or "encrypted"."""
        raw = _call(self._native.run, self._encode(args, kwargs), mode)
        vals = {
            name: (raw[name][0] if is_scalar else raw[name])
            for name, _, is_scalar in self._outputs
        }
        if self._style == "single":
            return next(iter(vals.values()))
        if self._style == "tuple":
            return tuple(vals.values())
        return vals

    __call__ = run

    def test(self, cases: int = 100, seed: int = 42, mode: str = "mock") -> TestReport:
        """Differential test against the plaintext reference on sampled inputs
        (range endpoints first, then uniform samples)."""
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
        return f"<veil.Model {self.name}({ins})>"


def compile(
    fn: Optional[Callable[..., Any]] = None,
    *,
    precision: float = 1e-3,
    name: Optional[str] = None,
    **publics: Any,
) -> Any:
    """Compile a function whose secret parameters are annotated with
    ``secret[shape, lo:hi]``. Other parameters are public and bound here:
    ``veil.compile(f, weights=W)``, or taken from their defaults.

    ``precision`` is the maximum absolute error allowed on every output.
    Usable as ``@veil.compile``, ``@veil.compile(precision=...)`` or a call.
    """

    def build(f: Callable[..., Any]) -> Model:
        text, (_, style) = trace(f, precision, name, publics)
        return Model(_call(_native.Model.compile, text), style)

    if fn is None:
        return build
    return build(fn)


def load(path: str) -> Model:
    """Load and verify a ``.veil`` artifact."""
    return Model(_call(_native.Model.load, str(path)), "dict")
