"""Tracing frontend: turns a typed Python function into Encompute IR (.eir text).

Secret parameters become ``Secret`` proxies. Arithmetic on them records IR;
anything that would reveal a secret to Python (``if``, ``print``, ``float``,
comparisons) raises a ``EncomputeError`` with a stable code instead.
"""

from __future__ import annotations

import builtins
import inspect
import math
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union


class EncomputeError(Exception):
    """A Encompute diagnostic with a stable code such as ``ENC1004``."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _err(code: str, message: str) -> EncomputeError:
    return EncomputeError(code, message)


# --- annotations -----------------------------------------------------------


@dataclass(frozen=True)
class _VectorShape:
    n: int


class Tensor:
    """Shape annotation: ``Tensor[n]`` is a vector of ``n`` elements."""

    def __class_getitem__(cls, n: int) -> _VectorShape:
        if not isinstance(n, int) or isinstance(n, bool) or n < 1:
            raise TypeError(f"Tensor[n] needs a positive integer, got {n!r}")
        return _VectorShape(n)


@dataclass(frozen=True)
class SecretSpec:
    """Result of ``secret[shape, lo:hi]``. ``length`` is None for a scalar."""

    length: Optional[int]
    lo: Optional[float]
    hi: Optional[float]

    def __repr__(self) -> str:
        shape = "float" if self.length is None else f"Tensor[{self.length}]"
        rng = "" if self.lo is None else f", {self.lo}:{self.hi}"
        return f"secret[{shape}{rng}]"


class _Secret:
    """``secret[float, lo:hi]`` or ``secret[Tensor[n], lo:hi]``."""

    def __getitem__(self, item: Any) -> SecretSpec:
        if not isinstance(item, tuple):
            item = (item,)
        if len(item) not in (1, 2):
            raise TypeError("use secret[shape] or secret[shape, lo:hi]")
        shape = item[0]
        if shape in (float, int):
            length = None
        elif isinstance(shape, _VectorShape):
            length = shape.n
        else:
            raise TypeError(f"secret shape must be float or Tensor[n], got {shape!r}")
        lo = hi = None
        if len(item) == 2:
            r = item[1]
            if not isinstance(r, slice) or r.step is not None:
                raise TypeError("the range is written lo:hi, e.g. secret[float, -1.0:1.0]")
            lo, hi = float(r.start), float(r.stop)
        return SecretSpec(length, lo, hi)

    def __repr__(self) -> str:
        return "encompute.secret"


class _Public:
    """``public[...]``: a parameter whose value is bound at compile time."""

    def __getitem__(self, item: Any) -> "_Public":
        return self

    def __repr__(self) -> str:
        return "encompute.public"


secret = _Secret()
public = _Public()


# --- graph ------------------------------------------------------------------


def _num(x: float) -> str:
    x = float(x)
    if not math.isfinite(x):
        raise _err("ENC1301", f"constant {x} is not finite")
    return repr(x)


def _nums(xs: Sequence[float]) -> str:
    return "[" + ", ".join(_num(x) for x in xs) + "]"


def _shape_text(length: Optional[int]) -> str:
    return "scalar" if length is None else f"vector<{length}>"


def _to_list(value: Any) -> Any:
    if hasattr(value, "tolist"):  # numpy arrays and scalars
        value = value.tolist()
    return value


class _Graph:
    def __init__(self) -> None:
        self.lines: List[str] = []

    def emit(self, op: str, ty: str) -> int:
        i = len(self.lines)
        self.lines.append(f"%{i} = {op} : {ty}")
        return i

    def constant(self, value: Any) -> Tuple[int, str, Any]:
        """Emit a public constant; returns (id, kind, dims)."""
        value = _to_list(value)
        if isinstance(value, bool):
            raise _err("ENC1301", "booleans are not numbers in Encompute")
        if isinstance(value, (int, float)):
            return self.emit(f"const [{_num(value)}]", "public scalar"), "scalar", None
        if isinstance(value, (list, tuple)) and value and all(
            isinstance(r, (list, tuple)) for r in value
        ):
            rows, cols = len(value), len(value[0])
            if cols == 0 or any(len(r) != cols for r in value):
                raise _err("ENC1301", "matrix rows must be non-empty and of equal length")
            flat = [x for r in value for x in r]
            i = self.emit(f"const {_nums(flat)}", f"public matrix<{rows}x{cols}>")
            return i, "matrix", (rows, cols)
        if isinstance(value, (list, tuple)) and value:
            return self.emit(f"const {_nums(value)}", f"public vector<{len(value)}>"), "vector", len(value)
        raise _err(
            "ENC1301",
            f"cannot use {type(value).__name__} as a public value; use a number, a list, or a numpy array",
        )


# --- traced secret values ---------------------------------------------------


class Secret:
    """A secret value inside a ``@encompute.compile`` function.

    Its contents are never available to Python: only arithmetic with other
    secrets and public constants is allowed.
    """

    __slots__ = ("_g", "_id", "_n")
    __array_ufunc__ = None  # make numpy defer to our reflected operators
    __array_priority__ = 1000

    def __init__(self, graph: _Graph, id_: int, length: Optional[int]):
        self._g = graph
        self._id = id_
        self._n = length

    # -- helpers
    def _new(self, op: str, length: Optional[int]) -> "Secret":
        return Secret(self._g, self._g.emit(op, f"secret {_shape_text(length)}"), length)

    def _operand(self, other: Any) -> Tuple[int, Optional[int], bool]:
        """(id, length, is_secret) for an operand of an elementwise op."""
        if isinstance(other, Secret):
            if other._g is not self._g:
                raise _err("ENC1301", "secret values from different compilations cannot be mixed")
            return other._id, other._n, True
        i, kind, dims = self._g.constant(other)
        if kind == "matrix":
            raise _err("ENC1301", "use `M @ x` or encompute.matvec(M, x) for matrix products")
        return i, (None if kind == "scalar" else dims), False

    def _elementwise(self, op: str, other: Any, reflected: bool = False) -> "Secret":
        oid, on, _ = self._operand(other)
        a, b = (oid, self._id) if reflected else (self._id, oid)
        n = self._n
        if n is not None and on is not None and n != on:
            raise _err("ENC1301", f"{op} needs equal lengths, got {n} and {on}")
        return self._new(f"{op} %{a}, %{b}", n if n is not None else on)

    # -- arithmetic
    def __add__(self, o: Any) -> "Secret":
        return self._elementwise("add", o)

    def __radd__(self, o: Any) -> "Secret":
        return self._elementwise("add", o, reflected=True)

    def __sub__(self, o: Any) -> "Secret":
        return self._elementwise("sub", o)

    def __rsub__(self, o: Any) -> "Secret":
        return self._elementwise("sub", o, reflected=True)

    def __mul__(self, o: Any) -> "Secret":
        return self._elementwise("mul", o)

    def __rmul__(self, o: Any) -> "Secret":
        return self._elementwise("mul", o, reflected=True)

    def __neg__(self) -> "Secret":
        return self._new(f"neg %{self._id}", self._n)

    def __pos__(self) -> "Secret":
        return self

    def __truediv__(self, o: Any) -> "Secret":
        if isinstance(o, Secret):
            raise _err(
                "ENC1002",
                "division by a secret value is not supported in v0.1; divide by public values only",
            )
        o = _to_list(o)
        if isinstance(o, (int, float)):
            if o == 0:
                raise ZeroDivisionError("division by zero")
            return self * (1.0 / o)
        if isinstance(o, (list, tuple)) and all(isinstance(x, (int, float)) for x in o):
            if any(x == 0 for x in o):
                raise ZeroDivisionError("division by zero")
            return self * [1.0 / x for x in o]
        return self._elementwise("mul", o)  # raises a typed error

    def __rtruediv__(self, o: Any) -> "Secret":
        raise _err(
            "ENC1002",
            "division by a secret value is not supported in v0.1; divide by public values only",
        )

    def __pow__(self, k: Any) -> "Secret":
        if isinstance(k, int) and not isinstance(k, bool) and k >= 1:
            if k == 1:
                return self
            if k == 2:
                return self * self
            return poly(self, [0.0] * k + [1.0])
        raise _err("ENC1005", f"secret ** {k!r}: only positive integer powers are supported")

    def __matmul__(self, o: Any) -> "Secret":
        if isinstance(o, Secret):
            return dot(self, o)
        o = _to_list(o)
        if isinstance(o, (list, tuple)) and o and isinstance(o[0], (list, tuple)):
            # x @ M == Mᵀ x
            return matvec([list(col) for col in zip(*o)], self)
        return dot(self, o)

    def __rmatmul__(self, o: Any) -> "Secret":
        o = _to_list(o)
        if isinstance(o, (list, tuple)) and o and isinstance(o[0], (list, tuple)):
            return matvec(o, self)
        return dot(o, self)

    # -- things that would reveal the secret
    def __bool__(self) -> bool:
        raise _err(
            "ENC1001",
            "Python control flow on a secret value (if, while, and/or/not, bool()); "
            "the value is encrypted at run time. Use arithmetic instead; encompute.select arrives in 0.3",
        )

    def _compare(self, other: Any) -> Any:
        raise _err(
            "ENC1003",
            "comparison of secret values (<, <=, >, >=, ==, !=) needs TFHE, which arrives in 0.3",
        )

    __lt__ = __le__ = __gt__ = __ge__ = __eq__ = __ne__ = _compare  # type: ignore[assignment]
    __hash__ = object.__hash__

    def _reveal(self, *_: Any) -> Any:
        raise _err(
            "ENC1004",
            "a secret value cannot flow into a public sink (print, str, format, float, int, logging)",
        )

    __str__ = __format__ = __float__ = __int__ = __index__ = __complex__ = _reveal  # type: ignore[assignment]

    def __repr__(self) -> str:
        return f"<secret {_shape_text(self._n)}>"

    def __len__(self) -> int:
        if self._n is None:
            raise TypeError("a secret scalar has no length")
        return self._n

    def __getitem__(self, _: Any) -> Any:
        raise _err("ENC1005", "indexing or slicing a secret vector is not supported in v0.1")

    def __iter__(self) -> Any:
        raise _err("ENC1005", "iterating over a secret vector is not supported in v0.1")


# --- functions ----------------------------------------------------------------


def _secret_arg(name: str, x: Any) -> Secret:
    if not isinstance(x, Secret):
        raise _err("ENC1301", f"encompute.{name} needs a secret argument here")
    return x


def sigmoid(x: Any) -> Any:
    """Elementwise 1 / (1 + e^-x). Encrypted: a Chebyshev approximation over
    the analyzed input range, with degree chosen to meet the precision."""
    if isinstance(x, Secret):
        return x._new(f"sigmoid %{x._id}", x._n)
    x = _to_list(x)
    if isinstance(x, (list, tuple)):
        return [1.0 / (1.0 + math.exp(-v)) for v in x]
    return 1.0 / (1.0 + math.exp(-x))


def sum(x: Any) -> Any:  # noqa: A001 - mirrors numpy naming
    """Sum of a vector's elements."""
    if isinstance(x, Secret):
        if x._n is None:
            raise _err("ENC1301", "encompute.sum needs a vector")
        return x._new(f"sum %{x._id}", None)
    return builtins.sum(_to_list(x))


def dot(a: Any, b: Any) -> Any:
    """Inner product of two vectors of equal length."""
    if not isinstance(a, Secret) and not isinstance(b, Secret):
        return builtins.sum(x * y for x, y in zip(_to_list(a), _to_list(b)))
    s = a if isinstance(a, Secret) else b
    ia, na, _ = s._operand(a)
    ib, nb, _ = s._operand(b)
    if na is None or nb is None or na != nb:
        raise _err("ENC1301", f"dot needs two vectors of equal length, got {na} and {nb}")
    return s._new(f"dot %{ia}, %{ib}", None)


def matvec(m: Any, x: Any) -> Secret:
    """Public matrix (rows × cols) times a secret vector of length cols."""
    x = _secret_arg("matvec", x)
    if isinstance(m, Secret):
        raise _err("ENC1005", "matvec needs a public matrix in v0.1")
    i, kind, dims = x._g.constant(m)
    if kind != "matrix":
        raise _err("ENC1301", "matvec needs a 2-D public matrix")
    rows, cols = dims
    if x._n != cols:
        raise _err("ENC1301", f"matvec: matrix has {cols} columns, vector has {x._n} elements")
    return x._new(f"matvec %{i}, %{x._id}", rows)


def poly(x: Any, coeffs: Sequence[float]) -> Any:
    """Elementwise c0 + c1·x + c2·x² + …"""
    coeffs = list(_to_list(coeffs))
    if isinstance(x, Secret):
        if len(coeffs) < 2:
            raise _err("ENC1301", "poly needs at least two coefficients")
        return x._new(f"poly %{x._id} {_nums(coeffs)}", x._n)
    return builtins.sum(c * x**k for k, c in enumerate(coeffs))


def square(x: Any) -> Any:
    return x * x


def select(*_: Any) -> Any:
    raise _err("ENC1005", "encompute.select (encrypted branching) needs TFHE comparisons, which arrive in 0.3")


# --- tracing -----------------------------------------------------------------

Outputs = Tuple[List[str], str]  # names, style: "single" | "tuple" | "dict"


def _ident(name: str) -> str:
    safe = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
    return safe if safe and not safe[0].isdigit() else "_" + safe


def trace(fn: Any, precision: float, name: Optional[str], publics: Dict[str, Any]) -> Tuple[str, Outputs]:
    """Trace ``fn`` into ``.eir`` text."""
    g = _Graph()
    sig = inspect.signature(fn, eval_str=True)
    args: Dict[str, Any] = {}
    unknown = set(publics) - set(sig.parameters)
    if unknown:
        raise TypeError(f"{fn.__name__}() has no parameters {sorted(unknown)}")
    for pname, p in sig.parameters.items():
        ann = p.annotation
        if isinstance(ann, SecretSpec):
            if pname in publics:
                raise TypeError(f"parameter {pname!r} is secret; it cannot be bound at compile time")
            if ann.lo is None:
                raise _err(
                    "ENC1101",
                    f"secret input {pname!r} has no declared range; write e.g. "
                    f"secret[{'float' if ann.length is None else f'Tensor[{ann.length}]'}, -1.0:1.0]",
                )
            ty = f"secret {_shape_text(ann.length)}"
            i = g.emit(f'input "{pname}" [{_num(ann.lo)}, {_num(ann.hi)}]', ty)
            args[pname] = Secret(g, i, ann.length)
        elif pname in publics:
            args[pname] = publics[pname]
        elif p.default is not inspect.Parameter.empty:
            args[pname] = p.default
        else:
            raise _err(
                "ENC1301",
                f"parameter {pname!r} needs a secret[...] annotation or a public value "
                f"(encompute.compile({fn.__name__}, {pname}=...))",
            )

    result = fn(**args)

    if isinstance(result, dict):
        items = list(result.items())
        style = "dict"
    elif isinstance(result, (tuple, list)):
        items = [(f"out{i}", v) for i, v in enumerate(result)]
        style = "tuple"
    else:
        items = [("out", result)]
        style = "single"
    outputs = []
    for oname, v in items:
        if not isinstance(v, Secret):
            raise _err(
                "ENC1301",
                f"output {oname!r} does not depend on any secret input; compute it outside Encompute",
            )
        outputs.append((_ident(str(oname)), v._id))

    header = [
        "encompute 0.1",
        f"program {_ident(name or fn.__name__)} precision {_num(precision)}",
    ]
    footer = [f'output "{n}" = %{i}' for n, i in outputs]
    return "\n".join(header + g.lines + footer) + "\n", ([n for n, _ in outputs], style)
