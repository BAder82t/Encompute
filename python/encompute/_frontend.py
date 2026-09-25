"""Tracing frontend: turns a typed Python function into Encompute IR (.eir text).

Secret parameters become ``Secret`` proxies. Arithmetic on them records IR;
anything that would reveal a secret to Python (``if``, ``print``, ``float``)
raises an ``EncomputeError`` with a stable code instead.

Two kinds of secret values exist (one kind per program in 0.3):

* approximate: ``secret[float, lo:hi]`` and ``secret[Tensor[n], lo:hi]``,
  computed with CKKS within a declared precision;
* exact: ``secret[u8, lo:hi]`` ... ``secret[i64, lo:hi]`` and
  ``secret[bool_]``, fixed-width integers and Booleans with comparisons,
  logic and ``encompute.select``, computed exactly.
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


# Exact values cross the API as f64, exact up to 2^53 (ADR-006).
MAX_EXACT = 2**53


class ExactType:
    """A fixed-width exact element type: ``u8`` ... ``i64`` or ``bool_``."""

    def __init__(self, name: str, lo: int, hi: int):
        self.name = name
        self.min = lo
        self.max = hi

    @property
    def is_bool(self) -> bool:
        return self.name == "bool"

    def fits(self, v: int) -> bool:
        return self.min <= v <= self.max and abs(v) <= MAX_EXACT

    def __repr__(self) -> str:
        return "encompute.bool_" if self.is_bool else f"encompute.{self.name}"


bool_ = ExactType("bool", 0, 1)
u8 = ExactType("u8", 0, 2**8 - 1)
u16 = ExactType("u16", 0, 2**16 - 1)
u32 = ExactType("u32", 0, 2**32 - 1)
u64 = ExactType("u64", 0, 2**64 - 1)
i8 = ExactType("i8", -(2**7), 2**7 - 1)
i16 = ExactType("i16", -(2**15), 2**15 - 1)
i32 = ExactType("i32", -(2**31), 2**31 - 1)
i64 = ExactType("i64", -(2**63), 2**63 - 1)
_EXACT: Dict[str, ExactType] = {t.name: t for t in (bool_, u8, u16, u32, u64, i8, i16, i32, i64)}


# --- confidentiality (ADR-010) ------------------------------------------------

_RELEASES = ("never", "owner_only", "allowed_parties", "aggregate_only", "public")
_KINDS = (
    "tensor", "dataset", "model", "embedding", "gradient", "model_update",
    "checkpoint", "adapter", "optimizer_state", "output", "generic",
)


def _check_text(what: str, s: str) -> str:
    if not isinstance(s, str) or not 0 < len(s) <= 128 or any(c in '"\\' or ord(c) < 32 or ord(c) == 127 for c in s):
        raise _err("ENC1906", f"{what} {s!r} must be 1-128 characters without quotes, backslashes or control characters")
    return s


def _check_id(what: str, s: str) -> str:
    ok = (
        isinstance(s, str)
        and 0 < len(s) <= 64
        and s[0].isascii()
        and s[0].isalnum()
        and all(c.islower() or c.isdigit() or c in "-_." for c in s)
    )
    if not ok:
        raise _err("ENC1906", f"{what} {s!r} must be 1-64 characters of a-z, 0-9, '-', '_', '.'")
    return s


class Party:
    """An authorization principal (a hospital, a company, a service), not a
    network host: ``Party("hospital-a", "Hospital A")``."""

    def __init__(self, id: str, name: Optional[str] = None):  # noqa: A002
        self.id = _check_id("party", id)
        self.name = _check_text("party name", name or id)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Party) and other.id == self.id

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"Party({self.id!r})"


def _release(r: str) -> str:
    if r not in _RELEASES:
        raise _err("ENC1906", f"release must be one of {', '.join(_RELEASES)}, got {r!r}")
    return r


def _kind(k: str) -> str:
    if k not in _KINDS:
        raise _err("ENC1906", f"asset kind must be one of {', '.join(_KINDS)}, got {k!r}")
    return k


_UNITS = ("record", "user", "patient", "device", "organization")


def _privacy_levels() -> Dict[str, Tuple[float, float, float]]:
    """Named privacy levels from the native library: one source of truth."""
    from . import _native

    return {n: (e, d, z) for n, e, d, z in _native.privacy_presets()}


class DP:
    """An explicit differential-privacy budget for an asset: every release
    derived from it is charged, and releases over ``(epsilon, delta)`` are
    refused. Most applications use a level instead: ``privacy="strong"``."""

    def __init__(
        self,
        epsilon: float,
        delta: float,
        unit: Optional[str] = None,
        clip_norm: float = 1.0,
        noise_multiplier: Optional[float] = None,
    ):
        if not (isinstance(epsilon, (int, float)) and math.isfinite(epsilon) and epsilon > 0):
            raise _err("ENC2203", f"epsilon must be positive, got {epsilon!r}")
        if not (isinstance(delta, (int, float)) and 0 < delta < 1):
            raise _err("ENC2203", f"delta must be in (0, 1), got {delta!r}")
        self.epsilon = float(epsilon)
        self.delta = float(delta)
        if unit is not None and unit not in _UNITS:
            _check_id("privacy unit", unit)
        self.unit = unit
        # Mechanism parameters, used when this DP object is given to
        # secure_aggregate (validated there).
        self.clip_norm = clip_norm
        self.noise_multiplier = noise_multiplier


class DiscreteGaussian:
    """An explicit DP mechanism for an aggregation: each party's vector is
    clipped to L2 norm ``clip_norm`` and discrete Gaussian noise with
    standard deviation ``noise_multiplier * clip_norm`` is added."""

    def __init__(self, clip_norm: float, noise_multiplier: float):
        for name, v in (("clip_norm", clip_norm), ("noise_multiplier", noise_multiplier)):
            if not (isinstance(v, (int, float)) and math.isfinite(v) and v > 0):
                raise _err("ENC2203", f"{name} must be positive, got {v!r}")
        self.clip_norm = float(clip_norm)
        self.noise_multiplier = float(noise_multiplier)


def _budget(privacy: Any) -> Optional[DP]:
    if privacy is None or isinstance(privacy, DP):
        return privacy
    levels = _privacy_levels()
    if privacy not in levels:
        raise _err("ENC2203", f"privacy must be one of {', '.join(levels)} or DP(...), got {privacy!r}")
    e, d, _ = levels[privacy]
    return DP(e, d)


def _mechanism(privacy: Any) -> Optional[DiscreteGaussian]:
    if privacy is None or isinstance(privacy, DiscreteGaussian):
        return privacy
    if isinstance(privacy, DP):
        if privacy.noise_multiplier is None:
            raise _err("ENC2203", "DP(...) on an aggregation needs noise_multiplier (or use a privacy level)")
        return DiscreteGaussian(privacy.clip_norm, privacy.noise_multiplier)
    levels = _privacy_levels()
    if privacy not in levels:
        raise _err("ENC2203", f"privacy must be one of {', '.join(levels)} or DiscreteGaussian(...), got {privacy!r}")
    return DiscreteGaussian(1.0, levels[privacy][2])


class Asset:
    """A confidential asset and its owners' policy. Bind a secret input to
    it with ``secret[shape, lo:hi, asset]``."""

    def __init__(
        self,
        id: str,  # noqa: A002
        *,
        owners: Sequence[Party],
        readers: Sequence[Party] = (),
        purposes: Sequence[str] = (),
        release: str = "never",
        kind: str = "dataset",
        derive: Optional[Dict[str, Any]] = None,
        privacy: Any = None,
        unit: str = "record",
    ):
        self.id = _check_id("asset", id)
        self.privacy = _budget(privacy)
        if isinstance(privacy, DP) and privacy.unit is not None:
            unit = privacy.unit
        if unit not in _UNITS:
            _check_id("privacy unit", unit)
        self.unit = unit
        self.owners = list(owners)
        if not self.owners:
            raise _err("ENC1906", f"asset {id} has no owner")
        self.readers = list(readers)
        self.purposes = [_check_text(f"asset {id} purpose", p) for p in purposes]
        self.release = _release(release)
        self.kind = _kind(kind)
        # {"gradient": ("aggregate_only", [coordinator])}
        self.derive: Dict[str, Tuple[str, List[Party]]] = {}
        for k, v in (derive or {}).items():
            rel, to = (v, []) if isinstance(v, str) else (v[0], list(v[1]))
            self.derive[_kind(k)] = (_release(rel), to)

    def parties(self) -> List[Party]:
        out = list(self.owners) + list(self.readers)
        for _, to in self.derive.values():
            out += to
        return out

    def eir(self) -> str:
        q = lambda xs: "[" + ", ".join(f'"{x}"' for x in sorted(xs)) + "]"  # noqa: E731
        line = (
            f'asset "{self.id}" {self.kind} owners {q(p.id for p in self.owners)} '
            f"readers {q(p.id for p in self.readers)} purposes {q(self.purposes)} "
            f"release {self.release}"
        )
        if self.derive:
            parts = [f"{k} {r} to {q(p.id for p in to)}" for k, (r, to) in sorted(self.derive.items())]
            line += " derive [" + ", ".join(parts) + "]"
        if self.privacy is not None:
            line += f' privacy unit "{self.unit}" epsilon {_num(self.privacy.epsilon)} delta {_num(self.privacy.delta)}'
        return line

    def __repr__(self) -> str:
        return f"Asset({self.id!r})"


def asset(
    id: str,  # noqa: A002
    *,
    owner: Optional[Party] = None,
    owners: Sequence[Party] = (),
    readers: Sequence[Party] = (),
    purposes: Sequence[str] = (),
    release: str = "never",
    kind: str = "dataset",
    derive: Optional[Dict[str, Any]] = None,
    privacy: Any = None,
    unit: str = "record",
) -> Asset:
    """Declare a confidential asset: who owns it, who may read it, what it
    may be used for, how it may be released, and which derived kinds its
    owners allow (``derive={"gradient": ("aggregate_only", [coordinator])}``)."""
    return Asset(
        id,
        owners=([owner] if owner else []) + list(owners),
        readers=readers,
        purposes=purposes,
        release=release,
        kind=kind,
        derive=derive,
        privacy=privacy,
        unit=unit,
    )


class _Output:
    """An output with a destination: ``reveal(x, to=party)``/``publish(x)``."""

    def __init__(self, value: Any, dest: str, party: Optional[Party] = None, aggregate: Optional[str] = None):
        self.value = value
        self.dest = dest
        self.party = party
        self.aggregate = aggregate


def reveal(value: Any, to: Party) -> _Output:
    """Output ``value`` revealed to party ``to`` (checked at compile time)."""
    return _Output(value, f'to "{to.id}"', to)


def secure_aggregate(
    value: Any,
    to: Optional[Party] = None,
    *,
    minimum: int,
    colluding: int,
    clip: Tuple[float, float],
    scale: int,
    modulus_bits: int,
    function: str = "sum",
    privacy: Any = None,
) -> _Output:
    """Output ``value``, a sum of one input per party, computed only by
    secure aggregation (ADR-012) and released to ``to`` (default: sealed)
    only if at least ``minimum`` parties contributed. ``colluding`` is how
    many parties may collude with the coordinator without learning another
    party's contribution (it raises the protocol threshold to
    ``(n + colluding) // 2 + 1``). Values are clipped to
    ``clip`` and encoded as integers ``round((x - clip[0]) * scale)`` modulo
    ``2**modulus_bits``; the compiler refuses encodings that could overflow.
    ``privacy`` (``"standard"``, ``"strong"``, ``"maximum"`` or
    ``DiscreteGaussian(...)``) adds differential-privacy noise, charged to
    the budgets of the contributing assets.
    """
    if function not in ("sum", "mean"):
        raise _err("ENC2106", f"aggregation function must be 'sum' or 'mean', got {function!r}")
    lo, hi = (float(c) for c in clip)
    for name, v in (("minimum", minimum), ("colluding", colluding), ("scale", scale), ("modulus_bits", modulus_bits)):
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise _err("ENC2106", f"{name} must be a non-negative integer, got {v!r}")
    rule = f"{function} minimum {minimum} colluding {colluding} clip [{_num(lo)}, {_num(hi)}] scale {scale} modulus {modulus_bits}"
    mech = _mechanism(privacy)
    if mech is not None:
        rule += f" dp discrete_gaussian clip_norm {_num(mech.clip_norm)} noise_multiplier {_num(mech.noise_multiplier)}"
    return _Output(value, f'to "{to.id}"' if to is not None else "", to, aggregate=rule)


def publish(value: Any) -> _Output:
    """Output ``value`` publicly (only allowed for public-release data)."""
    return _Output(value, "public")


@dataclass(frozen=True)
class SecretSpec:
    """Result of ``secret[shape, lo:hi]``. ``length`` is None for a scalar;
    ``elem`` is ``"f64"`` for approximate values or an exact type name."""

    length: Optional[int]
    lo: Optional[float]
    hi: Optional[float]
    elem: str = "f64"
    asset: Optional[Asset] = None

    def __repr__(self) -> str:
        if self.elem != "f64":
            rng = "" if self.elem == "bool" else f", {int(self.lo)}:{int(self.hi)}"
            return f"secret[{_EXACT[self.elem]!r}{rng}]"
        shape = "float" if self.length is None else f"Tensor[{self.length}]"
        rng = "" if self.lo is None else f", {self.lo}:{self.hi}"
        return f"secret[{shape}{rng}]"


def _exact_spec(t: ExactType, item: Tuple[Any, ...]) -> SecretSpec:
    if t.is_bool:
        if len(item) == 2:
            raise TypeError("secret[bool_] takes no range")
        return SecretSpec(None, 0.0, 1.0, "bool")
    lo, hi = max(t.min, -MAX_EXACT), min(t.max, MAX_EXACT)
    if len(item) == 2:
        r = item[1]
        if not isinstance(r, slice) or r.step is not None:
            raise TypeError(f"the range is written lo:hi, e.g. secret[{t.name}, 0:100]")
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (r.start, r.stop)):
            raise _err("ENC1101", f"secret[{t.name}, lo:hi] needs integer bounds, got {r.start!r}:{r.stop!r}")
        lo, hi = r.start, r.stop
        if not (t.fits(lo) and t.fits(hi) and lo <= hi):
            raise _err(
                "ENC1101",
                f"range {lo}:{hi} does not fit {t.name} (and exact values stay within ±2^53)",
            )
    return SecretSpec(None, float(lo), float(hi), t.name)


class _Secret:
    """``secret[float, lo:hi]``, ``secret[Tensor[n], lo:hi]``,
    ``secret[u8, lo:hi]`` (any exact integer type) or ``secret[bool_]``."""

    def __getitem__(self, item: Any) -> SecretSpec:
        if not isinstance(item, tuple):
            item = (item,)
        assets = [x for x in item if isinstance(x, Asset)]
        item = tuple(x for x in item if not isinstance(x, Asset))
        if len(assets) > 1:
            raise TypeError("a secret input is at most one asset")
        spec = self._spec(item)
        if assets:
            from dataclasses import replace

            spec = replace(spec, asset=assets[0])
        return spec

    def _spec(self, item: Tuple[Any, ...]) -> SecretSpec:
        if len(item) not in (1, 2):
            raise TypeError("use secret[shape], secret[shape, lo:hi] or secret[shape, lo:hi, asset]")
        shape = item[0]
        if isinstance(shape, ExactType):
            return _exact_spec(shape, item)
        if shape is bool:
            return _exact_spec(bool_, item)
        if shape in (float, int):
            length = None
        elif isinstance(shape, _VectorShape):
            length = shape.n
        else:
            raise TypeError(
                f"secret type must be float, Tensor[n], an exact type (u8, i32, ...) or bool_, got {shape!r}"
            )
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


def _exact_int(value: Any, t: ExactType) -> int:
    """A public Python value as an exact constant of type ``t``."""
    value = _to_list(value)
    if isinstance(value, bool) and not t.is_bool:
        raise _err("ENC1301", f"booleans are not {t.name} numbers; use 0 or 1, or a bool_ value")
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if not isinstance(value, int):
        raise _err(
            "ENC1301",
            f"exact {t.name} values combine with integer constants only, got {type(value).__name__} "
            "(approximate and exact values cannot be mixed in 0.3)",
        )
    v = int(value)
    if not t.fits(v):
        raise _err("ENC1301", f"constant {v} does not fit {t.name} (and exact values stay within ±2^53)")
    return v


class _Graph:
    def __init__(self) -> None:
        self.lines: List[str] = []
        self.derives: List[str] = []

    def emit(self, op: str, ty: str) -> int:
        i = len(self.lines)
        self.lines.append(f"%{i} = {op} : {ty}")
        return i

    def const_exact(self, value: Any, t: ExactType) -> int:
        """Emit a typed public constant (no detour through floating point
        beyond 2^53, which is refused)."""
        return self.emit(f"const [{float(_exact_int(value, t))!r}]", f"public {t.name}")

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

    Its contents are never available to Python: only operations with other
    secrets and public constants are allowed. Approximate (float) secrets
    support arithmetic; exact (integer/bool) secrets also support
    comparisons, logic, shifts, ``//`` and ``%`` by constants, and
    ``encompute.select``.
    """

    __slots__ = ("_g", "_id", "_n", "_e")
    __array_ufunc__ = None  # make numpy defer to our reflected operators
    __array_priority__ = 1000

    def __init__(self, graph: _Graph, id_: int, length: Optional[int], elem: str = "f64"):
        self._g = graph
        self._id = id_
        self._n = length
        self._e = elem

    @property
    def _exact(self) -> bool:
        return self._e != "f64"

    # -- helpers
    def _new(self, op: str, length: Optional[int]) -> "Secret":
        return Secret(self._g, self._g.emit(op, f"secret {_shape_text(length)}"), length)

    def _new_exact(self, op: str, elem: str) -> "Secret":
        return Secret(self._g, self._g.emit(op, f"secret {elem}"), None, elem)

    def _same_graph(self, other: "Secret") -> None:
        if other._g is not self._g:
            raise _err("ENC1301", "secret values from different compilations cannot be mixed")

    def _operand(self, other: Any) -> Tuple[int, Optional[int], bool]:
        """(id, length, is_secret) for an operand of an elementwise op."""
        if isinstance(other, Secret):
            self._same_graph(other)
            if self._exact and other._exact:
                raise _err("ENC1301", f"this operation works on approximate (float) values, not {other._e}")
            if other._exact or self._exact:
                raise _err(
                    "ENC1301",
                    "this program mixes approximate (float) and exact (integer/bool) values; "
                    "Encompute 0.3 runs one encrypted scheme per program",
                )
            return other._id, other._n, True
        i, kind, dims = self._g.constant(other)
        if kind == "matrix":
            raise _err("ENC1301", "use `M @ x` or encompute.matvec(M, x) for matrix products")
        return i, (None if kind == "scalar" else dims), False

    def _elementwise(self, op: str, other: Any, reflected: bool = False) -> "Secret":
        if self._exact:
            return self._exact_binary(op, other, reflected)
        oid, on, _ = self._operand(other)
        a, b = (oid, self._id) if reflected else (self._id, oid)
        n = self._n
        if n is not None and on is not None and n != on:
            raise _err("ENC1301", f"{op} needs equal lengths, got {n} and {on}")
        return self._new(f"{op} %{a}, %{b}", n if n is not None else on)

    # -- exact helpers
    def _exact_id(self, other: Any) -> int:
        """Operand id for an exact op: a secret of this type or a constant."""
        if isinstance(other, Secret):
            self._same_graph(other)
            if other._e != self._e:
                if not other._exact:
                    raise _err(
                        "ENC1301",
                        "this program mixes approximate (float) and exact (integer/bool) values; "
                        "Encompute 0.3 runs one encrypted scheme per program",
                    )
                raise _err(
                    "ENC1301",
                    f"operands have different types ({self._e} and {other._e}); convert one "
                    f"with encompute.cast(x, {self._e})",
                )
            return other._id
        return self._g.const_exact(other, _EXACT[self._e])

    def _exact_binary(self, op: str, other: Any, reflected: bool = False, result: Optional[str] = None) -> "Secret":
        oid = self._exact_id(other)
        a, b = (oid, self._id) if reflected else (self._id, oid)
        return self._new_exact(f"{op} %{a}, %{b}", result or self._e)

    def _need_exact(self, what: str) -> None:
        if not self._exact:
            raise _err(
                "ENC1003",
                f"{what} needs exact values: declare inputs as e.g. secret[u32, 0:1000] or "
                "secret[bool_] (approximate float values cannot be compared or branched on)",
            )

    def _public_int(self, what: str, v: Any) -> int:
        if isinstance(v, Secret):
            raise _err("ENC1002", f"{what} by a secret value is not supported; use a public constant")
        v = _to_list(v)
        if not isinstance(v, int) or isinstance(v, bool):
            raise _err("ENC1301", f"{what} needs a public integer, got {v!r}")
        return v

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
        if self._exact:
            return self._new_exact(f"neg %{self._id}", self._e)
        return self._new(f"neg %{self._id}", self._n)

    def __pos__(self) -> "Secret":
        return self

    def __truediv__(self, o: Any) -> "Secret":
        if self._exact:
            raise _err("ENC1301", "exact values divide with // (and % for the remainder)")
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
            "division by a secret value is not supported; divide by public values only",
        )

    def _divrem(self, op: str, o: Any) -> "Secret":
        if not self._exact:
            raise _err("ENC1301", "// and % need exact integer values; use / for approximate values")
        d = self._public_int("division", o)
        if d == 0:
            raise ZeroDivisionError("division by zero")
        return self._exact_binary(op, d)

    def __floordiv__(self, o: Any) -> "Secret":
        """Integer division by a public constant, rounding toward zero."""
        return self._divrem("div", o)

    def __mod__(self, o: Any) -> "Secret":
        """Remainder of division by a public constant (sign of the dividend)."""
        return self._divrem("rem", o)

    def __rfloordiv__(self, o: Any) -> "Secret":
        raise _err("ENC1002", "division by a secret value is not supported; divide by public values only")

    __rmod__ = __rfloordiv__

    def __pow__(self, k: Any) -> "Secret":
        if isinstance(k, int) and not isinstance(k, bool) and k >= 1:
            if k == 1:
                return self
            if k == 2 or self._exact:
                out = self
                for _ in range(k - 1):
                    out = out * self
                return out
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

    # -- comparisons: encrypted booleans (exact values only)
    def _compare(self, op: str, other: Any) -> "Secret":
        self._need_exact("comparison of secret values (<, <=, >, >=, ==, !=)")
        return self._exact_binary(op, other, result="bool")

    def __lt__(self, o: Any) -> "Secret":  # type: ignore[override]
        return self._compare("lt", o)

    def __le__(self, o: Any) -> "Secret":  # type: ignore[override]
        return self._compare("le", o)

    def __gt__(self, o: Any) -> "Secret":  # type: ignore[override]
        return self._compare("gt", o)

    def __ge__(self, o: Any) -> "Secret":  # type: ignore[override]
        return self._compare("ge", o)

    def __eq__(self, o: Any) -> "Secret":  # type: ignore[override]
        return self._compare("eq", o)

    def __ne__(self, o: Any) -> "Secret":  # type: ignore[override]
        return self._compare("ne", o)

    __hash__ = object.__hash__

    # -- logic: Boolean for bool_, bitwise for integers
    def _logic(self, op: str, other: Any) -> "Secret":
        self._need_exact(f"{op} (& | ^)")
        return self._exact_binary(op, other)

    def __and__(self, o: Any) -> "Secret":
        return self._logic("and", o)

    __rand__ = __and__

    def __or__(self, o: Any) -> "Secret":
        return self._logic("or", o)

    __ror__ = __or__

    def __xor__(self, o: Any) -> "Secret":
        return self._logic("xor", o)

    __rxor__ = __xor__

    def __invert__(self) -> "Secret":
        self._need_exact("~ (not)")
        return self._new_exact(f"not %{self._id}", self._e)

    def _shift(self, op: str, by: Any) -> "Secret":
        self._need_exact("shift")
        n = self._public_int("shift", by)
        if n < 0:
            raise _err("ENC1301", "negative shift amount")
        return self._new_exact(f"{op} %{self._id} {n}", self._e)

    def __lshift__(self, by: Any) -> "Secret":
        return self._shift("shl", by)

    def __rshift__(self, by: Any) -> "Secret":
        return self._shift("shr", by)

    def __rlshift__(self, _: Any) -> "Secret":
        raise _err("ENC1301", "a shift amount must be a public integer, not a secret value")

    __rrshift__ = __rlshift__

    # -- things that would reveal the secret
    def __bool__(self) -> bool:
        raise _err(
            "ENC1001",
            "Python control flow on a secret value (if, while, and/or/not, bool(), min/max); "
            "the value is encrypted at run time. Use encompute.select(condition, a, b), "
            "& | ~ for Boolean logic, or encompute.minimum/maximum",
        )

    def _reveal(self, *_: Any) -> Any:
        raise _err(
            "ENC1004",
            "a secret value cannot flow into a public sink (print, str, format, float, int, logging)",
        )

    __str__ = __format__ = __float__ = __int__ = __index__ = __complex__ = _reveal  # type: ignore[assignment]

    def __repr__(self) -> str:
        if self._exact:
            return f"<secret {self._e}>"
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


def confidential(value: Any, *, kind: str = "generic", release: str = "never") -> Any:
    """Mark ``value`` as a derived asset of ``kind`` released at most as
    ``release``. Restricting is always allowed; weakening (e.g. a gradient
    ``aggregate_only``) only if every source asset's owners permit it."""
    if not isinstance(value, Secret):
        raise _err("ENC1301", "encompute.confidential needs a secret value")
    value._g.derives.append(f"derive %{value._id} {_kind(kind)} {_release(release)}")
    return value


def _narrowest(values: Sequence[int]) -> ExactType:
    for t in (u8, u16, u32, u64) if min(values) >= 0 else (i8, i16, i32, i64):
        if all(t.fits(v) for v in values):
            return t
    raise _err("ENC1301", f"{values} do not fit an exact type within ±2^53")


def select(cond: Any, a: Any, b: Any, type: Optional[ExactType] = None) -> Secret:  # noqa: A002
    """``a if cond else b`` with an encrypted bool condition; both branches
    are computed. With two public branches the result type is ``type`` or
    the narrowest integer type holding both."""
    if not isinstance(cond, Secret) or cond._e != "bool":
        raise _err(
            "ENC1005",
            "encompute.select needs an encrypted bool condition, e.g. select(age >= 18, a, b)",
        )
    secrets = [x for x in (a, b) if isinstance(x, Secret)]
    if secrets:
        elem = secrets[0]._e
    elif type is not None:
        elem = type.name
    else:
        elem = _narrowest([_exact_int(a, i64), _exact_int(b, i64)]).name
    if type is not None and type.name != elem:
        raise _err("ENC1301", f"select branches are {elem}, not {type.name}")
    typed = Secret(cond._g, cond._id, None, elem)  # to type the constants
    ia, ib = typed._exact_id(a), typed._exact_id(b)
    return cond._new_exact(f"select %{cond._id}, %{ia}, %{ib}", elem)


def cast(x: Secret, to: ExactType) -> Secret:
    """Convert an exact value to integer type ``to``; the value must fit
    (range analysis proves it at compile time)."""
    if not isinstance(x, Secret) or not x._exact:
        raise _err("ENC1301", "encompute.cast needs an exact secret value")
    if not isinstance(to, ExactType):
        raise TypeError(f"cast target must be an exact type such as encompute.u16, got {to!r}")
    return x._new_exact(f"cast %{x._id}", to.name)


def lookup(x: Secret, table: Sequence[int]) -> Secret:
    """``table[x]`` for an encrypted index; entries have ``x``'s type."""
    if not isinstance(x, Secret) or not x._exact:
        raise _err("ENC1301", "encompute.lookup needs an exact secret index")
    t = _EXACT[x._e]
    entries = [_exact_int(v, t) for v in _to_list(table)]
    if not entries:
        raise _err("ENC1301", "lookup table is empty")
    return x._new_exact(f"lookup %{x._id} {_nums(entries)}", x._e)


def minimum(a: Any, b: Any) -> Any:
    """Elementwise minimum of exact values."""
    if isinstance(a, Secret):
        return a._exact_binary("min", b) if a._exact else a._need_exact("minimum")
    if isinstance(b, Secret):
        return minimum(b, a)
    return builtins.min(a, b)


def maximum(a: Any, b: Any) -> Any:
    """Elementwise maximum of exact values."""
    if isinstance(a, Secret):
        return a._exact_binary("max", b) if a._exact else a._need_exact("maximum")
    if isinstance(b, Secret):
        return maximum(b, a)
    return builtins.max(a, b)


# --- tracing -----------------------------------------------------------------

Outputs = Tuple[List[str], str]  # names, style: "single" | "tuple" | "dict"


def _ident(name: str) -> str:
    safe = "".join(c if c.isalnum() or c == "_" else "_" for c in name)
    return safe if safe and not safe[0].isdigit() else "_" + safe


def trace(
    fn: Any,
    precision: float,
    name: Optional[str],
    publics: Dict[str, Any],
    verification: str = "receipt",
    purpose: Optional[str] = None,
) -> Tuple[str, Outputs]:
    """Trace ``fn`` into ``.eir`` text."""
    g = _Graph()
    assets: Dict[str, Asset] = {}
    parties: Dict[str, Party] = {}

    def add_party(p: Party) -> None:
        known = parties.setdefault(p.id, p)
        if known.name != p.name:
            raise _err("ENC1906", f"party {p.id} is used with two names: {known.name!r} and {p.name!r}")

    def bind(a: Optional[Asset]) -> str:
        if a is None:
            return ""
        if a.id in assets and assets[a.id] is not a:
            raise _err("ENC1906", f"two different assets are named {a.id}")
        assets[a.id] = a
        for p in a.parties():
            add_party(p)
        return f' asset "{a.id}"'
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
            if ann.elem != "f64":
                i = g.emit(
                    f'input "{pname}" [{_num(ann.lo)}, {_num(ann.hi)}]{bind(ann.asset)}',
                    f"secret {ann.elem}",
                )
                args[pname] = Secret(g, i, None, ann.elem)
                continue
            if ann.lo is None:
                raise _err(
                    "ENC1101",
                    f"secret input {pname!r} has no declared range; write e.g. "
                    f"secret[{'float' if ann.length is None else f'Tensor[{ann.length}]'}, -1.0:1.0]",
                )
            ty = f"secret {_shape_text(ann.length)}"
            i = g.emit(f'input "{pname}" [{_num(ann.lo)}, {_num(ann.hi)}]{bind(ann.asset)}', ty)
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
    aggregates = []
    for oname, v in items:
        dest = ""
        if isinstance(v, _Output):
            dest = " " + v.dest if v.dest else ""
            if v.party is not None:
                add_party(v.party)
            if v.aggregate is not None:
                aggregates.append(f'aggregate "{_ident(str(oname))}" {v.aggregate}')
            v = v.value
        if not isinstance(v, Secret):
            raise _err(
                "ENC1301",
                f"output {oname!r} does not depend on any secret input; compute it outside Encompute",
            )
        outputs.append((_ident(str(oname)), v._id, dest))

    if purpose is not None:
        _check_text("purpose", purpose)
    header = [
        "encompute 0.1",
        f"program {_ident(name or fn.__name__)} precision {_num(precision)}"
        + (f' purpose "{purpose}"' if purpose else "")
        + (" verification required" if verification == "required" else ""),
    ]
    decls = [f'party "{p.id}" "{p.name}"' for p in parties.values()]
    decls += [a.eir() for a in assets.values()]
    footer = [f'output "{n}" = %{i}{d}' for n, i, d in outputs] + aggregates
    text = "\n".join(header + decls + g.lines + g.derives + footer) + "\n"
    return text, ([n for n, _, _ in outputs], style)
