"""python -m encompute compile model.py[:function] [-o out.encompute]"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

from . import Model, EncomputeError, compile as encompute_compile


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    spec.loader.exec_module(module)
    return module


def _compile(source: str, output: str | None) -> int:
    file, _, func = source.partition(":")
    path = Path(file)
    module = _load_module(path)
    if func:
        obj = getattr(module, func, None)
        if obj is None:
            raise SystemExit(f"{path} has no attribute {func!r}")
        model = obj if isinstance(obj, Model) else encompute_compile(obj)
    else:
        models = {k: v for k, v in vars(module).items() if isinstance(v, Model)}
        if len(models) != 1:
            names = ", ".join(sorted(models)) or "none"
            raise SystemExit(f"{path}: expected one @encompute.compile model, found {names}; use {file}:NAME")
        model = next(iter(models.values()))
    out = Path(output) if output else path.with_name(f"{model.name}.encompute")
    model.save(str(out))
    print(f"wrote {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m encompute")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compile", help="trace a Python function and write a .encompute artifact")
    c.add_argument("source", help="model.py or model.py:function")
    c.add_argument("-o", "--output")
    args = parser.parse_args(argv)
    try:
        return _compile(args.source, args.output)
    except EncomputeError as e:
        print(f"error[{e.code}]: {e.message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
