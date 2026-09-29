#!/usr/bin/env python3
"""The control the torch and transformers exceptions rely on
(security/exceptions.toml, compensating_controls): the shipped Python
package references none of the PyTorch, Transformers and Accelerate entry
points those exceptions declare unused.

    python3 scripts/release/scan_torch_usage.py [PATH ...]   # default: python/encompute

A static scan of the syntax tree, not a text search, so aliases do not hide
a use:

* ``import torch as T; T.load(...)``, ``import torch.jit``,
  ``from torch import load``, ``from torch.distributed import rpc``;
* ``getattr(torch, "load")`` (a literal name), and ``getattr(torch, name)``
  (any computed name on these packages, which cannot be checked);
* ``importlib.import_module("torch.jit")`` and ``__import__`` with a
  literal name; ``from torch import *``;
* Transformers ``Trainer`` (and ``*Trainer``, ``transformers.trainer``),
  Accelerate ``load_checkpoint_in_model`` / ``load_checkpoint_and_dispatch``
  under any name;
* ``trust_remote_code=`` anything but a literal ``False`` (``import_model``,
  which refuses a true value, excepted), and any ``weights_only=`` (it only
  means something to ``torch.load``).

What a static scan cannot see (a module name computed at run time, code in
the dependencies themselves) is out of its reach; the factories the worker
imports by name are held to an allowlist (encompute.torch.models.FACTORIES).

Exit 0: no finding. Exit 1: findings (one per line, path:line: what).
Exit 2: the scan could not run completely (a missing or unreadable path, a
file that does not parse, or no Python file at all): never a pass.
"""
from __future__ import annotations

import ast
import os
import sys

# Entry points, by qualified name: the name itself and everything under it.
BANNED = (
    "torch.load", "torch.serialization", "torch.hub", "torch.package",
    "torch.jit", "torch.compile", "torch._dynamo", "torch._inductor",
    "torch.export", "torch._export", "torch.fx", "torch.onnx",
    "torch.distributed", "torch.profiler", "torch.autograd.profiler",
    "transformers.trainer", "transformers.Trainer",
)
# Names banned wherever they come from (the regex this scan replaces matched
# them as words).
BANNED_NAMES = {"Trainer", "load_checkpoint_in_model", "load_checkpoint_and_dispatch"}
# Packages on which a computed getattr or a star import cannot be checked.
ROOTS = ("torch", "transformers", "accelerate")
# Callees that refuse trust_remote_code=True themselves (encompute.torch.hf).
TRUST_REMOTE_CODE_OK = {"import_model"}


def banned(qual: str | None) -> bool:
    if not qual:
        return False
    if any(qual == b or qual.startswith(b + ".") for b in BANNED):
        return True
    parts = qual.split(".")
    if parts[0] == "transformers" and any(p.endswith("Trainer") for p in parts[1:]):
        return True
    return any(p in BANNED_NAMES for p in parts)


def in_roots(qual: str | None) -> bool:
    return bool(qual) and qual.split(".")[0] in ROOTS


def literal_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class Scan(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.alias: dict[str, str] = {}  # local name -> qualified name
        self.findings: list[str] = []

    def hit(self, node: ast.AST, what: str) -> None:
        self.findings.append(f"{self.path}:{getattr(node, 'lineno', 0)}: {what}")

    # Qualified name of an expression, where it can be resolved.
    def qual(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.alias.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.qual(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call):
            f = node.func
            fq = self.qual(f) or (f.id if isinstance(f, ast.Name) else None)
            if fq in ("getattr",) and len(node.args) >= 2:
                name = literal_str(node.args[1])
                base = self.qual(node.args[0])
                return f"{base}.{name}" if base and name else None
            if fq in ("importlib.import_module", "__import__") and node.args:
                return literal_str(node.args[0])
        return None

    # Two passes: aliases first (module-wide, whatever the scope), then uses.
    def collect(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.alias[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.alias[top] = top
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    if a.name != "*":
                        self.alias[a.asname or a.name] = f"{node.module}.{a.name}"
        # Then plain assignments of what resolves (T = importlib.import_module(
        # "torch"), jit = torch.jit), until nothing changes.
        assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                   and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)]
        changed, rounds = True, 0
        while changed and rounds < 10:  # bounded: x = x.y would never settle
            changed, rounds = False, rounds + 1
            for n in assigns:
                q = self.qual(n.value)
                if q and in_roots(q) and self.alias.get(n.targets[0].id) != q:
                    self.alias[n.targets[0].id] = q
                    changed = True

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            if banned(a.name):
                self.hit(node, f"import {a.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and not node.level:
            for a in node.names:
                q = f"{node.module}.{a.name}"
                if a.name == "*" and in_roots(node.module):
                    self.hit(node, f"from {node.module} import * (cannot be checked)")
                elif banned(node.module) or banned(q):
                    self.hit(node, f"from {node.module} import {a.name}")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in BANNED_NAMES:
            self.hit(node, f"{node.id}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        q = self.qual(node)
        if banned(q):
            self.hit(node, q)
            return  # one finding per expression, not one per prefix
        if node.attr in BANNED_NAMES:
            self.hit(node, f".{node.attr}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        f = node.func
        fq = self.qual(f) or (f.id if isinstance(f, ast.Name) else None)
        q = self.qual(node)
        if q and banned(q):
            self.hit(node, f"{fq}({q!r})")
        elif fq == "getattr" and len(node.args) >= 2:
            base = self.qual(node.args[0])
            name = literal_str(node.args[1])
            if name in BANNED_NAMES:
                self.hit(node, f"getattr(..., {name!r})")
            elif in_roots(base) and name is None:
                self.hit(node, f"getattr({base}, <computed>) (cannot be checked)")
        callee = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
        for k in node.keywords:
            if k.arg == "trust_remote_code":
                literal_false = isinstance(k.value, ast.Constant) and k.value.value is False
                if not literal_false and callee not in TRUST_REMOTE_CODE_OK:
                    self.hit(k.value, "trust_remote_code= not a literal False")
            elif k.arg == "weights_only":
                self.hit(k.value, "weights_only= (torch.load)")
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if key is not None and literal_str(key) == "trust_remote_code" and not (
                    isinstance(value, ast.Constant) and value.value is False):
                self.hit(node, "'trust_remote_code': not a literal False")
            if key is not None and literal_str(key) == "weights_only":
                self.hit(node, "'weights_only': (torch.load)")
        self.generic_visit(node)


def scan_file(path: str) -> list[str]:
    with open(path, "rb") as fh:
        src = fh.read()
    tree = ast.parse(src, filename=path)
    s = Scan(path)
    s.collect(tree)
    s.visit(tree)
    return s.findings


def python_files(root: str) -> list[str]:
    if os.path.isfile(root):
        return [root]
    if not os.path.isdir(root):
        raise FileNotFoundError(f"no such file or directory: {root}")
    def fail(e: OSError) -> None:
        raise e

    out = []
    for d, dirs, files in os.walk(root, onerror=fail):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        out += [os.path.join(d, f) for f in sorted(files) if f.endswith(".py")]
    return out


def main(argv: list[str]) -> int:
    roots = argv or ["python/encompute"]
    findings: list[str] = []
    n = 0
    try:
        for r in roots:
            for p in python_files(r):
                findings += scan_file(p)
                n += 1
    except (OSError, SyntaxError, ValueError) as e:
        print(f"scan_torch_usage: cannot scan: {e}", file=sys.stderr)
        return 2
    if n == 0:
        print(f"scan_torch_usage: no Python files under {' '.join(roots)}", file=sys.stderr)
        return 2
    for f in findings:
        print(f)
    if findings:
        print(f"{len(findings)} findings in {n} files")
        return 1
    print(f"{n} files, no torch.load/serialization/hub/package/jit/compile/_dynamo/_inductor/"
          "export/fx/onnx/distributed/profiler, Trainer, load_checkpoint_* or weights_only; "
          "trust_remote_code only a literal False (or to import_model, which refuses True)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
