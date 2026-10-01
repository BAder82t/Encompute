#!/usr/bin/env python3
"""Tests of the exception-controls scan (scan_torch_usage.py).

    python3 -m unittest discover -s scripts/release -p 'test_scan_torch_usage.py'

scan.sh runs them before the scan itself, so a scan that has stopped
seeing aliased uses does not pass the release gate.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

SCAN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_torch_usage.py")

# Each one alone must fail the scan.
BANNED = {
    "direct": "import torch\ntorch.load('m.pt')\n",
    "import_as": "import torch as T\nT.load('m.pt')\n",
    "from_import": "from torch import load\nload('m.pt')\n",
    "from_import_as": "from torch import load as read\nread('m.pt')\n",
    "submodule_import": "import torch.distributed\n",
    "submodule_as": "import torch.jit as J\nJ.script(f)\n",
    "from_submodule": "from torch.distributed import rpc\n",
    "from_torch_submodule": "from torch import distributed\n",
    "serialization": "import torch\ntorch.serialization.load('m.pt')\n",
    "hub": "import torch\ntorch.hub.load('r', 'm')\n",
    "compile": "import torch\nm = torch.compile(m)\n",
    "inductor": "import torch._inductor.config\n",
    "export": "import torch as t\nt.export.export(m, x)\n",
    "fx": "from torch.fx import symbolic_trace\n",
    "profiler": "import torch\nwith torch.profiler.profile():\n    pass\n",
    "getattr_literal": "import torch\ngetattr(torch, 'load')('m.pt')\n",
    "getattr_alias": "import torch as T\nf = getattr(T, 'jit')\n",
    "getattr_computed": "import torch\nname = 'lo' + 'ad'\ngetattr(torch, name)\n",
    "import_module": "import importlib\nimportlib.import_module('torch.jit')\n",
    "import_module_attr": "import importlib\nT = importlib.import_module('torch')\nT.load('m.pt')\n",
    "dunder_import": "__import__('torch.distributed')\n",
    "reassigned": "import torch\nL = torch\nL.load('m.pt')\n",
    "star": "from torch import *\n",
    "trainer": "from transformers import Trainer\n",
    "trainer_attr": "import transformers as tf\ntf.Trainer(model=m)\n",
    "seq2seq_trainer": "from transformers import Seq2SeqTrainer\n",
    "trainer_module": "from transformers.trainer import Trainer\n",
    "accelerate": "from accelerate import load_checkpoint_in_model\n",
    "accelerate_utils": "import accelerate.utils as u\nu.load_checkpoint_and_dispatch(m, 'c')\n",
    "trust_remote_code_true": "AutoModel.from_pretrained('x', trust_remote_code=True)\n",
    "trust_remote_code_variable": "AutoModel.from_pretrained('x', trust_remote_code=flag)\n",
    "trust_remote_code_dict": "AutoModel.from_pretrained('x', **{'trust_remote_code': True})\n",
    "weights_only": "load('m.pt', weights_only=True)\n",
}

# The uses the shipped package makes today, which must pass.
ALLOWED = textwrap.dedent("""
    import importlib
    import torch
    from torch import nn
    from torch.func import functional_call, grad, vmap
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    x = torch.zeros(3)
    m = nn.Linear(3, 1)
    tok = AutoTokenizer.from_pretrained("p", local_files_only=True, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(
        "p", local_files_only=True, use_safetensors=True, trust_remote_code=False)
    pkg = import_model("src", trust_remote_code=trust_remote_code)
    getattr(importlib.import_module(mod), fn)
    import json
    json.load(fh)
""")


def scan(files: dict[str, str]) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as d:
        for name, src in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write(src)
        return subprocess.run([sys.executable, SCAN, d], capture_output=True, text=True)


class ScanTorchUsage(unittest.TestCase):
    def test_each_banned_use_fails(self):
        for name, src in BANNED.items():
            with self.subTest(name):
                r = scan({"m.py": src})
                self.assertEqual(r.returncode, 1, f"{name} passed:\n{src}{r.stdout}{r.stderr}")

    def test_the_package_s_own_uses_pass(self):
        r = scan({"m.py": ALLOWED})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_file_that_does_not_parse_fails(self):
        r = scan({"ok.py": "x = 1\n", "bad.py": "def f(:\n"})
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_a_missing_path_fails(self):
        r = subprocess.run([sys.executable, SCAN, "/nonexistent/encompute"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_no_python_file_fails(self):
        r = scan({"README.txt": "torch.load"})
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_an_unreadable_file_fails(self):
        if os.geteuid() == 0:
            self.skipTest("root reads any file")
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.py")
            with open(p, "w") as f:
                f.write("x = 1\n")
            os.chmod(p, 0)
            try:
                r = subprocess.run([sys.executable, SCAN, d], capture_output=True, text=True)
            finally:
                os.chmod(p, 0o600)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
