"""Secret canaries in a confidential fine-tuning run. Distinctive values
are planted in:
- both hospitals' datasets;
- the base-model weights;
- each worker's contribution;
- the model key.

Then every file in the run directory, and all output, is scanned. A canary
may appear only where it is allowed: the hospital's own dataset file, and
the model owner's own key store. Nowhere else, in any encoding."""

import json
import os
import struct
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

import encompute  # noqa: E402
from encompute import _native  # noqa: E402
from encompute.torch import finetune as ft  # noqa: E402

try:
    CLI = ft._cli()
except encompute.EncomputeError:
    pytest.skip("the encompute CLI is not built", allow_module_level=True)

DATA_CANARY = [61, 7, 59, 3, 57, 11, 53, 13]          # a token sequence, both hospitals
WEIGHT_CANARY = 1234.5678                             # planted in the base model
UPDATE_CANARY = 0.42424242                            # planted in each contribution

RUN = textwrap.dedent(f"""
    import sys, torch, encompute
    import encompute.torch as et

    def dataset(seed, n=64):
        g = torch.Generator().manual_seed(seed)
        x = torch.randint(0, 64, (n, 8), generator=g)
        x[5] = torch.tensor({DATA_CANARY})
        return et.private_dataset(x, (x[:, 0] < 32).long())

    p = encompute.Project("leak-lora", parties=["hospital-a", "hospital-b", "modelco"],
                          purpose="disease-training")
    torch.manual_seed(0)
    base = et.wrap_model("encompute.torch.models:tiny_classifier", vocab=64, dim=16)
    with torch.no_grad():
        base.head.weight[0, 0] = {WEIGHT_CANARY}
    m = p.model("base-model", owner="modelco", module=base)
    a = p.data("patients-a", owner="hospital-a", dataset=dataset(1))
    b = p.data("patients-b", owner="hospital-b", dataset=dataset(2))
    r = p.finetune(model=m, data=[a, b], privacy="standard", allow_development=True,
                   config=et.LoRAConfig(rounds=2, local_steps=2), workdir=sys.argv[1])
    print(r.lineage())
    r.close()
""")


def encodings(values, fmt):
    """Byte encodings a leak could take: raw little-endian, and text."""
    out = [b"".join(struct.pack("<" + fmt, v) for v in values)]
    if fmt == "q":
        out.append(json.dumps(values).encode())
        out.append(", ".join(map(str, values)).encode())
    else:
        out += [repr(v).encode() for v in values] + [f"{v:.6f}".encode() for v in values]
    return out


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    W = tmp_path_factory.mktemp("leak") / "run"
    env = dict(os.environ, ENCOMPUTE_CLI=CLI, ENCOMPUTE_CANARY_UPDATE=repr(UPDATE_CANARY))
    p = subprocess.run([sys.executable, "-c", RUN, str(W)], env=env, capture_output=True,
                       timeout=300)
    assert p.returncode == 0, p.stdout.decode() + p.stderr.decode()
    return W, p.stdout + p.stderr


def scan(W: Path, output: bytes, needles, allowed=()):
    hits = []
    for f in W.rglob("*"):
        if not f.is_file() or any(str(f).endswith(a) for a in allowed):
            continue
        data = f.read_bytes()
        hits += [f"{f.relative_to(W)}: {n[:24]!r}" for n in needles if n in data]
    hits += [f"output: {n[:24]!r}" for n in needles if n in output]
    return hits


def test_the_run_completed(run):
    W, out = run
    assert b"TRUST REQUIREMENTS SATISFIED" in out


def test_patient_data_stays_with_its_owner(run):
    W, out = run
    needles = encodings(DATA_CANARY, "q")
    # Each hospital's own dataset file holds it; nothing else may.
    assert (W / "hospital-a" / "dataset.bin").read_bytes().find(needles[0]) >= 0
    assert scan(W, out, needles, allowed=("hospital-a/dataset.bin",
                                          "hospital-b/dataset.bin")) == []


def test_model_weights_never_appear_in_the_clear(run):
    W, out = run
    assert scan(W, out, encodings([WEIGHT_CANARY], "f") + encodings([WEIGHT_CANARY], "d")) == []


def test_raw_updates_never_leave_a_worker(run):
    W, out = run
    needles = encodings([UPDATE_CANARY], "d") + encodings([UPDATE_CANARY], "f")
    assert scan(W, out, needles) == []


def test_keys_stay_in_the_owners_key_store(run):
    W, out = run
    st = json.loads((W / "run.json").read_text())
    mc = W / "modelco"
    b, url = ft._start_broker(CLI, mc, st["mock_root"])
    try:
        keys = dict(_native.acquire_training_keys(
            st["spec"], url, ["base-model", "checkpoints", "adapters"],
            str(mc / "coord.key"), str(W / "hw.seed"), ft.IMAGE)[0])
    finally:
        b.terminate()
        b.wait()
    needles = []
    for k in keys.values():
        needles += [bytes(k), bytes(k).hex().encode()]
    # The development key store holds keys unwrapped (a KEK-wrapped store
    # does not); it is the owner's own state. Nowhere else.
    assert scan(W, out, needles, allowed=("modelco/broker.json",)) == []


def test_no_raw_update_files(run):
    W, _ = run
    names = [str(f.relative_to(W)).lower() for f in W.rglob("*")]
    for bad in ("raw_update", "unmasked", "plaintext", "raw-gradient"):
        assert not [n for n in names if bad in n], bad
