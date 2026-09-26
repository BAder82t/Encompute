"""The native training bindings against the Rust crate's contract
fixtures (crates/encompute-training/tests/fixtures): same bytes in, same
result out, so Python and Rust semantics cannot drift apart. The Rust side
of each fixture is checked by crates/encompute-training/tests/contract.rs."""

import json
from pathlib import Path

import pytest

from encompute import _native

F = Path(__file__).resolve().parents[2] / "crates" / "encompute-training" / "tests" / "fixtures"


def text(name):
    return (F / name).read_text()


def test_training_spec_id():
    assert _native.training_spec_id(text("spec.json")) == text("spec.id")


def test_attestation_policy():
    got = _native.training_attestation_policy(text("spec.json"), "sha256:worker", True)
    assert json.loads(got) == json.loads(text("policy.json"))


def test_layout_digest():
    assert _native.layout_digest(text("layout.json")) == text("layout.digest")
    bad = json.loads(text("layout.json"))
    bad["entries"][1]["offset"] += 1
    with pytest.raises(_native.NativeError):
        _native.layout_digest(json.dumps(bad))


def test_tensor_manifest_and_encoder():
    b = (F / "tensors.bin").read_bytes()
    assert json.loads(_native.tensor_manifest(b)) == json.loads(text("tensors.manifest.json"))
    torch = pytest.importorskip("torch")
    from encompute.torch import tensors
    # The Python encoder reproduces the fixture byte for byte.
    again = tensors.dumps({"a": torch.arange(6, dtype=torch.float32).reshape(2, 3),
                           "b": torch.tensor([1, 2, 3], dtype=torch.int64)})
    assert again == b
    with pytest.raises(_native.NativeError):
        _native.tensor_manifest(b + b"\0")


def test_sealed_asset():
    sealed = (F / "sealed.bin").read_bytes()
    plain = b"contract weights"
    assert bytes(_native.open_asset(bytes([7] * 32), sealed, "contract", "base-model",
                                    _native.sha256_hex(plain))) == plain
    # And Rust-compatible sealing from Python round-trips.
    again = _native.seal_asset(bytes([7] * 32), "model", "contract", "base-model", plain)
    assert bytes(_native.open_asset(bytes([7] * 32), again, "contract", "base-model",
                                    _native.sha256_hex(plain))) == plain


def test_export_decision():
    with pytest.raises(_native.NativeError) as e:
        _native.check_export(text("program.eir"), text("spec.json"), "adapter-1")
    assert f"{e.value.args[0]}: {e.value.args[1]}" == text("export.txt")


def test_checkpoint_resume():
    spec = json.loads(text("spec.json"))
    header, payload = _native.resume_checkpoint(
        bytes([5] * 32), (F / "checkpoint.bin").read_bytes(), spec["project"],
        text("spec.id"), spec["policy_id"], spec["privacy_policy_id"], str(F / "ledgers"))
    assert json.loads(header) == json.loads(text("checkpoint.header.json"))
    assert bytes(payload) == b"adapter state"


def test_adapter_record_fixture_is_well_formed():
    r = json.loads(text("adapter-record.json"))
    assert r["record"]["version"] == 1
    assert r["record"]["training_spec_id"] == text("spec.id")
