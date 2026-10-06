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


def test_models_build_only_allowlisted_factories(tmp_path):
    """Review finding TR-1 (ENC-SF-2026-037): a spec's factory is not any importable callable.
    `models.build` (what every worker runs first) refuses anything the
    worker image does not ship, with the same native check the training
    spec validator applies, before importing it."""
    pytest.importorskip("torch")
    from encompute.torch import models
    marker = tmp_path / "factory-ran"
    stmt = f"open({str(marker)!r}, 'w').write('x')"
    for factory, kwargs in (("subprocess:run", {"args": f"touch {marker}", "shell": True}),
                            ("timeit:timeit", {"stmt": stmt, "number": 1}),
                            ("os:system", {"command": f"touch {marker}"}),
                            ("encompute.torch.models:TinyClassifier", {}),
                            ("encompute.torch.models:tiny_classifier", {"stmt": stmt})):
        with pytest.raises(ValueError):
            models.build(factory, kwargs)
        assert not marker.exists(), factory
    models.build("encompute.torch.models:tiny_classifier", {"vocab": 64, "dim": 8})



def _spec(**fields):
    s = json.loads(text("spec.json"))
    s.update(fields)
    return s


OTHER_BROKER = {"hospital-a-broker": "6" * 64}


def _bound(**brokers_of):
    """The fixture spec with every key bound to its owner's broker where
    ``brokers_of`` names one (owner -> broker ID), else to ModelCo's."""
    s = _spec()
    keys = _native.training_key_ids(json.dumps(s))
    s["asset_brokers"] = {k: brokers_of.get(owner, "modelco") for k, owner in keys.items()}
    s["broker_organizations"] = {"modelco": "modelco",
                                 **{b: o for o, b in brokers_of.items()}}
    if brokers_of:
        s["key_brokers"] = {**s["key_brokers"], **OTHER_BROKER}
    return s


def refused_spec(spec_text, needle):
    with pytest.raises(_native.NativeError) as e:
        _native.training_spec_id(spec_text)
    assert e.value.args[0] == "ENC2501"
    assert needle in e.value.args[1], e.value.args


def test_asset_brokers_are_optional_and_bound_into_the_spec_id():
    # Absent: the rc.4 spec and its ID, unchanged.
    assert "asset_brokers" not in json.loads(text("spec.json"))
    assert _native.training_spec_id(json.dumps(_spec())) == text("spec.id")
    one = _native.training_spec_id(json.dumps(_bound()))
    assert one != text("spec.id")
    two = _bound(**{"hospital-a": "hospital-a-broker"})
    assert _native.training_spec_id(json.dumps(two)) not in (one, text("spec.id"))


def test_worker_key_ids_match_spec_key_ids():
    s = json.dumps(_spec())
    keys = _native.training_key_ids(s)
    mine = _native.training_participant_keys(s, "hospital-a")
    assert mine == {"model": "base-model.hospital-a", "dataset": "dataset-patients-a",
                    "adapters": "adapters.hospital-a", "contribution": "contribution-hospital-a"}
    assert set(mine.values()) <= set(keys)
    assert keys["contribution-hospital-a"] == "hospital-a"
    assert keys["adapters.hospital-a"] == "modelco"
    # The confidential worker asks for exactly these: checked in
    # test_confidential_job.py::test_the_worker_asks_for_the_specs_keys_at_their_brokers.


def test_asset_brokers_must_cover_pin_and_bind_each_key_once():
    brokers = {**_spec()["key_brokers"], **OTHER_BROKER}
    # Two brokers without a binding: the one-broker rule.
    refused_spec(json.dumps(_spec(key_brokers=brokers)), "exactly one key broker")
    # A derived key left out.
    two = _bound(**{"hospital-a": "hospital-a-broker"})
    del two["asset_brokers"]["contribution-hospital-b"]
    refused_spec(json.dumps(two), "contribution-hospital-b")
    # A participant's contribution key at another participant's broker.
    two = _bound(**{"hospital-a": "hospital-a-broker"})
    two["asset_brokers"]["contribution-hospital-b"] = "hospital-a-broker"
    refused_spec(json.dumps(two), "contribution-hospital-b")
    # A broker without a pinned grant-signing key.
    one = _bound()
    one["asset_brokers"]["contribution-hospital-b"] = "hospital-b-broker"
    refused_spec(json.dumps(one), "hospital-b-broker")
    # One key bound twice in the JSON (a dict cannot say it; the text can).
    t = json.dumps(_bound(**{"hospital-a": "hospital-a-broker"}))
    dup = t.replace('"contribution-hospital-b": "modelco"',
                    '"contribution-hospital-b": "modelco", "contribution-hospital-a": "modelco"')
    assert dup != t
    refused_spec(dup, "more than once")


def test_a_key_outside_the_binding_is_refused_before_any_broker(tmp_path):
    seed = tmp_path / "mock.seed"
    seed.write_bytes(bytes([9] * 32))
    spec = json.dumps(_bound(**{"hospital-a": "hospital-a-broker"}))

    def acquire(assets, urls=None):
        # Port 9 (discard): nothing answers, so a refusal here is the
        # workload's own, before any request.
        with pytest.raises(_native.NativeError) as e:
            _native.acquire_session_keys(spec, "http://127.0.0.1:9", assets, bytes([1] * 32),
                                         "mock", str(seed), "sha256:worker", "hospital-a",
                                         broker_urls=urls)
        return e.value.args

    code, msg = acquire(["patients-a"], {"modelco": "http://127.0.0.1:9"})
    assert code == "ENC2004", (code, msg)
    assert "binds patients-a to no key broker" in msg
    # Several brokers: each key needs its broker's address; a bound broker
    # without one is an error, not a fallback to another broker.
    code, msg = acquire(["contribution-hospital-a"])
    assert code == "ENC2004" and "give each broker's address" in msg, msg
    code, msg = acquire(["contribution-hospital-a"], {"modelco": "http://127.0.0.1:9"})
    assert "no address for key broker hospital-a-broker" in msg, msg
    code, msg = acquire(["contribution-hospital-a"],
                        {"hospital-a-broker": "http://127.0.0.1:9#" + "ab" * 32})
    assert "comes from the training spec" in msg, msg
