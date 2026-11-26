"""Key and seed files the training bindings read (a party's or the
coordinator's key, a mock attestation seed) must be accessible to their
owner only, like the CLI's secret key files: otherwise ENC2605, before the
key signs anything."""

import json
import os
import sys

import pytest

from encompute import _native

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")

IMAGE = "sha256:" + "3" * 64


def seed_file(path, mode=0o600):
    path.write_bytes(os.urandom(32))
    path.chmod(mode)
    return str(path)


def attest(identity, mock_seed):
    return _native.attest_contribution("1" * 64, None, "2" * 64, identity, mock_seed, IMAGE)


def test_owner_only_key_files_are_used(tmp_path):
    record = json.loads(attest(seed_file(tmp_path / "party.key"), seed_file(tmp_path / "hw.seed")))
    assert record


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
@pytest.mark.parametrize("which", ["party.key", "hw.seed"])
def test_a_key_file_others_can_read_is_refused(tmp_path, which, mode):
    files = {f: seed_file(tmp_path / f) for f in ("party.key", "hw.seed")}
    os.chmod(files[which], mode)
    with pytest.raises(_native.NativeError) as e:
        attest(files["party.key"], files["hw.seed"])
    code, message = e.value.args
    assert code == "ENC2605", message
    assert which in message and "chmod 600" in message


def test_a_missing_or_wrong_length_file_keeps_its_error(tmp_path):
    with pytest.raises(_native.NativeError) as e:
        attest(str(tmp_path / "absent.key"), seed_file(tmp_path / "hw.seed"))
    assert e.value.args[0] == "ENC1102"
    short = tmp_path / "short.key"
    short.write_bytes(b"\0" * 16)
    short.chmod(0o600)
    with pytest.raises(_native.NativeError) as e:
        attest(str(short), seed_file(tmp_path / "hw2.seed"))
    assert e.value.args[0] == "ENC1102" and "32 bytes" in e.value.args[1]
