"""Crash and kill injection for confidential fine-tuning. A real run is
crashed (or one of its processes killed) at each point of a round. Recovery
must then find:
- every privacy ledger valid;
- every released round charged (no privacy cost forgotten);
- no adapter usable that was not accepted at the commit point.

Resuming must then complete the run with a satisfied trust report. The
Rust coordinator's own ledger-level crash points (after reservation, during
noise, before and after commit) are covered by the assurance check
dp_crash_injection."""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

import encompute  # noqa: E402
from encompute.torch import finetune as ft  # noqa: E402

try:
    CLI = ft._cli()
except encompute.EncomputeError:
    pytest.skip("the encompute CLI is not built", allow_module_level=True)

SETUP = textwrap.dedent("""
    import sys, torch, encompute
    import encompute.torch as et

    def dataset(seed, n=64):
        g = torch.Generator().manual_seed(seed)
        x = torch.randint(0, 64, (n, 8), generator=g)
        return et.private_dataset(x, (x[:, 0] < 32).long())

    p = encompute.Project("crash-lora", parties=["hospital-a", "hospital-b", "modelco"],
                          purpose="disease-training")
    torch.manual_seed(0)
    base = et.wrap_model("encompute.torch.models:tiny_classifier", vocab=64, dim=16)
    m = p.model("base-model", owner="modelco", module=base)
    a = p.data("patients-a", owner="hospital-a", dataset=dataset(1))
    b = p.data("patients-b", owner="hospital-b", dataset=dataset(2))
    r = p.finetune(model=m, data=[a, b], privacy="standard", allow_development=True,
                   config=et.LoRAConfig(rounds=2, local_steps=2), workdir=sys.argv[1],
                   verbose=False)
    r.close()
    sys.exit(0 if r.satisfied else 3)
""")

POINTS = [
    # (failpoint, whether the first run survives)
    ("after-local-training", False),      # a hospital worker dies before contributing
    ("after-contribution", False),        # ... after contributing
    ("kill-coordinator", False),          # the aggregation coordinator is killed mid-round
    ("after-aggregate-release", False),   # the orchestrator dies after the DP release
    ("after-adapter-write", False),       # ... after sealing the provisional adapter
    ("before-checkpoint-write", False),
    ("during-checkpoint-write", False),   # a torn checkpoint write
    ("before-trust-update", False),       # ... just before the commit point
    ("after-trust-update", False),        # ... just after it, before files move into place
    ("kill-broker", True),                # the key broker dies after keys were released
]


def ledger_counts(mc: Path, asset: str):
    path = mc / "ledgers" / f"{asset}.ledger"
    if not path.exists():
        return 0, 0
    lines = path.read_text().splitlines()[1:]
    kinds = [json.loads(line)["event"]["kind"] for line in lines]
    return kinds.count("reserve"), kinds.count("commit")


@pytest.mark.parametrize("point,survives", POINTS)
def test_crash_then_recover_and_resume(point, survives, tmp_path):
    W = tmp_path / "run"
    env = dict(os.environ, ENCOMPUTE_TRAINING_FAILPOINT=point, ENCOMPUTE_CLI=CLI)
    p = subprocess.run([sys.executable, "-c", SETUP, str(W)], env=env, capture_output=True,
                       text=True, timeout=300)
    if survives:
        assert p.returncode == 0, p.stdout + p.stderr
    else:
        assert p.returncode != 0, f"{point} did not interrupt the run"

    rec = ft.recover(str(W))
    assert rec["problems"] == [], rec
    mc = W / "modelco"
    # No privacy cost forgotten: every released round is reserved and
    # committed in every charged ledger, accepted or not.
    released = len(rec["accepted"]) + len(rec["lost"])
    for asset in ("gradient-patients-a", "gradient-patients-b"):
        reserves, commits = ledger_counts(mc, asset)
        assert commits == released, (point, reserves, commits, rec)
        assert reserves >= commits
    # Nothing unaccepted is usable.
    assert not list((mc / "pending").glob("*")) if (mc / "pending").exists() else True
    for f in mc.glob("adapter-*.enc"):
        r = int(f.name.split("-")[1].split(".")[0])
        assert r == 0 or r in rec["accepted"], (point, f.name, rec)

    # Resume to completion.
    r = ft.finetune(resume=str(W), verbose=False)
    try:
        # Either all rounds complete, or the budget runs out: a lost round's
        # privacy stays spent, so it can leave no room for the last one.
        assert r.rounds == 2 or (r.stopped and "privacy budget exhausted" in r.stopped), \
            (point, r.rounds, r.stopped)
        assert r.satisfied, (point, r.report)
        if r.stopped:
            assert rec["lost"], "the budget ran out without a lost round"
        if len(rec["accepted"]) + (1 if not survives else 0) >= 1 and r.recovery["accepted"]:
            # An older accepted checkpoint is refused once later rounds exist.
            first = min(r.recovery["accepted"])
            if first < max(int(x.name.split("-")[1].split(".")[0])
                           for x in (mc / "checkpoints").glob("round-*.enc")):
                with pytest.raises(encompute.EncomputeError):
                    r.resume(str(mc / "checkpoints" / f"round-{first}.enc"))
    finally:
        r.close()
