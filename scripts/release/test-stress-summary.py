#!/usr/bin/env python3
"""Self-test of stress-summary.py: synthetic per-test logs and, when present, real whole-binary logs.

  test-stress-summary.py [EVIDENCE_LOGDIR]    e.g. .../run-39047173820/window-load-logs
"""
import importlib.util
import os
import pathlib
import sys
import tempfile

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("stress_summary", here / "stress-summary.py")
ss = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ss)

PROOF = 'WINDOW-PROOF queued=["a"] behind target pids [1]; granted all; commit order ["a"]\n'
OK = "running 1 test\n{}.\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.1s\n"
CTL = "negative control 1: INCONCLUSIVE: x\nINCONCLUSIVE: y\nINCONCLUSIVE: z\nnegative control 2: INCONCLUSIVE: w\n"
fails = []


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        fails.append(what)


def build(tests, spec_fn):
    """spec_fn(bin, name, kind, run) -> (rc, text) or None to omit the run."""
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "results.tsv"), "w") as r:
        for b, t, k in tests:
            for i in range(1, ss.runs_of(k) + 1):
                x = spec_fn(b, t, k, i)
                if x is None:
                    continue
                rc, text = x
                r.write(f"{b}\t{t}\t{i}\t{rc}\t2\n")
                pathlib.Path(d, f"{b}.{t}.{i}.log").write_text(text)
    return d


def good(b, t, k, i):
    if k == "proven":
        return 0, OK.format(PROOF * 2 if i % 2 else PROOF)
    if k == "weak":
        return 0, OK.format(PROOF)
    if k == "readonly":
        return 0, OK.format("")
    return 0, OK.format(CTL)


def result(fn, **kw):
    d = build(ss.TESTS, fn)
    _, table, bad = ss.summarise(d, **kw)
    return table, bad


# the test list
names = [t for _, t, _ in ss.TESTS]
check(len(names) == len(set(names)), "no duplicate test names")
check(sum(k == "control" for _, _, k in ss.TESTS) == 1, "exactly one negative control")
check(sum(k == "weak" for _, _, k in ss.TESTS) == 1 and any(t.startswith("w05b") for _, t, k in ss.TESTS if k == "weak"), "w05b is the weak test")
check(not any(t.startswith("w05b") for _, t, k in ss.TESTS if k == "proven"), "w05b is not counted as proven")

table, bad = result(good)
check(not bad, f"all good logs pass ({bad[:1]})")
proven = [r for r in table if r[1] == "proven"]
check(all(r[2] == "45" and r[4] == "45" for r in proven), "45 runs and 45 good per proven test")
check(all(r[2] == "5" for r in table if r[1] == "control"), "control: 5 runs")

b0, t0, _ = ss.TESTS[0]  # a proven test


def mut(pred, rc_text):
    return lambda b, t, k, i: rc_text(b, t, k, i) if pred(b, t, k, i) else good(b, t, k, i)


_, bad = result(mut(lambda b, t, k, i: t == t0 and i == 7, lambda *a: (101, "test result: FAILED. 0 passed; 1 failed\n")))
check(len(bad) == 1 and "failed" in bad[0], "one failed run fails the job")
_, bad = result(mut(lambda b, t, k, i: t == t0 and i == 7, lambda *a: (0, OK.format(""))))
check(len(bad) == 1 and "no WINDOW-PROOF" in bad[0], "a passed run without WINDOW-PROOF fails a proven test")
_, bad = result(mut(lambda b, t, k, i: t == t0 and i == 9, lambda *a: (0, OK.format(PROOF + "INCONCLUSIVE: z\n"))))
check(len(bad) == 1 and "INCONCLUSIVE" in bad[0], "an INCONCLUSIVE line in a proven test fails")
_, bad = result(mut(lambda b, t, k, i: t == t0 and i == 3, lambda *a: (0, "running 0 tests\ntest result: ok. 0 passed; 0 failed\n")))
check(len(bad) == 1, "an exact filter that matched no test (exit 0, 0 passed) fails")
_, bad = result(lambda b, t, k, i: None if (t == t0 and i > 39) else good(b, t, k, i))
check(len(bad) == 1 and "only 39 runs" in bad[0], "39 runs are not enough")
_, bad = result(lambda b, t, k, i: None if (t == t0 and i > 40) else good(b, t, k, i))
check(not bad, "40 good runs are enough")
_, bad = result(mut(lambda b, t, k, i: k == "control" and i == 2, lambda *a: (0, OK.format(CTL.replace("INCONCLUSIVE: w", "ok")))))
check(len(bad) == 1 and "expected 4" in bad[0], "the control with 3 INCONCLUSIVE lines fails")
_, bad = result(mut(lambda b, t, k, i: k == "control", lambda *a: (0, OK.format(PROOF))))
check(len(bad) == 1, "the control without its INCONCLUSIVE lines fails")
_, bad = result(mut(lambda b, t, k, i: k == "weak" and i == 4, lambda *a: (0, OK.format(PROOF + "INCONCLUSIVE\n"))))
check(len(bad) == 1, "an INCONCLUSIVE line in w05b fails")
tw = [t for _, t, k in ss.TESTS if k == "weak"][0]
_, bad = result(mut(lambda b, t, k, i: k == "weak", lambda *a: (0, OK.format(""))))
check(not bad, "w05b needs no WINDOW-PROOF line")
_, bad = result(lambda b, t, k, i: None if t == t0 else good(b, t, k, i))
check(len(bad) == 1 and "0 runs" in bad[0].replace("only 0 runs", "0 runs"), "a test with no runs fails")

# summary output and the GITHUB_STEP_SUMMARY append
d = build(ss.TESTS, good)
gs = os.path.join(d, "gs.md")
os.environ["GITHUB_STEP_SUMMARY"] = gs
rc = ss.main([d])
check(rc == 0 and os.path.exists(os.path.join(d, "summary.txt")) and "RESULT: PASS" in pathlib.Path(gs).read_text(), "summary.txt and step summary written")
del os.environ["GITHUB_STEP_SUMMARY"]

# real whole-binary logs: the counting rules on the evidence of the rehearsal run
ev = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
if ev and ev.is_dir():
    n = 0
    for f in sorted(ev.glob("anchor_negatives.*.log")):
        text = f.read_text(errors="replace")
        check(text.count("INCONCLUSIVE") == ss.CONTROL_INCONCLUSIVE, f"real {f.name}: {ss.CONTROL_INCONCLUSIVE} INCONCLUSIVE lines (the control)")
        n += 1
    for f in sorted(ev.glob("anchor_window_adversarial.*.log")):
        text = f.read_text(errors="replace")
        check(text.count("WINDOW-PROOF") >= 1 and text.count("INCONCLUSIVE") == 0, f"real {f.name}: proof lines, no INCONCLUSIVE")
        n += 1
    # adapt: a per-test log built from a real proof line and a real INCONCLUSIVE block
    real = (ev / "anchor_window_adversarial.1.log").read_text(errors="replace")
    line = next(l for l in real.splitlines() if "WINDOW-PROOF" in l)
    p, pr, inc, g = ss.analyse_run("proven", 0, OK.format(line))
    check(g and pr == 1 and inc == 0, "real WINDOW-PROOF line, adapted to a per-test log, counts as one proven window")
    negs = (ev / "anchor_negatives.1.log").read_text(errors="replace")
    block = "\n".join(l for l in negs.splitlines() if "INCONCLUSIVE" in l)
    p, pr, inc, g = ss.analyse_run("control", 0, OK.format(block))
    check(g and inc == 4, "real control INCONCLUSIVE lines, adapted to a per-test log, count 4")
    check(n > 0, f"{n} real logs read")
else:
    print("skip real logs (no evidence directory given)")

if fails:
    print("FAILED:", *fails, sep="\n  ")
    sys.exit(1)
print("OK: stress-summary")
