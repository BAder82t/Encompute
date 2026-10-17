#!/usr/bin/env python3
"""Accounting of the per-test window stress (stdlib only).

  stress-summary.py --list                      print the tests: bin<TAB>name<TAB>kind<TAB>runs
  stress-summary.py LOGDIR [--min-proven N]     summarise LOGDIR/results.tsv and the run logs

LOGDIR/results.tsv has one line per run: bin, test, run, exit status, seconds (TAB separated).
The log of a run is LOGDIR/<bin>.<test>.<run>.log (cargo test ... --exact --nocapture, so it
contains exactly that one test).

Kinds:
  proven    a proven-window test: a run is GOOD when it exited 0, reported "1 passed" (an exact
            filter that matches nothing also exits 0), printed at least one WINDOW-PROOF line and
            no INCONCLUSIVE line. Needs >= MIN_PROVEN good runs and no failure and no INCONCLUSIVE.
  weak      the post-verification race (w05b): not a proven-window test. Needs >= MIN_PROVEN runs
            that passed, no failure, no INCONCLUSIVE. WINDOW-PROOF lines are reported, not required.
  readonly  the read-only window helper does not print WINDOW-PROOF: passes are counted, an
            unreached window panics with INCONCLUSIVE. Same rule as weak.
  control   the negative control: every run must pass and print exactly CONTROL_INCONCLUSIVE
            INCONCLUSIVE lines (two panic messages and the two lines the test prints about them).
Exit status 0 only when every test passes its rule.
"""
import os
import re
import sys

MIN_PROVEN = 40
RUNS = 45
CONTROL_RUNS = 5
CONTROL_INCONCLUSIVE = 4

W = "anchor_window_adversarial"
N = "anchor_negatives"
A = "anchor_window"
G = "anchor_genesis"
F = "anchor_failclosed"

TESTS = [
    (W, "w01_first_spend_erased_in_the_window", "proven"),
    (W, "w02_spend_replaced_by_a_forged_valid_entry", "proven"),
    (W, "w03_duplicate_answer_replaced_by_a_forged_entry", "readonly"),
    (W, "w05_genesis_rewritten_in_the_window_of_the_first_spend", "proven"),
    (W, "w05b_genesis_rewritten_after_the_service_read_it", "weak"),
    (W, "w06_two_concurrent_spends_one_erased", "proven"),
    (W, "w10_spend_on_a_ledger_created_then_erased_in_the_window", "proven"),
    (W, "w11_background_tick_racing_the_window", "proven"),
    (W, "w12_control_noop_attack_is_acknowledged", "proven"),
    (W, "w13_entry_and_audit_trace_erased_in_the_window", "proven"),
    (W, "w14_earlier_entry_modified_in_the_window", "proven"),
    (N, "revocation_undone_in_the_window_is_not_acknowledged", "proven"),
    (N, "failed_job_of_a_revocation_undone_in_the_window_is_not_acknowledged", "proven"),
    (N, "withdrawn_approval_restored_in_the_window_is_not_acknowledged", "proven"),
    (N, "service_disable_undone_in_the_window_is_not_acknowledged", "proven"),
    (N, "user_disable_undone_in_the_window_is_not_acknowledged", "proven"),
    (N, "cancelled_job_revived_in_the_window_is_not_acknowledged", "proven"),
    (N, "role_removal_undone_in_the_window_is_not_acknowledged", "proven"),
    (N, "project_leave_undone_in_the_window_is_not_acknowledged", "proven"),
    (N, "window_helper_negative_control_a_missed_window_is_inconclusive", "control"),
    (A, "spend_erased_in_the_window_is_not_acknowledged", "proven"),
    (A, "duplicate_answer_erased_in_the_window_is_not_acknowledged", "readonly"),
    (A, "repeated_erase_in_the_window_does_not_defeat_the_cap", "proven"),
    (A, "genesis_rewritten_in_the_window_is_not_acknowledged", "proven"),
    (A, "ledger_row_deleted_in_the_window_is_not_acknowledged", "proven"),
    (G, "g1_writer_forces_an_unanchored_ledger_with_its_own_genesis", "proven"),
    (F, "fc7_a_different_negative_id_in_the_database_is_refused", "proven"),
    (F, "fc8_a_different_event_in_the_ledger_is_refused", "proven"),
]


def runs_of(kind, runs=RUNS):
    return CONTROL_RUNS if kind == "control" else runs


def read_log(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def analyse_run(kind, rc, text):
    """-> (passed, proofs, inconclusive, good)"""
    proofs = text.count("WINDOW-PROOF") if text is not None else 0
    inc = text.count("INCONCLUSIVE") if text is not None else 0
    passed = rc == 0 and text is not None and re.search(r"test result: ok\. 1 passed; 0 failed", text) is not None
    if kind == "proven":
        good = passed and proofs >= 1 and inc == 0
    elif kind == "control":
        good = passed and inc == CONTROL_INCONCLUSIVE
    else:
        good = passed and inc == 0
    return passed, proofs, inc, good


def load_results(logdir):
    rows = {}
    path = os.path.join(logdir, "results.tsv")
    with open(path, encoding="utf-8") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 4:
                continue
            rows.setdefault((p[0], p[1]), []).append((int(p[2]), int(p[3]), float(p[4]) if len(p) > 4 else 0.0))
    return rows


def summarise(logdir, min_proven=MIN_PROVEN, runs=RUNS, tests=TESTS):
    rows = load_results(logdir)
    out, bad = [], []
    hdr = ["test", "kind", "runs", "passed", "good", "WINDOW-PROOF", "INCONCLUSIVE", "verdict"]
    table = []
    known = {(b, t) for b, t, _ in tests}
    for key in rows:
        if key not in known:
            bad.append(f"unexpected results for {key[0]} {key[1]}")
    for b, t, kind in tests:
        rs = rows.get((b, t), [])
        want = runs_of(kind, runs)
        n = passed = good = proofs = inc = 0
        why = []
        seen = set()
        for run, rc, _secs in rs:
            seen.add(run)
            text = read_log(os.path.join(logdir, f"{b}.{t}.{run}.log"))
            p, pr, ic, g = analyse_run(kind, rc, text)
            n += 1
            passed += p
            good += g
            proofs += pr
            inc += ic
            if not p:
                why.append(f"run {run} failed (exit {rc})")
            elif kind != "control" and ic:
                why.append(f"run {run}: {ic} INCONCLUSIVE")
            elif kind == "proven" and pr < 1:
                why.append(f"run {run}: no WINDOW-PROOF")
            elif kind == "control" and ic != CONTROL_INCONCLUSIVE:
                why.append(f"run {run}: {ic} INCONCLUSIVE, expected {CONTROL_INCONCLUSIVE}")
        if len(seen) != n:
            why.append("duplicate run numbers")
        need = want if kind == "control" else min_proven
        if n < need:
            why.append(f"only {n} runs recorded, need {need}")
        if good < need:
            why.append(f"{good} good runs, need {need}")
        if kind == "control" and n != want:
            why.append(f"{n} runs, expected {want}")
        verdict = "PASS" if not why else "FAIL: " + "; ".join(why[:3]) + (" ..." if len(why) > 3 else "")
        if why:
            bad.append(f"{b} {t}: " + "; ".join(why))
        table.append([f"{b}::{t}", kind, str(n), str(passed), str(good), str(proofs), str(inc), verdict])
    return hdr, table, bad


def render(hdr, table, bad, min_proven):
    proven = [r for r in table if r[1] == "proven"]
    lines = [
        "# window stress, one test per run",
        "",
        f"proven-window tests need >= {min_proven} runs that passed with at least one WINDOW-PROOF line and no INCONCLUSIVE;",
        f"the negative control needs {CONTROL_RUNS} passing runs with exactly {CONTROL_INCONCLUSIVE} INCONCLUSIVE lines each.",
        "",
        "| " + " | ".join(hdr) + " |",
        "|" + "|".join("---" for _ in hdr) + "|",
    ]
    lines += ["| " + " | ".join(r) + " |" for r in table]
    lines += ["", f"proven-window tests: {len(proven)}, total runs: {sum(int(r[2]) for r in table)}, "
              f"proven windows counted (proven tests): {sum(int(r[5]) for r in proven)}"]
    lines += ["", "RESULT: " + ("PASS" if not bad else "FAIL")]
    lines += [f"- {b}" for b in bad]
    return "\n".join(lines) + "\n"


def main(argv):
    if argv[:1] == ["--list"]:
        for b, t, k in TESTS:
            print(f"{b}\t{t}\t{k}\t{runs_of(k, int(os.environ.get('RUNS', RUNS)))}")
        return 0
    min_proven = int(os.environ.get("MIN_PROVEN", MIN_PROVEN))
    runs = int(os.environ.get("RUNS", RUNS))
    if "--min-proven" in argv:
        i = argv.index("--min-proven")
        min_proven = int(argv[i + 1])
        del argv[i : i + 2]
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    logdir = argv[0]
    hdr, table, bad = summarise(logdir, min_proven, runs)
    text = render(hdr, table, bad, min_proven)
    with open(os.path.join(logdir, "summary.txt"), "w", encoding="utf-8") as f:
        f.write(text)
    sys.stdout.write(text)
    gs = os.environ.get("GITHUB_STEP_SUMMARY")
    if gs:
        with open(gs, "a", encoding="utf-8") as f:
            f.write(text)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
