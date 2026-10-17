#!/usr/bin/env python3
"""Classify the runs of the window-test diagnostic (stdlib only).

TEST-ONLY diagnostic reader. Input: the directory written by
scripts/release/diag-tests.sh (results.jsonl, logs/, trace/). For every
cargo invocation it reads the log (which tests failed and why) and, for the
instrumented runs, the trace (one `verdict` event per in_window call), and
prints per test and run a classification, then a summary.

Classes
  pass                  the test passed (instrumented: and the verdict was window_ok)
  FAIL-untraced         an ORIGINAL run failed: no trace exists, so no verdict
  harness               instrumented run, verdict attack_before_target or attack_missed:
                        the attack did not reach the intended window (attack_missed includes the
                        two-table gap: `LOCK TABLE a, b` takes a, then b, and the service's read
                        of b ran in between, before the attacker held it)
  product-candidate     instrumented run failed an assertion although the verdict is
                        window_ok (target committed, then the attack changed rows and
                        committed before the response): the service acknowledged a
                        transition that was undone. Needs manual review of the trace.
  inconclusive          unknown verdict, no trace, or a failure unrelated to the window

usage: diag-classify-window.py <diag-dir> [--detail] [--target-only]
"""
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict

TARGETS = {
    "w05_genesis_rewritten_in_the_window_of_the_first_spend",
    "role_removal_undone_in_the_window_is_not_acknowledged",
}


def read_jsonl(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


def parse_log(text):
    """-> (failed test names, {name: failure text}, 'N passed; M failed' or '')"""
    failed = []
    m = re.search(r"failures:\n((?:    \S+\n)+)", text)
    if m:
        failed = [x.strip() for x in m.group(1).splitlines()]
    texts = {}
    for mm in re.finditer(r"---- (\S+) stdout ----\n(.*?)(?=\n---- \S+ stdout ----|\nfailures:\n)", text, re.S):
        texts[mm.group(1)] = mm.group(2).strip()
    res = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed", text)
    summary = f"{res[-1][1]} passed; {res[-1][2]} failed" if res else "no test result line"
    return failed, texts, summary


def classify(failed, verdict, failure_text):
    if not failed:
        if verdict is not None and verdict != "window_ok":
            return "inconclusive"  # cannot happen (hard rule), reported if it does
        return "pass"
    if verdict is None:
        return "FAIL-untraced"
    if "INCONCLUSIVE" in (failure_text or "") or verdict in ("attack_before_target", "attack_missed"):
        return "harness" if verdict in ("attack_before_target", "attack_missed") else "inconclusive"
    if verdict == "window_ok":
        return "product-candidate"
    return "inconclusive"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    detail = "--detail" in sys.argv
    target_only = "--target-only" in sys.argv
    if not args:
        print(__doc__)
        return 2
    d = pathlib.Path(args[0])
    runs = read_jsonl(d / "results.jsonl")
    rows = []  # (run, test, outcome, verdict, cls, verdict_event)
    for r in runs:
        log = d / r["log"] if r.get("log") else None
        text = log.read_text(errors="replace") if log and log.exists() else ""
        failed, ftexts, summary = parse_log(text)
        r["_summary"] = summary
        traced = r["variant"] == "traced"
        verdicts = {}
        if traced and r.get("trace"):
            for ev in read_jsonl(d / r["trace"]):
                if ev.get("ev") == "verdict":
                    verdicts.setdefault(ev["test"], []).append(ev)
        if r["mode"] == "alone":
            names = {r["test"]}
        elif r["mode"] == "full":
            names = set(failed) | TARGETS
        else:
            names = set(verdicts) | set(failed) | {r["test"]}
        for n in sorted(names):
            if target_only and n not in TARGETS:
                continue
            evs = verdicts.get(n, [])
            v = evs[-1]["verdict"] if evs else None
            if n in failed:
                outcome = "FAIL"
            elif r["rc"] != 0 and not failed and r["mode"] == "alone":
                outcome = "FAIL"  # build/harness error before any test result
            else:
                outcome = "PASS"
            cls = classify([n] if outcome == "FAIL" else [], v, ftexts.get(n))
            if outcome == "FAIL" and not ftexts.get(n) and not failed:
                cls = "inconclusive"
            if n in TARGETS or outcome == "FAIL" or (evs and v != "window_ok"):
                rows.append((r, n, outcome, v, cls, evs[-1] if evs else None, ftexts.get(n, "")))
    # ---- table ----
    print("per run: variant mode iteration | test | outcome | verdict | class")
    for r, n, outcome, v, cls, ev, ft in rows:
        print(f"{r['variant']:7} {r['mode']:5} #{r['iteration']:<3} {r['runner']:>3} | {n[:58]:58} | {outcome:4} | {str(v or '-'):20} | {cls}")
    # ---- summary ----
    print("\nSUMMARY per test / variant / mode: runs, failures, verdicts")
    agg = defaultdict(lambda: Counter())
    for r, n, outcome, v, cls, ev, ft in rows:
        if n not in TARGETS:
            continue
        k = (n, r["variant"], r["mode"])
        agg[k]["runs"] += 1
        agg[k]["fail"] += outcome == "FAIL"
        agg[k]["verdict:" + str(v or "-")] += 1
        agg[k]["class:" + cls] += 1
    for k in sorted(agg):
        c = agg[k]
        extra = ", ".join(f"{a}={b}" for a, b in sorted(c.items()) if a not in ("runs", "fail"))
        print(f"{k[0][:52]:52} {k[1]:7} {k[2]:5} runs={c['runs']:3} failed={c['fail']:3}  {extra}")
    print("\nverdict counts over ALL instrumented in_window calls (every test of the traced binaries):")
    tot = Counter()
    for r in runs:
        if r["variant"] == "traced" and r.get("trace"):
            for ev in read_jsonl(d / r["trace"]):
                if ev.get("ev") == "verdict":
                    tot[ev["verdict"]] += 1
    print("  " + (", ".join(f"{a}={b}" for a, b in sorted(tot.items())) or "none"))
    print("\nFAILED RUNS (original and instrumented) and their verdict:")
    nfail = 0
    for r, n, outcome, v, cls, ev, ft in rows:
        if outcome == "FAIL":
            nfail += 1
            first = (ft.splitlines() or [""])[-1][:140] if ft else ""
            print(f"  {r['id']}: {n}: verdict={v or 'n/a (original run, untraced)'} class={cls}  {first}")
            if detail and ev:
                print("    " + json.dumps({k: ev[k] for k in ev if k not in ("call_id",)})[:900])
    if not nfail:
        print("  none")
    # instrumented calls that did not reach the window but did not fail the run are impossible
    # (hard rule); list any traced non-window_ok call for completeness.
    if detail:
        print("\nDETAIL of non-window_ok calls:")
        for r in runs:
            if r["variant"] != "traced" or not r.get("trace"):
                continue
            evs = read_jsonl(d / r["trace"])
            by = defaultdict(list)
            for e in evs:
                by[e.get("call_id")].append(e)
            for cid, es in by.items():
                ver = next((e for e in es if e.get("ev") == "verdict"), None)
                if ver and ver["verdict"] != "window_ok":
                    att = next((e for e in es if e.get("ev") == "attacker"), {})
                    tgt = next((e for e in es if e.get("ev") == "target"), {})
                    print(f"  {r['id']} {ver['test']}: {ver['verdict']} -- {ver['reason']}")
                    print(f"     matched_holders={json.dumps(att.get('matched_holders'))[:400]}")
                    print(f"     service_first_block={json.dumps(tgt.get('service_first_block'))[:300]} lock_gap_suspected={tgt.get('lock_gap_suspected')}")
                    print(f"     target_xid={tgt.get('target_xid')} attacker_xid={att.get('attacker_xid')} lock_granted_ms={att.get('lock_granted_ms')} commit_done_ms={att.get('commit_done_ms')} call_end_ms={ver.get('call_end_ms')} result={ver.get('result')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
