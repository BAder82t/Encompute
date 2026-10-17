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
  environment           the run died on "too many clients already" (the service container's
                        max_connections, reached under heavy CPU load): not a window failure
  inconclusive          unknown verdict, no trace, or a failure unrelated to the window

Direct chronology (server log)
  When the PostgreSQL service logged every statement and lock wait during the instrumented
  runs (diag-tests.sh phase B), logs/pg-<id>.log.gz holds the server log of the databases of
  the run's in_window calls. For every call this script rebuilds, from the log alone, per
  backend pid and transaction: the target's COMMIT, the attacker's LOCK TABLE (the
  per-table `acquired AccessExclusiveLock .. after N ms` lines), the attack statement, the
  attacker's COMMIT, every post-commit statement of the service (parse / bind / execute,
  with the lock waits it ran into and for how long), and the response marker, and computes a
  verdict from those direct timestamps only (the in-test times are used only to cross-check):

    window_ok               every post-commit read of the call's tables ran after the attacker
                            committed (blocked on the attacker's lock, or later): it saw the
                            post-attack state
    tore                    a post-commit read ran BEFORE the attacker's lock on its table (no
                            wait, finished before the attacker's COMMIT) and a later read ran
                            after the attack: a mixed observation
    attack_after_all_reads  every post-commit read ran before the attacker's lock on its table;
                            the attacker committed after the last read but before the response
    attack_after_response   the attacker committed after the response
    unknown                 a needed line is missing or the reads do not fit these cases

  Three facts are reported separately per call: the read time(s), the mutation commit time
  (the attacker's COMMIT) and the acknowledgment time (the response marker, executed on the
  helper's own connection the instant the call returned).

usage: diag-classify-window.py <diag-dir> [--detail] [--target-only] [--timelines]
       diag-classify-window.py --filter-log <trace.jsonl>     (stdin: raw server log -> stdout)
       diag-classify-window.py --timeline-of <pglog(.gz)> <trace.jsonl>
"""
import gzip
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

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
    if "too many clients" in (failure_text or "") or "E53300" in (failure_text or ""):
        return "environment"  # the database refused a connection (max_connections), before the window
    if verdict is None:
        return "FAIL-untraced"
    if "INCONCLUSIVE" in (failure_text or "") or verdict in ("attack_before_target", "attack_missed"):
        return "harness" if verdict in ("attack_before_target", "attack_missed") else "inconclusive"
    if verdict == "window_ok":
        return "product-candidate"
    return "inconclusive"


# ---------------------------------------------------------------------------
# Direct chronology from the PostgreSQL server log
# ---------------------------------------------------------------------------
# Log line prefix (set by diag-tests.sh): '%m [%p] x=%x a=%a d=%d '. Order of the entries in the
# file is the order the server emitted them (one stderr pipe), so it, not the millisecond
# timestamp, is the tie-breaker everywhere below ("idx").
LINE = re.compile(
    r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) \S+ \[(\d+)\] x=(\d+) a=(.*?) d=(\S*) ([A-Z]+):  (.*)$"
)
# Two server processes can write into the one stderr pipe at the same time and their bytes then
# share a line ('duration: 0.035 ms 2026-.. [69] x=0 a= d= LOG: checkpoint ...'): split there.
GLUE = re.compile(r"(?<=\S) (?=\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3} \S+ \[\d+\] x=)")
WAIT = re.compile(
    r"^process (\d+) (still waiting for|acquired) (\w+) on relation (\d+) of database (\d+) after ([\d.]+) ms"
)
DUR_ONLY = re.compile(r"^duration: ([\d.]+) ms$")
DUR_TEXT = re.compile(r"^duration: ([\d.]+) ms  (parse|bind|statement|execute) ?(\S*?): ?(.*)$", re.S)
HOLD = re.compile(r"^Process holding the lock: ([\d, ]+)\. Wait queue: ([\d, ]*)\.?")


class Ent:
    __slots__ = ("idx", "ts", "pid", "xid", "app", "db", "lvl", "msg")

    def __init__(self, idx, ts, pid, xid, app, db, lvl, msg):
        self.idx, self.ts, self.pid, self.xid = idx, ts, pid, xid
        self.app, self.db, self.lvl, self.msg = app, db, lvl, msg


def _ts_us(s):
    d = datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
    return int(d.timestamp() * 1_000_000)


def read_text_any(path):
    path = pathlib.Path(path)
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.read()
    return path.read_text(errors="replace")


def parse_pglog(text):
    ents = []
    for raw in text.splitlines():
        for line in GLUE.split(raw):
            m = LINE.match(line)
            if m:
                ents.append(Ent(len(ents), _ts_us(m.group(1)), int(m.group(2)), int(m.group(3)),
                                m.group(4), m.group(5), m.group(6), m.group(7)))
            elif ents:  # continuation line of a multi-line statement
                ents[-1].msg += "\n" + line
    return ents


def filter_log(raw, trace_events):
    """Keeps the entries of the databases of the trace's calls (and nothing of other tests),
    with every long token-like run scrubbed. Parameters are not logged at all (the service is
    configured with log_parameter_max_length = 0)."""
    dbs = {e["database"] for e in trace_events if e.get("ev") == "server_ids"}
    keep = False
    out = []
    for rawline in raw.splitlines():
        for line in GLUE.split(rawline):
            m = LINE.match(line)
            if m:
                keep = m.group(5) in dbs
                if keep:
                    head = line[: m.start(7)]
                    out.append(head + re.sub(r"[A-Za-z0-9_=.\-]{32,}", "<redacted>", m.group(7)))
            elif keep:
                out.append(re.sub(r"[A-Za-z0-9_=.\-]{32,}", "<redacted>", line))
    return "\n".join(out) + ("\n" if out else "")


class Stmt:
    def __init__(self, pid, kind, name, text, xid, idx, ts):
        self.pid, self.kind, self.name, self.text = pid, kind, name, text
        self.xid = xid  # transaction id shown when the statement began (0: none yet)
        self.first_idx, self.first_ts = idx, ts
        self.parse_end = self.bind_end = None  # (idx, ts, dur_ms)
        self.exec_start = None  # (idx, ts)
        self.end = None  # (idx, ts, dur_ms): the statement finished
        self.waits = []  # {kind: still|acq, rel, mode, idx, ts, after_ms, holders: [pid]}

    def tables_in(self, tables):
        return [t for t in tables if re.search(r"\b%s\b" % re.escape(t), self.text)]


def build_statements(scope):
    """Per backend pid, the statements in log order, with their phases and lock waits."""
    by_name = {}
    simple_open = {}
    exec_open = {}
    buf = defaultdict(list)
    stmts = []
    last_wait = {}

    def attach(st, pid):
        st.waits.extend(buf.pop(pid, []))

    for e in scope:
        m, pid = e.msg, e.pid
        if e.lvl == "DETAIL":
            h = HOLD.match(m)
            if h and pid in last_wait:
                last_wait[pid]["holders"] = [int(x) for x in re.findall(r"\d+", h.group(1))]
                last_wait[pid]["queue"] = [int(x) for x in re.findall(r"\d+", h.group(2))]
            continue
        if e.lvl != "LOG":
            continue
        w = WAIT.match(m)
        if w:
            wd = {"kind": "still" if w.group(2).startswith("still") else "acq", "mode": w.group(3),
                  "rel": int(w.group(4)), "db": int(w.group(5)), "idx": e.idx, "ts": e.ts,
                  "after_ms": float(w.group(6)), "holders": [], "queue": []}
            last_wait[pid] = wd
            tgt = exec_open.get(pid) or simple_open.get(pid)
            (tgt.waits if tgt else buf[pid]).append(wd)
            continue
        if m.startswith("statement: "):
            st = Stmt(pid, "simple", "", m[len("statement: "):].strip(), e.xid, e.idx, e.ts)
            simple_open[pid] = st
            stmts.append(st)
            continue
        if m.startswith("execute "):
            name, _, text = m[len("execute "):].partition(": ")
            st = by_name.get((pid, name))
            if st is None:
                st = Stmt(pid, "ext", name, text.strip(), e.xid, e.idx, e.ts)
                by_name[(pid, name)] = st
                stmts.append(st)
            st.exec_start = (e.idx, e.ts)
            exec_open[pid] = st
            continue
        d = DUR_ONLY.match(m)
        if d:
            dur = float(d.group(1))
            st = exec_open.pop(pid, None) or simple_open.pop(pid, None)
            if st is not None:
                st.end = (e.idx, e.ts, dur)
            simple_open.pop(pid, None)
            continue
        d = DUR_TEXT.match(m)
        if d:
            dur, phase, name, text = float(d.group(1)), d.group(2), d.group(3), d.group(4).strip()
            if phase in ("parse", "bind"):
                st = by_name.get((pid, name))
                if st is None:
                    st = Stmt(pid, "ext", name, text, e.xid, e.idx, e.ts - int(dur * 1000))
                    by_name[(pid, name)] = st
                    stmts.append(st)
                st.first_idx = min(st.first_idx, e.idx)
                if phase == "parse":
                    st.parse_end = (e.idx, e.ts, dur)
                    st.first_ts = min(st.first_ts, e.ts - int(dur * 1000))
                else:
                    st.bind_end = (e.idx, e.ts, dur)
                attach(st, pid)
            elif phase == "statement":  # 'duration: .. statement: ..' (statement logged at its end)
                st = Stmt(pid, "simple", "", text, e.xid, e.idx, e.ts - int(dur * 1000))
                st.end = (e.idx, e.ts, dur)
                stmts.append(st)
    return stmts


def _ms(a, b):
    return (a - b) / 1000.0


def _marker(ents, kind, cid):
    want = "statement: SELECT 'diag:%s:%s'" % (kind, cid)
    return next((e for e in ents if e.msg.startswith(want)), None)


def analyze_call(ents, cid, ids, att, tgt, endev, startev):
    """-> dict with the timeline facts and the direct verdict, from the server log only."""
    r = {"call_id": cid, "verdict": "unknown", "reason": "", "reads": [], "service": [], "facts": {}}
    if ids is None:
        r["reason"] = "no server_ids event in the trace"
        return r
    s_mark = _marker(ents, "call_start", cid)
    e_mark = _marker(ents, "response", cid)
    if not s_mark or not e_mark:
        r["reason"] = "the call_start/response marker is not in the server log (%s)" % (
            "start missing" if not s_mark else "response missing")
        return r
    db = s_mark.db
    helper = s_mark.pid
    # The attacker may still be running when the call returns (it then commits AFTER the
    # response); the helper joins it and then drops the slowing trigger, which ends the scope.
    end_idx = next((e.idx for e in ents if e.idx > e_mark.idx and e.pid == helper
                    and e.msg.startswith("statement: DROP TRIGGER IF EXISTS atk_slow")), ents[-1].idx if ents else 0)
    scope = [e for e in ents if s_mark.idx <= e.idx <= end_idx and e.db == db]
    stmts = build_statements(scope)
    tables = list(startev.get("tables", [])) if startev else []
    oid2t = {v: k for k, v in ids.get("relation_oids", {}).items()}
    offset = ids.get("clock_offset_us", 0)
    apid = (att or {}).get("pid")
    for e in scope:
        if e.app == "diag-attacker-" + cid:
            apid = e.pid
            break
    mon = ids.get("monitor_pid")
    # ---- the attacker ----
    ast = [s for s in stmts if s.pid == apid]
    locks = [s for s in ast if s.text.upper().startswith("LOCK TABLE")]  # one, or two with the forced-gap self-test
    lock = locks[0] if locks else None
    attack = next((s for s in ast if s.text.startswith("SET LOCAL session_replication_role")), None)
    acommit = next((s for s in ast if s.text.upper() == "COMMIT"), None)
    facts = r["facts"]
    if not lock or not acommit or not all(x.end for x in locks) or not acommit.end:
        r["reason"] = "the attacker's LOCK TABLE / COMMIT is not in the server log"
        return r
    grants = {}
    for w in [w for x in locks for w in x.waits]:
        t = oid2t.get(w["rel"], "oid%d" % w["rel"])
        g = grants.setdefault(t, {})
        if w["kind"] == "still":
            g["wait_since"] = (w["idx"], w["ts"])
            g["holders"] = w["holders"]
        else:
            g["acquired"] = (w["idx"], w["ts"])
            g["after_ms"] = w["after_ms"]
    facts["attacker"] = {
        "pid": apid, "lock_stmt": (lock.first_idx, lock.first_ts), "lock_end": locks[-1].end[:2], "grants": grants,
        "attack": (attack.first_idx, attack.first_ts, attack.end[:2] if attack and attack.end else None) if attack else None,
        "commit": (acommit.first_idx, acommit.first_ts, acommit.end[:2]),
    }
    atables = []
    if attack:
        atables = sorted(set(re.findall(r"(?:UPDATE|DELETE FROM|INSERT INTO)\s+(\w+)", attack.text, re.I)))
    facts["attack_tables"] = atables
    # ---- the target commit ----
    skip = {helper, apid, mon}
    svc = [s for s in stmts if s.pid not in skip]
    txid = (tgt or {}).get("target_xid")
    cands = [s for s in svc if s.kind == "simple" and s.text.upper() == "COMMIT" and s.xid
             and (txid is None or s.xid == txid)]
    tcommit = None
    src = "log: service COMMIT with the target's xid %s" % txid
    if txid is not None:
        tcommit = cands[0] if cands else None
    elif cands:
        before = [c for c in cands if c.first_idx < locks[-1].end[0]]
        tcommit = (before or cands)[-1]
        src = "log: last service COMMIT with an xid before the attacker's lock (target xid unknown)"
    if tcommit is None or not tcommit.end:
        r["reason"] = "the target's COMMIT is not in the server log (xid %s)" % txid
        return r
    facts["target_commit"] = {"pid": tcommit.pid, "xid": tcommit.xid, "idx": tcommit.first_idx,
                              "ts": tcommit.first_ts, "end": tcommit.end[:2], "source": src}
    facts["response"] = {"idx": e_mark.idx, "ts": e_mark.ts}
    facts["call_start"] = {"idx": s_mark.idx, "ts": s_mark.ts}
    # ---- the service after the commit ----
    post = sorted((s for s in svc if s.first_idx > tcommit.first_idx), key=lambda s: s.first_idx)
    reads = []
    a_commit_start, a_commit_end = acommit.first_idx, acommit.end[0]
    for s in post:
        if s.exec_start is None or s.exec_start[0] > e_mark.idx or not s.text.lstrip().upper().startswith("SELECT"):
            continue
        hit = s.tables_in(tables)
        if not hit:
            continue
        t = hit[0]
        ws = [w for w in s.waits if oid2t.get(w["rel"]) == t]
        acq = next((w for w in ws if w["kind"] == "acq"), None)
        still = next((w for w in ws if w["kind"] == "still"), None)
        rd = {"pid": s.pid, "table": t, "tables": hit, "text": re.sub(r"\s+", " ", s.text)[:90],
              "exec_start": s.exec_start, "exec_end": s.end[:2] if s.end else None,
              "wait_since": (still["idx"], still["ts"]) if still else None,
              "acquired": (acq["idx"], acq["ts"]) if acq else None,
              "blocked_ms": acq["after_ms"] if acq else None,
              "holders": still["holders"] if still else []}
        if ws:
            if acq is None:
                rd["state"] = "wait_unfinished"
            elif acq["idx"] > a_commit_start:
                rd["state"] = "post_attack_blocked"
            else:
                rd["state"] = "blocked_other"
        elif s.end and s.end[0] < a_commit_start:
            rd["state"] = "pre_attack_unblocked"
            g = grants.get(t, {}).get("acquired")
            rd["before_attacker_lock_grant"] = (s.end[0] < g[0]) if g else None  # exact grant known only if it waited
            rd["before_lock_stmt_end"] = s.end[0] < locks[-1].end[0]
        elif s.exec_start[0] > a_commit_end:
            rd["state"] = "post_attack_unblocked"
        else:
            rd["state"] = "indeterminate"
        reads.append(rd)
    r["reads"] = reads
    r["service"] = [{"pid": s.pid, "kind": s.kind, "text": re.sub(r"\s+", " ", s.text)[:70], "idx": s.first_idx,
                     "ts": s.first_ts, "xid": s.xid, "end": s.end[:2] if s.end else None,
                     "waits": [(w["kind"], oid2t.get(w["rel"], w["rel"]), w["after_ms"], w["ts"]) for w in s.waits],
                     "wait_rows": [(w["idx"], w["ts"], "service pid %d %s %s on %s%s" % (
                         s.pid, "WAITS for" if w["kind"] == "still" else "ACQUIRED", w["mode"], oid2t.get(w["rel"], w["rel"]),
                         (" (holder pids %s)" % w["holders"]) if w["kind"] == "still" else " after %.1f ms" % w["after_ms"]))
                         for w in s.waits]}
                    for s in post if s.first_idx <= e_mark.idx]
    # ---- cross-check with the in-test clocks (server clock = client wall + offset) ----
    xc = {}
    if endev:
        xc["response_marker_minus_client_call_end_ms"] = round(_ms(e_mark.ts, endev["wall_us"] + offset), 3)
    if att and att.get("commit_wall_us"):
        xc["client_commit_returned_minus_server_commit_end_ms"] = round(_ms(att["commit_wall_us"] + offset, acommit.end[1]), 3)
    if startev:
        xc["client_call_start_minus_server_marker_ms"] = round(_ms(startev["wall_us"] + offset, s_mark.ts), 3)
    xc["clock_offset_us"] = offset
    xc["clock_rtt_us"] = ids.get("clock_rtt_us")
    r["xcheck"] = xc
    # ---- the verdict, from the log only ----
    st = [x["state"] for x in reads]
    resp = e_mark.idx
    if a_commit_end > resp:
        r["verdict"], r["reason"] = "attack_after_response", "the attacker's COMMIT finished after the response marker"
    elif not reads:
        r["verdict"], r["reason"] = "unknown", "the service ran no post-commit read of the call's tables"
    elif any(x in ("wait_unfinished", "blocked_other", "indeterminate") for x in st):
        r["verdict"], r["reason"] = "unknown", "a read does not fit the cases: " + ",".join(sorted(set(st)))
    else:
        pre = [x for x in reads if x["state"] == "pre_attack_unblocked"]
        post_r = [x for x in reads if x["state"].startswith("post_attack")]
        if pre and post_r:
            later = [q for q in post_r if any(q["exec_start"][0] > p["exec_start"][0] for p in pre)]
            r["verdict"] = "tore"
            r["reason"] = ("a read of %s ran before the attacker's lock on it and a later read of %s ran after the attack"
                           % (",".join(sorted({p["table"] for p in pre})), ",".join(sorted({q["table"] for q in later or post_r}))))
        elif pre:
            r["verdict"] = "attack_after_all_reads"
            r["reason"] = "every post-commit read ran before the attacker's lock on its table; the attacker committed before the response"
        else:
            r["verdict"] = "window_ok"
            r["reason"] = "every post-commit read ran after the attacker's COMMIT (blocked on its lock or later)"
    r["tables_not_read_after_commit"] = [t for t in tables if t not in {x["table"] for x in reads}]
    return r


def render_timeline(r, startev=None):
    f = r["facts"]
    out = ["  call %s  direct verdict: %s -- %s" % (r["call_id"], r["verdict"], r["reason"])]
    if "target_commit" not in f or "attacker" not in f:
        return "\n".join(out)
    t0 = f["target_commit"]["ts"]
    ev = []
    a = f["attacker"]
    tc = f["target_commit"]
    ev.append((tc["idx"], tc["ts"], "service pid %d COMMIT of the target transaction (xid %s) [read-before-this are pre-commit]" % (tc["pid"], tc["xid"])))
    ev.append((a["lock_stmt"][0], a["lock_stmt"][1], "attacker pid %d: LOCK TABLE sent" % a["pid"]))
    for t, g in sorted(a["grants"].items(), key=lambda kv: kv[1].get("acquired", (10**12, 0))[0]):
        if "wait_since" in g:
            ev.append((g["wait_since"][0], g["wait_since"][1], "attacker waits for AccessExclusiveLock on %s (holder pids %s)" % (t, g.get("holders"))))
        if "acquired" in g:
            ev.append((g["acquired"][0], g["acquired"][1], "attacker ACQUIRED AccessExclusiveLock on %s after %.1f ms (logged: it had to wait)" % (t, g["after_ms"])))
    ev.append((a["lock_end"][0], a["lock_end"][1], "attacker LOCK TABLE finished (every table granted; tables not listed above were granted without waiting, at or before this line)"))
    if a["attack"]:
        ev.append((a["attack"][0], a["attack"][1], "attacker attack statement sent (%s)" % ",".join(f.get("attack_tables", []))))
        if a["attack"][2]:
            ev.append((a["attack"][2][0], a["attack"][2][1], "attack statement finished"))
    ev.append((a["commit"][0], a["commit"][1], "attacker COMMIT sent"))
    ev.append((a["commit"][2][0], a["commit"][2][1], "attacker COMMIT finished [MUTATION COMMIT TIME]"))
    ev.append((f["response"]["idx"], f["response"]["ts"], "response marker (helper, the instant the call returned) [ACKNOWLEDGMENT TIME]"))
    for s in r["service"]:
        w = ""
        if s["waits"]:
            acq = [x for x in s["waits"] if x[0] == "acq"]
            w = "  BLOCKED on %s%s" % (",".join(sorted({str(x[1]) for x in s["waits"]})),
                                         (" for %.1f ms, lock acquired at +%.1f ms" % (acq[0][2], _ms(acq[0][3], t0))) if acq else " (never acquired)")
        ev.append((s["idx"], s["ts"], "service pid %d %s%s%s" % (
            s["pid"], "statement (parse end)" if s["kind"] == "ext" else "simple statement",
            ": " + s["text"] if s["text"] else ": (empty query: connection validity check)", w)))
        shown = set()
        for wk in s.get("wait_rows", []):
            key = wk[2].split(" (holder")[0] if "WAITS" in wk[2] else wk[2]
            if key not in shown:  # the server repeats 'still waiting' while a wait goes on
                shown.add(key)
                ev.append(wk)
    for x in r["reads"]:
        ev.append((x["exec_start"][0], x["exec_start"][1], "  -> READ of %s executed [%s]%s" % (x["table"], x["state"],
                   "" if x.get("before_lock_stmt_end") is None else " (before the attacker's LOCK TABLE finished: %s)" % x["before_lock_stmt_end"])))
    ev.sort(key=lambda e: (e[0], e[1]))
    seen = set()
    for idx, ts, label in ev:
        if (idx, label) in seen:
            continue
        seen.add((idx, label))
        out.append("    +%9.3f ms  #%-6d %s" % (_ms(ts, t0), idx, label))
    out.append("    cross-check with the in-test clocks: " + json.dumps(r.get("xcheck", {})))
    if r.get("tables_not_read_after_commit"):
        out.append("    tables with NO post-commit read by the service: %s" % r["tables_not_read_after_commit"])
    return "\n".join(out)


def direct_for_run(d, run):
    """-> {call_id: result} for a traced run that has a server log, or {}"""
    pg = run.get("pglog")
    if not pg or not (d / pg).exists() or not run.get("trace"):
        return {}
    ents = parse_pglog(read_text_any(d / pg))
    evs = read_jsonl(d / run["trace"])
    by = defaultdict(dict)
    for e in evs:
        if e.get("ev") in ("server_ids", "attacker", "target", "call_start", "call_end", "verdict"):
            by[e.get("call_id")][e["ev"]] = e
    res = {}
    for cid, g in by.items():
        r = analyze_call(ents, cid, g.get("server_ids"), g.get("attacker"), g.get("target"), g.get("call_end"), g.get("call_start"))
        r["test"] = (g.get("call_start") or {}).get("test", "")
        r["old_verdict"] = (g.get("verdict") or {}).get("verdict")
        r["old_reason"] = (g.get("verdict") or {}).get("reason", "")
        r["lock_gap_suspected"] = (g.get("target") or {}).get("lock_gap_suspected")
        r["tables"] = (g.get("call_start") or {}).get("tables")
        res[cid] = r
    return res


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "--filter-log":
        sys.stdout.write(filter_log(sys.stdin.read(), read_jsonl(sys.argv[2])))
        return 0
    if len(sys.argv) >= 4 and sys.argv[1] == "--timeline-of":
        ents = parse_pglog(read_text_any(sys.argv[2]))
        by = defaultdict(dict)
        for e in read_jsonl(sys.argv[3]):
            if e.get("ev") in ("server_ids", "attacker", "target", "call_start", "call_end"):
                by[e.get("call_id")][e["ev"]] = e
        for cid, g in by.items():
            r = analyze_call(ents, cid, g.get("server_ids"), g.get("attacker"), g.get("target"), g.get("call_end"), g.get("call_start"))
            print(render_timeline(r))
        return 0
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    detail = "--detail" in sys.argv
    timelines = "--timelines" in sys.argv
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
    # ---- direct chronology (only when the runs carry a server log) ----
    failed_by_run = {(r["id"], n) for r, n, outcome, *_ in rows if outcome == "FAIL"}
    directs = []  # (run, result)
    for r in runs:
        if r["variant"] == "traced" and r.get("pglog"):
            for cid, res in direct_for_run(d, r).items():
                res["failed"] = (r["id"], res["test"]) in failed_by_run
                directs.append((r, res))
    if not directs:
        return 0
    print("\n" + "=" * 100)
    print("DIRECT CHRONOLOGY from the PostgreSQL server log (verdict computed from log timestamps only)")
    print("=" * 100)
    cnt = Counter((res["test"], res["verdict"]) for _, res in directs)
    print("direct verdict per test, all instrumented in_window calls with a server log:")
    for (t, v), c in sorted(cnt.items()):
        print(f"  {t[:60]:60} {v:24} {c}")
    cross = Counter((res["old_verdict"], res["verdict"], res["failed"]) for _, res in directs)
    print("\nprevious (inferred) verdict  x  direct verdict  x  test failed:")
    for (o, v, f), c in sorted(cross.items(), key=lambda kv: (str(kv[0][0]), kv[0][1], kv[0][2])):
        print(f"  old={str(o):22} direct={v:24} failed={f!s:5} {c}")
    # the inference: 'the service's read of the LAST table of LOCK TABLE a, b ran before the attacker held it'
    inferred = [(r, x) for r, x in directs if x["old_verdict"] == "attack_missed" and x.get("lock_gap_suspected") is True]
    print(f"\nINFERENCE CHECK: calls the old rule called attack_missed through the lock-gap rule: {len(inferred)}")
    conf = refut = unk = 0
    for r, x in inferred:
        last = (x.get("tables") or [""])[-1]
        pre_last = any(q["table"] == last and q["state"] == "pre_attack_unblocked" for q in x["reads"])
        if x["verdict"] in ("tore", "attack_after_all_reads", "attack_after_response") and pre_last:
            conf += 1
        elif x["verdict"] == "unknown":
            unk += 1
        else:
            refut += 1
    print(f"  confirmed by the log (a read of the last-locked table ran unblocked, before the attacker's lock on it): {conf}")
    print(f"  refuted (the log shows every read after the attack): {refut}   not decidable from the log: {unk}")
    show = [(r, x) for r, x in directs if timelines or x["failed"] or x["verdict"] != "window_ok" or x["old_verdict"] != "window_ok"]
    print(f"\nTIMELINES ({len(show)} calls: failed runs and every call whose direct or previous verdict is not window_ok; --timelines for all):")
    for r, x in show:
        print(f"\n[{r['id']}] test {x['test']}  run-failed={x['failed']}  old verdict={x['old_verdict']}")
        print(render_timeline(x))
        for q in x["reads"]:
            print(f"      read {q['table']:16} pid {q['pid']} exec@#{q['exec_start'][0]} state={q['state']} blocked_ms={q['blocked_ms']} {q['text'][:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
