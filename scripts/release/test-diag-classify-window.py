#!/usr/bin/env python3
"""Self-test of the direct-chronology classifier in diag-classify-window.py (stdlib only).

Builds small synthetic PostgreSQL server logs in the format diag-tests.sh configures
('%m [%p] x=%x a=%a d=%d ', log_statement=all, log_min_duration_statement=0, log_lock_waits=on)
for the cases the classifier distinguishes and checks the verdict computed from the log alone:

  window_ok               the service's reads of both tables are blocked behind the attacker
  tore                    the read of the second table ran before the attacker locked it
  attack_after_all_reads  both reads ran before the attacker's locks, the attacker committed
                          before the response
  attack_after_response   the attacker committed after the response
  unknown                 no post-commit read
"""
import importlib.util
import pathlib
import sys

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("dcw", here / "diag-classify-window.py")
dcw = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(dcw)

CID, DB = "1-0-1", "enc_test_db"
HELPER, ATT, SVC = 10, 20, 30
OID = {"privacy_entries": 100, "privacy_ledgers": 200}


class Log:
    def __init__(self):
        self.lines, self.t = [], 0

    def add(self, pid, x, app, msg, dt=1, lvl="LOG"):
        self.t += dt
        ms = self.t
        self.lines.append(
            "2026-10-17 09:00:%02d.%03d UTC [%d] x=%d a=%s d=%s %s:  %s" % (ms // 1000, ms % 1000, pid, x, app, DB, lvl, msg)
        )

    def svc_read(self, table, name, blocked_by_attacker_commit=None):
        """a service read; blocked: wait lines first (they precede the end of its parse)."""
        text = "SELECT x FROM %s WHERE asset_id = $1" % table
        if blocked_by_attacker_commit:
            self.add(SVC, 0, "[unknown]", "process %d still waiting for AccessShareLock on relation %d of database 1 after 1.1 ms" % (SVC, OID[table]))
            self.add(SVC, 0, "[unknown]", "Process holding the lock: %d. Wait queue: %d." % (ATT, SVC), lvl="DETAIL")
            blocked_by_attacker_commit()
            self.add(SVC, 0, "[unknown]", "process %d acquired AccessShareLock on relation %d of database 1 after 50.0 ms" % (SVC, OID[table]))
        self.add(SVC, 0, "[unknown]", "duration: 0.1 ms  parse %s: %s" % (name, text))
        self.add(SVC, 0, "[unknown]", "duration: 0.1 ms  bind %s: %s" % (name, text))
        self.add(SVC, 0, "[unknown]", "execute %s: %s" % (name, text))
        self.add(SVC, 0, "[unknown]", "duration: 0.1 ms")

    def attacker_commit(self):
        a = "diag-attacker-" + CID
        self.add(ATT, 5, a, "statement: SET LOCAL session_replication_role = replica; UPDATE privacy_ledgers SET g = 1")
        self.add(ATT, 5, a, "duration: 0.5 ms")
        self.add(ATT, 5, a, "statement: COMMIT")
        self.add(ATT, 0, a, "duration: 0.1 ms")


def scenario(kind):
    g = Log()
    h = "diag-helper-" + CID
    a = "diag-attacker-" + CID
    g.add(HELPER, 0, h, "statement: SELECT 'diag:call_start:%s'" % CID)
    g.add(ATT, 0, a, "statement: LOCK TABLE privacy_entries, privacy_ledgers IN ACCESS EXCLUSIVE MODE")
    g.add(ATT, 5, a, "process %d still waiting for AccessExclusiveLock on relation 100 of database 1 after 1.0 ms" % ATT)
    g.add(ATT, 5, a, "Process holding the lock: %d. Wait queue: %d." % (SVC, ATT), lvl="DETAIL")
    g.add(SVC, 4, "[unknown]", "statement: COMMIT", dt=100)
    g.add(SVC, 0, "[unknown]", "duration: 0.1 ms")
    g.add(ATT, 5, a, "process %d acquired AccessExclusiveLock on relation 100 of database 1 after 100.0 ms" % ATT)
    if kind == "window_ok":
        g.add(ATT, 5, a, "duration: 100.0 ms")  # ledgers granted straight after entries
        g.svc_read("privacy_ledgers", "s1", g.attacker_commit)
        g.svc_read("privacy_entries", "s2")
    elif kind == "tore":
        g.svc_read("privacy_ledgers", "s1")  # unblocked: the attacker has not asked for ledgers yet
        g.add(ATT, 5, a, "duration: 100.0 ms", dt=5)
        g.svc_read("privacy_entries", "s2", g.attacker_commit)
    elif kind == "attack_after_all_reads":
        g.svc_read("privacy_ledgers", "s1")
        g.svc_read("privacy_entries", "s2")
        g.add(ATT, 5, a, "duration: 100.0 ms", dt=5)
        g.attacker_commit()
    elif kind == "attack_after_response":
        g.svc_read("privacy_ledgers", "s1")
        g.svc_read("privacy_entries", "s2")
    elif kind == "unknown":
        g.add(ATT, 5, a, "duration: 100.0 ms")
        g.attacker_commit()
    g.add(HELPER, 0, h, "statement: SELECT 'diag:response:%s'" % CID, dt=3)
    if kind == "attack_after_response":
        g.add(ATT, 5, a, "duration: 100.0 ms", dt=5)
        g.attacker_commit()
    g.add(HELPER, 0, h, "statement: DROP TRIGGER IF EXISTS atk_slow ON audit_events", dt=2)
    return "\n".join(g.lines) + "\n"


ids = {"relation_oids": OID, "clock_offset_us": 0, "monitor_pid": 11}
start = {"tables": ["privacy_entries", "privacy_ledgers"], "wall_us": 0, "test": "t"}
target = {"target_xid": 4}
att = {"pid": ATT}

bad = 0
for kind in ["window_ok", "tore", "attack_after_all_reads", "attack_after_response", "unknown"]:
    ents = dcw.parse_pglog(scenario(kind))
    r = dcw.analyze_call(ents, CID, ids, att, target, None, start)
    ok = r["verdict"] == kind
    print("%-24s -> %-24s %s" % (kind, r["verdict"], "ok" if ok else "FAIL: " + r["reason"]))
    if not ok:
        bad += 1
        print(dcw.render_timeline(r))
# a glued line (two processes writing into one line) is split
glued = "2026-10-17 09:00:00.001 UTC [1] x=0 a=b d=db LOG:  duration: 0.035 ms 2026-10-17 09:00:00.002 UTC [69] x=0 a= d= LOG:  checkpoint starting: immediate\n"
e = dcw.parse_pglog(glued)
if [x.msg for x in e] != ["duration: 0.035 ms", "checkpoint starting: immediate"]:
    print("FAIL: glued line", [x.msg for x in e])
    bad += 1
# the log filter keeps only the databases of the trace and scrubs long token-like runs
raw = (
    "2026-10-17 09:00:00.001 UTC [1] x=0 a=b d=%s LOG:  statement: SELECT '%s'\n"
    "2026-10-17 09:00:00.002 UTC [2] x=0 a=b d=other LOG:  statement: SELECT 2\n" % (DB, "k" * 40)
)
out = dcw.filter_log(raw, [{"ev": "server_ids", "database": DB}])
if "other" in out or "k" * 40 in out or "<redacted>" not in out:
    print("FAIL: filter", out)
    bad += 1
sys.exit(1 if bad else 0)
