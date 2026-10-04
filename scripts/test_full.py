#!/usr/bin/env python3
"""The full test run (scripts/test-full.sh): precheck, run, verify.

Everything that decides what must run is data in the manifest
(scripts/test-manifest.json). This file only knows how to check a
dependency, run a command, read cargo's output (or, for a command that is not
cargo test, the marker and count lines its suite declares), and compare the
two. It never reports success for a suite it did not see run.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "scripts" / "test-manifest.json"
LABELS = {
    "postgres": "PostgreSQL",
    "openbao": "OpenBao",
    "openfhe": "OpenFHE",
    "migrations": "Migrations",
    "tfhe": "TFHE-rs research",
    "gcp": "Google Cloud",
}
ORDER = ["postgres", "openbao", "openfhe", "migrations", "tfhe", "gcp"]


# --- Dependencies ----------------------------------------------------------------


def tcp_reachable(url, default_port):
    u = urlparse(url)
    host, port = u.hostname, u.port or default_port
    if not host:
        return False, "not a URL: " + url
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError as e:
        return False, "cannot reach %s:%s (%s)" % (host, port, e)
    return True, ""


def example(name, arg, env):
    """Runs the control plane's readiness probe (an example, never shipped)."""
    p = subprocess.run(
        ["cargo", "run", "-q", "-p", "encompute-control", "--example", name, "--", arg],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=1800,
    )
    out = (p.stdout.strip().splitlines() or [p.stderr.strip()[-300:]])[-1]
    return p.returncode == 0, out


def check_postgres(env):
    url = env.get("ENCOMPUTE_TEST_DATABASE_URL")
    if not url:
        return False, "ENCOMPUTE_TEST_DATABASE_URL is not set"
    ok, why = tcp_reachable(url, 5432)
    if not ok:
        return False, why
    return example("testenv", "postgres", env)


def check_migrations(env, postgres_ok):
    if not postgres_ok:
        return False, "needs PostgreSQL"
    return example("testenv", "migrations", env)


def check_openbao(env):
    addr, token = env.get("ENCOMPUTE_TEST_BAO_ADDR"), env.get("ENCOMPUTE_TEST_BAO_TOKEN")
    if not addr or not token:
        return False, "ENCOMPUTE_TEST_BAO_ADDR and ENCOMPUTE_TEST_BAO_TOKEN must be set"
    try:
        r = urllib.request.urlopen(addr.rstrip("/") + "/v1/sys/health", timeout=5)
        if r.status != 200:
            return False, "health check answered %s" % r.status
        req = urllib.request.Request(
            addr.rstrip("/") + "/v1/auth/token/lookup-self", headers={"X-Vault-Token": token}
        )
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:  # urllib raises many things; all mean "not usable"
        return False, "cannot use %s (%s)" % (addr, e)
    return True, "%s answers; the token is valid" % addr


def check_openfhe(env):
    root = Path(env.get("OPENFHE_ROOT") or ROOT / ".deps" / "openfhe")
    need = [root / "include/openfhe/pke/openfhe.h", root / "lib/libOPENFHEpke_static.a"]
    missing = [str(p) for p in need if not p.exists()]
    if missing:
        return False, "not installed at %s (scripts/install-openfhe.sh or OPENFHE_ROOT)" % root
    env["OPENFHE_ROOT"] = str(root)
    return True, str(root)


def check_tfhe(env):
    if env.get("ENCOMPUTE_TFHE"):
        return True, "ENCOMPUTE_TFHE is set"
    return False, "ENCOMPUTE_TFHE is not set"


def check_gcp(env):
    ok = env.get("ENCOMPUTE_GCP_PROJECT") and env.get("ENCOMPUTE_BROKER_URL")
    if ok and subprocess.run(["which", "gcloud"], capture_output=True).returncode == 0:
        return True, "project %s" % env["ENCOMPUTE_GCP_PROJECT"]
    return False, "no GCP environment (ENCOMPUTE_GCP_PROJECT, ENCOMPUTE_BROKER_URL, gcloud)"


def precheck(deps, env):
    """{dependency: (ok, detail)} for the dependencies in `deps`."""
    out = {}
    wanted = set(deps)
    if "migrations" in wanted:
        wanted.add("postgres")
    for d in ORDER:
        if d not in wanted:
            continue
        if d == "postgres":
            out[d] = check_postgres(env)
        elif d == "openbao":
            out[d] = check_openbao(env)
        elif d == "openfhe":
            out[d] = check_openfhe(env)
        elif d == "migrations":
            out[d] = check_migrations(env, out["postgres"][0])
        elif d == "tfhe":
            out[d] = check_tfhe(env)
        elif d == "gcp":
            out[d] = check_gcp(env)
    return out


# --- Manifest --------------------------------------------------------------------


def read_manifest(path, chain=()):
    """The manifest at `path` with the one it "extends" merged under it.

    A run or suite with the id or name of one in the base is merged onto it
    field by field (so it can raise a minimum without repeating the command);
    any other is added. Nothing can be removed, and a minimum may only go up.
    """
    path = Path(path).resolve()
    m = json.loads(path.read_text())
    files, errors = [path], []
    if not m.get("extends"):
        return m, files, errors
    base_path = (path.parent / m["extends"]).resolve()
    if base_path in chain or base_path == path:
        return m, files, ["extends loops back to %s" % base_path.name]
    base, bfiles, errors = read_manifest(base_path, chain + (path,))
    files += bfiles
    for key, ident in (("runs", "id"), ("suites", "name")):
        merged = {e[ident]: dict(e) for e in base.get(key, [])}
        for e in m.get(key, []):
            old = merged.get(e[ident])
            if old is not None:
                for k in ("min_tests", "min_db_backed"):
                    if k in e and e[k] < old.get(k, 0):
                        errors.append("%s %s lowers %s from %s to %s" % (key[:-1], e[ident], k, old[k], e[k]))
            merged[e[ident]] = {**(old or {}), **e}
        m[key] = list(merged.values())
    return m, files, errors


def load_manifest(path):
    m, files, errors = read_manifest(path)
    m["files"] = [str(f) for f in files]
    runs = {r["id"]: r for r in m.get("runs", [])}
    if len(runs) != len(m.get("runs", [])):
        errors.append("duplicate run ids")
    names = set()
    for r in runs.values():
        for d in r.get("needs", []) + [a["dep"] for a in r.get("allow_unavailable", [])]:
            if d not in LABELS:
                errors.append("run %s: unknown dependency %s" % (r["id"], d))
        if not isinstance(r.get("command"), list) or not r["command"]:
            errors.append("run %s: no command" % r["id"])
        if r.get("parser", "cargo") not in ("cargo", "lines"):
            errors.append("run %s: unknown parser %s" % (r["id"], r["parser"]))
    for s in m.get("suites", []):
        if s["name"] in names:
            errors.append("duplicate suite %s" % s["name"])
        names.add(s["name"])
        s.setdefault("target", s["name"])
        if s["run"] not in runs:
            errors.append("suite %s: unknown run %s" % (s["name"], s["run"]))
            continue
        if runs[s["run"]].get("parser") == "lines":
            for k in ("marker", "count"):
                if not s.get(k):
                    errors.append("suite %s: a lines suite needs a %s pattern" % (s["name"], k))
        if s.get("required", True):
            if s.get("min_tests", 0) < 1:
                errors.append("required suite %s needs min_tests >= 1" % s["name"])
            if runs[s["run"]].get("allow_unavailable"):
                errors.append("required suite %s is in a run that may be skipped" % s["name"])
    return m, runs, errors


# --- Running and reading cargo ----------------------------------------------------


def artifact_map(command, env, log):
    """executable path -> (package, target id), from cargo's own build output."""
    if command[0] != "cargo" or "test" not in command:
        return {}, True, ""
    i = command.index("test")
    cmd = command[: i + 1] + ["--no-run", "--message-format=json"] + command[i + 1 :]
    with open(log, "w") as out:
        p = subprocess.run(cmd, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=out, text=True)
    amap = {}
    for line in p.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        if j.get("reason") != "compiler-artifact" or not j.get("executable"):
            continue
        if not j.get("profile", {}).get("test"):
            continue
        pkg = Path(j["manifest_path"]).parent.name
        t = j["target"]
        kind = t["kind"][0]
        if kind == "test":
            ident = "%s/%s" % (pkg, t["name"])
        elif kind == "bin":
            ident = "%s/bin:%s" % (pkg, t["name"])
        else:
            ident = "%s/lib" % pkg
        amap[os.path.relpath(j["executable"], ROOT)] = ident
    tail = Path(log).read_text()[-1500:] if p.returncode else ""
    return amap, p.returncode == 0, tail


RUNNING = re.compile(r"^\s*Running .*\((\S+)\)\s*$")
DOCTEST = re.compile(r"^\s*Doc-tests (\S+)")
RESULT = re.compile(
    r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored"
)
IGNORED = re.compile(r"^test (\S+) \.\.\. ignored(?:, (.*))?$")


def parse_cargo(text, amap):
    """{suite id: {passed, failed, ignored, skips}} from cargo test output."""
    suites, cur = {}, None

    def section(ident):
        return suites.setdefault(
            ident, {"passed": 0, "failed": 0, "ignored": 0, "skips": [], "seen": 0}
        )

    named_ignored = {}
    for line in text.splitlines():
        m = RUNNING.match(line)
        if m:
            exe = m.group(1)
            ident = amap.get(exe) or "?/" + re.sub(r"-[0-9a-f]{8,}$", "", Path(exe).name)
            cur = section(ident)
            named_ignored[ident] = 0
            continue
        m = DOCTEST.match(line)
        if m:
            ident = "%s/doc" % m.group(1).replace("_", "-")
            cur = section(ident)
            named_ignored[ident] = 0
            continue
        if cur is None:
            continue
        m = RESULT.search(line)
        if m:
            cur["seen"] += 1
            cur["passed"] += int(m.group(2))
            cur["failed"] += int(m.group(3))
            cur["ignored"] += int(m.group(4))
            continue
        m = IGNORED.match(line)
        if m:
            cur["skips"].append("ignored: %s%s" % (m.group(1), " (%s)" % m.group(2) if m.group(2) else ""))
            continue
        if "SKIPPED" in line:
            cur["skips"].append(line.strip()[:200])
    for ident, s in suites.items():
        named = sum(1 for k in s["skips"] if k.startswith("ignored:"))
        if s["ignored"] > named:
            s["skips"].append("ignored: %d test(s) marked #[ignore]" % (s["ignored"] - named))
    return suites


def parse_lines(text, suites):
    """The same shape as parse_cargo, for a command that is not `cargo test`.

    Each suite declares regular expressions: `marker` (a line that must appear:
    the command's own verdict), `count` (one match per passing check), and
    optionally `fail` (a failing check) and `skip` (a skipped one). A suite
    whose marker never appears is as good as not run.
    """
    out = {}
    for s in suites:
        pats = {k: re.compile(s[k]) for k in ("marker", "count", "fail", "skip") if s.get(k)}
        sec = {"passed": 0, "failed": 0, "ignored": 0, "skips": [], "seen": 0}
        for line in text.splitlines():
            if "marker" in pats and pats["marker"].search(line):
                sec["seen"] = 1
            if "count" in pats and pats["count"].search(line):
                sec["passed"] += 1
            elif "fail" in pats and pats["fail"].search(line):
                sec["failed"] += 1
            if "skip" in pats and pats["skip"].search(line):
                sec["skips"].append(line.strip()[:200])
        out[s["target"]] = sec
    return out


def run_command(run, env, logdir, nocapture):
    cmd = list(run["command"])
    if cmd[0] == "cargo" and "test" in cmd:
        # Every suite reports, so one failure does not hide the rest.
        cmd.insert(cmd.index("test") + 1, "--no-fail-fast")
        if nocapture and run.get("nocapture", True):
            cmd += ["--", "--nocapture"]
    log = logdir / (run["id"] + ".log")
    t0 = time.time()
    # Output goes to a file, not a pipe: a server a test leaked must not hold
    # this runner open.
    with open(log, "w") as out:
        try:
            p = subprocess.run(
                cmd, cwd=ROOT, env=env, stdout=out, stderr=subprocess.STDOUT,
                timeout=run.get("timeout_s", 7200),
            )
            code = p.returncode
        except subprocess.TimeoutExpired:
            code = -1
            out.write("\nTIMED OUT\n")
    return code, time.time() - t0, log


def allowed(skip, rules):
    for r in rules:
        if r["match"] in skip:
            return r["reason"]
    return None


# --- Main ------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(prog="test-full.sh", add_help=True)
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--runs", help="comma-separated run ids (default: the manifest's defaults)")
    ap.add_argument("--mode", choices=["cold", "template"], default="cold")
    ap.add_argument("--release", action="store_true", help="refuse any mode but cold")
    ap.add_argument("--json", help="the machine-readable summary (default target/test-full/summary.json)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--no-nocapture", action="store_true", help="do not pass --nocapture to cargo")
    a = ap.parse_args()

    def fail(msg):
        print(msg)
        print("FULL TEST FAILED")
        sys.exit(1)

    try:
        m, runs, errors = load_manifest(a.manifest)
    except (OSError, ValueError, KeyError) as e:
        fail("MANIFEST UNREADABLE: %s" % e)
    if errors:
        fail("MANIFEST INVALID:\n  " + "\n  ".join(errors))
    if a.release and a.mode != "cold":
        fail("--release needs --mode cold: a template clone must never be release evidence")
    selected = [r for r in m["runs"] if (r["id"] in a.runs.split(",") if a.runs else r.get("default", True))]
    if a.runs:
        unknown = set(a.runs.split(",")) - set(runs)
        if unknown:
            fail("unknown run(s): %s" % ", ".join(sorted(unknown)))
    if not selected:
        fail("no runs selected")
    ids = {r["id"] for r in selected}
    suites = [s for s in m["suites"] if s["run"] in ids]
    if a.list:
        total_min = sum(r.get("min_tests", 0) for r in selected)
        for r in selected:
            print("run %-18s min %5d tests, %4d db-backed  needs %s" % (
                r["id"], r.get("min_tests", 0), r.get("min_db_backed", 0), ",".join(r.get("needs", [])) or "-"))
            print("    " + " ".join(r["command"]))
        for s in suites:
            print("  suite %-44s %-9s min %4d  %s" % (
                s["name"], "required" if s.get("required", True) else "optional", s.get("min_tests", 0), s["run"]))
        print("total minimum: %d" % total_min)
        return

    env = dict(os.environ)
    env["ENCOMPUTE_REQUIRE_SERVICES"] = "1"
    env["ENCOMPUTE_TEST_DB_MODE"] = a.mode
    env["CARGO_TERM_COLOR"] = "never"
    env.pop("NO_COLOR", None)
    logdir = ROOT / "target" / "test-full"
    logdir.mkdir(parents=True, exist_ok=True)
    t_start = time.time()

    manifest_rel = os.path.relpath(a.manifest, ROOT) if str(a.manifest).startswith(str(ROOT)) else a.manifest
    print("FULL TEST RUN  manifest %s  databases: %s" % (manifest_rel, a.mode))
    if a.mode != "cold":
        print("  (template mode: fast development databases, not release evidence)")
    print()

    # PRECHECK
    needed = []
    for r in selected:
        for d in r.get("needs", []):
            if d not in needed:
                needed.append(d)
    if any(d == "postgres" for d in needed) and "migrations" not in needed:
        needed.append("migrations")
    pre = precheck(needed, env)
    # A dependency only runs that may be skipped need is reported as such.
    soft = {d for d in pre if all(
        d in [x["dep"] for x in r.get("allow_unavailable", [])]
        for r in selected if d in r.get("needs", []))
        and any(d in r.get("needs", []) for r in selected)}
    print("PRECHECK")
    for d in ORDER:
        if d in pre:
            ok, detail = pre[d]
            status = "PASS" if ok else ("SKIPPED-ALLOWED" if d in soft else "FAIL")
            print("  %s %s  %s" % ((LABELS[d] + " ").ljust(22, "."), status, detail))
    print()

    failures, unexpected, problems = [], [], []
    results = {}      # suite name -> dict
    run_info = {}
    other_binaries = 0
    exec_log_total = 0

    # Which runs can run: every need must pass, unless the run allows it to be
    # unavailable (then it is skipped, and the skip is allowed).
    runnable, blocked = [], {}
    for r in selected:
        missing = [d for d in r.get("needs", []) if not pre[d][0]]
        if "postgres" in r.get("needs", []) and "migrations" in pre and not pre["migrations"][0] and pre["postgres"][0]:
            missing.append("migrations")
        if not missing:
            runnable.append(r)
            continue
        allow = {x["dep"]: x["reason"] for x in r.get("allow_unavailable", [])}
        if all(d in allow for d in missing):
            blocked[r["id"]] = ("allowed", "; ".join(allow[d] for d in missing))
        else:
            blocked[r["id"]] = ("fail", ", ".join(LABELS[d] for d in missing) + " unavailable")
    if any(v[0] == "fail" for v in blocked.values()):
        # Fail closed and fast: nothing else runs, so a missing service is
        # never buried under a long run that cannot be the release evidence.
        print("Required suites cannot run.")
        for r in runnable:
            blocked[r["id"]] = ("fail", "not started (a required dependency is unavailable)")
        runnable = []

    for r in runnable:
        print("running %s ..." % r["id"], flush=True)
        renv = dict(env)
        exec_log = tempfile.NamedTemporaryFile(prefix="exec-", suffix=".log", delete=False)
        exec_log.close()
        renv["ENCOMPUTE_TEST_EXEC_LOG"] = exec_log.name
        amap, built, tail = artifact_map(r["command"], renv, logdir / (r["id"] + ".build.log"))
        info = {"exit": None, "seconds": 0.0, "tests": 0, "db_backed": 0, "built": built}
        run_info[r["id"]] = info
        if not built:
            problems.append("run %s: the build failed (%s)" % (r["id"], logdir / (r["id"] + ".build.log")))
            info["build_tail"] = tail
            print("  build failed:\n" + "\n".join("    | " + l for l in tail.splitlines()[-12:]))
            os.unlink(exec_log.name)
            continue
        code, secs, log = run_command(r, renv, logdir, not a.no_nocapture)
        text = log.read_text(errors="replace")
        if r.get("parser", "cargo") == "lines":
            parsed = parse_lines(text, [s for s in suites if s["run"] == r["id"]])
        else:
            parsed = parse_cargo(text, amap)
        info.update(exit=code, seconds=round(secs, 1), tests=sum(s["passed"] for s in parsed.values()),
                    binaries={k: {"passed": v["passed"], "failed": v["failed"], "ignored": v["ignored"]}
                              for k, v in sorted(parsed.items())})
        info["db_backed"] = sum(1 for _ in open(exec_log.name)) if os.path.exists(exec_log.name) else 0
        os.unlink(exec_log.name)
        exec_log_total += info["db_backed"]
        if code != 0:
            problems.append("run %s exited %s (%s)" % (r["id"], code, log))
        if info["tests"] < r.get("min_tests", 0):
            problems.append("run %s ran %d tests, the manifest's minimum is %d" % (r["id"], info["tests"], r["min_tests"]))
        if info["db_backed"] < r.get("min_db_backed", 0):
            problems.append("run %s took %d databases, the minimum is %d (DB-backed tests returned early?)" % (
                r["id"], info["db_backed"], r["min_db_backed"]))
        listed = {s["name"]: s for s in suites if s["run"] == r["id"]}
        targets = {s["target"] for s in listed.values()}
        for ident, sec in parsed.items():
            if ident not in targets:
                other_binaries += 1
                for sk in sec["skips"]:
                    if not allowed(sk, r.get("allowed_skips", [])):
                        unexpected.append("%s: %s" % (ident, sk))
                if sec["failed"]:
                    problems.append("%s: %d test(s) failed" % (ident, sec["failed"]))
        for name, s in listed.items():
            sec = parsed.get(s["target"])
            res = {"run": r["id"], "target": s["target"], "required": s.get("required", True),
                   "min_tests": s.get("min_tests", 0), "tests": 0, "failed": 0, "skips": [], "allowed_skips": []}
            results[name] = res
            if sec is None or sec["seen"] == 0:
                res["status"] = "FAIL"
                res["why"] = ("its marker line was not found: %s" % s["marker"] if s.get("marker")
                              else "did not run (the binary reported no result)")
                continue
            res["tests"], res["failed"] = sec["passed"], sec["failed"]
            bad = []
            for sk in sec["skips"]:
                why = allowed(sk, s.get("allowed_skips", []) + r.get("allowed_skips", []))
                if why:
                    res["allowed_skips"].append("%s [%s]" % (sk, why))
                else:
                    res["skips"].append(sk)
                    unexpected.append("%s: %s" % (name, sk))
            if sec["failed"]:
                bad.append("%d failed" % sec["failed"])
            if sec["passed"] == 0:
                bad.append("zero tests")
            elif sec["passed"] < s.get("min_tests", 0):
                bad.append("%d tests, minimum %d" % (sec["passed"], s["min_tests"]))
            if res["skips"]:
                bad.append("%d unexpected skip(s)" % len(res["skips"]))
            res["status"] = "FAIL" if bad else "PASS"
            if bad:
                res["why"] = ", ".join(bad)

    # Suites of runs that did not execute.
    for s in suites:
        if s["name"] in results:
            continue
        st = blocked.get(s["run"])
        if st and st[0] == "allowed":
            results[s["name"]] = {"run": s["run"], "status": "SKIPPED-ALLOWED", "why": st[1], "tests": 0,
                                  "required": s.get("required", True), "min_tests": s.get("min_tests", 0)}
        else:
            why = ("not run: %s" % st[1]) if st else "not run (its build failed)"
            results[s["name"]] = {"run": s["run"], "status": "FAIL", "why": why, "tests": 0,
                                  "required": s.get("required", True), "min_tests": s.get("min_tests", 0)}

    print()
    print("SUITES")
    for r in selected:
        if blocked.get(r["id"], ("",))[0] == "fail":
            n = sum(1 for s in suites if s["run"] == r["id"])
            print("  %-16s %s: %d suites, %s" % ("FAIL (not run)", r["id"], n, blocked[r["id"]][1]))
            failures.append("run %s did not run: %s" % (r["id"], blocked[r["id"]][1]))
    for s in suites:
        res = results[s["name"]]
        if blocked.get(s["run"], ("",))[0] == "fail":
            continue
        if res["status"] == "PASS":
            extra = "%d tests" % res["tests"]
            if res.get("allowed_skips"):
                extra += ", %d allowed skip(s)" % len(res["allowed_skips"])
        else:
            extra = res.get("why", "")
        print("  %-16s %s  %s" % (res["status"], s["name"], extra))
        for sk in res.get("skips", []):
            print("                     unexpected skip: %s" % sk)
        if res["status"] == "FAIL":
            failures.append("%s: %s" % (s["name"], res.get("why", "")))
    failures += problems

    # Totals: the minimum covers the runs that were able to run.
    total_min = sum(r.get("min_tests", 0) for r in selected if r["id"] not in blocked)
    total = sum(i["tests"] for i in run_info.values())
    if not any(v[0] == "fail" for v in blocked.values()) and total < total_min:
        failures.append("total %d tests, the manifest's minimum is %d" % (total, total_min))

    print()
    print("Total tests: %d (minimum %d)" % (total, total_min))
    print("DB-backed test databases taken: %d" % exec_log_total)
    print("Unexpected skips: %d" % len(unexpected))
    print("Failures: %d" % len(failures))
    for f in failures:
        print("  - " + f)
    ok = not failures and not unexpected
    print("FULL TEST PASSED" if ok else "FULL TEST FAILED")

    summary = {
        "manifest": manifest_rel,
        "manifest_sha256": hashlib.sha256(Path(a.manifest).read_bytes()).hexdigest(),
        "manifest_files": {Path(f).name: hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in m["files"]},
        "database_mode": a.mode,
        "duration_s": round(time.time() - t_start, 1),
        "precheck": {d: {"status": "PASS" if v[0] else "FAIL", "detail": v[1]} for d, v in pre.items()},
        "expected_suites": [s["name"] for s in suites],
        "executed_suites": [n for n, r in results.items() if r.get("tests")],
        "skipped_suites": [{"name": n, "reason": r["why"], "allowed": True}
                           for n, r in results.items() if r["status"] == "SKIPPED-ALLOWED"],
        "failed_suites": [{"name": n, "reason": r.get("why", "")} for n, r in results.items() if r["status"] == "FAIL"],
        "suites": results,
        "runs": run_info,
        "other_binaries_run": other_binaries,
        "total_tests": total,
        "total_min_tests": total_min,
        "db_backed_databases": exec_log_total,
        "unexpected_skips": unexpected,
        "failures": failures,
        "result": "PASSED" if ok else "FAILED",
    }
    jpath = Path(a.json) if a.json else logdir / "summary.json"
    jpath.parent.mkdir(parents=True, exist_ok=True)
    jpath.write_text(json.dumps(summary, indent=2) + "\n")
    print("summary: %s" % jpath)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
