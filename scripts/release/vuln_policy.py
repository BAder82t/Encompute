#!/usr/bin/env python3
"""The release severity policy, applied to the scanners' JSON reports.

    scripts/release/vuln_policy.py [--cargo-audit F] [--pip-audit F ...]
        [--trivy F ...] [--grype F ...] [--exceptions security/exceptions.toml]
        [--osv-cache F] [--offline] [--report F.md]

Policy (docs/release-process.md, "Severity policy"):

* Critical and High block the release. The only way past one is an
  exception whose status is ``not_affected`` with a VEX justification (the
  vulnerable code is not present, or cannot be reached): an analysis, not a
  waiver.
* Medium blocks unless security/exceptions.toml records it with a reason,
  an owner and an expiry (``accepted_risk`` or ``not_affected``).
* Low is reported.
* A finding whose severity cannot be determined counts as High.
* An expired exception blocks; an exception that matches nothing is reported
  as stale. No exception may run longer than MAX_DAYS.

Severities: the scanner's own rating (trivy, grype), else the GitHub
advisory's rating (GHSA, through OSV), else a CVSS v3 base score computed
from the advisory's vector.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import sys
import urllib.request

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

LEVELS = ["none", "low", "medium", "high", "critical"]
MAX_DAYS = 183
VEX = {"component_not_present", "vulnerable_code_not_present",
       "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary",
       "inline_mitigations_already_exist"}


# --- CVSS v3.x base score ---------------------------------------------------------
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    if not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["C"][m["I"]]) * (1 - _W["C"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1.0) * (impact + expl), 10))


def rating(score: float) -> str:
    if score == 0:
        return "none"
    return "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


def norm(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip().lower()
    return {"moderate": "medium", "important": "high", "negligible": "low",
            "informational": "low", "info": "low"}.get(s, s if s in LEVELS else None)


# --- OSV lookups ------------------------------------------------------------------
class Osv:
    def __init__(self, cache: str | None, offline: bool):
        self.path, self.offline = cache, offline
        self.cache = {}
        if cache and os.path.exists(cache):
            with open(cache) as f:
                self.cache = json.load(f)

    def get(self, vid: str) -> dict | None:
        if vid in self.cache:
            return self.cache[vid]
        if self.offline:
            return None
        try:
            with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=20) as r:
                v = json.load(r)
        except Exception:
            v = None
        self.cache[vid] = v
        return v

    def save(self):
        if self.path:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w") as f:
                json.dump(self.cache, f)

    def severity(self, ids: list[str]) -> tuple[str | None, str]:
        """The severity and where it came from."""
        for vid in sorted(ids, key=lambda i: not i.startswith("GHSA-")):
            v = self.get(vid)
            if not v:
                continue
            lab = norm((v.get("database_specific") or {}).get("severity"))
            if lab:
                return lab, f"{vid} rating"
            for s in v.get("severity") or []:
                sc = cvss3_score(s.get("score", ""))
                if sc is not None:
                    return rating(sc), f"{vid} CVSS {sc}"
            for a in v.get("affected") or []:
                lab = norm((a.get("ecosystem_specific") or {}).get("severity"))
                if lab:
                    return lab, f"{vid} ecosystem rating"
        return None, "unknown"


# --- Scanner inputs ---------------------------------------------------------------
def from_cargo_audit(path, osv):
    d = json.load(open(path))
    out, notes = [], []
    for v in d.get("vulnerabilities", {}).get("list", []):
        a, p = v["advisory"], v["package"]
        ids = [a["id"]] + list(a.get("aliases") or [])
        sev, src = None, "unknown"
        if a.get("cvss"):
            sc = cvss3_score(a["cvss"])
            if sc is not None:
                sev, src = rating(sc), f"CVSS {sc}"
        if not sev:
            sev, src = osv.severity(ids)
        out.append(dict(source="cargo-audit", package=p["name"], version=p["version"], ids=ids,
                        severity=sev, sev_source=src, title=a.get("title", ""),
                        fixed=", ".join((v.get("versions") or {}).get("patched") or []) or "none"))
    for kind, ws in (d.get("warnings") or {}).items():
        for w in ws or []:
            a = w.get("advisory") or {}
            notes.append(f"cargo-audit {kind}: {w['package']['name']} {w['package']['version']}"
                         f" {a.get('id', '')} {a.get('title', '')}".rstrip())
    return out, notes


def from_pip_audit(path, osv):
    d = json.load(open(path))
    out, notes, seen = [], [], set()
    for dep in d.get("dependencies", []):
        if dep.get("skip_reason"):
            notes.append(f"pip-audit skipped {dep['name']}: {dep['skip_reason']}")
        for v in dep.get("vulns") or []:
            key = (dep["name"], v["id"])
            if key in seen:
                continue
            seen.add(key)
            ids = [v["id"]] + list(v.get("aliases") or [])
            sev, src = osv.severity(ids)
            out.append(dict(source="pip-audit", package=dep["name"], version=dep["version"],
                            ids=ids, severity=sev, sev_source=src,
                            title=(v.get("description") or "").split(". ")[0][:100],
                            fixed=", ".join(v.get("fix_versions") or []) or "none"))
    return out, notes


def from_trivy(path, _osv):
    d = json.load(open(path))
    out, target = [], d.get("ArtifactName", path)
    for r in d.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            ids = [v["VulnerabilityID"]] + list(v.get("VendorIDs") or [])
            out.append(dict(source=f"trivy {target}", package=v["PkgName"],
                            version=v.get("InstalledVersion", ""), ids=ids,
                            severity=norm(v.get("Severity")), sev_source="trivy",
                            title=(v.get("Title") or "")[:100],
                            fixed=v.get("FixedVersion") or "none",
                            os_unfixed=r.get("Class") == "os-pkgs" and not v.get("FixedVersion")))
    return out, []


def from_grype(path, _osv):
    d = json.load(open(path))
    out = []
    target = ((d.get("source") or {}).get("target") or {})
    target = target.get("userInput", path) if isinstance(target, dict) else path
    for m in d.get("matches") or []:
        v, a = m["vulnerability"], m["artifact"]
        ids = [v["id"]] + [r["id"] for r in m.get("relatedVulnerabilities") or []]
        fix = v.get("fix") or {}
        out.append(dict(source=f"grype {target}", package=a["name"], version=a["version"],
                        ids=ids, severity=norm(v.get("severity")), sev_source="grype",
                        title=(v.get("description") or "")[:100],
                        fixed=", ".join(fix.get("versions") or []) or "none",
                        os_unfixed=a.get("type") in ("deb", "rpm", "apk")
                        and fix.get("state") != "fixed"))
    return out, []


# --- Exceptions -------------------------------------------------------------------
def load_exceptions(path):
    if not path or not os.path.exists(path):
        return []
    if tomllib is None:
        sys.exit("vuln_policy: Python 3.11+ is needed to read the exceptions file")
    with open(path, "rb") as f:
        doc = tomllib.load(f)
    # One approval may cover the whole file; an entry may carry its own.
    approval = (doc.get("approval") or {}).get("approved_by", "")
    out = []
    for e in doc.get("exception", []):
        e = dict(e)
        e.setdefault("approved_by", approval)
        out.append(e)
    return out


def exception_problems(e, today):
    p = []
    for k in ("id", "package", "status", "reason", "expires"):
        if not e.get(k):
            p.append(f"missing {k}")
    if not str(e.get("approved_by") or "").strip():
        p.append("not approved (approved_by is empty)")
    exp = e.get("expires")
    if isinstance(exp, str):
        exp = dt.date.fromisoformat(exp)
    if isinstance(exp, dt.date):
        if exp < today:
            p.append(f"expired {exp}")
        elif (exp - today).days > MAX_DAYS:
            p.append(f"expiry {exp} is more than {MAX_DAYS} days away")
    if e.get("status") not in ("accepted_risk", "not_affected"):
        p.append("status must be accepted_risk or not_affected")
    if e.get("status") == "not_affected" and e.get("justification") not in VEX:
        p.append(f"not_affected needs a justification in {sorted(VEX)}")
    return p


def _list(v):
    return v if isinstance(v, list) else [v]


def match(e, f):
    return f["package"] in _list(e.get("package")) and any(i in f["ids"] for i in _list(e.get("id")))


# --- Main -------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cargo-audit")
    ap.add_argument("--pip-audit", action="append", default=[])
    ap.add_argument("--trivy", action="append", default=[])
    ap.add_argument("--grype", action="append", default=[])
    ap.add_argument("--exceptions", default="security/exceptions.toml")
    ap.add_argument("--osv-cache")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--report", help="also write a Markdown report here")
    ap.add_argument("--today", help="YYYY-MM-DD (tests)")
    a = ap.parse_args()
    today = dt.date.fromisoformat(a.today) if a.today else dt.date.today()
    osv = Osv(a.osv_cache, a.offline)

    findings, notes = [], []
    inputs = ([(from_cargo_audit, a.cargo_audit)] if a.cargo_audit else []) + \
        [(from_pip_audit, p) for p in a.pip_audit] + [(from_trivy, p) for p in a.trivy] + \
        [(from_grype, p) for p in a.grype]
    for fn, path in inputs:
        f, n = fn(path, osv)
        findings += f
        notes += n
    osv.save()

    exceptions = load_exceptions(a.exceptions)
    bad_exc = {}
    for e in exceptions:
        pr = exception_problems(e, today)
        if pr:
            bad_exc[id(e)] = pr
    used = set()
    rows, blocking = [], 0
    counts = {k: 0 for k in LEVELS + ["unknown"]}
    for f in findings:
        sev = f["severity"] or "unknown"
        counts[sev] += 1
        eff = "high" if sev == "unknown" else sev
        e = next((e for e in exceptions if match(e, f)), None)
        if e is not None:
            used.add(id(e))
        verdict = "REPORTED"
        if f.get("os_unfixed") and not e:
            # A base-image package the distribution has not fixed: reported
            # and re-checked at every release (docs/release-process.md).
            verdict = "REPORTED (no fix in the distribution)"
        elif eff in ("critical", "high"):
            if e and id(e) not in bad_exc and e["status"] == "not_affected":
                verdict = f"EXCEPTED (not_affected: {e['justification']}, until {e['expires']})"
            elif e and id(e) in bad_exc:
                verdict = "BLOCKING (exception invalid: " + "; ".join(bad_exc[id(e)]) + ")"
            elif e:
                verdict = "BLOCKING (high/critical: only a not_affected analysis can pass)"
            else:
                verdict = "BLOCKING"
        elif eff == "medium":
            if e and id(e) not in bad_exc:
                verdict = f"EXCEPTED ({e['status']}, until {e['expires']})"
            elif e:
                verdict = "BLOCKING (exception invalid: " + "; ".join(bad_exc[id(e)]) + ")"
            else:
                verdict = "BLOCKING (medium: needs an exception)"
        if verdict.startswith("BLOCKING"):
            blocking += 1
        rows.append((f["source"], f["package"], f["version"], f["ids"][0], sev, f["sev_source"],
                     f["fixed"], verdict))
    stale = [e for e in exceptions if id(e) not in used]

    rows.sort(key=lambda r: (not r[7].startswith("BLOCKING"), -LEVELS.index(r[4]) if r[4] in LEVELS
                             else -3, r[1], r[3]))
    lines = ["| source | package | version | id | severity | rated by | fixed in | verdict |",
             "|---|---|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    for r in rows:
        print(f"{r[4]:8} {r[1]}=={r[2]} {r[3]} [{r[0]}; fixed in {r[6]}] {r[7]}")
    for n in notes:
        print(f"NOTE      {n}")
    for e in stale:
        print(f"STALE     exception {e.get('id')} ({e.get('package')}) matches no finding"
              + (f": {'; '.join(bad_exc[id(e)])}" if id(e) in bad_exc else ""))
    summary = (f"{len(findings)} findings: " + ", ".join(f"{counts[k]} {k}" for k in
               ["critical", "high", "medium", "low", "unknown"] if counts[k]) +
               f"; {blocking} blocking; {len(exceptions)} exceptions ({len(stale)} stale)")
    print(summary)
    if a.report:
        with open(a.report, "w") as f:
            f.write("# Vulnerability scan\n\n" + summary + "\n\n" + "\n".join(lines) + "\n")
            if notes:
                f.write("\n## Notes\n\n" + "\n".join(f"- {n}" for n in notes) + "\n")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
