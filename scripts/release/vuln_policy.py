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
* An exception that matches nothing is reported as stale. No exception may
  run longer than MAX_DAYS.

Exceptions are narrow and machine-checked. Every entry names exactly one
advisory (``id``), one package (``package``) and the exact installed
version(s) the scanner reports (``version``; a list only for spellings of
the same release, e.g. ``2.3.1`` and ``2.3.1+cpu``), and carries a
``reason``, ``compensating_controls``, an ``added`` date, an ``expires``
date and a ``tracking`` URL (the upstream advisory or issue). An exception
matches a finding only when the advisory, the package and the version all
match: one written for torch 2.3.1 does not cover 2.3.2. The file-level
approval covers the entries added on or before its ``approved_on``; a later
entry needs a new approval. Any invalid entry (a missing field, a wildcard
or list where one exact value is required, an expired or over-long entry,
a missing approval) fails the gate whether or not it matches a finding, and
a finding whose advisory and package match an exception for another
version blocks with that reason.

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
import re
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
REQUIRED = ("id", "package", "version", "status", "reason", "compensating_controls",
            "added", "expires", "tracking")
# One advisory: CVE-2025-32434, GHSA-xxxx-xxxx-xxxx, PYSEC-2024-1, RUSTSEC-2023-0071,
# DLA-4792-1, DSA-5000-1, TEMP-0841856-B18BAF.
ADVISORY = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+"
                      r"|RUSTSEC-\d{4}-\d{4}|DLA-\d+-\d+|DSA-\d+-\d+|TEMP-\d+-[0-9A-F]+)$")
# One exact version as scanners print it (PEP 440, SemVer, Debian epoch:version~rev):
# no wildcard, range or separator.
EXACT_VERSION = re.compile(r"^[0-9][A-Za-z0-9.+:~_-]*$")
PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


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
    # One approval may cover the whole file (the entries added on or before
    # its date); an entry may carry its own approved_by and approved_on.
    approval = doc.get("approval") or {}
    out = []
    for e in doc.get("exception", []):
        e = dict(e)
        if "approved_by" not in e:
            e["approved_by"] = approval.get("approved_by", "")
            e["approved_on"] = approval.get("approved_on")
        out.append(e)
    return out


def _date(v):
    """A TOML date or a YYYY-MM-DD string, else None."""
    if isinstance(v, dt.datetime):
        return None
    if isinstance(v, dt.date):
        return v
    if isinstance(v, str):
        try:
            return dt.date.fromisoformat(v)
        except ValueError:
            return None
    return None


def _versions(e):
    v = e.get("version")
    return v if isinstance(v, list) else [v]


def exception_problems(e, today):
    p = []
    for k in REQUIRED:
        v = e.get(k)
        if v is None or v == "" or v == [] or (isinstance(v, str) and not v.strip()):
            p.append(f"missing {k}")
    # Narrow: one advisory, one package, exact versions. No wildcard, list or range.
    i = e.get("id")
    if isinstance(i, list):
        p.append("id must be one advisory, not a list (one entry per advisory)")
    elif i and not ADVISORY.match(str(i)):
        p.append(f"id {i!r} is not one exact advisory ID (CVE, GHSA, PYSEC, RUSTSEC, DLA, DSA, TEMP)")
    pkg = e.get("package")
    if isinstance(pkg, list):
        p.append("package must be one package, not a list")
    elif pkg and not PACKAGE.match(str(pkg)):
        p.append(f"package {pkg!r} is not one exact package name")
    if e.get("version") not in (None, "", []):
        for v in _versions(e):
            if not isinstance(v, str) or not EXACT_VERSION.match(v):
                p.append(f"version {v!r} is not one exact installed version (no wildcard or range)")
    cc = e.get("compensating_controls")
    if isinstance(cc, list) and not all(isinstance(c, str) and c.strip() for c in cc):
        p.append("compensating_controls has an empty item")
    tr = e.get("tracking")
    if tr and not (isinstance(tr, str) and re.match(r"^https://\S+$", tr)):
        p.append(f"tracking {tr!r} is not an https URL of the upstream advisory or issue")
    added, exp = _date(e.get("added")), _date(e.get("expires"))
    if e.get("added") and added is None:
        p.append(f"added {e.get('added')!r} is not a date (YYYY-MM-DD)")
    if e.get("expires") and exp is None:
        p.append(f"expires {e.get('expires')!r} is not a date (YYYY-MM-DD)")
    if added and added > today:
        p.append(f"added {added} is in the future")
    if exp:
        if exp < today:
            p.append(f"expired {exp}")
        elif (exp - today).days > MAX_DAYS:
            p.append(f"expiry {exp} is more than {MAX_DAYS} days away")
        if added and (exp - added).days > MAX_DAYS:
            p.append(f"runs {(exp - added).days} days from {added}, more than {MAX_DAYS}")
    if not str(e.get("approved_by") or "").strip():
        p.append("not approved (approved_by is empty)")
    else:
        on = _date(e.get("approved_on"))
        if on is None:
            p.append("not approved (approved_on is missing)")
        elif added and on < added:
            p.append(f"not approved (added {added}, after the approval of {on})")
    if e.get("status") not in ("accepted_risk", "not_affected"):
        p.append("status must be accepted_risk or not_affected")
    if e.get("status") == "not_affected" and e.get("justification") not in VEX:
        p.append(f"not_affected needs a justification in {sorted(VEX)}")
    return p


def advisory_match(e, f):
    """The same advisory and package, whatever the version."""
    return isinstance(e.get("id"), str) and e.get("package") == f["package"] and e["id"] in f["ids"]


def match(e, f):
    """Advisory, package and exact installed version."""
    return advisory_match(e, f) and f["version"] in _versions(e)


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
        other = None if e else next((x for x in exceptions if advisory_match(x, f)), None)
        verdict = "REPORTED"
        if other is not None and eff in ("critical", "high", "medium"):
            # An exception for another version of the package covers nothing:
            # the analysis was made for different code.
            verdict = (f"BLOCKING (the exception is for version {', '.join(map(str, _versions(other)))}"
                       f", installed {f['version']})")
        elif f.get("os_unfixed") and not e:
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
        print(f"STALE     exception {e.get('id')} ({e.get('package')} {e.get('version')}) matches no finding")
    # An invalid exception fails the gate even when it matches nothing: an
    # expired, blanket or unapproved entry must be fixed or removed.
    for e in exceptions:
        if id(e) in bad_exc:
            print(f"BLOCKING  invalid exception {e.get('id')} ({e.get('package')} {e.get('version')}): "
                  + "; ".join(bad_exc[id(e)]))
    summary = (f"{len(findings)} findings: " + ", ".join(f"{counts[k]} {k}" for k in
               ["critical", "high", "medium", "low", "unknown"] if counts[k]) +
               f"; {blocking} blocking; {len(exceptions)} exceptions ({len(stale)} stale, "
               f"{len(bad_exc)} invalid)")
    print(summary)
    if a.report:
        with open(a.report, "w") as f:
            f.write("# Vulnerability scan\n\n" + summary + "\n\n" + "\n".join(lines) + "\n")
            if notes:
                f.write("\n## Notes\n\n" + "\n".join(f"- {n}" for n in notes) + "\n")
            bad = [e for e in exceptions if id(e) in bad_exc]
            if bad:
                f.write("\n## Invalid exceptions (blocking)\n\n" + "\n".join(
                    f"- {e.get('id')} ({e.get('package')} {e.get('version')}): "
                    + "; ".join(bad_exc[id(e)]) for e in bad) + "\n")
    return 1 if blocking or bad_exc else 0


if __name__ == "__main__":
    sys.exit(main())
