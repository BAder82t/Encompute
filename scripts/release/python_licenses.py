#!/usr/bin/env python3
"""License audit of the pinned Python dependencies (the SDK's extras).

    scripts/release/python_licenses.py scripts/release/python/constraints.txt \\
        [--json target/release-scan/python-licenses.json]

Reads each pinned package's license from PyPI (license expression, license
field, or trove classifiers), normalizes it to SPDX and applies the release
policy: permissive licenses pass; MPL-2.0 (file-level copyleft, used
unmodified) passes as reviewed; anything else, or a license that cannot be
determined, fails. Exit status 1 on a failure.
"""

import argparse
import json
import re
import sys
import urllib.request

PERMISSIVE = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "PSF-2.0",
              "CNRI-Python", "Unlicense", "Zlib", "BSL-1.0", "0BSD"}
REVIEWED = {"MPL-2.0": "file-level copyleft; used unmodified (certifi, tqdm)"}
# Free-text license fields and trove classifiers, to SPDX.
ALIASES = {
    "apache": "Apache-2.0", "apache 2.0": "Apache-2.0", "apache 2.0 license": "Apache-2.0",
    "apache-2.0": "Apache-2.0", "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "mit": "MIT", "mit license": "MIT",
    "bsd": "BSD-3-Clause", "bsd-3": "BSD-3-Clause", "bsd license": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause", "bsd-2-clause": "BSD-2-Clause",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mpl-2.0": "MPL-2.0",
    "python software foundation license": "PSF-2.0", "isc license (iscl)": "ISC",
}
# Packages whose PyPI metadata is not machine-readable, checked by hand.
MANUAL = {
    "numpy": "BSD-3-Clause",   # "Copyright (c) 2005-2023, NumPy Developers" + BSD classifier
}


def to_spdx(name, info):
    if name.lower() in MANUAL:
        return MANUAL[name.lower()], "manual"
    expr = info.get("license_expression")
    if expr:
        return expr, "license_expression"
    lic = (info.get("license") or "").strip()
    if lic and len(lic) < 60:
        if lic.lower() in ALIASES:
            return ALIASES[lic.lower()], "license"
        if re.fullmatch(r"[A-Za-z0-9.+\- ()]+", lic) and any(
                t in PERMISSIVE | set(REVIEWED) for t in re.split(r"\s+(?:OR|AND)\s+|[()]", lic)):
            return lic, "license"
    cls = [c.split("::")[-1].strip() for c in info.get("classifiers") or []
           if c.startswith("License ::")]
    spdx = sorted({ALIASES.get(c.lower()) for c in cls} - {None})
    if spdx:
        return " OR ".join(spdx), "classifier"
    return None, "unknown"


def verdict(expr):
    if not expr:
        return "FAIL", "license unknown"
    terms = [t for t in re.split(r"\s+(?:OR|AND|WITH)\s+|[()]", expr) if t.strip()]
    ors = [t.strip() for t in re.split(r"\s+OR\s+", expr)]
    # An OR passes if one branch passes; an AND needs all of its terms.
    def ok(branch, allowed):
        return all(t.strip() in allowed for t in re.split(r"\s+AND\s+|[()]", branch) if t.strip())
    if any(ok(b, PERMISSIVE) for b in ors):
        return "PASS", ""
    if any(ok(b, PERMISSIVE | set(REVIEWED)) for b in ors):
        return "REVIEWED", "; ".join(REVIEWED[t] for t in terms if t in REVIEWED)
    return "FAIL", f"not allowed: {expr}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("lock")
    ap.add_argument("--json")
    a = ap.parse_args()
    pins = re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\;+]+)", open(a.lock).read(), re.M)
    result, status = {}, 0
    for name, ver in pins:
        try:
            with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{ver}/json",
                                        timeout=30) as r:
                info = json.load(r)["info"]
        except Exception as e:  # noqa: BLE001 - reported as a failure
            info, err = {}, str(e)
        else:
            err = ""
        expr, src = to_spdx(name, info)
        v, why = verdict(expr)
        if err:
            v, why = "FAIL", f"PyPI lookup failed: {err}"
        if v == "FAIL":
            status = 1
        result[name] = {"version": ver, "spdx": expr, "source": src, "verdict": v, "note": why}
        print(f"{v:9} {name + '==' + ver:34} {expr or '?':32} ({src}) {why}")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(result, f, indent=1, sort_keys=True)
    print(f"\n{len(pins)} packages: "
          f"{sum(r['verdict'] == 'PASS' for r in result.values())} permissive, "
          f"{sum(r['verdict'] == 'REVIEWED' for r in result.values())} reviewed, "
          f"{sum(r['verdict'] == 'FAIL' for r in result.values())} failed")
    return status


if __name__ == "__main__":
    sys.exit(main())
