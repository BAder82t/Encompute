#!/usr/bin/env python3
"""A CycloneDX 1.5 SBOM of Encompute's production build: every Rust crate
the production packages resolve to with the given features, plus the native
OpenFHE library they link.

    scripts/sbom.py [--features encompute-cli/openfhe,...] > sbom.cdx.json
"""

import argparse
import json
import subprocess
import sys

PRODUCTION = ["encompute-cli", "encompute-evaluator", "encompute-control", "encompute-py"]
FEATURES = "encompute-cli/openfhe,encompute-evaluator/openfhe,encompute-py/openfhe"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default=FEATURES)
    a = ap.parse_args()
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--features", a.features],
        capture_output=True, text=True, check=True).stdout)
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    roots = [p["id"] for p in meta["packages"] if p["name"] in PRODUCTION]
    # Normal (runtime) dependencies only, reachable from the production roots.
    seen, stack = set(), list(roots)
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in nodes[i]["deps"]:
            if any(k["kind"] in (None, "normal") for k in d["dep_kinds"]):
                stack.append(d["pkg"])
    components = []
    for i in sorted(seen, key=lambda i: (pkgs[i]["name"], pkgs[i]["version"])):
        p = pkgs[i]
        c = {"type": "library", "name": p["name"], "version": p["version"],
             "purl": f"pkg:cargo/{p['name']}@{p['version']}"}
        if p.get("license"):
            c["licenses"] = [{"expression": p["license"]}]
        components.append(c)
    components.append({
        "type": "library", "name": "OpenFHE", "version": "1.5.1",
        "licenses": [{"expression": "BSD-2-Clause"}],
        "purl": "pkg:github/openfheorg/openfhe-development@v1.5.1",
        "description": "native C++ library, statically linked (scripts/install-openfhe.sh)"})
    json.dump({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
               "metadata": {"component": {"type": "application", "name": "encompute",
                                          "version": pkgs[roots[0]]["version"]},
                            "properties": [{"name": "encompute:features", "value": a.features}]},
               "components": components}, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
