#!/usr/bin/env python3
"""CycloneDX 1.5 SBOMs of Encompute's production artifacts: every Rust crate
an artifact resolves to with the given features, the native OpenFHE library
it links (when built with OpenFHE) and, for the Python wheel, the pinned
Python dependencies of its extras.

    scripts/sbom.py [--features encompute-cli/openfhe,...] > sbom.cdx.json
        the whole production build (every binary and the extension), as before

    scripts/sbom.py --artifact cli --file target/release/encompute -o encompute.cdx.json
    scripts/sbom.py --artifact evaluator --file target/release/encompute-evaluator -o ...
    scripts/sbom.py --artifact control --file target/release/encompute-control -o ...
    scripts/sbom.py --artifact wheel --file dist/encompute-*.whl \\
        --python-lock scripts/release/python/constraints.txt \\
        [--python-licenses target/release-scan/python-licenses.json] -o ...

The output is deterministic for a commit: the timestamp is SOURCE_DATE_EPOCH
and the serial number is derived from the content.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid

PRODUCTION = ["encompute-cli", "encompute-evaluator", "encompute-control", "encompute-py"]
FEATURES = "encompute-cli/openfhe,encompute-evaluator/openfhe,encompute-py/openfhe"
# One artifact: its root package, its default features and its name.
ARTIFACTS = {
    "cli": ("encompute-cli", "encompute-cli/openfhe", "encompute"),
    "evaluator": ("encompute-evaluator", "encompute-evaluator/openfhe", "encompute-evaluator"),
    "control": ("encompute-control", "", "encompute-control"),
    "wheel": ("encompute-py", "encompute-py/openfhe", "encompute"),
}
OPENFHE_VERSION = "1.5.1"
OPENFHE_COMMIT = "1306d14f8c26bb6150d3e6ad54f28dfe1007689e"


def openfhe_component():
    return {
        "type": "library", "name": "OpenFHE", "version": OPENFHE_VERSION,
        "bom-ref": f"pkg:github/openfheorg/openfhe-development@v{OPENFHE_VERSION}",
        "purl": f"pkg:github/openfheorg/openfhe-development@v{OPENFHE_VERSION}",
        "licenses": [{"expression": "BSD-2-Clause"}],
        "supplier": {"name": "OpenFHE (Duality Technologies and contributors)"},
        "externalReferences": [
            {"type": "vcs", "url": "https://github.com/openfheorg/openfhe-development"}],
        "description": "native C++ library (CKKS, BGV, BinFHE), statically linked; "
                       "built from the pinned tag by scripts/install-openfhe.sh",
        "properties": [{"name": "encompute:vcs-commit", "value": OPENFHE_COMMIT},
                       {"name": "encompute:linkage", "value": "static"}],
    }


def cargo_components(roots_names, features):
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked"]
    if features:
        cmd += ["--features", features]
    meta = json.loads(subprocess.run(cmd, capture_output=True, text=True, check=True).stdout)
    pkgs = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    roots = [p["id"] for p in meta["packages"] if p["name"] in roots_names]
    # Normal (runtime) dependencies only, reachable from the roots.
    seen, stack = set(), list(roots)
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        for d in nodes[i]["deps"]:
            if any(k["kind"] in (None, "normal") for k in d["dep_kinds"]):
                stack.append(d["pkg"])

    def ref(i):
        p = pkgs[i]
        return f"pkg:cargo/{p['name']}@{p['version']}"

    components, deps = [], []
    for i in sorted(seen, key=lambda i: (pkgs[i]["name"], pkgs[i]["version"])):
        p = pkgs[i]
        c = {"type": "library", "name": p["name"], "version": p["version"],
             "bom-ref": ref(i), "purl": ref(i)}
        if p.get("license"):
            c["licenses"] = [{"expression": p["license"].replace("/", " OR ")}]
        if p.get("source") is None:
            c["properties"] = [{"name": "encompute:workspace-crate", "value": "true"}]
        components.append(c)
        on = sorted({ref(d["pkg"]) for d in nodes[i]["deps"]
                     if d["pkg"] in seen and any(k["kind"] in (None, "normal")
                                                 for k in d["dep_kinds"])})
        deps.append({"ref": ref(i), "dependsOn": on})
    version = pkgs[roots[0]]["version"] if roots else "0"
    return components, deps, [ref(r) for r in roots], version


def python_components(lock, licenses_file):
    lic = {}
    if licenses_file and os.path.exists(licenses_file):
        with open(licenses_file) as f:
            lic = {k.lower(): v for k, v in json.load(f).items()}
    out = []
    for name, ver in re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\;]+)", open(lock).read(), re.M):
        purl = f"pkg:pypi/{name.lower()}@{ver}"
        c = {"type": "library", "name": name, "version": ver, "bom-ref": purl, "purl": purl,
             "scope": "optional",
             "properties": [{"name": "encompute:python-extra",
                             "value": "test, torch, huggingface (pinned; not installed by default)"}]}
        entry = lic.get(name.lower())
        if entry and entry.get("spdx"):
            c["licenses"] = [{"expression": entry["spdx"]}]
        out.append(c)
    return out


def file_hashes(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return [{"alg": "SHA-256", "content": h.hexdigest()}]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", choices=sorted(ARTIFACTS),
                    help="one release artifact (default: the whole production build)")
    ap.add_argument("--features", help="cargo features (default: the artifact's)")
    ap.add_argument("--file", help="the built artifact, to record its SHA-256")
    ap.add_argument("--python-lock", help="the pinned Python dependencies (wheel)")
    ap.add_argument("--python-licenses", help="JSON from scripts/release/python_licenses.py")
    ap.add_argument("-o", "--output", help="write here instead of stdout")
    a = ap.parse_args()

    if a.artifact:
        root, default_features, name = ARTIFACTS[a.artifact]
        roots, features = [root], a.features if a.features is not None else default_features
    else:
        roots, features, name = PRODUCTION, a.features if a.features is not None else FEATURES, \
            "encompute"
    components, deps, root_refs, version = cargo_components(roots, features)
    with_openfhe = "openfhe" in features
    if with_openfhe:
        components.append(openfhe_component())
        for d in deps:
            if d["ref"] in {c["bom-ref"] for c in components
                            if c["name"] in ("encompute-openfhe", "encompute-openfhe-exact")}:
                d["dependsOn"].append(openfhe_component()["bom-ref"])
        deps.append({"ref": openfhe_component()["bom-ref"], "dependsOn": []})
    if a.artifact == "wheel" and a.python_lock:
        components += python_components(a.python_lock, a.python_licenses)

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or 0)
    stamp = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    kind = "application" if a.artifact != "wheel" else "library"
    main_ref = f"encompute:{a.artifact or 'production'}@{version}"
    meta_component = {"type": kind, "name": name, "version": version, "bom-ref": main_ref,
                      "licenses": [{"expression": "AGPL-3.0-only"}],
                      "purl": (f"pkg:pypi/encompute@{version}" if a.artifact == "wheel"
                               else f"pkg:github/BAder82t/Encompute@v{version}")}
    if a.file:
        meta_component["hashes"] = file_hashes(a.file)
        meta_component["properties"] = [{"name": "encompute:file",
                                         "value": os.path.basename(a.file)}]
    deps.append({"ref": main_ref, "dependsOn": sorted(root_refs)})
    body = {"components": components, "dependencies": deps}
    serial = uuid.uuid5(uuid.NAMESPACE_URL, "encompute-sbom:" + hashlib.sha256(
        json.dumps([meta_component, body], sort_keys=True).encode()).hexdigest())
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "serialNumber": f"urn:uuid:{serial}",
           "metadata": {"timestamp": stamp,
                        "tools": {"components": [{"type": "application",
                                                  "name": "encompute scripts/sbom.py"}]},
                        "component": meta_component,
                        "properties": [{"name": "encompute:features", "value": features},
                                       {"name": "encompute:openfhe",
                                        "value": OPENFHE_VERSION if with_openfhe else "none"}]},
           **body}
    out = open(a.output, "w") if a.output else sys.stdout
    json.dump(bom, out, indent=1)
    out.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
