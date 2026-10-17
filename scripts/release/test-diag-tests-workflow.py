#!/usr/bin/env python3
"""Static checks of the diagnostic jobs in .github/workflows/release.yml (needs PyYAML).

1. every job except diag-build, diag-compare and diag-tests is skipped when diagnostic=true
   (its `if` is `${{ !inputs.diagnostic }}`), and those three run only when it is true;
2. diag-tests is nonpublishing: contents: read only, no forbidden strings;
3. the services of diag-tests are the services of release-check.
"""
import pathlib
import sys

import yaml

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
path = root / ".github/workflows/release.yml"
text = path.read_text()
wf = yaml.safe_load(text)
jobs = wf["jobs"]
DIAG = {"diag-build", "diag-compare", "diag-tests"}
bad = []
for name, job in jobs.items():
    cond = str(job.get("if", "")).replace(" ", "")
    if name in DIAG:
        if cond != "${{inputs.diagnostic}}":
            bad.append(f"{name}: if={job.get('if')!r}, expected inputs.diagnostic")
    elif cond != "${{!inputs.diagnostic}}":
        bad.append(f"{name}: if={job.get('if')!r}, expected !inputs.diagnostic")
    print(f"{name:16} runs when diagnostic=true: {name in DIAG}   if: {job.get('if')}")

job = jobs["diag-tests"]
if job.get("permissions") != {"contents": "read"}:
    bad.append(f"diag-tests permissions: {job.get('permissions')}")
if job["runs-on"] != "ubuntu-24.04":
    bad.append("diag-tests runner")
if job["services"] != jobs["release-check"]["services"]:
    bad.append("diag-tests services differ from release-check")
if sorted(job["strategy"]["matrix"]["n"]) != [1, 2, 3]:
    bad.append("diag-tests matrix")
# the job's own text
lines = text.splitlines()
start = next(i for i, l in enumerate(lines) if l.startswith("  diag-tests:"))
block = "\n".join(lines[start:])
for forbidden in [
    "docker/login-action", "cosign", "gh release", "git tag", "packages:", "id-token",
    "attestations", "secrets.", "GITHUB_TOKEN", "sigstore", "docker push", "ghcr.io",
]:
    if forbidden in block:
        bad.append(f"diag-tests contains forbidden string {forbidden!r}")
uses = [l.strip() for l in block.splitlines() if "uses:" in l]
print("diag-tests actions:", *uses, sep="\n  ")
if bad:
    print("FAILED:", *bad, sep="\n  ")
    sys.exit(1)
print("OK: gating, permissions, services and forbidden strings")
