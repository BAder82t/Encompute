#!/usr/bin/env python3
"""Static checks of the rehearsal jobs in .github/workflows/release.yml (needs PyYAML).

  test-rehearsal-workflow.py [ROOT] [--base-ref GITREF]

1. job gating: for each of (diagnostic, rehearsal, stress) in {false,true}^3 and for a tag
   push (no inputs), exactly the intended jobs run (the `if` expressions are evaluated;
   stress wins over rehearsal, rehearsal over diagnostic);
2. rehearsal and stress jobs: `permissions` is exactly {contents: read}, none is a `needs` of any
   other job outside the rehearsal set, none contains a forbidden string;
3. tag push runs prepare, binaries, images, release-check, release and no other job;
4. rehearse-compare runs compare-shipped-digests.sh with the arguments of `release`;
5. rehearse-release-check: same services/env as release-check, no allow-skip, --repro,
   five images load-only (push false), no outputs that push;
6. with --base-ref: the existing jobs (also the rehearsal ones) differ from that ref only in their `if:` line.
"""
import pathlib
import re
import subprocess
import sys

import yaml

args = sys.argv[1:]
base_ref = None
if "--base-ref" in args:
    i = args.index("--base-ref")
    base_ref = args[i + 1]
    del args[i : i + 2]
root = pathlib.Path(args[0] if args else ".")
path = root / ".github/workflows/release.yml"
text = path.read_text()
wf = yaml.safe_load(text)
jobs = wf["jobs"]
on = wf.get("on", wf.get(True))
bad = []

REAL = ["prepare", "binaries", "images", "release-check", "release"]
DIAG = ["diag-build", "diag-compare"]
REH = ["rehearse-prepare", "rehearse-binaries", "rehearse-release-check", "rehearse-compare", "rehearse-window-load"]
STRESS = ["stress-window"]
if set(jobs) != set(REAL + DIAG + REH + STRESS):
    bad.append(f"unexpected job set: {sorted(jobs)}")

inp = on["workflow_dispatch"]["inputs"]
for k in ("diagnostic", "rehearsal", "stress"):
    if inp.get(k, {}).get("type") != "boolean" or inp[k].get("default") is not False:
        bad.append(f"input {k} must be a boolean defaulting to false")


def evaluate(expr, ctx):
    """Evaluate a `${{ ... }}` made only of inputs.X, !, && and ||."""
    m = re.fullmatch(r"\$\{\{(.*)\}\}", str(expr).strip(), re.S)
    if not m:
        raise ValueError(f"not a single expression: {expr!r}")
    e = m.group(1)
    if not re.fullmatch(r"[\sA-Za-z_.!&|()]*", e):
        raise ValueError(f"unsupported expression: {e!r}")
    e = re.sub(r"inputs\.(\w+)", lambda g: f"ctx[{g.group(1)!r}]", e)
    e = e.replace("&&", " and ").replace("||", " or ")
    e = re.sub(r"!(?!=)", " not ", e)
    return bool(eval(e, {"ctx": ctx}))  # noqa: S307 (the character set is checked above)


def running(ctx):
    return {n for n, j in jobs.items() if ("if" not in j) or evaluate(j["if"], ctx)}


F, T = False, True
cases = {"tag push (no inputs)": ({"diagnostic": None, "rehearsal": None, "stress": None}, set(REAL))}
for d in (F, T):
    for r in (F, T):
        for st in (F, T):
            want = set(STRESS) if st else set(REH) if r else set(DIAG) if d else set(REAL)
            cases[f"dispatch diagnostic={d} rehearsal={r} stress={st}"] = ({"diagnostic": d, "rehearsal": r, "stress": st}, want)
for label, (ctx, want) in cases.items():
    got = running(ctx)
    ok = got == want
    print(f"{'ok  ' if ok else 'FAIL'} {label}: runs {sorted(got)}")
    if not ok:
        bad.append(f"{label}: runs {sorted(got)}, want {sorted(want)}")

# every job of a mode needs only jobs of the same mode
for n in REH:
    needs = jobs[n].get("needs", [])
    needs = [needs] if isinstance(needs, str) else needs
    for d in needs:
        if d not in REH:
            bad.append(f"{n} needs {d}, outside the rehearsal set")
for n in REAL + DIAG + REH:
    needs = jobs[n].get("needs", [])
    needs = [needs] if isinstance(needs, str) else needs
    for d in needs:
        if d in STRESS or (n in REAL + DIAG and d in REH):
            bad.append(f"{n} needs {d}")
if jobs["stress-window"].get("needs"):
    bad.append("stress-window must not need any job")
for n in REAL + DIAG + REH:
    if "!inputs.stress" not in str(jobs[n].get("if")):
        bad.append(f"{n} does not exclude stress: {jobs[n].get('if')!r}")

# permissions and forbidden strings
lines = text.splitlines()
starts = {}
for i, l in enumerate(lines):
    m = re.match(r"^  ([a-z][a-z0-9-]*):\s*$", l)
    if m and m.group(1) in jobs:
        starts[m.group(1)] = i
order = sorted(starts, key=starts.get)


def job_text(n):
    i = starts[n]
    j = next((starts[o] for o in order if starts[o] > i), len(lines))
    return "\n".join(lines[i:j])


FORBIDDEN = [
    "docker/login-action", "cosign", "gh release", "git tag", "packages:", "id-token", "attestations",
    "secrets.", "GITHUB_TOKEN", "GH_TOKEN", "sigstore", "docker push", "ghcr.io", "push: true", "push=true",
    "attest-build-provenance", "allow-skip", "contents: write",
]
for n in REH + STRESS:
    if jobs[n].get("permissions") != {"contents": "read"}:
        bad.append(f"{n} permissions: {jobs[n].get('permissions')!r}, want exactly contents: read")
    if jobs[n]["runs-on"] not in ("ubuntu-24.04", "${{ matrix.os }}"):
        bad.append(f"{n} runner {jobs[n]['runs-on']!r}")
    block = job_text(n)
    for f in FORBIDDEN:
        if f in block:
            bad.append(f"{n} contains forbidden string {f!r}")
    # uses: only pinned actions that the real jobs use
    for l in block.splitlines():
        m = re.search(r"uses:\s*(\S+)", l)
        if m and not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", m.group(1)):
            bad.append(f"{n}: unpinned action {m.group(1)}")
if "matrix" in jobs["rehearse-binaries"]["strategy"]:
    inc = jobs["rehearse-binaries"]["strategy"]["matrix"]["include"]
    if [i["target"] for i in inc] != ["linux-x86_64"] or inc[0]["os"] != "ubuntu-24.04":
        bad.append(f"rehearse-binaries matrix: {inc}")
sw = jobs["stress-window"]
if sw.get("timeout-minutes") != 240 or sw["runs-on"] != "ubuntu-24.04" or sw.get("if") != "${{ inputs.stress }}":
    bad.append("stress-window must be ubuntu-24.04, timeout 240, if inputs.stress")
rw = jobs["rehearse-window-load"]
if sw["services"] != rw["services"] or sw["env"] != rw["env"]:
    bad.append("stress-window services/env differ from rehearse-window-load")
sruns = [st.get("run", "") for st in sw["steps"]]
if "scripts/release/stress-window.sh stress-logs" not in [r.strip() for r in sruns]:
    bad.append("stress-window must run scripts/release/stress-window.sh stress-logs")
if not any("--no-run" in r for r in sruns):
    bad.append("stress-window does not build the test binaries once")
ups = [st for st in sw["steps"] if str(st.get("uses", "")).startswith("actions/upload-artifact@")]
if len(ups) != 1 or ups[0].get("if") != "always()" or ups[0]["with"].get("path") != "stress-logs/":
    bad.append("stress-window must upload stress-logs/ with always()")
for sf in ("stress-window.sh", "stress-summary.py"):
    body = (root / "scripts/release" / sf).read_text()
    for f in ("docker login", "cosign", "gh release", "git tag", "git push", "secrets.", "GITHUB_TOKEN", "docker push", "curl "):
        if f in body:
            bad.append(f"{sf} contains forbidden string {f!r}")
if jobs["rehearse-window-load"].get("timeout-minutes") != 120:
    bad.append("rehearse-window-load timeout-minutes")
if jobs["rehearse-release-check"].get("timeout-minutes") != 300:
    bad.append("rehearse-release-check timeout-minutes")

# release-check fidelity
rc, rrc = jobs["release-check"], jobs["rehearse-release-check"]
if rc["services"] != rrc["services"] or jobs["rehearse-window-load"]["services"] != rc["services"]:
    bad.append("services differ from release-check")
for k in ("ENCOMPUTE_TEST_DATABASE_URL", "ENCOMPUTE_TEST_BAO_ADDR", "ENCOMPUTE_TEST_BAO_TOKEN", "REQUIRE_IMAGES", "REQUIRE_TOOLS"):
    if rc["env"].get(k) != rrc["env"].get(k):
        bad.append(f"env {k} differs from release-check")
if set(rc["env"]) - set(rrc["env"]) != set() or set(rrc["env"]) != set(rc["env"]):
    bad.append(f"env keys differ: {sorted(rc['env'])} vs {sorted(rrc['env'])}")
runs = [s.get("run", "") for s in rrc["steps"]]
if not any(r.strip() == "./scripts/release-check.sh --repro" for r in runs):
    bad.append("rehearse-release-check must run ./scripts/release-check.sh --repro exactly")
real_runs = [s.get("run", "") for s in rc["steps"]]
for r in real_runs:
    if r and r not in runs:
        bad.append(f"real release-check run step missing from the rehearsal: {r[:60]!r}")
builds = [s for s in rrc["steps"] if str(s.get("uses", "")).startswith("docker/build-push-action@")]
if len(builds) != 5:
    bad.append(f"{len(builds)} image builds, want 5")
real_builds = [s for s in jobs["images"]["steps"] if str(s.get("uses", "")).startswith("docker/build-push-action@")]
for a, b in zip(real_builds, builds):
    for k in ("context", "file", "platforms", "target"):
        if a["with"].get(k) != b["with"].get(k):
            bad.append(f"image build {a['with'].get('file')}: {k} differs")
    if str(b["with"].get("load")).lower() != "true" or str(b["with"].get("push")).lower() != "false":
        bad.append(f"image build {b['with'].get('file')} is not load-only")
    if "SOURCE_DATE_EPOCH=" not in b["with"].get("build-args", ""):
        bad.append(f"image build {b['with'].get('file')}: no SOURCE_DATE_EPOCH build arg")

# the tarball comparison
def compare_cmd(job):
    cs = [s["run"].strip() for s in job["steps"] if "compare-shipped-digests.sh" in s.get("run", "") and "usage" not in s.get("run", "")
          and s["run"].strip().startswith("scripts/release/compare-shipped-digests.sh")]
    return cs


a, b = compare_cmd(jobs["release"]), compare_cmd(jobs["rehearse-compare"])
if len(a) != 1 or a != b:
    bad.append(f"compare-shipped-digests.sh invocation differs: release {a} vs rehearse-compare {b}")
else:
    print("ok   compare invocation:", b[0])
for s in jobs["rehearse-compare"]["steps"]:
    if "compare-shipped-digests.sh" in s.get("run", "") and s.get("continue-on-error"):
        bad.append("the comparison must not continue-on-error")
rb = jobs["rehearse-binaries"]
pk = next((s["run"] for s in rb["steps"] if s.get("name") == "package, SBOMs"), "")
if 'dist/encompute-$V-$T.tar.gz' not in pk or "pack.py" not in pk:
    bad.append("rehearse-binaries does not package the tarball like binaries")

# the existing jobs differ from the base only in their `if:` line
if base_ref:
    old = subprocess.run(["git", "-C", str(root), "show", f"{base_ref}:.github/workflows/release.yml"],
                         capture_output=True, text=True, check=True).stdout.splitlines()
    ostarts = {}
    for i, l in enumerate(old):
        m = re.match(r"^  ([a-z][a-z0-9-]*):\s*$", l)
        if m and m.group(1) in jobs:
            ostarts[m.group(1)] = i
    oorder = sorted(ostarts, key=ostarts.get)
    for n in REAL + DIAG + REH:
        i = ostarts[n]
        j = next((ostarts[o] for o in oorder if ostarts[o] > i), len(old))
        o = [l for l in old[i:j] if not re.match(r"^    if: ", l)]
        c = [l for l in job_text(n).splitlines() if not re.match(r"^    if: ", l)]
        # trailing blank/comment lines between jobs belong to the next job's header
        for x in (o, c):
            while x and (x[-1].strip() == "" or x[-1].startswith("  #")):
                x.pop()
        if o != c:
            bad.append(f"existing job {n} differs from {base_ref} beyond its `if:` line")
        else:
            print(f"ok   {n}: identical to {base_ref} except `if:`")

if bad:
    print("FAILED:", *bad, sep="\n  ")
    sys.exit(1)
print("OK: gating, permissions, forbidden strings, release-check fidelity, comparison")
