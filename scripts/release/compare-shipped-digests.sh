#!/usr/bin/env bash
# Refuses to sign Linux binaries that are not the ones the release check
# reproduced. `release-check.sh --repro` builds the three release binaries
# twice and keeps the digests of the matching builds (repro-check.sh
# --digests); the `binaries` job builds the ones that are packaged, apart from
# that. Reproducibility makes the two builds the same bytes, and this script
# checks they are: the SHA-256 of each binary in the Linux tarball must equal
# the digest the gate recorded.
#
#   scripts/release/compare-shipped-digests.sh DIGESTS TARBALL [NAME ...]
#
# DIGESTS has lines "sha256  name". NAMEs default to the three release
# binaries. The set of names in DIGESTS must be exactly NAMEs, the tarball
# must hold each NAME once, and nothing else but the licence files that
# scripts/release/pack.py is given in the release workflow. Exit 0 only when
# every one matches. macOS arm64 binaries are not compared: no gate build
# exists for them (docs/release-process.md).
set -uo pipefail
if [ $# -lt 2 ]; then echo "usage: $0 DIGESTS TARBALL [NAME ...]" >&2; exit 2; fi
digests="$1"; tarball="$2"; shift 2
names=("$@")
[ ${#names[@]} -gt 0 ] || names=(encompute encompute-evaluator encompute-control)
fail() { echo "SHIPPED DIGESTS DIFFER: $*"; exit 1; }
[ -f "$digests" ] || fail "no gate digests at $digests (the release check did not record them)"
[ -f "$tarball" ] || fail "no tarball at $tarball"
python3 -I - "$digests" "$tarball" "${names[@]}" <<'PY'
import hashlib, re, sys, tarfile

digests, tarball, names = sys.argv[1], sys.argv[2], sys.argv[3:]
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
DOCS = {"LICENSE", "LICENSING.md", "THIRD_PARTY_NOTICES.md"}


def die(msg):
    print(f"SHIPPED DIGESTS DIFFER: {msg}")
    sys.exit(1)


want = {}
text = open(digests).read()
if text and not text.endswith("\n"):
    die(f"{digests} ends in a truncated line")
for n, line in enumerate(text.splitlines(), 1):
    m = re.fullmatch(r"([0-9a-f]{64})  ([\w.-]+)", line)
    if not m:
        die(f"{digests} line {n} is not 'sha256  name'")
    if m.group(1) == EMPTY:
        die(f"{digests} records the digest of empty input for {m.group(2)}")
    if m.group(2) in want:
        die(f"{digests} names {m.group(2)} twice")
    want[m.group(2)] = m.group(1)
got = {}
extra = []
with tarfile.open(tarball) as tar:
    for member in tar.getmembers():
        if member.isdir():
            continue
        base = member.name.rsplit("/", 1)[-1]
        if not member.isfile():
            extra.append(f"{member.name}: not a regular file")
        elif base in names:
            if base in got:
                die(f"{tarball} holds {base} twice")
            got[base] = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
        elif base not in DOCS:
            extra.append(f"{member.name}: not a binary the gate reproduced")
bad = []
for n in names:
    if n not in want:
        bad.append(f"{n}: the gate recorded no digest")
    elif n not in got:
        bad.append(f"{n}: not in {tarball}")
    elif want[n] != got[n]:
        bad.append(f"{n}: gate build {want[n]}, shipped {got[n]}")
    else:
        print(f"{n:24} {got[n]}  MATCH")
for n in sorted(set(want) - set(names)):
    bad.append(f"{n}: the gate recorded a digest for a file that is not a release binary")
bad += extra
if bad:
    print("SHIPPED DIGESTS DIFFER:\n  " + "\n  ".join(bad))
    sys.exit(1)
print(f"SHIPPED DIGESTS MATCH: {len(names)} binaries in {tarball} are the ones the release check reproduced")
PY
