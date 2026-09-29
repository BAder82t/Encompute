#!/usr/bin/env bash
# Reproducible-build pins: every input a release build takes is fixed and
# consistent. Fails on the first mismatch in each group; prints a table.
#
#   scripts/release/check-pins.sh [--network]   # --network: also resolve the OpenFHE tag upstream
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
status=0
row() { printf '%-30s %s\n' "$1" "$2"; }
bad() { row "$1" "FAIL: $2"; status=1; }

# Rust toolchain: rust-toolchain.toml, CI, the Dockerfiles.
tc="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)"
if ! echo "$tc" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then bad "Rust toolchain" "rust-toolchain.toml channel '$tc' is not an exact version"
else
  # fuzz.yml is exempt: cargo-fuzz needs a nightly compiler, and fuzzing
  # builds no release artifact.
  # Actions are pinned by commit SHA with the version as a comment.
  off="$(grep -hoE 'dtolnay/rust-toolchain@[^ ]+( # [^ ]+)?' $(ls .github/workflows/*.yml | grep -v '/fuzz.yml$') | sort -u | grep -vE "@[0-9a-f]{40} # $tc\$" || true)"
  dk="$(grep -h '^FROM rust:' Dockerfile.* deploy/confidential-space*/Dockerfile | grep -v "rust:$tc-" || true)"
  if [ -n "$off" ]; then bad "Rust toolchain" "workflows use $off (want $tc)"
  elif [ -n "$dk" ]; then bad "Rust toolchain" "Dockerfiles use $dk (want rust:$tc-*)"
  else row "Rust toolchain" "PASS ($tc: rust-toolchain.toml, workflows, Dockerfiles)"; fi
fi

# Cargo.lock is current (a release builds --locked).
if cargo metadata --format-version 1 --locked >/dev/null 2>&1; then row "Cargo.lock" "PASS (--locked resolves)"
else bad "Cargo.lock" "out of date: cargo metadata --locked fails"; fi

# Docker base images pinned by digest.
unpinned="$(grep -hE '^FROM ' Dockerfile.* deploy/confidential-space*/Dockerfile | grep -v '@sha256:[0-9a-f]\{64\}' | grep -vE '^FROM [a-z]+ AS|^FROM (runtime|build) ' || true)"
if [ -n "$unpinned" ]; then bad "Docker base images" "not pinned by digest: $(echo "$unpinned" | tr '\n' ';')"
else row "Docker base images" "PASS ($(grep -hcE '^FROM .*@sha256:' Dockerfile.* deploy/confidential-space*/Dockerfile | paste -sd+ - | bc) FROM lines pinned by digest)"; fi

# GitHub Actions pinned by full commit SHA, with the version as a comment.
unpinned_uses="$(grep -hE '^[[:space:]]*(- )?uses: ' .github/workflows/*.yml | grep -vE 'uses: [^ ]+@[0-9a-f]{40} # [^ ]+$' || true)"
if [ -n "$unpinned_uses" ]; then bad "GitHub Actions" "not pinned by commit SHA: $(echo "$unpinned_uses" | sed 's/^ *//' | tr '\n' ';')"
else row "GitHub Actions" "PASS ($(grep -hE '^[[:space:]]*(- )?uses: ' .github/workflows/*.yml | wc -l | tr -d ' ') uses pinned by SHA)"; fi

# OpenFHE: one version everywhere, a commit, and the install checks it.
v_inst="$(sed -n 's/^OPENFHE_VERSION="\(.*\)"/\1/p' scripts/install-openfhe.sh)"
c_inst="$(sed -n 's/^OPENFHE_COMMIT="\(.*\)"/\1/p' scripts/install-openfhe.sh)"
v_sbom="v$(sed -n 's/^OPENFHE_VERSION = "\(.*\)"/\1/p' scripts/sbom.py)"
c_sbom="$(sed -n 's/^OPENFHE_COMMIT = "\(.*\)"/\1/p' scripts/sbom.py)"
v_rev="$(sed -n 's/^version = "\(.*\)"/\1/p' security/openfhe-review.toml)"
c_rev="$(sed -n 's/^commit = "\(.*\)"/\1/p' security/openfhe-review.toml)"
if [ -z "$c_inst" ] || ! echo "$c_inst" | grep -qE '^[0-9a-f]{40}$'; then bad "OpenFHE pin" "no 40-hex OPENFHE_COMMIT in scripts/install-openfhe.sh"
elif ! grep -q 'rev-parse HEAD' scripts/install-openfhe.sh; then bad "OpenFHE pin" "install-openfhe.sh does not verify the commit"
elif [ "$v_inst" != "$v_sbom" ] || [ "$v_inst" != "$v_rev" ]; then bad "OpenFHE pin" "versions differ: install $v_inst, sbom $v_sbom, review $v_rev"
elif [ "$c_inst" != "$c_sbom" ] || [ "$c_inst" != "$c_rev" ]; then bad "OpenFHE pin" "commits differ: install $c_inst, sbom $c_sbom, review $c_rev"
else
  msg="$v_inst @ $c_inst"
  if [ "${1:-}" = "--network" ]; then
    up="$(git ls-remote https://github.com/openfheorg/openfhe-development.git "refs/tags/$v_inst" 2>/dev/null | cut -f1)"
    if [ "$up" != "$c_inst" ]; then bad "OpenFHE pin" "upstream tag $v_inst is ${up:-unresolvable}, pinned $c_inst"; msg=""; fi
    [ -z "$msg" ] || msg="$msg, upstream tag matches"
  fi
  if [ -n "$msg" ]; then
    src="${OPENFHE_SRC:-.deps/src/openfhe-development}"
    if [ -d "$src/.git" ] && [ "$(git -C "$src" rev-parse HEAD)" != "$c_inst" ]; then
      bad "OpenFHE pin" "the local source at $src is $(git -C "$src" rev-parse HEAD)"
    else row "OpenFHE pin" "PASS ($msg)"; fi
  fi
fi

# Python: the lock matches the training image's pins and pyproject's ranges.
lock=scripts/release/python/constraints.txt
req=deploy/confidential-space-training/requirements.txt
if [ ! -f "$lock" ]; then bad "Python lock" "no $lock (scripts/release/lock-python.sh)"
else
  miss=""
  while read -r pin; do
    n="${pin%%==*}"; v="${pin#*==}"
    grep -qiE "^$n==$v(\+[a-z0-9.]+)? " "$lock" || miss="$miss $pin"
  done < <(grep -E '^[A-Za-z0-9_.-]+==' "$req" | sed 's/ *#.*//')
  # The training image installs its own hashed lock: same versions as ours.
  img_lock=deploy/confidential-space-training/requirements.lock
  if [ -f "$img_lock" ]; then
    while read -r pin; do
      awk -v p="$pin" 'tolower($1)==tolower(p){f=1} END{exit !f}' "$lock" || miss="$miss $pin"
    done < <(grep -oE '^[A-Za-z0-9_.-]+==[^ ]+' "$img_lock")
  fi
  if [ -n "$miss" ]; then bad "Python lock" "differs from $req or $img_lock:$miss"
  elif python3 - "$lock" <<'PY'
import re, sys
try:
    import tomllib
except ImportError:
    sys.exit(0)
from importlib.util import find_spec
lock = dict(re.findall(r"^([a-z0-9_.-]+)==([^\s+\\]+)", open(sys.argv[1]).read(), re.M))
extras = tomllib.load(open("pyproject.toml", "rb"))["project"]["optional-dependencies"]
if find_spec("packaging") is None:
    sys.exit(0)
from packaging.requirements import Requirement
bad = []
for group in extras.values():
    for spec in group:
        r = Requirement(spec)
        v = lock.get(r.name.lower())
        if v is None or (r.specifier and v not in r.specifier):
            bad.append(f"{spec} (lock: {v})")
if bad:
    print("pyproject extras not satisfied by the lock: " + ", ".join(bad))
    sys.exit(1)
PY
  then row "Python lock" "PASS ($(grep -cE '^[a-z0-9]' "$lock") hashed pins; matches $req and pyproject extras)"
  else bad "Python lock" "see above"; fi
fi

# C++ toolchain: recorded, not pinned (docs/release-process.md).
cxx="$( (c++ --version 2>/dev/null || true) | head -n 1)"
cm="$( (cmake --version 2>/dev/null || true) | head -n 1)"
row "C++ toolchain (recorded)" "${cxx:-no c++}; ${cm:-no cmake}"

echo
[ $status -eq 0 ] && echo "PINS PASSED" || echo "PINS FAILED"
exit $status
