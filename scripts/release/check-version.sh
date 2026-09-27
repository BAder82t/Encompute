#!/usr/bin/env bash
# A release tag must match the versions the artifacts carry:
#   tag v0.3.0-rc.1  ->  Cargo workspace 0.3.0-rc.1, pyproject 0.3.0rc1
#   tag v0.3.0       ->  Cargo workspace 0.3.0,      pyproject 0.3.0
#
#   scripts/release/check-version.sh v0.3.0-rc.1
set -euo pipefail
cd "$(dirname "$0")/../.."
TAG="${1:?usage: $0 vX.Y.Z[-rc.N]}"
if ! echo "$TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then
  echo "tag $TAG is not vX.Y.Z or vX.Y.Z-rc.N" >&2
  exit 1
fi
want="${TAG#v}"
want_py="$(echo "$want" | sed -E 's/-rc\.([0-9]+)$/rc\1/')"
cargo_v="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)"
py_v="$(sed -n '/^\[project\]/,/^\[/s/^version = "\(.*\)"/\1/p' pyproject.toml)"
ok=1
[ "$cargo_v" = "$want" ] || { echo "Cargo.toml workspace version is $cargo_v, the tag says $want" >&2; ok=0; }
[ "$py_v" = "$want_py" ] || { echo "pyproject.toml version is $py_v, the tag says $want_py" >&2; ok=0; }
if ! cargo metadata --format-version 1 --locked >/dev/null 2>&1; then
  echo "Cargo.lock is out of date for version $cargo_v (cargo update -w)" >&2; ok=0
fi
[ $ok = 1 ] && echo "version $want (Python $want_py) matches $TAG"
[ $ok = 1 ]
