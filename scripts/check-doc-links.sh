#!/usr/bin/env bash
# Checks that every relative link in the Markdown files resolves to a file
# or directory in the repository, and that a #fragment names a heading in
# the target Markdown file. Web links are not fetched.
#
#   scripts/check-doc-links.sh                 README, examples, docs, top-level pages
#   scripts/check-doc-links.sh FILE.md ...     only these files
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 - "$@" <<'PY'
import re, sys, pathlib

root = pathlib.Path.cwd()
args = sys.argv[1:]
if args:
    files = [pathlib.Path(a) for a in args]
else:
    files = sorted(
        set(root.glob("*.md"))
        | set((root / "docs").rglob("*.md"))
        | set((root / "examples").rglob("*.md"))
        | set((root / "deploy").rglob("*.md"))
        | set((root / "security-review").rglob("*.md"))
    )

def slug(h):
    h = re.sub(r"`", "", h.strip().lower())
    h = re.sub(r"[^\w\- ]", "", h)
    return h.replace(" ", "-")

def anchors(path):
    out, fence = set(), False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fence = not fence
        elif not fence and line.startswith("#"):
            out.add(slug(line.lstrip("#")))
    return out

link = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
bad = 0
checked = 0
for f in files:
    fence = False
    for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        line = re.sub(r"`[^`]*`", "", line)  # links inside code spans are not links
        for m in link.finditer(line):
            t = m.group(1)
            if re.match(r"[a-z][a-z0-9+.-]*:", t):
                continue
            path, _, frag = t.partition("#")
            dest = (f.parent / path).resolve() if path else f.resolve()
            checked += 1
            if not dest.exists():
                print(f"{f}:{n}: missing target {t}")
                bad += 1
            elif frag and dest.suffix == ".md" and slug(frag) not in anchors(dest):
                print(f"{f}:{n}: no heading for #{frag} in {dest.relative_to(root)}")
                bad += 1
print(f"{checked} relative links checked in {len(files)} files, {bad} broken")
sys.exit(1 if bad else 0)
PY
