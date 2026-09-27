#!/usr/bin/env python3
"""A deterministic .tar.gz: sorted entries, fixed owner, modes normalized,
every mtime (and the gzip header's) set to SOURCE_DATE_EPOCH. The same
files give the same bytes on Linux and macOS.

    scripts/release/pack.py OUT.tar.gz PREFIX FILE[=NAME] ...
"""

import gzip
import io
import os
import sys
import tarfile


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    out, prefix, items = sys.argv[1], sys.argv[2].strip("/"), sys.argv[3:]
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or 0)
    entries = []
    for it in items:
        src, _, name = it.partition("=")
        entries.append((f"{prefix}/{name or os.path.basename(src)}", src))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for arc, src in sorted(entries):
            info = tarfile.TarInfo(arc)
            data = open(src, "rb").read()
            info.size = len(data)
            info.mtime = epoch
            info.mode = 0o755 if os.access(src, os.X_OK) else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    with open(out, "wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f,
                                             mtime=epoch, compresslevel=9) as gz:
        gz.write(buf.getvalue())
    return 0


if __name__ == "__main__":
    sys.exit(main())
