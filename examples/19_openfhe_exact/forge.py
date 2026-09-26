"""An attacker's tool for example 19: edits envelopes the way someone on the
network (or a malicious client) could, and sends them to the evaluator.

Checksums are not signatures: anyone can recompute them. Every edit below
reseals the outer envelope, so what refuses it is a binding check inside.

    forge.py header   IN OUT key=value...      rewrite outer header fields
    forge.py swap     IN OUT OTHER NAME        take input NAME from OTHER
    forge.py params   IN OUT NAME              edit NAME's inner parameter ID
    forge.py corrupt  IN OUT NAME              flip a ciphertext bit in NAME
                                               (outer checksum recomputed)
    forge.py post     URL PATH FILE            POST FILE; print the outcome
"""

import hashlib
import json
import struct
import sys
import urllib.error
import urllib.request

OUTER = b"ENCM"
INNER = b"ENCBINF1"


def read(path):
    b = open(path, "rb").read()
    assert b[:4] == OUTER, "not an Encompute envelope"
    n = struct.unpack("<I", b[6:10])[0]
    header = json.loads(b[10 : 10 + n])
    payload = b[10 + n : -32]
    items, at = {}, 0
    for it in header["items"]:
        items[it["name"]] = bytearray(payload[at : at + it["len"]])
        at += it["len"]
    return header, items


def write(path, header, items):
    header["items"] = [{"name": k, "len": len(v)} for k, v in items.items()]
    h = json.dumps(header, separators=(",", ":")).encode()
    body = OUTER + struct.pack("<HI", 1, len(h)) + h + b"".join(items.values())
    open(path, "wb").write(body + hashlib.sha256(body).digest())


def reseal_inner(e):
    body = bytes(e[:-32])
    e[-32:] = hashlib.sha256(body).digest()


def inner_offsets(e):
    assert bytes(e[:8]) == INNER, "not an OpenFHE exact ciphertext"
    n = struct.unpack("<I", e[12:16])[0]
    params = 16 + n
    return params, params + 32 + 16 + 2 + 4 + 8  # parameter ID, first payload


def main(cmd, *a):
    if cmd == "post":
        url, path, file = a
        req = urllib.request.Request(url + path, data=open(file, "rb").read(), method="POST")
        try:
            with urllib.request.urlopen(req) as r:
                print(f"HTTP {r.status}: accepted")
                return 0
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            try:
                body = json.loads(body).get("error", body)
            except ValueError:
                pass
            print(f"HTTP {e.code}: {body}")
            return 1
    src, out = a[0], a[1]
    header, items = read(src)
    if cmd == "header":
        for kv in a[2:]:
            k, v = kv.split("=", 1)
            header[k] = v
    elif cmd == "swap":
        _, other = read(a[2])
        items[a[3]] = other[a[3]]
    elif cmd == "params":
        e = items[a[2]]
        p, _ = inner_offsets(e)
        e[p] ^= 1
        reseal_inner(e)
    elif cmd == "corrupt":
        # Only the outer checksum is recomputed: the ciphertext's own
        # checksum must catch the flipped bit.
        e = items[a[2]]
        _, first = inner_offsets(e)
        e[first + 16] ^= 1
    else:
        raise SystemExit(__doc__)
    write(out, header, items)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
