#!/usr/bin/env python3
"""A throwaway OpenID Connect identity provider for tests: an ES256 key, its
JWKS, and signed ID tokens. Never use it for anything real.

    test-idp.py keygen DIR                   writes DIR/idp.pem (0600) and DIR/jwks.json
    test-idp.py token DIR SUBJECT [--iss URL] [--aud AUD] [--ttl SECONDS]
"""

import base64
import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

KID = "test-idp-1"


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def keygen(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)
    k = ec.generate_private_key(ec.SECP256R1())
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    p = d / "idp.pem"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    n = k.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": KID, "use": "sig", "alg": "ES256",
           "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}
    (d / "jwks.json").write_text(json.dumps({"keys": [jwk]}))


def token(d: Path, sub: str, iss: str, aud: str, ttl: int) -> str:
    k = serialization.load_pem_private_key((d / "idp.pem").read_bytes(), None)
    header = b64(json.dumps({"alg": "ES256", "typ": "JWT", "kid": KID}).encode())
    now = int(time.time())
    payload = b64(json.dumps({"iss": iss, "aud": aud, "sub": sub, "iat": now, "exp": now + ttl}).encode())
    der = k.sign(f"{header}.{payload}".encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{header}.{payload}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def main(argv):
    if len(argv) >= 2 and argv[0] == "keygen":
        keygen(Path(argv[1]))
        return 0
    if len(argv) >= 3 and argv[0] == "token":
        opts = {"--iss": "https://idp.test.invalid", "--aud": "encompute", "--ttl": "3600"}
        rest = argv[3:]
        for i in range(0, len(rest) - 1, 2):
            opts[rest[i]] = rest[i + 1]
        print(token(Path(argv[1]), argv[2], opts["--iss"], opts["--aud"], int(opts["--ttl"])))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
