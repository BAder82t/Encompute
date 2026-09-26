"""Canonical tensor serialization: a JSON header (name, dtype, shape,
offset, length) and the raw little-endian bytes. Deterministic, so its
SHA-256 is a stable commitment, and loading it runs no code (unlike a
pickle)."""

from __future__ import annotations

import json
from typing import Dict

import numpy as np
import torch

MAGIC = b"ENCTENS1"
DTYPES = {"float32": torch.float32, "float64": torch.float64, "int64": torch.int64}


def dumps(tensors: Dict[str, torch.Tensor]) -> bytes:
    header = []
    body = bytearray()
    for name in sorted(tensors):
        t = tensors[name].detach().cpu().contiguous()
        dtype = str(t.dtype).replace("torch.", "")
        if dtype not in DTYPES:
            raise ValueError(f"{name}: unsupported dtype {dtype}")
        raw = t.numpy().astype(t.numpy().dtype.newbyteorder("<"), copy=False).tobytes()
        header.append({"name": name, "dtype": dtype, "shape": list(t.shape),
                       "offset": len(body), "length": len(raw)})
        body += raw
    h = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    return MAGIC + len(h).to_bytes(4, "little") + h + bytes(body)


def loads(data: bytes) -> Dict[str, torch.Tensor]:
    """Loads a canonical tensor file, after the native validator (the single
    authority for this format) has checked it: a pickle, or a malformed or
    padded file, is refused before anything is read."""
    from .. import _native

    try:
        header = json.loads(_native.tensor_manifest(bytes(data)))
    except _native.NativeError as e:
        raise ValueError(e.args[1]) from None
    n = int.from_bytes(data[8:12], "little")
    body = memoryview(data)[12 + n:]
    out = {}
    for e in header:
        raw = bytes(body[e["offset"]:e["offset"] + e["length"]])
        np_dtype = np.dtype(e["dtype"]).newbyteorder("<")
        arr = np.frombuffer(raw, dtype=np_dtype).reshape(e["shape"]).copy()
        out[e["name"]] = torch.from_numpy(arr)
    return out
