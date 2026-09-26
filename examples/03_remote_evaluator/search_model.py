"""The 0.2 demo model: a 384-d encrypted query against 64 public documents.

    python examples/03_remote_evaluator/search_model.py OUT_DIR

writes OUT_DIR/search.encompute (compiled artifact), OUT_DIR/query.json
(client input) and OUT_DIR/expected.json (plaintext scores, for checking).
"""

import json
import sys
from pathlib import Path

import numpy as np

import encompute
from encompute import Tensor, secret

DIM, DOCS = 384, 64

out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
out.mkdir(parents=True, exist_ok=True)
rng = np.random.default_rng(7)
docs = rng.normal(size=(DOCS, DIM))
docs /= np.linalg.norm(docs, axis=1, keepdims=True)


@encompute.compile(precision=1e-3)
def search(q: secret[Tensor[DIM], -1.0:1.0]):
    return docs @ q


search.save(str(out / "search.encompute"))
q = docs[17] + 0.05 * rng.normal(size=DIM)
q /= np.linalg.norm(q)
(out / "query.json").write_text(json.dumps({"q": q.tolist()}))
(out / "expected.json").write_text(json.dumps({"out": (docs @ q).tolist()}))
print(f"wrote {out}/search.encompute, query.json, expected.json")
