"""Demo 2: encrypted embedding similarity (private semantic search).

The client encrypts a normalized 384-dimensional query embedding. The
evaluator computes its similarity to 64 public document embeddings without
seeing the query or the scores. The client decrypts the scores and ranks.

    python examples/01_ckks_private_inference/semantic_search.py [--mode encrypted|mock]
"""

import argparse

import numpy as np

import encompute
from encompute import Tensor, secret

DIM, DOCS = 384, 64


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="encrypted" if encompute.has_openfhe() else "mock")
    ap.add_argument("--cases", type=int, default=20)
    args = ap.parse_args()

    rng = np.random.default_rng(7)
    docs = rng.normal(size=(DOCS, DIM))
    docs /= np.linalg.norm(docs, axis=1, keepdims=True)

    @encompute.compile(precision=1e-3)
    def similarity(q: secret[Tensor[DIM], -1.0:1.0]):
        return docs @ q

    print(similarity.explain())

    # A query close to document 17.
    q = docs[17] + 0.05 * rng.normal(size=DIM)
    q /= np.linalg.norm(q)
    scores = np.array(similarity(q, mode=args.mode))
    plain = docs @ q
    top = np.argsort(-scores)[:5]
    print(f"top-5 ({args.mode}): {top.tolist()}  plaintext: {np.argsort(-plain)[:5].tolist()}")
    print(f"max score error: {np.max(np.abs(scores - plain)):.2e}")

    rep = similarity.test(cases=args.cases, mode=args.mode)
    print(rep)
    print(similarity.bench(reps=5, mode=args.mode))
    ok = rep.passed and top[0] == 17
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
