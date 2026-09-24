"""Demo 1: encrypted logistic-regression scoring (32 features).

A client encrypts a feature vector; the evaluator scores it with public
weights without seeing the features or the score; the client decrypts.

    python examples/logistic_regression.py [--cases N] [--mode encrypted|mock]
"""

import argparse
import time

import numpy as np

import encompute
from encompute import Tensor, secret

FEATURES = 32


def train(seed: int = 0):
    """Plain logistic regression by gradient descent on synthetic data."""
    rng = np.random.default_rng(seed)
    true_w = rng.normal(0, 0.3, FEATURES)
    X = rng.uniform(-1, 1, (4000, FEATURES))
    y = (rng.uniform(size=4000) < 1 / (1 + np.exp(-(X @ true_w - 0.2)))).astype(float)
    w, b = np.zeros(FEATURES), 0.0
    for _ in range(500):
        p = 1 / (1 + np.exp(-(X @ w + b)))
        w -= 0.5 * X.T @ (p - y) / len(y)
        b -= 0.5 * float(np.mean(p - y))
    return w, b


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=int, default=200)
    ap.add_argument("--mode", default="encrypted" if encompute.has_openfhe() else "mock")
    args = ap.parse_args()

    w, b = train()

    @encompute.compile(precision=1e-3)
    def score(x: secret[Tensor[FEATURES], -1.0:1.0]):
        return encompute.sigmoid(encompute.dot(w, x) + b)

    print(score.explain())

    x = np.random.default_rng(1).uniform(-1, 1, FEATURES)
    t = time.perf_counter()
    enc = score(x, mode=args.mode)
    first = time.perf_counter() - t
    print(f"one {args.mode} score: {enc:.6f} (plaintext {score(x):.6f}), "
          f"{first * 1e3:.0f} ms including keygen")

    rep = score.test(cases=args.cases, mode=args.mode)
    print(rep)
    print(score.bench(reps=5, mode=args.mode))
    score.save("logistic.encompute")
    print("wrote logistic.encompute")
    raise SystemExit(0 if rep.passed else 1)


if __name__ == "__main__":
    main()
