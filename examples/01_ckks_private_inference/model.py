"""01: approximate private inference with CKKS.

A logistic-regression score over 32 private features. The client encrypts
the features; the evaluator computes on ciphertexts; the client decrypts.
The same compiled program runs in three modes, and the results must agree
within the declared precision.

    python model.py [--encrypted]
"""

import sys

import numpy as np

import encompute
from encompute import Tensor, secret

FEATURES = 32
rng = np.random.default_rng(0)
weights = rng.normal(0, 0.3, FEATURES)
bias = -0.2


@encompute.compile(precision=1e-3)
def score(x: secret[Tensor[FEATURES], -1.0:1.0]):
    return encompute.sigmoid(encompute.dot(weights, x) + bias)


def main():
    encrypted = "--encrypted" in sys.argv
    x = np.random.default_rng(1).uniform(-1, 1, FEATURES)

    clear = score(x)                      # plaintext reference semantics
    mock = score(x, mode="mock")          # the compiled plan, unencrypted
    print(f"Scheme            {score.semantics} (CKKS)")
    print(f"Clear result      {clear:.5f}")
    print(f"Mock result       {mock:.5f}")
    results = [("mock", mock)]
    if encrypted:
        enc = score(x, mode="encrypted")  # OpenFHE: the evaluator sees ciphertexts
        print(f"Encrypted result  {enc:.5f}")
        results.append(("encrypted", enc))

    worst = max(abs(r - clear) for _, r in results)
    print(f"Absolute error    {worst:.5f}")
    print("Allowed error     0.00100")
    ok = worst <= 1e-3
    # Over many sampled inputs, not just one.
    rep = score.test(cases=100, mode=results[-1][0])
    print(f"Sampled inputs    {rep.cases} cases, max error {rep.max_error:.2e}")
    print("PASS" if ok and rep.passed else "FAIL")
    raise SystemExit(0 if ok and rep.passed else 1)


if __name__ == "__main__":
    main()
