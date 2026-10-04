"""00: hello, encrypted. A five-minute first run.

A clinic has four private test results. A risk service has a small model.
The service scores the results without ever seeing them. This script plays
both roles in one process and explains each step as it goes.

    python hello.py [--encrypted]

Without OpenFHE in the build it runs in mock mode, which checks the same
plan but encrypts nothing, and says so.
"""

import sys

import encompute
from encompute import Tensor, secret

# The risk service's model. These weights are public to the evaluator.
WEIGHTS = [0.8, -0.5, 1.2, 0.3]
BIAS = -0.4


@encompute.compile(precision=1e-3)
def risk(panel: secret[Tensor[4], 0.0:1.0]):
    return encompute.sigmoid(encompute.dot(WEIGHTS, panel) + BIAS)


def refused(what, build):
    """Builds or runs something unsafe and prints the refusal."""
    try:
        build()
    except encompute.EncomputeError as e:
        print(f"  tried: {what}")
        print(f"  refused: {e}")
        return True
    print(f"  NOT REFUSED (this is a bug): {what}")
    return False


def main():
    encrypted = "--encrypted" in sys.argv
    mode = "encrypted" if encrypted else "mock"
    panel = [0.62, 0.18, 0.91, 0.40]  # the clinic's private values, each in [0, 1]

    print("Step 1. The clinic's private data (the evaluator never sees this)")
    print(f"  panel = {panel}")

    print("\nStep 2. What the risk service is told: the program, not the data")
    sec = risk.security
    print(f"  scheme    {sec['scheme']} ({risk.semantics}), {sec['security_level']}")
    print("  the evaluator can see:")
    for item in sec["evaluator_observes"]:
        print(f"    - {item}")
    print(f"  evaluator receives the secret key: {'yes' if sec['evaluator_receives_secret_key'] else 'no'}")

    if encrypted:
        print("\nStep 3. Encrypt, compute while encrypted, decrypt")
        result = risk(panel, mode="encrypted")
        b = risk.bench(reps=1, mode="encrypted")
        print("  (the sizes below come from a second encrypted run with fresh keys)")
        print("  the clinic made a secret key and public keys, and encrypted the panel")
        print(f"  the evaluator received {b['request_bytes']:,} bytes of ciphertext")
        print(f"    and {b['evaluation_key_bytes']:,} bytes of evaluation keys (no secret key)")
        print("  the evaluator computed sigmoid(weights . panel + bias) on ciphertext")
        print(f"  it returned {b['response_bytes']:,} bytes: one ciphertext only the clinic can open")
        print(f"  the clinic decrypted it (timings in ms: keygen {b['keygen_ms']:.0f}, "
              f"encrypt {b['encrypt_ms']:.0f}, evaluate {b['evaluate_ms']:.0f}, decrypt {b['decrypt_ms']:.0f})")
    else:
        print("\nStep 3. Compute (mock mode: nothing is encrypted in this run)")
        print("  OpenFHE is not in this build, so this ran the same plan on plain numbers.")
        print("  Use a build with OpenFHE (the released wheel has it) to see real encryption.")
        result = risk(panel, mode="mock")

    print("\nStep 4. Check the answer against plain Python")
    clear = risk(panel)
    error = abs(result - clear)
    print(f"  plain result      {clear:.5f}")
    print(f"  {mode + ' result':<17} {result:.5f}")
    print(f"  difference        {error:.5f}  (allowed: 0.00100)")

    print("\nStep 5. What Encompute refuses to do")
    ok = refused("a value outside the declared range [0, 1]", lambda: risk([2.0, 0, 0, 0], mode=mode))

    def branch():
        @encompute.compile()
        def leaky(p: secret[Tensor[4], 0.0:1.0]):
            if encompute.sum(p) > 0.5:
                return p
            return p

    ok &= refused("an if-statement on a secret", branch)

    def show():
        @encompute.compile()
        def noisy(p: secret[Tensor[4], 0.0:1.0]):
            print(p)
            return p

    ok &= refused("printing a secret", show)

    passed = ok and error <= 1e-3
    print("\nPASS" if passed else "\nFAIL")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
