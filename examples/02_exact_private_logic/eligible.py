"""02: exact private logic on encrypted integers and Booleans.

    python eligible.py

The client encrypts age, income and risk score; the evaluator decides
eligibility on ciphertexts and returns an encrypted Boolean. Exact
programs have no approximation error: every mode must agree bit for bit.
"""

import encompute
from encompute import secret, u8, u16, u32


@encompute.compile()
def eligible(
    age: secret[u8, 0:120],
    income: secret[u32, 0:1_000_000],
    risk: secret[u16, 0:1000],
):
    return (age >= 18) & (income >= 40_000) & (risk <= 650)


# Each case sits on or next to a threshold: >=, <= and & must be exact.
CASES = [
    (dict(age=31, income=52_000, risk=410), True),
    (dict(age=18, income=40_000, risk=650), True),
    (dict(age=17, income=52_000, risk=410), False),
    (dict(age=31, income=39_999, risk=410), False),
    (dict(age=31, income=52_000, risk=651), False),
]


def main():
    enc = encompute.has_exact()
    print(f"Scheme            {eligible.semantics} (OpenFHE exact: integers and Booleans)")
    if not enc:
        print("Encrypted mode    not run: OpenFHE is not in this build")
    ok = True
    for inputs, want in CASES:
        clear = eligible(**inputs)
        mock = eligible(**inputs, mode="mock")
        results = [clear, mock]
        if enc:
            results.append(eligible(**inputs, mode="encrypted"))
        same = all(r == want for r in results)
        ok &= same
        args = " ".join(f"{k}={v}" for k, v in inputs.items())
        print(f"{args:<34} clear={clear!s:<5} mock={mock!s:<5}"
              + (f" encrypted={results[2]!s:<5}" if enc else "")
              + ("  MATCH" if same else "  MISMATCH"))
    # Sampled inputs on the mock: encrypted, every case costs seconds.
    rep = eligible.test(cases=500, mode="mock")
    print(f"Sampled inputs    {rep.cases} cases, {rep.mismatches} mismatches")
    ok &= rep.passed
    print("MATCH" if ok else "MISMATCH")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
