"""Private eligibility: an exact (integer/Boolean) Encompute program.

    python examples/02_exact_private_logic/eligibility.py              # run in clear and mock modes
    encompute compile examples/02_exact_private_logic/eligibility.py:eligibility

The evaluator computes the decision on encrypted inputs and returns an
encrypted Boolean; only the client can decrypt it. With the research
`tfhe-rs` build, mode="encrypted" runs on TFHE-rs.
"""

import encompute
from encompute import secret, u8, u16, u32


@encompute.compile()
def eligibility(
    age: secret[u8, 0:120],
    income: secret[u32, 0:1_000_000],
    debt: secret[u32, 0:500_000],
    risk: secret[u16, 0:1000],
):
    adult = age >= 18
    debt_ok = debt * 100 < income * 40
    risk_ok = risk <= 650
    return adult & debt_ok & risk_ok


if __name__ == "__main__":
    applicant = dict(age=31, income=120_000, debt=21_000, risk=400)
    print("clear:", eligibility(**applicant))
    print("mock: ", eligibility(**applicant, mode="mock"))
    if encompute.has_tfhe():
        print("tfhe: ", eligibility(**applicant, mode="encrypted"))
    print(eligibility.test(cases=1000))
    print(eligibility.explain())
