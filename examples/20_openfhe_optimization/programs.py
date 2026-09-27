"""Example 20: optimized exact execution.

    encompute compile programs.py:eligibility   comparisons: BinFHE, optimized circuit
    encompute compile programs.py:score         u8/u16 arithmetic: selected for BGV
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


# Additions and multiplications by constants only: every operation is in
# the BGV subset, so the whole program runs on BGV, which is far cheaper
# than bootstrapping every gate.
@encompute.compile()
def score(visits: secret[u16, 0:50], spend: secret[u16, 0:2000]):
    return visits * 3 + spend * 2 + 7
