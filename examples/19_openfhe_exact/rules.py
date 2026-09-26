"""Example 19: exact programs on OpenFHE exact.

    encompute compile rules.py:screen      Boolean logic
    encompute compile rules.py:tier        a table lookup on an encrypted index

The eligibility rule is examples/02_exact_private_logic/eligibility.py.
"""

import encompute
from encompute import bool_, secret, u8, u16


@encompute.compile()
def screen(member: secret[bool_], consent: secret[bool_], flagged: secret[bool_]):
    return member & consent & ~flagged


# Risk tier of a 0..255 score, read from a table the evaluator sees but
# indexed by a value it cannot.
TIERS = [3, 1, 4, 1, 5, 9, 2, 6]


@encompute.compile()
def tier(score: secret[u8, 0:255]):
    return encompute.lookup(score >> 5, TIERS)

