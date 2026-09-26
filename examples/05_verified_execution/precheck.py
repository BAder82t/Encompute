"""05: a loan pre-check that requires verified execution.

    encompute compile precheck.py:precheck

Every operation is in the proven subset (u8/u16/bool; add, sub, mul,
constants; and/or/xor/not), so it compiles to OpenFHE BGV and every result
must carry an execution proof: no proof, no decryption.
"""

import encompute
from encompute import bool_, secret, u16


@encompute.compile(verification="required")
def precheck(income: secret[u16, 0:5000], member: secret[bool_], flagged: secret[bool_]):
    return {"score": income * 3 + 7, "ok": member & ~flagged}
