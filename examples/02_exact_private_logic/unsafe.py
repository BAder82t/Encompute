"""A deliberately unsafe exact program: income * 1_000_000 can reach 10^12,
which does not fit in u32. Compilation must refuse it (ENC1303)."""

import encompute
from encompute import secret, u32


@encompute.compile()
def scaled(income: secret[u32, 0:1_000_000]):
    return income * 1_000_000
