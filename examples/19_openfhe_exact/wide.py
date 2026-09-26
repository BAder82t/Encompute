"""Outside the capability matrix: OpenFHE exact evaluates lookups as
multiplexer trees and supports tables up to 256 entries, so compiling this
1001-entry table fails with ENC1501.

    encompute compile wide.py:wide
"""

import encompute
from encompute import secret, u16


@encompute.compile()
def wide(score: secret[u16, 0:1000]):
    return encompute.lookup(score, list(range(1001)))
