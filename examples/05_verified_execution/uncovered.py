"""A comparison is outside the proven subset: with verification="required"
this program must be refused at compile time (ENC1801)."""

import encompute
from encompute import secret, u8


@encompute.compile(verification="required")
def adult(age: secret[u8, 0:120]):
    return age >= 18
