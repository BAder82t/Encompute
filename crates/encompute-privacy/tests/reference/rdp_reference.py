"""Reference vectors for the Rényi DP accountant (crates/encompute-privacy
src/rdp.rs), computed independently of it:

- autodp's `rdp_acct.general_upperbound` (Zhu and Wang 2019, Theorem 6;
  exact for orders up to 51, where autodp's truncation covers every term);
- an arbitrary-precision (mpmath, 60 digits) implementation of the same
  theorem for every order the accountant uses (2..256, then to 1024),
  which must agree with autodp where both apply;
- the CKS 2020 Proposition 12 conversion to (epsilon, delta), in mpmath.

    pip install autodp mpmath
    python rdp_reference.py > rdp_vectors.json
"""

import json

import mpmath as mp
from autodp import rdp_acct

mp.mp.dps = 60
ORDERS = list(range(2, 257)) + [288, 320, 384, 448, 512, 640, 768, 1024]


def theorem6(rho, q, alpha):
    rho, q = mp.mpf(rho), mp.mpf(q)
    a = alpha
    s = (1 - q) ** (a - 1) * (a * q - q + 1)
    s += mp.binomial(a, 2) * q**2 * (1 - q) ** (a - 2) * mp.e ** (2 * rho)
    for j in range(3, a + 1):
        s += 3 * mp.binomial(a, j) * q**j * (1 - q) ** (a - j) * mp.e ** ((j - 1) * j * rho)
    return mp.log(s) / (a - 1)


def autodp_expression(rho, q, a):
    """autodp's rearrangement of Theorem 6 (general_upperbound), transcribed
    term for term into 60-digit arithmetic, divided by (a - 1). It must
    equal `theorem6` to many digits: the same bound, rearranged. autodp's
    own float evaluation subtracts nearly equal terms, and drifts at high
    orders."""
    rho, q = mp.mpf(rho), mp.mpf(q)
    f = lambda x: x * rho  # noqa: E731
    cgf = lambda x: (x - 1) * f(x)  # noqa: E731
    pos = (1 - q) ** a + 3 * mp.e ** (-f(a)) * ((1 - q) + q * mp.e ** f(a)) ** a
    neg = 0
    for l in range(3, a):  # autodp's cur_k = a - 1 for orders <= 51
        neg += mp.binomial(a, l) * 3 * (1 - q) ** (a - l) * q**l * (
            mp.e ** ((l - 1) * f(a)) - mp.e ** cgf(l))
    neg += a * (a - 1) / 2 * q**2 * (1 - q) ** (a - 2) * (3 * mp.e ** f(a) - mp.e ** f(2))
    neg += 2 * q * a * (1 - q) ** (a - 1)
    neg += (1 - q) ** a * 3 * mp.e ** (-f(a))
    return mp.log(pos - neg) / (a - 1)


def curve(rho, q):
    return [min(theorem6(rho, q, a), a * mp.mpf(rho)) for a in ORDERS]


def epsilon(total, delta):
    delta = mp.mpf(delta)
    best = mp.inf
    for r, a in zip(total, ORDERS):
        e = r + (mp.log(1 / delta) + (a - 1) * mp.log(1 - mp.mpf(1) / a) - mp.log(a)) / (a - 1)
        best = min(best, e)
    return max(best, 0)


cases = []
for z in (0.8, 1.0, 1.2, 2.0, 4.0):
    rho = 1 / (2 * z * z)
    for q in (0.001, 0.01, 0.0128, 0.05, 0.1, 0.5):
        c = curve(rho, q)
        # Independent checks against autodp, orders 3..51:
        # - its expression, in 60 digits, is the same bound (to 1e-40);
        # - its own float evaluation agrees up to its cancellation error,
        #   and never below the exact value by more than that error.
        for a in range(3, 52):
            mine = theorem6(rho, q, a)
            assert abs(autodp_expression(rho, q, a) - mine) <= mp.mpf(10) ** -40 * max(1, abs(mine))
            ref = rdp_acct.general_upperbound(lambda x: x * rho, a, q) / (a - 1)
            assert abs(ref - float(mine)) <= 1e-3 * max(1e-12, abs(float(mine))), (z, q, a, ref, mine)
        for delta in (1e-5, 1e-6):
            for steps in (1, 10, 100, 1000):
                cases.append({
                    "rho": rho, "q": q, "steps": steps, "delta": delta,
                    "curve": [float(x) for x in c],
                    "epsilon": float(epsilon([x * steps for x in c], delta)),
                })
print(json.dumps({"orders": ORDERS, "source": "autodp general_upperbound + mpmath",
                  "cases": cases}, indent=0))
