"""General discrete-log solver — Pohlig-Hellman + BSGS (pure standard library)

DLP in CTF comes in basically three kinds: small modulus (BSGS), smooth modulus
(Pohlig-Hellman), special structure (anomalous/SSSA — those are left to the
skeleton; we do not pretend to compute them).
One entry point, `discrete_log`, picks the route and says which one it used.
"""

import math

from .algebra import bsgs, factor_limited, gcd, is_prime, modinv


def bsgs_order(g, h, p, order, max_m: int = 1 << 22):
    """BSGS under a known group order (faster and more accurate than mod p-1)"""
    m = math.isqrt(order) + 1
    if m > max_m:
        return None
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    factor = modinv(pow(g, m, p), p)
    if factor is None:
        return None
    gamma = h % p
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def pohlig_hellman(g, h, p, order=None, factors=None, max_m: int = 1 << 20):
    """Pohlig-Hellman: when the group order is smooth, split the DLP into DLPs
    over small prime powers and recombine them with CRT

    Returns:
        {"x", "order", "factors", "used"} or None (order not smooth / over budget)
    """
    p = int(p)
    order = order or (p - 1)
    if factors is None:
        factors = factor_limited(order, max_steps=300000)
        if factors is None:
            return None
    if not factors:
        return None
    from .algebra import crt as _crt
    residues = []
    for q, e in factors.items():
        qe = q ** e
        # push g down into the order-q^e subgroup
        gi = pow(g, order // qe, p)
        hi = pow(h, order // qe, p)
        # find x mod q^e digit by digit
        x_k = 0
        gamma = pow(gi, q ** (e - 1), p)
        for k in range(e):
            # h_k = (h * g^{-x_k})^{q^{e-1-k}}
            exp = order // qe * q ** (e - 1 - k)
            hk = pow(hi * modinv(pow(gi, x_k, p), p) % p, q ** (e - 1 - k), p)
            d = bsgs(gamma, hk, p, q, max_m=max_m)
            if d is None:
                return None
            x_k += d * (q ** k)
        residues.append((x_k % qe, qe))
    res = _crt(residues)
    if not res:
        return None
    x, m = res
    return {"x": x, "order": order, "modulus": m,
            "factors": {str(k): v for k, v in factors.items()},
            "used": "Pohlig-Hellman"}


def discrete_log(g, h, p, order=None, max_m: int = 1 << 22):
    """Single entry point: small-group BSGS → smooth-order Pohlig-Hellman → give
    up (and say why)

    Returns: {"x": int, "used": str} or {"x": None, "note": str}
    """
    g, h, p = int(g), int(h), int(p)
    order = order or (p - 1)
    if p.bit_length() <= 48:
        x = bsgs(g, h, p, order, max_m=max_m)
        if x is not None and pow(g, x, p) == h % p:
            return {"x": x, "used": "BSGS (small group)"}
    ph = pohlig_hellman(g, h, p, order)
    if ph and pow(g, ph["x"], p) == h % p:
        return {"x": ph["x"], "used": ph["used"],
                "note": f"order factored as {ph['factors']}"}
    return {"x": None,
            "note": "BSGS over budget and the group order is not smooth — needs a "
                    "special-structure attack (anomalous/SSSA etc.), write that by "
                    "hand in the workbench"}


def is_smooth(n: int, bound: int = 10 ** 6):
    """Is n B-smooth (a feasibility pre-check for Pohlig-Hellman)"""
    fac = factor_limited(n, max_steps=300000)
    if fac is None:
        return False, None
    return all(q <= bound for q in fac), fac


def dlog_feasibility(p, bound: int = 10 ** 6):
    """Do not solve anything; just judge whether this DLP falls to the generic
    methods → a verdict plus the reason
    Returns: {"feasible": bool, "why": str} - a judgement only, never a
             solution.
    """
    order = p - 1
    if p.bit_length() <= 48:
        return {"feasible": True, "why": f"modulus is only {p.bit_length()} bits, BSGS suffices"}
    smooth, fac = is_smooth(order, bound)
    if smooth:
        return {"feasible": True,
                "why": f"group order {order} is {bound}-smooth → Pohlig-Hellman"}
    if fac is None:
        return {"feasible": False,
                "why": "factorising the group order is over budget (large prime factor)"}
    big = [q for q in fac if q > bound]
    return {"feasible": False,
            "why": f"group order has a large prime factor {big[:2]} → generic "
                   "methods fail, needs a special-structure attack"}
