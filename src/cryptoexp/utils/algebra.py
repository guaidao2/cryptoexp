"""Number-theory infrastructure — pure standard library (zero core dependencies)

Includes: extended Euclid / modular inverse / CRT / integer square and k-th roots /
Miller-Rabin primality / Pollard rho (Brent) factorisation / continued fractions
and convergents / Wiener attack / Fermat factorisation / baby-step giant-step
discrete log / Tonelli-Shanks modular square root / LCG parameter recovery.

Optional accelerator: when gmpy2 is installed its is_prime / gcd are used for
speed (auto-detected; its absence does not affect correctness).
"""

import math
import random

try:  # optional accelerator, core usability is unaffected
    import gmpy2 as _gmpy2
except Exception:  # pragma: no cover - environment dependent
    _gmpy2 = None

HAS_GMPY2 = _gmpy2 is not None


# ────────────────────────── basics ──────────────────────────

def egcd(a: int, b: int):
    """Extended Euclid → (g, x, y) with a*x + b*y = g"""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def gcd(a: int, b: int) -> int:
    if _gmpy2 is not None:
        return int(_gmpy2.gcd(a, b))
    return math.gcd(a, b)


def lcm(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return abs(a // gcd(a, b) * b)


def modinv(a: int, m: int):
    """Modular inverse; returns None when it does not exist
    (never raises — the caller decides what to do)"""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        return None
    return x % m


def crt(congruences):
    """Chinese remainder theorem: [(a1, m1), (a2, m2), ...] → (x, M);
    the moduli must be pairwise coprime

    Returns None when they are not coprime — the caller must judge that itself
    (it is, for example, the precondition of the RSA common-modulus case).
    """
    if not congruences:
        return None
    x, M = 0, 1
    for a, m in congruences:
        g = gcd(M, m)
        if g != 1:
            return None
        M2 = M * m
        # x + M*t ≡ a (mod m)
        inv = modinv(M % m, m)
        if inv is None:
            return None
        t = ((a - x) % m) * inv % m
        x = (x + M * t) % M2
        M = M2
    return x % M, M


def isqrt(n: int) -> int:
    if n < 0:
        raise ValueError("isqrt: negative number")
    return math.isqrt(n)


def iroot(n: int, k: int):
    """Integer k-th root: returns (root, exact) — Newton iteration, stable for big ints"""
    if n < 0:
        if k % 2 == 0:
            raise ValueError("iroot: even root does not accept negative numbers")
        # Exactness has to be recomputed here: the recursive call reports whether
        # |n| was a perfect k-th power, but the *sign* is ours. Returning the inner
        # flag directly gave iroot(-27, 3) == (-3, False) — right root, wrong flag,
        # which silently misleads every caller that trusts it.
        r, _ = iroot(-n, k)
        return -r, (-r) ** k == n
    if n in (0, 1) or k == 1:
        return n, True
    if k == 2:
        r = math.isqrt(n)
        return r, r * r == n
    # initial value: 2^(ceil(bits/k))
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // (x ** (k - 1))) // k
        if y >= x:
            break
        x = y
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    return x, x ** k == n


def exact_root(n: int, k: int):
    """Returns the root when it is exactly a k-th power, else None"""
    r, ok = iroot(n, k)
    return r if ok else None


def perfect_square(n: int):
    """Returns the square root when n is a perfect square, else None"""
    if n < 0:
        return None
    r = math.isqrt(n)
    return r if r * r == n else None


# ────────────────────────── primality and factorisation ──────────────────────────

_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def is_prime(n: int) -> bool:
    """Miller-Rabin with the first 12 primes as bases → deterministic for n < 3.3e24"""
    if n < 2:
        return False
    for p in _MR_BASES:
        if n % p == 0:
            return n == p
    if _gmpy2 is not None:
        return bool(_gmpy2.is_prime(n))
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _MR_BASES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def prime_sieve(limit: int):
    """Small prime table (for trial division)"""
    if limit < 2:
        return []
    sieve = bytearray([1]) * (limit + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, math.isqrt(limit) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i, v in enumerate(sieve) if v]


_SMALL_PRIMES = prime_sieve(100000)


def next_prime(n: int) -> int:
    if n < 2:
        return 2
    cand = n + 1 if n % 2 == 0 else n + 2
    if cand % 2 == 0:
        cand -= 1
    if cand < 2:
        cand = 2
    if cand == 2:
        return 2
    while not is_prime(cand):
        cand += 2
    return cand


def pollard_rho(n: int, seed: int = 2, max_steps: int = None):
    """Brent's improved Pollard rho — returns one non-trivial factor of n

    max_steps: iteration cap (None = unlimited). Over the cap we return None
    rather than running on — work inside the analyser must stay bounded,
    otherwise a single large semiprime hangs the tool (we hit this in testing).
    """
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    steps = 0
    while True:
        y, c, m = seed, 1, 128
        g = r = q = 1
        x = ys = y
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            steps += r
            if max_steps is not None and steps > max_steps:
                return None
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = gcd(q, n)
                k += m
                steps += m
                if max_steps is not None and steps > max_steps:
                    return None
            r *= 2
        if g == n:
            g = 1
            while g == 1 and ys != x:
                ys = (ys * ys + c) % n
                g = gcd(abs(x - ys), n)
            if g == n or g == 1:
                seed += 1
                continue
        if 1 < g < n:
            return g
        seed += 1


def factor_limited(n: int, max_steps: int = 500000):
    """Bounded factorisation — returns None once the step budget is spent
    (analyser-only, guaranteed never to hang)

    First trial-divides by primes below 10^6 (cheap, and it covers a large share
    of CTF tasks), then runs bounded Pollard rho on what remains; when the budget
    runs out we give up at once and the caller records the conclusion as
    "not factored within budget".
    """
    if n < 0:
        raise ValueError("negative number")
    out = {}
    if n in (0, 1):
        return out
    for p in _SMALL_PRIMES:
        if p * p > n:
            break
        if n % p == 0:
            e = 0
            while n % p == 0:
                n //= p
                e += 1
            out[p] = e
    if n == 1:
        return out
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            out[m] = out.get(m, 0) + 1
            continue
        d = pollard_rho(m, max_steps=max_steps)
        if d is None:
            return None  # budget spent: return None as a whole, no half-conclusion
        stack.append(d)
        stack.append(m // d)
    return out


def factor(n: int, max_small: int = 100000):
    """Integer factorisation → {prime: exp} (small-prime trial division + recursive Pollard rho)

    Note: this is a best-effort factoriser, meant for CTF-sized n; large n is
    slow — the caller should bring a timeout/budget (the analyser offers it as a
    "lead" and it must not block the main flow).
    """
    if n < 0:
        raise ValueError("factor: negative number")
    out = {}
    if n in (0, 1):
        return out
    for p in _SMALL_PRIMES:
        if p * p > n:
            break
        if n % p == 0:
            e = 0
            while n % p == 0:
                n //= p
                e += 1
            out[p] = e
    if n == 1:
        return out
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            out[m] = out.get(m, 0) + 1
            continue
        d = pollard_rho(m)
        stack.append(d)
        stack.append(m // d)
    return out


def divisors(n: int):
    """All positive divisors of n (factorises first — use with care for large n)"""
    fac = factor(n)
    divs = [1]
    for p, e in fac.items():
        divs = [d * p ** k for d in divs for k in range(e + 1)]
    return sorted(divs)


# ────────────────────────── continued fractions / approximants ──────────────────────────

def continued_fraction(a: int, b: int):
    """Rational a/b → list of continued-fraction coefficients"""
    cf = []
    while b:
        q, a, b = a // b, b, a % b
        cf.append(q)
    return cf


def convergents(cf):
    """Continued fraction → convergents (h/k) one at a time, a generator"""
    h_prev, h_cur = 1, cf[0] if cf else 0
    k_prev, k_cur = 0, 1
    if cf:
        yield h_cur, k_cur
    for a in cf[1:]:
        h_prev, h_cur = h_cur, a * h_cur + h_prev
        k_prev, k_cur = k_cur, a * k_cur + k_prev
        yield h_cur, k_cur


def wiener_attack(e: int, n: int):
    """Wiener attack: when d is too small (d < n^0.25/3) recover it from the
    convergents of e/n → (d, p, q) or None"""
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        # x^2 - (n - phi + 1)x + n = 0
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        sq = perfect_square(disc)
        if sq is None or (s + sq) % 2:
            continue
        p = (s + sq) // 2
        q = (s - sq) // 2
        if p * q == n and p > 1 and q > 1:
            return d, min(p, q), max(p, q)
    return None


def wiener_recover_d(e: int, n: int):
    """Algebra-side name: recover a small d from e/n → (d, p, q) or None

    (rsa_ops.wiener_attack is the same algorithm wrapped in the result dict,
    for the infrastructure layer to call)
    """
    return wiener_attack(e, n)


def fermat_factor(n: int, max_iter: int = 1000000):
    """Fermat factorisation: extremely fast when p/q are close → (p, q) or None"""
    if n % 2 == 0:
        return 2, n // 2
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = perfect_square(b2)
        if b is not None:
            return a - b, a + b
        a += 1
    return None


def close_factor_probe(n: int, max_iter: int = 20000):
    """Cheap probe: are p and q close? (only a few rounds, so the analyser can
    judge the attack surface)"""
    return fermat_factor(n, max_iter=max_iter)


# ────────────────────────── discrete log / modular square root ──────────────────────────

def bsgs(g: int, h: int, p: int, order: int = None, max_m: int = 1 << 22):
    """Baby-step giant-step for x s.t. g^x ≡ h (mod p); over budget returns None"""
    order = order or (p - 1)
    m = math.isqrt(order) + 1
    if m > max_m:
        return None
    table = {}
    cur = 1
    for j in range(m):
        table.setdefault(cur, j)
        cur = cur * g % p
    # g^{-m}
    factor = modinv(pow(g, m, p), p)
    if factor is None:
        return None
    gamma = h % p
    for i in range(m + 1):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


def tonelli_shanks(a: int, p: int):
    """Modular square root modulo an odd prime → r, or None when there is no solution"""
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if pow(a, (p - 1) // 2, p) != 1:
        return None
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    q, s = p - 1, 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(a, q, p), pow(a, (q + 1) // 2, p)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1:
            t2 = t2 * t2 % p
            i += 1
            if i == m:
                return None
        b = pow(c, 1 << (m - i - 1), p)
        m, c = i, b * b % p
        t = t * c % p
        r = r * b % p
    return r


# ────────────────────────── randomness / LCG ──────────────────────────

def lcg_recover(states, modulus: int = None):
    """Recover LCG parameters from consecutive outputs (x_{n+1} = a*x_n + c mod m)

    Returns {a, c, m} or None. When the modulus is unknown it is estimated with
    the gcd trick over the difference sequence.
    """
    xs = [int(x) for x in states]
    if len(xs) < 4:
        return None
    if modulus is None:
        diffs = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
        d2 = [diffs[i + 1] * diffs[i - 1] - diffs[i] * diffs[i] for i in range(1, len(diffs) - 1)]
        g = 0
        for v in d2:
            g = gcd(g, abs(v))
            if g == 1:
                break
        if g <= 1:
            return None
        modulus = g
    m = modulus
    # solve for a from triples: (x2-x1)*a ≡ (x3-x2) (mod m)
    for i in range(len(xs) - 2):
        d1 = (xs[i + 1] - xs[i]) % m
        d2 = (xs[i + 2] - xs[i + 1]) % m
        inv = modinv(d1, m)
        if inv is None:
            continue
        a = d2 * inv % m
        c = (xs[i + 1] - a * xs[i]) % m
        # verify against every sample (not one mismatch allowed)
        if all((a * xs[j] + c) % m == xs[j + 1] % m for j in range(len(xs) - 1)):
            return {"a": a, "c": c, "m": m}
    return None


def rand_int_below(n: int, rng: random.Random = None) -> int:
    """Uniform random integer in [0, n) (for tests / target-range generation)"""
    rng = rng or random
    return rng.randrange(n)
