"""Modular arithmetic beyond plain inverses — the layer between `algebra` and a task.

Why this module exists: almost every number-theory CTF task needs one of a small set
of *derived* quantities (a Legendre/Jacobi/Kronecker symbol to decide whether a square
root exists, phi/lambda to shrink a key space, a multiplicative order to run Pohlig-
Hellman, a CRT over *non-coprime* moduli to glue partial results, a p-1 / p+1 factor
sweep). Writing them again per task is where sign conventions and edge cases get lost,
so they live here once, tested.

Empirical notes worth keeping:
  * `algebra.crt` deliberately refuses non-coprime moduli (it is the precondition check
    for the RSA common-modulus case). Partial-information tasks hand you moduli that are
    *not* coprime, so `crt_general`/`crt_list` below merge them properly instead.
  * Composite modular square roots are NOT a single extra root of the prime one: mod 15
    has four roots of 4 ({2, 7, 8, 13}), and only the CRT over the prime powers gets all
    of them. Missing roots here silently breaks broadcast / Rabin style attacks.
  * Everything that can legitimately fail returns None. Raising is reserved for input
    that is not a number-theoretic object at all (non-positive modulus, bad base).

Pure standard library; factorisation is delegated to `algebra`.
"""

from itertools import product as _product

from .algebra import (
    crt,
    factor_limited,
    gcd,
    iroot,
    is_prime,
    modinv,
    perfect_square,
    tonelli_shanks,
)

# Explicit export list: without it the helper imports above (crt, gcd, iroot, is_prime,
# modinv, ...) leak into `from .modular import *` and shadow the package-level names.
__all__ = [
    "legendre_symbol", "jacobi_symbol", "kronecker_symbol", "is_quadratic_residue",
    "sqrt_mod", "totient", "carmichael", "mobius", "is_squarefree", "sum_of_divisors",
    "divisor_count", "order_mod", "primitive_root", "is_primitive_root",
    "crt_general", "crt_list", "gcd_list", "lcm_list",
    "pollard_pm1", "williams_pp1", "is_smooth", "smooth_part",
    "integer_log", "integer_nthroot_safe", "binomial_mod", "pow_mod_list",
]


# ────────────────────────── symbols ──────────────────────────

def legendre_symbol(a: int, p: int) -> int:
    """(a/p) for an odd prime p → 1 (residue), -1 (non-residue), 0 (p | a)

    The sign convention is the classical one, i.e. the value of a^((p-1)/2) mod p
    mapped to {-1, 0, 1} — NOT the "1/0" indicator some libraries return.
    p is assumed prime; for composite p use jacobi_symbol.
    """
    if p == 2:
        raise ValueError("legendre_symbol: p must be an odd prime")
    if p < 2:
        raise ValueError("legendre_symbol: modulus must be > 1")
    r = pow(a % p, (p - 1) // 2, p)
    return -1 if r == p - 1 else r


def jacobi_symbol(a: int, n: int) -> int:
    """(a/n) for any positive odd n → 1 / -1 / 0, computed without factoring n

    Convention matches the standard: (1001/9907) = -1, and the value is 0 exactly
    when gcd(a, n) > 1. Note the trap this convention creates — (a/n) = 1 does NOT
    imply that a is a quadratic residue mod n when n is composite (it only does for
    prime n); use is_quadratic_residue when that is what you mean.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("jacobi_symbol: n must be a positive odd integer")
    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def kronecker_symbol(a: int, n: int) -> int:
    """Kronecker symbol (a/n) → 1 / -1 / 0 for *any* integer n (including 0, ±1, even)

    Definition used here: (a/n) = (a/|n|), and |n| is split into its 2-power part and its
    odd part. For the 2-power part the classical rules apply — the factor is
    (-1)^((a^2-1)/8) per factor 2, so a ≡ 3 or 5 (mod 8) flips the sign — and the odd
    part goes through the Jacobi symbol. Two conventions are worth spelling out because
    they differ between libraries: (a/-1) = -1 exactly when a < 0, and n = 0 gives 1 for
    |a| = 1 and 0 otherwise.

    Do not confuse the two 2-related symbols: (2/a) for odd a is (-1)^((a^2-1)/8), while
    (a/2) is (+1) for a ≡ ±1 (mod 8) and (-1) for a ≡ ±3 (mod 8). Only the second is a
    Kronecker numerator rule, and mixing them up is the usual source of a wrong sign.
    """
    if n == 0:
        return 1 if abs(a) == 1 else 0
    n = abs(n)
    result = 1
    # (a/-1) = -1 exactly when a < 0, and the |n| == 1 case must go through it: for
    # n = -1 the 2-adic loop below is skipped entirely, so an early `return 1` here
    # would report (+1) and lose the sign of a (kronecker(3,-1) must be -1).
    if a < 0:
        result = -result
    while n % 2 == 0:
        n //= 2
        if a % 2 == 0:
            return 0
        if a % 8 in (3, 5):
            result = -result
    if n == 1:
        return result
    return result * jacobi_symbol(a, n)


def is_quadratic_residue(a: int, p: int) -> bool:
    """True when x^2 ≡ a (mod p) has a solution, p an odd prime

    Deliberately False for a ≡ 0: the classical definition counts only the non-zero
    residues, and callers usually want "is there a non-trivial root". If you need to
    accept 0 as well, test `a % p == 0 or is_quadratic_residue(a, p)`.
    """
    if p == 2:
        return True
    if p < 2:
        raise ValueError("is_quadratic_residue: modulus must be > 1")
    a %= p
    if a == 0:
        return False
    return pow(a, (p - 1) // 2, p) == 1


# ────────────────────────── modular square roots ──────────────────────────

def _valuation(a: int, p: int):
    """p-adic valuation j = max{k : p^k divides a} → (j, a // p^j)"""
    j = 0
    while a % p == 0:
        a //= p
        j += 1
    return j, a


# Zero has MORE than one root as soon as the modulus is a square, and those roots are
# not "±0": mod 9 the solutions of x^2 ≡ 0 are {0, 3, 6}. Enumerating them is fine for
# small prime powers (which is where a ≡ 0 mod p^e actually shows up), and the cap keeps
# a huge exponent from turning the CRT into a blow-up.
_MAX_ZERO_ROOTS = 65536
_MAX_BRUTE_PK = 1 << 20  # above this, use the arithmetic paths rather than a sweep


def _sqrt_zero_prime_power(p: int, e: int):
    """Roots of x^2 ≡ 0 (mod p^e) → the multiples of p^ceil(e/2), or None if too many

    Zero has many roots here rather than one (mod 9 they are {0, 3, 6}), because x^2 ≡ 0
    (mod p^e) only forces p^ceil(e/2) | x. The cap keeps a large exponent from turning
    the outer CRT into a blow-up.
    """
    step = p ** ((e + 1) // 2)
    pk = p ** e
    if pk // step > _MAX_ZERO_ROOTS:
        return None
    return list(range(0, pk, step))


def _hensel_root(a: int, p: int, e: int, r: int):
    """Lift one root r of x^2 ≡ a (mod p) up to a root mod p^e (a a unit mod p)

    Returns None if the lift cannot be completed. a must be a unit, otherwise 2r may not
    be invertible and the derivative condition behind Hensel's lemma does not hold.
    """
    cur = r % p
    power = p
    for _ in range(e - 1):
        power *= p
        inv = modinv(2 * cur % p, p)
        if inv is None:
            return None
        f = (cur * cur - a) // (power // p)
        cur = (cur - f * inv * (power // p)) % power
    return cur % power


def _root_set(pk: int, p: int, e: int, squared: int):
    """Every x in [0, pk) with x^2 ≡ squared (mod pk) → sorted list

    A direct sweep, and deliberately so. The arithmetic shortcuts for prime powers are
    full of traps that a sweep cannot have — the count is not always two (x^2 ≡ 9 mod 27
    has six roots, x^2 ≡ 0 mod 16 has four) — so the cheap exact answer is used whenever
    the prime power is small, which covers essentially every CTF modulus.

    For a bigger prime power the analytic route is taken instead (in the callers): units
    via Tonelli-Shanks plus a verified Hensel lift, and the scaled/zero cases through
    _sqrt_zero_prime_power. It is exact for odd p and uses the documented lifts for 2.
    """
    if pk <= _MAX_BRUTE_PK:
        return [x for x in range(pk) if (x * x - squared) % pk == 0]
    return None


def _sqrt_odd_prime_power(a: int, p: int, e: int):
    """Roots of x^2 ≡ a (mod p^e) for an odd prime p → sorted list, or None

    Structure: write a = p^j·u with u a unit. An odd j has no solution at all (a square
    is never divisible by p exactly once); an even j = 2i sends every root to p^i times a
    root of u, and THAT step is the trap. A root y of u is only determined modulo
    p^(e-j), while the roots x live modulo p^e, so each y stands for the p^j lifts
    y + t·p^(e-j). Enumerating them is not optional: x^2 ≡ 9 (mod 27) has six roots
    ({3, 6, 12, 15, 21, 24}) and the naive "x = p^(j/2)·y" form returns only {3, 6}.
    The reduced problem (a unit) is answered by a direct sweep for a small prime power
    and by Tonelli-Shanks plus a verified Hensel lift otherwise.
    """
    pk = p ** e
    a %= pk
    if a == 0:
        return _sqrt_zero_prime_power(p, e)
    j, _ = _valuation(a, p)
    if j:
        if j % 2:
            return None
        sub = _sqrt_odd_prime_power(a // p ** j, p, e - j)
        if sub is None:
            return None
        scale = p ** (j // 2)
        step = p ** (e - j)
        roots = {((y + t * step) * scale) % pk for y in sub for t in range(p ** j)}
        return sorted(roots)
    direct = _root_set(pk, p, e, a)
    if direct is not None:
        return direct
    r = tonelli_shanks(a % p, p)
    if r is None:
        return None
    out = set()
    for cand in {r % p, -r % p}:
        lifted = _hensel_root(a, p, e, cand)
        if lifted is not None and (lifted * lifted - a) % pk == 0:
            out.add(lifted % pk)
    return sorted(out) if out else None


def _sqrt_power_of_two(a: int, e: int):
    """Roots of x^2 ≡ a (mod 2^e) → sorted list, or None

    The 2-adic rules, stated once: e = 1 gives the single root a; e = 2 has roots iff
    a ≡ 1 (mod 4); for e >= 3 a unit has exactly four roots (±t, ±t + 2^(e-1)); an even a
    with v_2(a) = j recurses with the scale 2^(j/2) applied to each root of a/2^j, and an
    odd j admits no solution. Small moduli are swept (the reference answer); for a larger
    2^e the scaled recursion and the four-root lift are used.
    """
    pk = 1 << e
    a %= pk
    if a == 0:
        return _sqrt_zero_prime_power(2, e)
    direct = _root_set(pk, 2, e, a)
    if direct is not None:
        return direct
    if e == 1:
        return [a % 2]
    if a % 2:
        t = None
        for cand in range(1, pk, 2):
            if (cand * cand - a) % pk == 0:
                t = cand
                break
        if t is None:
            return None
        half = pk >> 1
        return sorted({t % pk, -t % pk, (t + half) % pk, (-t + half) % pk})
    j, _ = _valuation(a, 2)
    if j % 2:
        return None  # v_2(a) odd cannot be a square
    sub = _sqrt_power_of_two(a >> j, e - j)
    if sub is None:
        return None
    scale = 1 << (j // 2)
    return sorted({x * scale % pk for x in sub})


def sqrt_mod(a: int, p: int = None, n: int = None):
    """All square roots of a → sorted list, or None when there is none

    `p=` an odd prime (Tonelli-Shanks) or 2. `n=` any modulus: n is factored, the
    roots modulo every prime power are taken and recombined with the CRT, so the
    *complete* root set comes back — mod 15 the answer for a=4 is [2, 7, 8, 13].
    With a composite n whose factorisation exceeds the budget of `factor_limited`
    the answer is None: an honest "unknown" rather than a partial root list, which
    would silently break a broadcast/Rabin style attack that assumes it has them all.

    The modulus must be passed by keyword (`p=` or `n=`); a bare second positional
    argument would be ambiguous between the two.
    """
    if (p is None) == (n is None):
        raise ValueError("sqrt_mod: give exactly one of p= (prime) or n= (modulus)")
    if p is not None:
        m = p
        if m < 2:
            raise ValueError("sqrt_mod: modulus must be > 1")
        if m == 2:
            return [a % 2]
        r = tonelli_shanks(a % m, m)
        if r is None:
            return None
        return sorted({r % m, (-r) % m})
    m = n
    if m <= 0:
        raise ValueError("sqrt_mod: modulus must be positive")
    if m == 1:
        return [0]
    a %= m
    if a == 0:
        # Not a single root: x^2 ≡ 0 (mod m) is solved by every multiple of the
        # "half modulus" per prime power. Returning [0] here is the bug that makes
        # sqrt_mod(0, n=16) answer [0] instead of [0, 4, 8, 12].
        fac0 = factor_limited(m)
        if fac0 is None:
            return [0]
        parts = [_sqrt_zero_prime_power(q, e) for q, e in sorted(fac0.items())]
        if any(part is None for part in parts):
            return None
        moduli = [q ** e for q, e in sorted(fac0.items())]
        roots = []
        for combo in _product(*parts):
            got = crt(list(zip(combo, moduli)))
            if got is not None:
                roots.append(got[0] % m)
        return sorted(set(roots)) if roots else None
    fac = factor_limited(m)
    if fac is None:
        # A modulus we cannot factor: returning a partial root set would silently
        # break a CRT-based attack, so we say "unknown" with None instead.
        return None
    # roots per prime power, then CRT over them: mod 15 this is what produces all
    # four roots of 4 ({2, 7, 8, 13}) rather than just ±2.
    per_prime = []
    primes = []
    total = 1
    for q in sorted(fac):
        e = fac[q]
        sub = _sqrt_power_of_two(a, e) if q == 2 else _sqrt_odd_prime_power(a, q, e)
        if sub is None:
            return None
        total *= len(sub)
        if total > _MAX_ZERO_ROOTS:
            return None  # the root set is degenerate (a ≡ 0 mod several prime powers)
        per_prime.append(sub)
        primes.append(q ** e)
    roots = []
    for combo in _product(*per_prime):
        got = crt(list(zip(combo, primes)))
        if got is not None:
            roots.append(got[0] % m)
    if not roots:
        return None
    return sorted(set(roots))


# ────────────────────────── arithmetic functions ──────────────────────────

def totient(n: int):
    """Euler phi via factor_limited → int, or None when n is not factored in budget"""
    if n < 1:
        raise ValueError("totient: n must be positive")
    if n == 1:
        return 1
    fac = factor_limited(n)
    if fac is None:
        return None
    phi = 1
    for q, e in fac.items():
        phi *= (q - 1) * q ** (e - 1)
    return phi


def carmichael(n: int):
    """Carmichael lambda(n) = lcm of the prime-power component orders → int or None

    For 2^e the component is 1 (e=1), 2 (e=2) and 2^(e-2) (e>=3) — the reason
    lambda differs from phi for n divisible by 8, and the reason a modulus built
    from two large primes gives lambda = lcm(p-1, q-1) rather than their product.
    """
    if n < 1:
        raise ValueError("carmichael: n must be positive")
    if n == 1:
        return 1
    fac = factor_limited(n)
    if fac is None:
        return None
    lam = 1
    for q, e in fac.items():
        if q == 2:
            if e == 1:
                comp = 1
            elif e == 2:
                comp = 2
            else:
                comp = 1 << (e - 2)
        else:
            comp = (q - 1) * q ** (e - 1)
        lam = lam * comp // gcd(lam, comp)
    return lam


def mobius(n: int):
    """Moebius mu(n) → 1 (squarefree, even number of primes), -1 (squarefree, odd),
    0 (divisible by a square). None when factorisation exceeded its budget.

    mu is cheap "sieve-like" information: a non-zero mu is exactly the squarefree
    test, and summing mu is the classic way to count squarefree values.
    """
    if n < 1:
        raise ValueError("mobius: n must be positive")
    if n == 1:
        return 1
    fac = factor_limited(n)
    if fac is None:
        return None
    if any(e > 1 for e in fac.values()):
        return 0
    return -1 if len(fac) % 2 else 1


def is_squarefree(n: int):
    """True when no prime square divides n; None when n could not be factored"""
    if n < 1:
        raise ValueError("is_squarefree: n must be positive")
    mu = mobius(n)
    if mu is None:
        return None
    return mu != 0


def sum_of_divisors(n: int):
    """sigma(n) = product of (q^(e+1)-1)/(q-1) over the prime powers → int or None"""
    if n < 1:
        raise ValueError("sum_of_divisors: n must be positive")
    fac = factor_limited(n)
    if fac is None:
        return None
    total = 1
    for q, e in fac.items():
        total *= (q ** (e + 1) - 1) // (q - 1)
    return total


def divisor_count(n: int):
    """tau(n) = product of (e+1) → int or None"""
    if n < 1:
        raise ValueError("divisor_count: n must be positive")
    fac = factor_limited(n)
    if fac is None:
        return None
    total = 1
    for e in fac.values():
        total *= e + 1
    return total


# ────────────────────────── multiplicative order / primitive roots ──────────────────────────

def _divisors_of(fac: dict):
    """All divisors from a {prime: exp} dict (used for the order search)"""
    divs = [1]
    for q, e in fac.items():
        divs = [d * q ** k for d in divs for k in range(e + 1)]
    return divs


def order_mod(a: int, n: int):
    """Multiplicative order of a modulo n → int, or None (not a unit / budget spent)

    Bounded on purpose: the candidate set is the divisors of lambda(n), so the cost
    is dominated by factoring lambda(n). When that factorisation exceeds the budget
    of `factor_limited` we return None instead of walking up to phi(n) — an
    unbounded upward scan inside an analyser is exactly the hang we refuse to add.
    """
    if n < 1:
        raise ValueError("order_mod: modulus must be positive")
    a %= n
    if gcd(a, n) != 1:
        return None
    if n == 1:
        return 1
    if a in (0, 1):
        return 1
    lam = carmichael(n)
    if lam is None:
        return None
    fac = factor_limited(lam)
    if fac is None:
        return None
    best = lam
    for d in _divisors_of(fac):
        if d < best and pow(a, d, n) == 1:
            best = d
    return best


def primitive_root(p: int, max_tries: int = 100000):
    """Smallest primitive root modulo the prime p → int, or None (not prime / budget)

    Factors p-1 once, then walks candidates; a candidate g is a primitive root iff
    g^((p-1)/q) != 1 for every prime q | p-1. The smallest primitive root is small
    in practice (2, 3, 5, ...), so the walk rarely goes far; max_tries bounds the
    pathological case.
    """
    if p < 2:
        raise ValueError("primitive_root: modulus must be > 1")
    if p == 2:
        return 1
    if not is_prime(p):
        return None
    fac = factor_limited(p - 1)
    if fac is None:
        return None
    for g in range(2, min(p, 2 + max_tries)):
        if all(pow(g, (p - 1) // q, p) != 1 for q in fac):
            return g
    return None


def is_primitive_root(g: int, p: int) -> bool:
    """True when g generates (Z/pZ)*, p an odd prime (order of g equals phi(p))"""
    if p == 2:
        return g % 2 == 1
    if not is_prime(p):
        return False
    g %= p
    if g == 0:
        return False
    return order_mod(g, p) == p - 1


# ────────────────────────── CRT with non-coprime moduli ──────────────────────────

def crt_general(congruences):
    """CRT for arbitrary (possibly non-coprime) moduli → (x, lcm) or None

    Returns the unique solution x modulo the lcm of the moduli, or None when the
    system is inconsistent. Merging x ≡ a (mod m) and x ≡ b (mod n) needs
    (b - a) ≡ 0 (mod gcd(m, n)); then the new modulus is m*n/gcd(m, n), not m*n.
    `algebra.crt` refuses this case on purpose (coprimality is the precondition it
    is asked to certify), so partial-information attacks need this one.
    """
    if not congruences:
        return None
    x, M = 0, 1
    for a, m in congruences:
        if m <= 0:
            raise ValueError("crt_general: moduli must be positive")
        a %= m
        g = gcd(M, m)
        if (a - x) % g:
            return None  # inconsistent: the residues disagree modulo gcd(M, m)
        # x + M*t ≡ a (mod m) with M*t ≡ (a - x) (mod m) → divide through by g
        m_g, a_g = m // g, (a - x) // g
        inv = modinv((M // g) % m_g, m_g)
        if inv is None:
            return None
        t = a_g * inv % m_g
        M2 = M * m_g
        x = (x + M * t) % M2
        M = M2
    return x % M, M


def crt_list(values, moduli):
    """Convenience wrapper: parallel lists → crt_general(zip(values, moduli))"""
    if len(values) != len(moduli):
        raise ValueError("crt_list: values and moduli must have the same length")
    return crt_general(list(zip(values, moduli)))


def gcd_list(xs):
    """gcd of a sequence (gcd_list([]) = 0, the additive identity for gcd)"""
    g = 0
    for x in xs:
        g = gcd(g, abs(x))
    return g


def lcm_list(xs):
    """lcm of a sequence (empty → 1; a zero anywhere → 0)"""
    out = 1
    for x in xs:
        if x == 0:
            return 0
        out = out * abs(x) // gcd(out, x)
    return out


# ────────────────────────── factorisation: p-1 and p+1 ──────────────────────────

def pollard_pm1(n: int, bound: int = 100000, retries: int = 8):
    """Pollard p-1: returns a non-trivial factor of n, or None

    Wins when some prime factor p of n has p-1 smooth up to `bound`. The accumulator is
    x = a^(bound!) mod n, which is 1 mod p once p-1 | bound!, and the factor appears as
    gcd(x - 1, n).

    The gcd == n case is the one that needs care, and a single-step backtrack does not
    solve it: gcd == n means BOTH p-1 and q-1 are smooth, and stepping back one exponent
    leaves both collapsed just the same (101*103 with bound 30 gives gcd n at every single
    step of the run — its p-1 = 100 and q-1 = 102 both divide 30!). The fix is to shrink
    the bound: 100 | 10! but 102 does not, so gcd != n at bound 10. Each halving of the
    bound carries a fresh base, and the loop is capped by `retries`.
    """
    if n < 2:
        raise ValueError("pollard_pm1: n must be > 1")
    if n % 2 == 0:
        return 2
    current = bound
    for _ in range(max(1, retries)):
        for a in (2, 3, 5):
            x = a % n
            for j in range(2, current + 1):
                x = pow(x, j, n)
            g = gcd(x - 1, n)
            if 1 < g < n:
                return g
        # nothing but gcd == n (or 1) anywhere: retry with a smaller smoothness bound
        if current <= 1:
            break
        current //= 2
    return None


def _prime_powers_upto(bound: int):
    """Every p^a <= bound, ascending — the smooth multipliers of the p-1 / p+1 methods

    A plain sieve rather than trial division per candidate: this list is built once per
    call with a bound that defaults to 100000, and a naive `is_prime` per integer turns a
    cheap precomputation into a visible pause.
    """
    if bound < 2:
        return []
    sieve = bytearray([1]) * (bound + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, int(bound ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    out = []
    for p in range(2, bound + 1):
        if not sieve[p]:
            continue
        power = p
        while power <= bound:
            out.append(power)
            power *= p
    return out


def _lucas_v(k: int, P: int, n: int) -> int:
    """V_k(P, 1) mod n by the binary doubling chain

    The chain is V_{2m} = V_m^2 - 2, V_{2m+1} = V_m*V_{m+1} - P, V_{2m+2} = V_{m+1}^2 - 2,
    so one pass over the bits of k costs O(log k) multiplications and no growing
    Fibonacci-style state. `format(k, 'b')` rather than `bin(k)[2:]` only for clarity —
    the two are the same string.
    """
    if k == 0:
        return 2
    v0, v1 = 2, P % n
    for bit in format(k, "b"):
        if bit == "0":
            v0, v1 = (v0 * v0 - 2) % n, (v0 * v1 - P) % n
        else:
            v0, v1 = (v0 * v1 - P) % n, (v1 * v1 - 2) % n
    return v0  # the leading '1' bit advances the pair from index 1 to index k


def williams_pp1(n: int, bound: int = 100000, max_checks: int = 4096):
    """Williams p+1: returns a non-trivial factor of n, or None

    The p-1 sibling: it needs p+1 smooth. Work happens in the Lucas sequence V_k(P, 1)
    over Z/nZ, and the factor appears as gcd(V_M(P) - 2, n) for M = lcm(1..bound), i.e.
    the product of every prime power p^a <= bound, the accumulated smooth index.

    Why the index is composed prime power by prime power instead of multiplied out: the
    composition law is V_k(V_m(P)) = V_{km}(P), so V_M can be built as a chain of small
    doubling walks, one per prime power. Both routes cost O(log M) modular
    multiplications in total, but the single-integer route holds intermediates of ~150k
    bits for bound = 100000, while the chain keeps every value below n.

    A few small P are tried because only the factors whose discriminant P^2-4 is a
    non-residue respond to a given P; the loop is bounded (gcd checked every max_checks
    compositions), so this never runs away.
    """
    if n < 2:
        raise ValueError("williams_pp1: n must be > 1")
    if n % 2 == 0:
        return 2
    root = perfect_square(n)
    if root is not None:
        return root
    factors = _prime_powers_upto(bound)
    for P in (3, 4, 5, 7, 9, 11):
        cur = P % n  # V_1(P)
        steps = 0
        for q in factors:
            cur = _lucas_v(q, cur, n)
            steps += 1
            if steps % max_checks == 0:
                g = gcd(cur - 2, n)
                if 1 < g < n:
                    return g
        g = gcd(cur - 2, n)
        if 1 < g < n:
            return g
    return None


# ────────────────────────── smoothness ──────────────────────────

def is_smooth(n: int, bound: int):
    """True when every prime factor of n is <= bound (n <= 1 is trivially smooth)

    Returns None when n could not be factored within budget — "not known to be
    smooth" is not the same as "not smooth", and conflating them mislabels a factor.
    """
    if n < 0:
        raise ValueError("is_smooth: n must be non-negative")
    if n <= 1:
        return True
    fac = factor_limited(n)
    if fac is None:
        return None
    return max(fac) <= bound


def smooth_part(n: int, bound: int):
    """Largest divisor of n built only from primes <= bound → int, or None

    This is the quantity a p-1 / p+1 style attack actually accumulates; the leftover
    n // smooth_part is the part that needs a different method.
    """
    if n < 1:
        raise ValueError("smooth_part: n must be positive")
    if n == 1:
        return 1
    fac = factor_limited(n)
    if fac is None:
        return None
    out = 1
    for q, e in fac.items():
        if q <= bound:
            out *= q ** e
    return out


# ────────────────────────── integer helpers ──────────────────────────

def integer_log(n: int, b: int) -> int:
    """Floor of log_b(n), i.e. the largest e with b^e <= n (n >= 1, b >= 2)

    Exact integer arithmetic — float logs are off by one at the boundaries, which
    breaks "is this a perfect power" checks.
    """
    if n < 1:
        raise ValueError("integer_log: n must be >= 1")
    if b < 2:
        raise ValueError("integer_log: base must be >= 2")
    e = 0
    power = 1
    while power * b <= n:
        power *= b
        e += 1
    return e


def integer_nthroot_safe(n: int, k: int, max_bits: int = 4096, max_k: int = 4096):
    """Integer k-th root → the root when it is exact, else None

    Wraps `algebra.iroot` with the guards an analyser needs: absurd k and inputs so
    large that the Newton iteration would dominate the run are rejected with None
    instead of eating the budget. For n < 0 only an odd k is meaningful.

    Exactness is decided by comparing root**k with n rather than trusting iroot's
    `exact` flag: algebra.iroot returns (-3, False) for iroot(-27, 3) — the root is
    right but the flag is not, and a caller that trusts it silently loses every
    negative perfect power (this is how the bug was found).
    """
    if k < 1 or k > max_k:
        return None
    if n < 0 and k % 2 == 0:
        return None
    if abs(n).bit_length() > max_bits:
        return None
    try:
        root, _ = iroot(n, k)
    except (ValueError, OverflowError):
        return None
    root = int(root)
    return root if root ** k == n else None


def binomial_mod(n: int, k: int, m: int) -> int:
    """C(n, k) mod m for any modulus m > 0

    Additive Pascal recurrence — correct for composite m, where the "divide by the
    small factors" tricks used for prime m silently break (no modular inverse for
    the factors of m). Cost is O(k) multiplications, so it is meant for the modest
    k that CTF combinatorial tasks use, not for huge n.
    """
    if m <= 0:
        raise ValueError("binomial_mod: modulus must be positive")
    if k < 0 or n < 0:
        return 0
    if k > n:
        return 0
    k = min(k, n - k)
    row = 1
    for i in range(1, k + 1):
        row = row * (n - k + i) // i  # exact integer division at every step
    return row % m


def pow_mod_list(base: int, exponents, mod: int):
    """[pow(base, e, mod) for e in exponents] — one call for a batch of exponents"""
    if mod <= 0:
        raise ValueError("pow_mod_list: modulus must be positive")
    return [pow(base, e, mod) for e in exponents]
