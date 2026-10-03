"""Polynomial armoury over Z and over GF(p), plus integer-encoded GF(2) polynomials.

Why this module exists: "find the roots", "is this polynomial irreducible over GF(p)",
"reduce a polynomial modulo another" are the routine steps behind CRC/LFSR recovery,
Reed-Solomon / Shamir reconstruction, finite-field Diffie-Hellman variants and the
Rabin / Kronecker style factorisation tasks. Every one of them is a few lines of
bookkeeping, and every one of those few lines is where an off-by-one in the degree or
a missing leading-zero trim turns into a wrong answer.

Representation rules (fixed here so callers never have to guess):
  * a polynomial is a list of coefficients in ASCENDING order — c[0] is the constant
    term, c[i] multiplies x^i. This matches the equally common `[6, 0, 1]` spelling of
    x^2 - 1 and makes polynomial-from-roots read naturally.
  * trailing (high-degree) zeros are ignored on input and never produced on output.
  * the zero polynomial is `[]` or `None`, and is returned as `[]`.
  * every routine returns None — never raises — for a mathematically impossible or
    undefined request (division by the zero polynomial, a non-exact integer division,
    a modulus larger than the internal budget). Raising is kept for input that is not
    a polynomial at all.
  * GF(2) polynomials use the integer encoding the whole field uses: bit i of the
    integer is the coefficient of x^i, so x^4 + x + 1 is 0b10011 = 19. The two encodings
    never mix: the `gf2_*` family takes and returns plain ints, nothing else.

Pure standard library; the number theory is imported from `.algebra`.
"""

from .algebra import gcd as _int_gcd
from .algebra import is_prime, modinv

# Explicit export list: without it the helper imports above leak into
# `from .polytools import *` and collide with the package-level names.
__all__ = [
    "poly_divmod", "poly_mod", "poly_gcd", "poly_derivative", "poly_roots_mod_p",
    "poly_from_roots", "poly_compose", "poly_powmod", "poly_eval_mod",
    "poly_is_irreducible", "poly_resultant",
    "gf2_poly_mul", "gf2_poly_mod", "gf2_poly_divmod", "gf2_poly_gcd", "gf2_poly_roots",
]

_MAX_DEGREE = 40  # Sylvester determinant elimination is O(d^3): refuse beyond this


# ────────────────────────── generic list helpers ──────────────────────────

def _as_list(f):
    """Accept a list/tuple (or a None zero polynomial) → ascending coefficient list"""
    if f is None:
        return []
    if not isinstance(f, (list, tuple)):
        raise TypeError("polynomial must be a list of coefficients in ascending order")
    out = [int(c) for c in f]
    # trim high-degree zeros here and nowhere else: every other helper calls this, so
    # a degree can never be read off a polynomial with a spurious trailing zero
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return [] if out == [0] else out


def _reduce(f, p):
    """Reduce coefficients modulo p (and trim); p=None keeps integer coefficients"""
    f = _as_list(f)
    if p is None:
        return f
    if p <= 1:
        raise ValueError("polynomial modulus must be > 1")
    return _as_list([c % p for c in f])


def _deg(f):
    """Degree of a trimmed polynomial; the zero polynomial has degree -1"""
    return len(f) - 1


def _mul(f, g, p=None):
    """Schoolbook product; the zero polynomial absorbs the other operand"""
    if not f or not g:
        return []
    out = [0] * (len(f) + len(g) - 1)
    for i, a in enumerate(f):
        if not a:
            continue
        for j, b in enumerate(g):
            out[i + j] += a * b
    if p is not None:
        out = [c % p for c in out]
    return _as_list(out)


def _sub(f, g, p=None):
    """f - g coefficient-wise (lengths may differ)"""
    n = max(len(f), len(g))
    out = [0] * n
    for i in range(n):
        a = f[i] if i < len(f) else 0
        b = g[i] if i < len(g) else 0
        out[i] = a - b
    if p is not None:
        out = [c % p for c in out]
    return _as_list(out)


def _monic(f, p):
    """Scale to leading coefficient 1 mod p; over Z only the sign is normalised

    The Z branch is deliberately not a division: forcing a monic result over Z would
    push the polynomial out of Z[x] (leading coefficient 1/2 for 2x + 1), which is why
    the integer routines below work with primitive parts instead.
    """
    f = _as_list(f)
    if not f:
        return []
    if p is None:
        return [-c for c in f] if f[-1] < 0 else f
    inv = modinv(f[-1] % p, p)
    if inv is None:
        return f
    return _as_list([c * inv % p for c in f])


def _content(f):
    """gcd of the integer coefficients (positive); content([]) = content(0) = 0

    Folded by hand rather than `gcd(*coeffs)`: a degree-1 or zero polynomial would pass
    a single argument (or none) and a two-argument gcd cannot absorb that.
    """
    g = 0
    for c in f:
        g = abs(_int_gcd(g, abs(c)))
    return g


def _primitive_part(f):
    """f divided by its content, with a positive leading coefficient"""
    f = _as_list(f)
    if not f:
        return []
    c = _content(f)
    if c:
        f = [x // c for x in f]
    if f[-1] < 0:
        f = [-x for x in f]
    return _as_list(f)


# ────────────────────────── division, gcd, derivative ──────────────────────────

def poly_divmod(f, g, p=None):
    """Polynomial division → (quotient, remainder), or None when it is undefined

    Over GF(p) (p given) this is ordinary long division and always succeeds for a
    non-zero g, because every non-zero leading coefficient is invertible. Over Z
    (p=None) only integer-coefficient division is possible: when a running leading
    coefficient is not divisible by lc(g) the true quotient has fractional
    coefficients, and we return None rather than silently floor-dividing. So over Z
    both outcomes are meaningful — ([-1, 1], [7]) for x^2+6 by x+1 (a valid quotient
    with a non-zero remainder), and None for x^2+1 by 2x (no integer quotient at all).

    In both successful cases `f == q*g + r` with deg r < deg g. On failure this returns
    a single None (not a tuple) — callers must test for that before unpacking.
    """
    f = _reduce(f, p)
    g = _reduce(g, p)
    if not g:
        return None  # division by the zero polynomial
    if _deg(f) < _deg(g):
        return [], f
    lead_g = g[-1]
    dg = _deg(g)
    inv_lead = None if p is None else modinv(lead_g, p)
    if p is not None and inv_lead is None:
        return None
    rem = list(f)
    quot = [0] * (_deg(f) - dg + 1)
    while rem and _deg(rem) >= dg:
        shift = _deg(rem) - dg
        coef = rem[-1]
        if p is None:
            if coef % lead_g:
                return None  # not exactly divisible over Z
            q = coef // lead_g
        else:
            q = coef * inv_lead % p
        quot[shift] = q
        # Subtract only the LOW coefficients, then zero the leading one: writing to
        # rem[shift + dg] first would clobber the very coefficient the next iteration
        # reads as `coef`, which silently returns a wrong quotient (off by one term).
        for i in range(dg):
            rem[shift + i] -= q * g[i]
            if p is not None:
                rem[shift + i] %= p
        rem[shift + dg] = 0
        rem = _as_list(rem)
    return _as_list(quot), rem


def poly_mod(f, g, p=None):
    """Remainder of f modulo g → list, or None when the division is undefined"""
    got = poly_divmod(f, g, p)
    if got is None:
        return None
    return got[1]


def _poly_gcd_mod(f, g, p):
    """Euclid over GF(p), normalised to monic"""
    f, g = _reduce(f, p), _reduce(g, p)
    while g:
        r = poly_mod(f, g, p)
        if r is None:
            return None
        f, g = g, r
    return _monic(f, p)


def _pseudo_remainder(f, g):
    """Integer pseudo-remainder: lc(g)^(deg f - deg g + 1) * f mod g, exactly

    The standard recurrence multiplies the running remainder by lc(g) and then subtracts
    (leading coefficient of the ORIGINAL remainder) · x^shift · g. Capturing the
    coefficient AFTER the multiplication is the classic bug: it feeds lc(g)·coef into the
    subtraction and the result is off by exactly one factor of lc(g) (that is how
    gcd(x^2-1, x^3+x) came out as 1 instead of x+1). The scaling exponent is likewise not
    decoration — it is what keeps the result inside Z[x] when ordinary division would
    need fractions.
    """
    f = _as_list(f)
    g = _as_list(g)
    if not g:
        return None
    m, n = _deg(f), _deg(g)
    if m < n:
        return f
    lead = g[-1]
    rem = list(f)
    while rem and _deg(rem) >= n:
        shift = _deg(rem) - n
        coef = rem[-1]  # the coefficient of the unscaled remainder
        rem = [x * lead for x in rem]
        for i in range(n + 1):
            rem[shift + i] -= coef * g[i]
        rem = _as_list(rem)
    return _as_list([x * lead ** (m - n + 1) for x in rem])


def poly_gcd(f, g, p=None):
    """Polynomial gcd → list, or None when a division inside the algorithm failed

    Over GF(p) this is the plain Euclidean algorithm with a monic result; over Z it is
    the primitive PRS, i.e. after every pseudo-remainder the content of the
    coefficients is divided out. That step is not cosmetic: without it the coefficients
    grow doubly exponentially and even a degree-20 gcd never returns. The Z result is
    primitive with a positive leading coefficient, so gcd(x^2-1, x-1) == [-1, 1].
    """
    if p is None:
        f, g = _as_list(f), _as_list(g)
        if not f:
            return _primitive_part(g)
        if not g:
            return _primitive_part(f)
        while g:
            r = _pseudo_remainder(f, g)
            if r is None:
                return None
            f, g = g, _primitive_part(r)
        return _primitive_part(f)
    return _poly_gcd_mod(f, g, p)


def poly_derivative(f, p=None):
    """Formal derivative (c*x^n → n*c*x^(n-1)); over GF(p) the n are taken mod p

    Needed by squarefree and irreducibility work: over GF(p) the derivative detects the
    inseparable case (a non-constant f with f' == 0 is a p-th power), which is exactly
    the trap behind "f has no roots, so it must be irreducible".
    """
    f = _reduce(f, p)
    if len(f) <= 1:
        return []
    out = [i * f[i] for i in range(1, len(f))]
    if p is not None:
        out = [c % p for c in out]
    return _as_list(out)


def poly_eval_mod(f, x: int, p: int) -> int:
    """Horner evaluation of f at x modulo p → int in [0, p)

    Horner, not `sum(c * x**i)`: with a big p the naive form builds gigantic powers and
    the extra cost is paid for nothing.
    """
    if p <= 1:
        raise ValueError("poly_eval_mod: modulus must be > 1")
    f = _reduce(f, p)
    acc = 0
    for c in reversed(f):
        acc = (acc * (x % p) + c) % p
    return acc


def poly_from_roots(roots, p=None):
    """Monic polynomial with exactly the given roots → list (ascending)

    Multiplicity is honoured: [2, 2] gives (x-2)^2, not (x-2). Handy the other way
    round too — turn a recovered root set into the polynomial a task expects.
    """
    out = [1]
    for r in roots:
        factor = [-int(r), 1] if p is None else [(-int(r)) % p, 1]
        out = _mul(out, factor, p)
    return out


# ────────────────────────── roots over GF(p) ──────────────────────────

def poly_roots_mod_p(f, p: int, max_direct: int = 256):
    """All roots of f in GF(p) → sorted list; [] when there are none

    Strategy: strip repeated factors with gcd(f, f'); isolate the product of the
    distinct linear factors as gcd(f, x^p - x) — that polynomial is exactly the set of
    roots, because x^p - x is the product of all (x - a) over GF(p) — then split the
    result with Cantor-Zassenhaus equal-degree splitting. Degree 1 needs the direct
    solve, since no split test can ever separate a single linear factor. For small p
    the whole thing short-circuits to a brute-force sweep of the field, which is both
    faster and harder to get wrong.

    Returns None when p is not prime or f is the zero polynomial (then every field
    element is a root, which is not a usable answer).
    """
    if p < 2:
        raise ValueError("poly_roots_mod_p: modulus must be > 1")
    if not is_prime(p):
        return None
    f = _reduce(f, p)
    if not f:
        return None
    if _deg(f) == 0:
        return []
    if p <= max_direct:
        return sorted(x for x in range(p) if poly_eval_mod(f, x, p) == 0)
    roots = set()
    if _deg(f) == 1:
        inv = modinv(f[1], p)
        if inv is not None:
            roots.add((-f[0] * inv) % p)
        return sorted(roots)
    core = f
    df = poly_derivative(f, p)
    if df:
        d = _poly_gcd_mod(f, df, p)
        if d is None:
            return None
        if _deg(d) >= 1:
            # every root of gcd(f, f') is a root of f with multiplicity >= 2
            if _deg(d) == 1:
                inv = modinv(d[1], p)
                if inv is not None:
                    roots.add((-d[0] * inv) % p)
            else:
                sub = poly_roots_mod_p(d, p, max_direct)
                if sub is None:
                    return None
                roots.update(sub)
            divided = poly_divmod(f, d, p)
            if divided is None:
                return None
            core = divided[0]
    lin = _poly_gcd_mod(core, _sub(poly_powmod([0, 1], p, core, p), [0, 1], p), p)
    if lin is None:
        return None
    for factor in _split_linear(lin, p):
        if _deg(factor) == 1:
            inv = modinv(factor[1], p)
            if inv is not None:
                roots.add((-factor[0] * inv) % p)
        else:
            # split budget spent: fall back to evaluating this factor directly
            roots.update(x for x in range(p) if poly_eval_mod(factor, x, p) == 0)
    return sorted(roots)


def _split_linear(f, p: int, max_rounds: int = 200):
    """Cantor-Zassenhaus equal-degree splitting of a squarefree root product

    Returns the linear factors found. Each round splits with
    gcd(f, (x + a)^((p-1)/2) - 1); the offset a is taken from a counter rather than a
    random source so that a failing run is reproducible. A round that splits nothing is
    simply retried, and when the round budget is spent the unresolved factor is handed
    back as-is — a bounded, honest partial answer rather than an endless loop.
    """
    f = _monic(f, p)
    if _deg(f) <= 1:
        return [f] if f else []
    out = []
    stack = [f]
    rounds = 0
    while stack:
        cur = stack.pop()
        if _deg(cur) == 1:
            out.append(cur)
            continue
        split = None
        while rounds < max_rounds:
            rounds += 1
            cand = poly_powmod([rounds % p, 1], (p - 1) // 2, cur, p)
            if cand is None:
                continue
            d = _poly_gcd_mod(cur, _sub(cand, [1], p), p)
            if d is None:
                continue
            if 0 < _deg(d) < _deg(cur):
                split = d
                break
        if split is None:
            out.append(cur)  # budget spent: return the unresolved factor
            continue
        other = poly_divmod(cur, split, p)
        if other is None:
            out.append(cur)
            continue
        stack.append(split)
        stack.append(other[0])
    return out


def poly_compose(f, g, p=None):
    """f(g(x)) → list (Horner in the polynomial ring: no repeated power recomputation)

    The accumulator is seeded with the coefficient itself, NOT with []: `_mul([], g)`
    is [] by the zero-polynomial rule, so starting from [] collapses the whole Horner
    chain to [] — the classic way a composition silently returns nothing.
    """
    f = _reduce(f, p)
    g = _reduce(g, p)
    acc = []
    for c in reversed(f):
        if acc:
            acc = _mul(acc, g, p)
        if c:
            if acc:
                acc[0] += c
            else:
                acc = [c]
        if p is not None and acc:
            acc = [x % p for x in acc]
    return _as_list(acc)


def poly_powmod(f, e: int, g, p=None):
    """f^e mod g by square-and-multiply → list, or None when a reduction failed

    With g = [] there is nothing to reduce modulo and the plain e-th power comes back —
    the convenient way to build x^(p^k) before reducing it yourself. A negative exponent
    is not defined here and gives None.
    """
    if e < 0:
        return None
    f = _reduce(f, p)
    g = _reduce(g, p)
    result = _reduce([1], p)
    base = f if not g else poly_mod(f, g, p)
    if base is None:
        return None
    while e:
        if e & 1:
            result = _mul(result, base, p)
            if g:
                result = poly_mod(result, g, p)
                if result is None:
                    return None
        e >>= 1
        if e:
            base = _mul(base, base, p)
            if g:
                base = poly_mod(base, g, p)
                if base is None:
                    return None
    return result


def poly_is_irreducible(f, p: int):
    """Rabin irreducibility test over GF(p) → True/False, or None on a failed reduction

    f of degree n is irreducible iff x^(p^n) ≡ x (mod f) and gcd(f, x^(p^(n/q)) - x) = 1
    for every prime q | n. The second condition is what separates irreducible
    polynomials from products of lower-degree irreducibles whose degrees divide n — the
    first condition alone accepts those. Intended for small degree (up to about 20):
    the cost is one modular exponentiation per prime divisor plus one final check.
    """
    if p < 2:
        raise ValueError("poly_is_irreducible: modulus must be > 1")
    if not is_prime(p):
        return None
    f = _reduce(f, p)
    n = _deg(f)
    if n <= 0:
        return False
    if n == 1:
        return True
    x_poly = [0, 1]
    n_copy = n
    qs = []
    d = 2
    while d * d <= n_copy:
        if n_copy % d == 0:
            qs.append(d)
            while n_copy % d == 0:
                n_copy //= d
        d += 1
    if n_copy > 1:
        qs.append(n_copy)
    for q in qs:
        h = poly_powmod(x_poly, p ** (n // q), f, p)
        if h is None:
            return None
        g = _poly_gcd_mod(f, _sub(h, x_poly, p), p)
        if g is None:
            return None
        if _deg(g) >= 1:
            return False
    h = poly_powmod(x_poly, p ** n, f, p)
    if h is None:
        return None
    return _sub(h, x_poly, p) == []


# ────────────────────────── resultant ──────────────────────────

def _sylvester(f, g):
    """Sylvester matrix of f, g in the CLASSICAL (descending) column order

    The classical layout is the one whose determinant equals lc(f)^deg(g)·prod g(roots of
    f), and that is the convention this module documents: res(x-1, x+1) = +2, res(x^2+6,
    x+1) = +7. Laying the columns out in the ascending (c0 first) order used everywhere
    else in this file flips the determinant by (-1)^(k(k-1)/2), k = deg f + deg g — which
    is what made the integer path disagree in sign with the GF(p) recursion.

    The row/column indices are chosen so the result matches the classical definition
    directly: row i (0 <= i < n) is x^i·f placed in columns 0..m, and row n+i is x^i·g
    placed in columns 0..n.
    """
    f = _as_list(f)
    g = _as_list(g)
    m, n = _deg(f), _deg(g)
    rows = m + n
    mat = [[0] * rows for _ in range(rows)]
    for i in range(n):
        for j in range(m + 1):
            mat[i][i + j] = f[m - j]
    for i in range(m):
        for j in range(n + 1):
            mat[n + i][i + j] = g[n - j]
    return mat, (m, n)


def _det_bareiss(mat, p=None):
    """Exact determinant by Bareiss fraction-free elimination

    Bareiss rather than a cofactor expansion: each step divides by the previous pivot,
    so intermediate entries stay small integers instead of exploding — the only reason
    a 20x20 matrix is feasible at all. With p given, the elimination runs mod p.
    """
    n = len(mat)
    if n == 0:
        return 1
    M = [[(x % p if p is not None else x) for x in row] for row in mat]
    sign = 1
    prev = 1
    for k in range(n - 1):
        if M[k][k] == 0:
            swap = None
            for i in range(k + 1, n):
                if M[i][k] != 0:
                    swap = i
                    break
            if swap is None:
                return 0
            M[k], M[swap] = M[swap], M[k]
            sign = -sign
        piv = M[k][k]
        for i in range(k + 1, n):
            for j in range(k + 1, n):
                num = M[i][j] * piv - M[i][k] * M[k][j]
                if p is None:
                    M[i][j] = num // prev
                else:
                    M[i][j] = num % p
            M[i][k] = 0
        prev = piv
    det = M[n - 1][n - 1] % p if p is not None else M[n - 1][n - 1]
    if sign < 0:
        det = -det
    return det % p if p is not None else det


def _resultant_rec(f, g, p):
    """Resultant over GF(p) by division, only used when a modulus is given

    With f = q·g + r and k = deg r, the identity used is
        res(f, g) = (-1)^(deg f · deg g) · lc(g)^(deg f - k) · res(g, r).
    Writing res(r, g) instead of res(g, r) is the sign trap: the two differ by
    (-1)^(k·n), and for res(x-1, x+1) the wrong order returns -2 where the product
    formula lc(f)^deg(g)·prod g(roots of f) gives +2. When deg f is already below deg g
    the arguments are swapped first (res is antisymmetric up to (-1)^(mn)), so the
    recursion always makes progress. Over Z this path is not used, because f mod g can
    leave Z[x].
    """
    f, g = _reduce(f, p), _reduce(g, p)
    m, n = _deg(f), _deg(g)
    if m < 0 or n < 0:
        return None
    if m == 0 and n == 0:
        return f[0] * g[0]
    if m == 0:
        return f[0] ** n
    if n == 0:
        return g[0] ** m
    if m < n:
        return _resultant_rec(g, f, p)
    q, r = poly_divmod(f, g, p)
    if q is None:
        return None
    if not r:
        return 0  # a common factor: the resultant vanishes by definition
    k = _deg(r)
    sign = -1 if (m * n) % 2 else 1
    lead = g[-1] ** (m - k)
    sub = _resultant_rec(g, r, p)
    if sub is None:
        return None
    return sign * lead * sub


def poly_resultant(f, g, p=None):
    """Resultant Res(f, g) → int, or None when it is undefined or too large

    res(f, g) = lc(f)^deg(g) · prod g(roots of f), and it vanishes exactly when f and g
    share a common factor (a common root) — the standard probe for "do these two
    polynomials share a root mod p".

    Over GF(p) the Euclidean recursion is used; over Z the determinant of the Sylvester
    matrix is, because the recursion needs exact polynomial division over Z and fails
    whenever lc(g) does not divide the remainder's leading coefficient (res of two
    ordinary integer quadratics is a perfectly well-defined integer, and returning None
    for it is wrong).

    Edge conventions: a zero operand against a non-constant one gives 0; a non-zero
    constant c as an operand contributes c^deg(other). With p given the answer is in
    [0, p); with p=None it is an exact (possibly large) integer.
    """
    f = _reduce(f, p)
    g = _reduce(g, p)
    m, n = _deg(f), _deg(g)
    if m < 0 and n < 0:
        return None
    if m < 0 or n < 0:
        other = n if m < 0 else m
        return 0 if other > 0 else 1
    if m == 0 and n == 0:
        val = f[0] * g[0]
        return val % p if p is not None else val
    if m + n > _MAX_DEGREE:
        return None
    if p is not None:
        return _resultant_rec(f, g, p) % p
    mat, _ = _sylvester(f, g)
    return _det_bareiss(mat, None)


# ────────────────────────── GF(2), integer-encoded ──────────────────────────
# Encoding note: bit i of the integer is the coefficient of x^i, so the polynomial
# itself reads right to left — x^4 + x + 1 is 0b1_0011 = 19. This is the encoding CRC
# tables, LFSR taps and every CTF "poly = 0x..." line already use, so no conversion is
# needed at the boundary. The list encoding above is never mixed with this one.

def _gf2(a: int) -> int:
    """Validate/return an integer-encoded GF(2) polynomial (the encoding is canonical)

    Unlike the list encoding there is nothing to trim: the highest set bit IS the
    degree, so an integer encoding cannot carry high-degree zeros. Only the range is
    checked, because a negative int is not a polynomial.
    """
    if not isinstance(a, int) or isinstance(a, bool):
        raise TypeError("GF(2) polynomial must be an integer")
    if a < 0:
        raise ValueError("GF(2) polynomial encoding must be a non-negative integer")
    return a


def _gf2_degree(a: int) -> int:
    """Degree of the integer-encoded polynomial (0 has degree -1)"""
    return a.bit_length() - 1


def gf2_poly_mul(a: int, b: int) -> int:
    """Product of two GF(2) polynomials (carry-less multiply) → int

    Shift-and-XOR is the definition, not a shortcut: in F_2[x] there is no carry, so the
    product is the XOR of the shifted copies. A `*` on the integers would carry into the
    neighbouring coefficients and is the classic bug in hand-rolled CRC code.
    """
    a = _gf2(a)
    b = _gf2(b)
    out = 0
    while b:
        if b & 1:
            out ^= a
        b >>= 1
        a <<= 1
    return out


def gf2_poly_mod(a: int, b: int):
    """Remainder of a modulo b → int, or None when b is the zero polynomial

    Long division with shifts and XOR: align the divisor's top bit under the dividend's
    top bit, XOR, repeat. b = 0 is undefined, hence None.
    """
    a = _gf2(a)
    b = _gf2(b)
    if b == 0:
        return None
    db = _gf2_degree(b)
    while a and _gf2_degree(a) >= db:
        a ^= b << (_gf2_degree(a) - db)
    return a


def gf2_poly_divmod(a: int, b: int):
    """(quotient, remainder) over GF(2) → (int, int), or None when b is zero"""
    a = _gf2(a)
    b = _gf2(b)
    if b == 0:
        return None
    db = _gf2_degree(b)
    quot = 0
    while a and _gf2_degree(a) >= db:
        shift = _gf2_degree(a) - db
        quot |= 1 << shift
        a ^= b << shift
    return quot, a


def gf2_poly_gcd(a: int, b: int) -> int:
    """gcd over GF(2) → int (monic by construction; gcd(0, 0) = 0)

    Monic normalisation is free in this encoding: any non-zero constant is the unit 1,
    and "monic" here just means the leading bit is set — which is true of every non-zero
    integer-encoded polynomial. So the raw Euclid remainder is already the canonical gcd.
    """
    a = _gf2(a)
    b = _gf2(b)
    while b:
        a, b = b, gf2_poly_mod(a, b)
    return a


def gf2_poly_roots(a: int):
    """Roots of a GF(2) polynomial → subset of [0, 1], ascending; None when a is zero

    Over GF(2) only two values exist, so a direct evaluation is the honest answer rather
    than a factorisation: 0 is a root iff the constant term (bit 0) is clear, and 1 is a
    root iff an even number of coefficients are set (the polynomial evaluates to 0 at 1).
    Checking exactly these two cases means no root can be missed.
    """
    a = _gf2(a)
    if a == 0:
        return None  # every element of the field is a root: not a usable answer
    roots = []
    if a & 1 == 0:
        roots.append(0)
    if bin(a).count("1") % 2 == 0:
        roots.append(1)
    return roots
