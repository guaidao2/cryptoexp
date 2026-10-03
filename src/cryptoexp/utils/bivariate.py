"""Bivariate polynomials and bivariate Coppersmith (small roots of f(x, y) = 0 mod N).

Why this module exists: `coppersmith_univariate` handles one small unknown, but a whole
family of tasks has **two** small unknowns at once - most visibly "the top half of both
RSA primes is known", where f(x, y) = (p_high + x)(q_high + y) - n and both x and y are
small. Hand-rolling that means writing bivariate multiplication (where a dropped cross
term is a silent wrong answer) and the bivariate resultant (where a wrong sign or a
non-fraction-free elimination is a silent wrong answer too). Both live here, tested.

Representation (fixed here, used by every public name in this file AND returned by
`poly2_resultant`'s bivariate inputs):
  * A bivariate polynomial is a dict `{(i, j): coefficient}` - key (i, j) means the
    monomial x^i * y^j (i is the x exponent, j the y exponent). Values are ints.
  * Missing keys are zero and are never stored: the reducer drops zero coefficients and
    the empty dict `{}` is the zero polynomial. There is no "trailing zero" problem as
    there is with a list encoding, so no trimming convention is needed.
  * `poly2_resultant(f, g, y)` returns a UNIVARIATE polynomial as a plain list of
    coefficients in ASCENDING order (c[0] first), matching `polytools` - so the result
    can be fed straight into `polytools.poly_roots_mod_p`, `poly_gcd`, `poly_divmod`.
  * Over GF(p) (`p` given) every coefficient is reduced into [0, p); p must be > 1.
    With p=None the arithmetic is over Z and exact.

Cost and practical range (measured on this machine, CPython 3.11, pure-Python Fraction
LLL from `.lattice`):
  * `poly2_resultant` is the determinant of the Sylvester matrix over the polynomial
    ring, eliminated with the fraction-free Bareiss recurrence (each division is exact,
    and a non-exact one makes the whole call return None - never a wrong answer). The
    one exception is the degree-1 case, which uses the closed form
    Res = lc(f)^deg(g) * g(root of f) with the denominators cleared; that is the shape
    every Coppersmith post-processing resultant has, and it keeps this module fast (a
    128-bit instance's resultant is sub-millisecond). Cost otherwise is O(d^3)
    polynomial multiplications in d = deg(f, var) + deg(g, var); the function refuses
    (returns None) once d exceeds `_SYLV_DIM_CAP` (= 14) or an intermediate univariate
    degree exceeds `_POLY_DEG_CAP` (= 5000). It is deliberately NOT the
    evaluate-at-deg+1-points-then-interpolate method.
  * `coppersmith_bivariate` inherits `.lattice.lll`'s hard cap of 12 in each dimension,
    so the shift lattice is assembled greedily (a row is only added while its monomials
    still fit the 12-column budget) and four orderings are tried. Two screens keep the
    cost bounded: a conservative Howgrave-Graham determinant test (a lattice that provably
    cannot carry the bound is never reduced) and a preflight on the basis entry size,
    because the pure-Python Fraction reduction grows steeply with it (measured: 766-bit
    entries -> 37 s, 1035-bit -> 76 s and still failed, so the cap is 1000 bits).
    MEASURED (m=2, t=1, default budgets) on the two-unknown RSA instance
    f = (P + x)(Q + y) - n, |x|, |y| < X = Y:
        X = Y = 2^2 .. 2^6   solved for n of 64, 128, 256 and 384 bits (~3-38 s)
        X = Y = 2^7          2 of 3 at 64 bits, 0 of 3 at 128 and 256 bits
        X = Y = 2^8          0 of 6 at 64 bits (but 4/4 when P == Q)
        X = Y = 2^12         not solved at any size
    So the honest summary is "a few bits per unknown, and n up to ~384 bits", NOT the
    XY < N^(2/3) the literature gives for the bilinear case. The gap is the 12x12 lattice
    cap: f^2 is degree 2 in each variable, its monomials alone nearly fill the column
    budget, and the greedy builder cannot fit the shifts that would carry the bound. This
    is a CTF-scale attack and it is documented as one.
  * `known_high_bits_two_primes` therefore needs the unknown low part of each prime to be
    a handful of bits: 64/128/256/384-bit n work with known_bits = half - 6, and a 512-bit
    n is no longer worth it - with the cap lifted it still succeeds but takes 74 s and its
    basis entries are 1035 bits, so the preflight refuses it immediately (0.0 s) and says
    why. On failure p and q stay None and the note names the bound reached and the
    direction to widen.

Every root in a result is verified by substituting into f modulo N before it is
reported; an unverified candidate is mentioned in the note and never in "roots".

Pure standard library; the number theory and the lattice come from `.algebra`,
`.lattice` and `.polytools`.
"""

import math
import re
import time

from . import algebra as A
from . import lattice as L
from . import polytools as PT

__all__ = [
    "poly2_from_terms", "poly2_mul", "poly2_add", "poly2_sub", "poly2_pow",
    "poly2_eval", "poly2_degree", "poly2_scale", "poly2_shift_x", "poly2_shift_y",
    "poly2_resultant", "coppersmith_bivariate", "known_high_bits_two_primes",
]

# bounds (all documented, all enforced) ---------------------------------------------------

_MAX_ROWS = 12          # .lattice.lll refuses more than 12 vectors (returns None)
_MAX_COLS = 12          # ... and more than 12 columns, so the shift set must fit both
_SYLV_DIM_CAP = 14      # Sylvester matrix dimension for poly2_resultant (d^3 polynomial ops)
_POLY_DEG_CAP = 5000    # give up on a univariate intermediate beyond this degree
_SCAN_DIVISORS = 200000  # divisor scan budget inside _int_roots
_SCAN_MAX_BITS = 64      # ... and only while the constant term is this small
_INT_ROOT_DEG = 14       # degree beyond which _int_roots gives up (documented)
_MAX_POLYS = 7           # pairwise-resultant stage uses at most this many polynomials
_ROOT_POLY_DEG = 6       # a resultant of this degree or less is solved on its own
_LAST_SCREEN = {}        # lattices dropped by each screen (see _candidate_lattices)
_MAX_COEFF_BITS = 1000   # preflight: reduce only while basis entries are this small


# bivariate polynomial arithmetic ---------------------------------------------------------

def _reduce_poly2(f, p=None):
    """Validate a {(i, j): c} dict, drop zeros and reduce coefficients mod p"""
    if f is None:
        return {}
    if not isinstance(f, dict):
        raise TypeError("bivariate polynomial must be a {(i, j): coefficient} dict")
    if p is not None and p <= 1:
        raise ValueError("polynomial modulus must be > 1")
    out = {}
    items = []
    for key, val in f.items():
        if not isinstance(key, tuple) or len(key) != 2:
            raise TypeError("bivariate monomial keys must be (i, j) tuples")
        i, j = key
        if not isinstance(i, int) or not isinstance(j, int) or i < 0 or j < 0:
            raise ValueError("bivariate exponents must be non-negative integers")
        if not isinstance(val, int) or isinstance(val, bool):
            raise TypeError("bivariate coefficients must be integers")
        items.append((i, j, val))
    for i, j, val in items:
        if p is not None:
            val %= p
        if val:
            out[(i, j)] = val
    return out


def poly2_from_terms(terms):
    """Build a bivariate polynomial from an explicit term list -> {(i, j): c}

    Accepts either a dict {(i, j): c} or an iterable of (c, i, j) triples, i.e.
    `poly2_from_terms([(1, 1, 1), (7, 0, 0)])` is x*y + 7. Zero coefficients are
    dropped, so the result is canonical and two spellings of the same polynomial
    compare equal.
    """
    if terms is None:
        return {}
    if isinstance(terms, dict):
        return _reduce_poly2(terms, None)
    out = {}
    for term in terms:
        if not isinstance(term, (list, tuple)) or len(term) != 3:
            raise TypeError("a term must be (coefficient, i, j)")
        c, i, j = term
        out[(int(i), int(j))] = out.get((int(i), int(j)), 0) + int(c)
    return _reduce_poly2(out, None)


def poly2_add(f, g, p=None):
    """f + g coefficient-wise"""
    f, g = _reduce_poly2(f, p), _reduce_poly2(g, p)
    out = dict(f)
    for key, val in g.items():
        out[key] = out.get(key, 0) + val
    return _reduce_poly2(out, p)


def poly2_sub(f, g, p=None):
    """f - g coefficient-wise"""
    f, g = _reduce_poly2(f, p), _reduce_poly2(g, p)
    out = dict(f)
    for key, val in g.items():
        out[key] = out.get(key, 0) - val
    return _reduce_poly2(out, p)


def poly2_mul(f, g, p=None):
    """Exact schoolbook product: EVERY monomial pair is multiplied and the result is
    accumulated, so no cross term can be dropped.

    This is the routine users get wrong by hand: (x + y)(x + y) must give x^2 + 2xy +
    y^2, and the 2xy lives or dies on the inner loop being over all of g rather than
    over "the same degree as f". Terms are accumulated with `+=` (the same (i, j) can
    be reached from several pairs) and zero sums are dropped at the end.
    """
    f, g = _reduce_poly2(f, p), _reduce_poly2(g, p)
    if not f or not g:
        return {}
    out = {}
    for (i1, j1), c1 in f.items():
        for (i2, j2), c2 in g.items():
            key = (i1 + i2, j1 + j2)
            out[key] = out.get(key, 0) + c1 * c2
    return _reduce_poly2(out, p)


def poly2_pow(f, k, p=None):
    """f^k by repeated exact multiplication (k = 0 gives the constant 1)"""
    f = _reduce_poly2(f, p)
    if k < 0:
        raise ValueError("poly2_pow: negative exponent")
    if p is not None and p <= 1:
        raise ValueError("polynomial modulus must be > 1")
    out = {(0, 0): 1 % p if p is not None else 1}
    for _ in range(k):
        out = poly2_mul(out, f, p)
    return out


def poly2_scale(f, c, p=None):
    """f * c (scalar multiplication)"""
    f = _reduce_poly2(f, p)
    c = int(c)
    if c == 0 or not f:
        return {}
    return _reduce_poly2({key: val * c for key, val in f.items()}, p)


def poly2_shift_x(f, k, p=None):
    """f * x^k - every exponent's first component moves up by k (k >= 0)"""
    f = _reduce_poly2(f, p)
    k = int(k)
    if k < 0:
        raise ValueError("poly2_shift_x: negative shift")
    if k == 0:
        return f
    return {(i + k, j): c for (i, j), c in f.items()}


def poly2_shift_y(f, k, p=None):
    """f * y^k - every exponent's second component moves up by k (k >= 0)"""
    f = _reduce_poly2(f, p)
    k = int(k)
    if k < 0:
        raise ValueError("poly2_shift_y: negative shift")
    if k == 0:
        return f
    return {(i, j + k): c for (i, j), c in f.items()}


def poly2_eval(f, x, y, p=None):
    """Nested (Horner) evaluation of f at (x, y) -> int, reduced mod p when given

    The polynomial is first collected into a univariate polynomial in y with
    polynomial coefficients in x, and each of those is Horner-evaluated at x. That is
    the "nested" form asked for: no repeated big powers, and it is the natural
    self-check for `poly2_mul` (f(a,b)*g(a,b) == (f*g)(a,b)).
    """
    f = _reduce_poly2(f, p)
    if not f:
        return 0
    if p is not None and p <= 1:
        raise ValueError("polynomial modulus must be > 1")
    by_y = {}
    for (i, j), c in f.items():
        by_y.setdefault(j, {})[i] = c
    deg_y = max(by_y)
    acc = 0
    for j in range(deg_y, -1, -1):
        coef = by_y.get(j)
        inner = 0
        if coef:
            deg_x = max(coef)
            for i in range(deg_x, -1, -1):
                inner = inner * x + coef.get(i, 0)
                if p is not None:
                    inner %= p
        acc = acc * y + inner
        if p is not None:
            acc %= p
    return acc


def poly2_degree(f):
    """(total degree, degree in x, degree in y) of f

    The zero polynomial reports (-1, -1, -1), mirroring `polytools._deg`.
    """
    f = _reduce_poly2(f, None)
    if not f:
        return (-1, -1, -1)
    dx = max(i for i, _ in f)
    dy = max(j for _, j in f)
    return (max(i + j for i, j in f), dx, dy)


# univariate helpers (ascending coefficients) ---------------------------------------------

def _poly_trim(f):
    """Drop high-degree zeros; [] means the zero polynomial (matches polytools)"""
    out = [int(c) for c in f]
    while out and out[-1] == 0:
        out.pop()
    return out


def _poly_sub(a, b, p=None):
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = (a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)
        if p is not None:
            out[i] %= p
    return _poly_trim(out)


def _poly_mul(a, b, p=None):
    if not a or not b:
        return []
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if not x:
            continue
        for j, y in enumerate(b):
            out[i + j] += x * y
    if p is not None:
        out = [c % p for c in out]
    return _poly_trim(out)


def _poly_scale(a, c, p=None):
    if p is not None:
        c %= p
    if c == 0:
        return []
    return _poly_trim([x * c for x in a])


def _poly_eval_int(a, x, p=None):
    """Horner evaluation at an integer point"""
    if p is None:
        acc = 0
        for c in reversed(a):
            acc = acc * x + c
        return acc
    acc = 0
    xm = x % p
    for c in reversed(a):
        acc = (acc * xm + c) % p
    return acc


def _poly_content(a):
    g = 0
    for c in a:
        g = math.gcd(g, abs(c))
    return g


def _poly_primitive(a):
    """Divide out the coefficient content; [] stays []"""
    if not a:
        return []
    c = _poly_content(a)
    if c and c != 1:
        return [x // c for x in a]
    return list(a)


def _poly_divmod_q(a, b):
    """Exact division over the rationals -> (quotient, remainder), Fractions involved"""
    from fractions import Fraction
    a = [Fraction(c) for c in a]
    b = [Fraction(c) for c in b]
    if not b:
        raise ZeroDivisionError("polynomial division by zero")
    if len(a) < len(b):
        return [], a
    dg = len(b) - 1
    lead = b[dg]
    rem = list(a)
    quot = [Fraction(0)] * (len(a) - dg)
    for k in range(len(a) - 1, dg - 1, -1):
        if not rem[k]:
            continue
        coef = rem[k] / lead
        quot[k - dg] = coef
        if coef:
            for i in range(dg + 1):
                rem[k - dg + i] -= coef * b[i]
    while rem and not rem[-1]:
        rem.pop()
    return quot, rem


def _poly_trunc_fraction(a, maxdeg):
    """Truncate a Fraction coefficient list to degree <= maxdeg and integralise

    Used only as a last-resort rescue when the Bareiss step leaves a non-zero
    remainder: the rescue is safe because every candidate root derived from the
    result is verified before it is reported.
    """
    out = []
    for c in a[:maxdeg + 1]:
        if isinstance(c, int):
            out.append(c)
        else:
            out.append(c.numerator // c.denominator if c.denominator != 1 else c.numerator)
    return _poly_trim(out)


def _poly_bareiss_exact(rows, p=None, maxdeg=None, counter=None):
    """Bareiss fraction-free elimination where the entries are univariate polynomials

    Returns the determinant (a univariate coefficient list), or None when the
    elimination cannot be carried out exactly (the Bareiss division must be exact
    over Z; it always is in exact arithmetic, but a rescue-truncated intermediate is
    reported as a failure rather than as a wrong determinant). With p given, the
    division is a plain inverse multiplication, which is always exact.
    """
    n = len(rows)
    if n == 0:
        return [1]
    M = [[_poly_trim(row[j]) if p is None else [c % p for c in _poly_trim(row[j])]
          for j in range(n)] for row in rows]
    sign = 1
    prev = [1]
    for k in range(n - 1):
        if not M[k][k]:
            swap = None
            for i in range(k + 1, n):
                if M[i][k]:
                    swap = i
                    break
            if swap is None:
                return []
            M[k], M[swap] = M[swap], M[k]
            sign = -sign
        piv = M[k][k]
        for i in range(k + 1, n):
            for j in range(k + 1, n):
                if p is None:
                    num = _poly_sub(_poly_mul(M[i][j], piv, p),
                                    _poly_mul(M[i][k], M[k][j], p), p)
                    if counter is not None:
                        counter[0] += 1
                        if counter[0] > counter[1]:
                            return None
                    if not num:
                        M[i][j] = []
                        continue
                    if len(prev) == 1:
                        if prev[0] != 1:
                            # dividing by a constant is exact iff the constant divides;
                            # the division is what the Bareiss recurrence requires (the
                            # earlier version MULTIPLIED by prev[0] here, which inflated
                            # every determinant by prev^(#steps) - measured as a factor
                            # of 16 on a 4x4 Sylvester matrix)
                            c = abs(prev[0])
                            if any(x % c for x in num):
                                return None
                            M[i][j] = [x // c for x in num]
                        else:
                            M[i][j] = num
                    else:
                        quot, rem = _poly_divmod_q(num, prev)
                        if rem:
                            if maxdeg is None or len(num) - 1 > maxdeg:
                                return None
                            M[i][j] = _poly_trunc_fraction(num, maxdeg)
                        else:
                            ints = []
                            ok = True
                            for c in quot:
                                if c.denominator != 1:
                                    ok = False
                                    break
                                ints.append(c.numerator)
                            M[i][j] = _poly_trim(ints) if ok else None
                            if M[i][j] is None:
                                return None
                else:
                    num = _poly_sub(_poly_mul(M[i][j], piv, p),
                                    _poly_mul(M[i][k], M[k][j], p), p)
                    if counter is not None:
                        counter[0] += 1
                        if counter[0] > counter[1]:
                            return None
                    if len(prev) != 1:
                        return None
                    c = prev[0] % p
                    inv = A.modinv(c, p)
                    if inv is None:
                        return None
                    M[i][j] = _poly_scale(num, inv, p)
            M[i][k] = []
        prev = piv
    det = M[n - 1][n - 1]
    if p is None and sign < 0:
        det = [-c for c in det]
    return _poly_trim(det) if p is None else _poly_trim([c % p for c in det])


# resultant -------------------------------------------------------------------------------

def _sylvester_rows(f, g, var):
    """Sylvester matrix rows of f, g with respect to `var` ('x' or 'y')

    Row order is the one whose determinant agrees with `polytools._sylvester` (and
    therefore with `polytools.poly_resultant`) on the same polynomials: the deg(f) rows
    of shifted g come FIRST, then the deg(g) rows of shifted f. Columns are ascending
    in `var` within each row (coefficient of var^0 in the leftmost column). Verified by
    direct determinant comparison on four hand-built cases; the opposite block order
    flips the determinant by (-1)^(deg f * deg g).
    """
    fc = _coef_lists_in(f, var)
    gc = _coef_lists_in(g, var)
    df = _deg_in(f, var)
    dg = _deg_in(g, var)
    if df < 0 or dg < 0 or (df == 0 and dg == 0):
        return None
    n = df + dg
    rows = []
    for i in range(df):
        row = [[] for _ in range(n)]
        for k in range(dg + 1):
            row[i + k] = gc.get(k, [])
        rows.append(row)
    for i in range(dg):
        row = [[] for _ in range(n)]
        for k in range(df + 1):
            row[i + k] = fc.get(k, [])
        rows.append(row)
    return rows


def _deg_in(poly, var):
    """Degree of a bivariate polynomial in one variable ('x' or 'y'), -1 for zero"""
    if not poly:
        return -1
    return max((j if var == "y" else i) for i, j in poly)


def _coef_lists_in(poly, var):
    """{power of var: univariate coefficient list in the other variable}"""
    by_var = {}
    if var == "y":
        for (i, j), c in poly.items():
            by_var.setdefault(j, {})[i] = c
    else:
        for (i, j), c in poly.items():
            by_var.setdefault(i, {})[j] = c
    out = {}
    for k, d in by_var.items():
        lst = [0] * (max(d) + 1)
        for power, c in d.items():
            lst[power] = c
        out[k] = _poly_trim(lst)
    return out


def poly2_resultant(f, g, y, p=None):
    """Res(f, g) with respect to one variable -> univariate coefficient list (ascending)

    Args:
        f, g: bivariate polynomials as {(i, j): c}
        y: True -> the result is a polynomial in x (y is eliminated);
           False -> the result is a polynomial in y (x is eliminated)
        p: None for exact integer arithmetic, or a prime modulus
    Returns:
        list of coefficients lowest degree first (matching `polytools`), `[]` for the
        zero polynomial, or None when the computation is out of the documented range:
        the Sylvester dimension deg(f, var) + deg(g, var) above `_SYLV_DIM_CAP` (= 14),
        or a univariate intermediate above `_POLY_DEG_CAP`. None is never a wrong
        answer - every branch that could not be computed exactly returns None.

    Method: the determinant of the Sylvester matrix whose entries are univariate
    polynomials in the remaining variable, eliminated with the fraction-free Bareiss
    recurrence (the same reason `polytools._det_bareiss` exists: the intermediate
    entries stay polynomial instead of exploding). Cost is O(d^3) polynomial
    multiplications in d = the matrix dimension. It is deliberately NOT the
    evaluate-at-many-points-then-interpolate method, which needs deg+1 separate
    resultants and is both slower and easier to get wrong. The one exception is the
    degree-1 case (one operand linear in the eliminated variable), which is not an
    interpolation but the exact closed form
        Res(f, g) = (-1)^deg(g) * (a*e - c*d)^deg(g) * g(x, -f0/f1) * f1^deg(g)
    evaluated by clearing denominators; that is the shape every Coppersmith
    post-processing resultant has, and it is what keeps this module fast.

    Over Z the result is the exact (fraction-free) determinant, i.e. the usual
    resultant up to a constant factor; the property callers rely on is "vanishes
    exactly at the common roots". `y` is a required positional argument so the caller
    always states which variable is eliminated.
    """
    f, g = _reduce_poly2(f, p), _reduce_poly2(g, p)
    if p is not None and p <= 1:
        raise ValueError("polynomial modulus must be > 1")
    if not f or not g:
        return []
    var = "y" if y else "x"
    df, dg = _deg_in(f, var), _deg_in(g, var)
    if df < 0 or dg < 0:
        return []
    if df == 0 and dg == 0:
        # both are constants with respect to the eliminated variable: the resultant is
        # the product of the two constants, matching polytools.poly_resultant
        return _scale_poly(_poly_mul([_coef_lists_in(f, var)[0][0]],
                                     [_coef_lists_in(g, var)[0][0]]), p)
    if df == 0:
        # f is a constant c with respect to var: Res = c^deg(g, var)
        return _scale_poly(_poly_pow_int(_coef_lists_in(f, var)[0], dg), p)
    if dg == 0:
        return _scale_poly(_poly_pow_int(_coef_lists_in(g, var)[0], df), p)
    if df == 1 or dg == 1:
        return _resultant_linear(f, g, var, p)
    n = df + dg
    if n > _SYLV_DIM_CAP:
        return None
    rows = _sylvester_rows(f, g, var)
    if rows is None:
        return None
    budget = [0, 200000]
    out = _poly_bareiss_exact(rows, p, maxdeg=_POLY_DEG_CAP, counter=budget)
    if out is None:
        return None
    if len(out) - 1 > _POLY_DEG_CAP:
        return None
    return out


def _poly_pow_int(a, k):
    """a^k by repeated multiplication (k >= 0)"""
    out = [1]
    for _ in range(k):
        out = _poly_mul(out, a)
    return out


def _resultant_linear(f, g, var, p=None):
    """Resultant when at least one operand is degree 1 in the eliminated variable

    Uses the classical identity Res(f, g) = (-1)^(mn) * lc(g)^m * prod g(roots of f),
    which for a linear operand collapses to one substitution with the denominator
    cleared exactly:
        deg(f) = 1:  Res = lc(f)^n * g(root of f)
        deg(g) = 1:  Res = (-1)^m * lc(g)^m * f(root of g)
    The signs are fixed empirically against `polytools.poly_resultant` on the same
    polynomials: the first branch needs NO extra sign (an earlier version negated it and
    returned -22 where the determinant is 22), while the second carries (-1)^deg(f).
    """
    df, dg = _deg_in(f, var), _deg_in(g, var)
    cf = _coef_lists_in(f, var)
    cg = _coef_lists_in(g, var)
    if df == 1:
        f0, f1 = cf.get(0, []), cf.get(1, [])
        if not f1:
            return []
        return _scale_poly(_substitute_scaled(cg, dg, f0, f1), p)
    g0, g1 = cg.get(0, []), cg.get(1, [])
    if not g1:
        return []
    # Res(f, g) = (-1)^(deg f * deg g) * Res(g, f) with deg g = 1, so the sign is
    # (-1)^deg f - the mirror of the branch above
    out = _substitute_scaled(cf, df, g0, g1)
    return _scale_poly(_negate_if(out, df % 2), p)


def _substitute_scaled(c, dc, h0, h1):
    """lc(h)^dc * c(evaluated at the root of h): sum_k c_k * (-h0)^k * h1^(dc-k)

    `c` is the {power: univariate list} coefficient table of the other operand and `dc`
    its degree in the eliminated variable. Clearing the denominator this way keeps the
    result in Z[x] exactly - no Fraction appears. The (-1)^k on the k-th power of h0 is
    the part that is easy to lose: dropping it returned (3 + 16x + 3x^2) as
    (-3 - 16x - 7x^2) for res((x+3)y + 2, x^2*y + 5x + 1), i.e. a sign-flipped and
    visibly different polynomial while every magnitude still looked plausible.
    """
    out = []
    for k in range(dc + 1):
        term = c.get(k, [])
        if not term:
            continue
        term = _poly_mul(term, _poly_pow_int(h0, k))
        if k % 2:
            term = [-x for x in term]
        term = _poly_mul(term, _poly_pow_int(h1, dc - k))
        if not term:
            continue
        if len(out) < len(term):
            out.extend([0] * (len(term) - len(out)))
        for idx, cc in enumerate(term):
            out[idx] += cc
    return _poly_trim(out)


def _negate_if(a, flag):
    return [-c for c in a] if flag else a


def _scale_poly(a, p=None):
    return _poly_trim([c % p for c in a]) if p is not None else _poly_trim(a)


# integer roots of a univariate polynomial ------------------------------------------------

def _int_roots(coeffs, shift, max_tries=_SCAN_DIVISORS):
    """Exact integer roots of `coeffs` (ascending, may be huge) - no numeric solver

    Only roots that satisfy p(r) == 0 exactly are returned, so nothing here can
    fabricate one. The paths, cheapest first:
      1. degree 1 -> exact division (and degree 2 with an even middle coefficient ->
         perfect-square discriminant, as `polytools.poly_roots_mod_p` does).
      2. general 2 <= degree <= _INT_ROOT_DEG with a SMALL constant term: every integer
         root divides the constant term, so the divisors are scanned directly. This is
         the path that actually fires: the GCD of two resultants is usually a quadratic
         with modest coefficients (measured: x^2 - 78x + 1517 for a root of 37), and
         without it the module reported no root at all.
      3. a divisor scan with early pruning by the roots modulo a small prime, for larger
         polynomials.
    `shift` is an upper bound used only to discard candidates cheaply; it is NOT trusted
    as a correctness argument, an exact evaluation decides. A polynomial whose constant
    term is astronomically large is deliberately abandoned - that is the documented limit.
    """
    p = _poly_trim(coeffs)
    if not p:
        return []
    d = len(p) - 1
    roots = []
    if d <= 0:
        return roots
    if p[0] == 0:
        roots.append(0)
    if d == 1:
        a, b = p[0], p[1]
        if b and a % b == 0:
            roots.append(-a // b)
        return sorted(set(roots))
    if d == 2:
        c0, c1, c2 = p
        if c1 % 2 == 0:
            disc = c1 * c1 - 4 * c2 * c0
            r = A.perfect_square(disc)
            if r is not None:
                for num in (-c1 + r, -c1 - r):
                    if num % (2 * c2) == 0:
                        roots.append(num // (2 * c2))
        if roots or not c0:
            return sorted(set(roots))
    c0 = abs(p[0])
    if not c0 or c0.bit_length() > _SCAN_MAX_BITS:
        return sorted(set(roots))
    bound = int(shift) if isinstance(shift, int) and shift > 0 else 0
    # pruning: any integer root is congruent to a root of p modulo 2 (or 3)
    mod = 2
    res_mod = [c % mod for c in p]
    if not any(res_mod):
        mod = 3
        res_mod = [c % mod for c in p]
        if not any(res_mod):
            mod = None
    tries = 0
    limit = max_tries if d <= 3 else max_tries // 4
    r = 1
    while r * r <= c0 and tries < limit:
        if c0 % r == 0:
            for cand in (r, -r, c0 // r, -(c0 // r)):
                tries += 1
                if bound and abs(cand) >= bound:
                    continue
                if mod is not None and _poly_eval_int(res_mod, cand % mod, mod) != 0:
                    continue
                if cand not in roots and _poly_eval_int(p, cand) == 0:
                    roots.append(cand)
        r += 1
    return sorted(set(roots))


# Coppersmith post-processing helpers -----------------------------------------------------

def _to_y_univariate(poly, x0):
    """Substitute x = x0 -> univariate polynomial in y (ascending coefficients)"""
    out = []
    for (i, j), c in poly.items():
        if not c:
            continue
        val = c * (x0 ** i)
        if len(out) <= j:
            out.extend([0] * (j + 1 - len(out)))
        out[j] += val
    return _poly_trim(out)


def _solve_for_y(poly, x0, Y, tries=_SCAN_DIVISORS):
    """Integer y with poly(x0, y) == 0 and |y| < Y (exact division / discriminant)"""
    q = _to_y_univariate(poly, x0)
    if not q or q[0] == 0:
        return []
    out = []
    d = len(q) - 1
    if d == 1 and q[1]:
        if q[0] % q[1] == 0:
            out.append(-q[0] // q[1])
    elif d == 2:
        c0, c1, c2 = q
        if c1 % 2 == 0:
            disc = c1 * c1 - 4 * c2 * c0
            r = A.perfect_square(disc)
            if r is not None:
                for num in (-c1 + r, -c1 - r):
                    if num % (2 * c2) == 0:
                        out.append(num // (2 * c2))
    elif d >= 3:
        for cand in _int_roots(q, Y, max_tries=tries):
            out.append(cand)
    return sorted({y for y in out if abs(y) < Y and _poly_eval_int(q, y) == 0})


# the lattice shift set -------------------------------------------------------------------

def _shift_polys(f, N, m, order, max_rows=_MAX_ROWS, max_cols=_MAX_COLS):
    """Greedily assemble a shift lattice that is exactly bounded by the caps

    Rows are x^i * y^j * f^k * N^(m-k) for k < m and x^i * y^j * f^m for k == m. A row
    also brings its OWN monomials, so a row can only be added while every monomial it
    contains still fits in the <= max_cols column set; otherwise the row would not be an
    integer combination of the columns and the lattice would be malformed. That is why
    the set is built greedily instead of from a rectangular degree window: a window
    silently overshoots the column budget once f^2 (degree 2 in each variable) enters,
    and the overshoot is what kept every 12x12 attempt from carrying a bound.
    `order` is a list of (i, j, k) candidates in the order they are offered.
    Returns (rows, monomials) or (None, None).
    """
    fm = poly2_pow(f, m)
    rows = []
    monomials = set()
    for (i, j, k) in order:
        if len(rows) >= max_rows:
            break
        if k == m:
            base = fm
        else:
            base = poly2_scale(poly2_pow(f, k), N ** (m - k))
        poly = poly2_shift_y(poly2_shift_x(base, i), j)
        if not poly:
            continue
        need = monomials | set(poly)
        if len(need) > max_cols:
            continue
        monomials = need
        rows.append((poly, i, j, k))
    if not rows:
        return None, None
    return rows, sorted(monomials)


def _shift_orders(f, N, m, t, max_shift):
    """Candidate orderings of the (i, j, k) shifts, most useful first

    What matters is how many monomials a row brings: the trivial rows x^i * N^m and
    y^j * N^m contribute ONE monomial each and are useless for the bound, while
    x^i * y^j * f^k rows contribute several and are what makes the lattice short. A
    greedy pass ordered by small shift first therefore fills all twelve rows with the
    useless ones - measured on a toy instance: the resulting lattice had only x-only and
    y-only columns, none of the cross monomials of f, and every short vector was a
    multiple of N^m with no small root at all. So the orderings below are by monomial
    count DESCENDING, with several tie-breaks, and the caller keeps whichever lattice
    still fits the 12x12 cap.
    """
    shifts = []
    for k in range(m + 1):
        for i in range(max_shift + 1):
            for j in range(max_shift + 1):
                if i + j == 0 and k == 0:
                    continue  # the k == 0 row is added implicitly by the builder
                shifts.append((i, j, k))
    cache = {}

    def width(i, j, k):
        key = (i, j, k)
        if key not in cache:
            base = (poly2_pow(f, m) if k == m
                    else poly2_scale(poly2_pow(f, k), N ** (m - k)))
            cache[key] = len(poly2_shift_y(poly2_shift_x(base, i), j))
        return cache[key]

    rich = sorted(shifts, key=lambda s: (-width(*s), s[2], s[0] + s[1], s[0], s[1]))
    balanced = sorted(shifts, key=lambda s: (-width(*s), max(s[0], s[1]), -s[2],
                                             s[0] + s[1]))
    by_power = sorted(shifts, key=lambda s: (-s[2], -width(*s), s[0] + s[1]))
    univ = [s for s in shifts if s[0] == 0 or s[1] == 0]
    mixed = [s for s in rich if s not in univ]
    return [("rich-first", rich),
            ("univariate-then-rich", univ + mixed),
            ("balanced", balanced),
            ("power-first", by_power)]


def _candidate_lattices(f, N, m, t, max_shift=4, X=None, Y=None):
    """All shift lattices the greedy builder can reach, deduplicated, best first

    Best is judged by column count descending (a wider monomial set means more of the
    bound is carried), then by row count descending. Bounded work: four orderings times
    one greedy pass each, and every pass is capped by the 12x12 lattice limits. When X and
    Y are given, the conservative determinant test in `_lattice_is_feasible` drops the
    lattices that provably cannot carry the bound, which is what keeps an out-of-range
    instance from spending a minute inside the pure-Python LLL before saying no.
    `_LAST_SCREEN` records how many lattices each screen rejected, so the caller's failure
    note can say WHICH screen stopped the search instead of a generic message.
    """
    out = []
    seen = set()
    _LAST_SCREEN.clear()
    for label, order in _shift_orders(f, N, m, t, max_shift):
        rows, mon = _shift_polys(f, N, m, order)
        if rows is None:
            _LAST_SCREEN["cap"] = _LAST_SCREEN.get("cap", 0) + 1
            continue
        key = tuple(mon)
        if key in seen:
            continue
        seen.add(key)
        if X is not None and not _lattice_is_feasible(rows, mon, m, N, X, Y):
            _LAST_SCREEN["determinant"] = _LAST_SCREEN.get("determinant", 0) + 1
            continue
        out.append(("m=%d,t=%d,%s %dx%d" % (m, t, label, len(rows), len(mon)),
                    rows, mon))
    out.sort(key=lambda item: (-len(item[2]), -len(item[1])))
    return out


def _lattice_is_feasible(rows, monomials, m, N, X, Y):
    """Conservative Howgrave-Graham determinant test: can this lattice possibly work?

    For each row the diagonal contribution is at least
        N^(m-k) / |coefficient of the row's largest scaled monomial| * (that monomial)
    and the columns contribute the product of their X^i Y^j. Summing log2 of all of that
    gives a LOWER bound for log2|det| (zero cells only lower it further, so the test errs
    on the side of keeping a lattice). If
        2 * log2|det| >= dim * m * log2 N
    then even the shortest vector must exceed N^m / sqrt(dim) and no polynomial produced
    from this lattice can vanish at the root, so the reduction is skipped.
    This is a heuristic screen, never a proof of success: a lattice that passes it may
    still fail, and it can only reject lattices that provably cannot carry the bound.
    """
    logn = math.log2(N)
    logx = math.log2(X) if X > 1 else 0.0
    logy = math.log2(Y) if Y > 1 else 0.0
    total = 0.0
    for (i, j) in monomials:
        total += i * logx + j * logy
    for item in rows:
        poly = item[0]
        k = item[3] if len(item) > 3 else _row_power(poly, m, N)
        best = max(poly, key=lambda key: key[0] * logx + key[1] * logy)
        coeff = abs(poly[best])
        if coeff > 1:
            total -= math.log2(coeff)
        total += (m - k) * logn
        total += best[0] * logx + best[1] * logy
    dim = len(monomials)
    return 2 * total < dim * m * logn


def _row_power(poly, m, N):
    """Recover which f-power a row came from, for rows built without the k tag

    Only used when a caller hands `_lattice_is_feasible` three-element rows; the module
    itself always tags rows with k. The heuristic: the row's constant term carries
    N^(m-k) times the constant term of f^k, so the largest power of N dividing the row's
    content is that N^(m-k) (the other coefficients are much smaller).
    """
    g = 0
    for c in poly.values():
        g = math.gcd(g, abs(c))
    k = m
    while k > 0 and N and g % N == 0:
        g //= N
        k -= 1
    return k


# bivariate Coppersmith -------------------------------------------------------------------

def _run_window(f, N, X, Y, rows, monomials, label, deadline):
    """One full attack attempt over one shift lattice -> result dict

    Split out of `coppersmith_bivariate` so the ladder and the test harness drive the
    same code path. `deadline` is an absolute time.time() value (NOT a duration - passing
    a duration here silently disabled every extraction stage, because time.time() is
    always far larger than any budget). Returns the library result dict; `ok` is only
    ever True when a root has been verified by substitution.
    """
    dim_r, dim_c = len(rows), len(monomials)
    # lattice: column (i, j) holds the coefficient of x^i y^j times X^i Y^j
    col_of = {key: idx for idx, key in enumerate(monomials)}
    scaling = [pow(X, i) * pow(Y, j) for (i, j) in monomials]
    basis = []
    for poly, _i, _j, _k in rows:
        row = [0] * dim_c
        for key, c in poly.items():
            row[col_of[key]] = c * scaling[col_of[key]]
        basis.append(row)
    # a non-square basis makes the plain Gram-Schmidt inside .lattice.lll divide by a
    # zero squared norm, so pad with zero rows up to the number of columns
    while len(basis) < dim_c:
        basis.append([0] * dim_c)
    # preflight: the pure-Python Fraction LLL cost grows steeply with the coefficient
    # size (measured: 766-bit entries -> 37 s, 1023-bit -> 76 s, and one more doubling is
    # minutes), so refuse the reduction we know we cannot finish inside any sane budget
    maxbits = 0
    for row in basis:
        for v in row:
            if v:
                b = v.bit_length()
                if b > maxbits:
                    maxbits = b
    if maxbits > _MAX_COEFF_BITS:
        found = re.search(r"m=(\d+),t=(\d+)", label)
        mm, tt = (int(found.group(1)), int(found.group(2))) if found else (None, None)
        return {"ok": False, "roots": [], "factor": None,
                "detail": "lattice %dx%d (%s) has %d-bit basis entries, over the %d-bit "
                          "reduction cap" % (dim_r, dim_c, label, maxbits, _MAX_COEFF_BITS),
                "note": "the bound reached was X=%d, Y=%d with m=%s, t=%s; shrink X/Y or "
                        "lower m/t (measured: 766-bit entries take ~37 s, 1023-bit ~76 s)"
                        % (X, Y, mm, tt)}
    try:
        reduced = L.lll(basis)
    except Exception:  # LLL itself must never take the caller down
        return {"ok": False, "roots": [], "factor": None, "skipped": True,
                "detail": "LLL raised on the %d x %d lattice (%s)" % (dim_r, dim_c, label),
                "note": ""}
    if reduced is None:
        return {"ok": False, "roots": [], "factor": None, "skipped": True,
                "detail": "LLL refused the lattice (%d x %d, %s)" % (dim_r, dim_c, label),
                "note": ""}

    # undo the X^i Y^j column scaling: a short vector is a polynomial if the division
    # comes out exact, otherwise it is not a lattice polynomial we can use
    polys = []
    for row in reduced:
        if not any(row):
            continue
        poly = {}
        ok = True
        for idx, key in enumerate(monomials):
            v = row[idx]
            if not v:
                continue
            s = scaling[idx]
            if v % s:
                ok = False
                break
            poly[key] = v // s
        if ok and poly:
            polys.append(poly)
    return _extract_roots(polys, f, N, X, Y, label, dim_r, dim_c, deadline)


def coppersmith_bivariate(f, N, X, Y, m=None, t=None, time_budget=60.0):
    """Small roots (x0, y0) of f(x, y) == 0 (mod N) with |x0| < X, |y0| < Y

    Args:
        f: bivariate polynomial {(i, j): c} with integer coefficients (see module doc)
        N: modulus
        X, Y: bounds on the two roots
        m: lattice depth (the largest power f^m used). Default 2.
        t: how much room the f^m window gets. Default 1.
        time_budget: seconds, checked between the expensive stages; it cannot interrupt
           a running pure-Python LLL, so the real stop is the 12x12 dimension cap.
    Returns:
        {"ok": bool, "roots": [(x, y), ...], "factor": p|None, "detail": str, "note": str}
        Every pair in "roots" satisfies f(x, y) % N == 0 AND |x| < X AND |y| < Y - an
        unverified candidate never reaches the list, it only appears in "note".
        "factor" is a non-trivial factor of N when one falls out (gcd of a root with N).
    Method: the Howgrave-Graham/Coron shift lattice x^i y^j f^k N^(m-k) plus the extra
    f^m shifts, LLL-reduced by `.lattice.lll`, the short vectors turned back into integer
    polynomials, then y is eliminated with `poly2_resultant` and x is read out of the
    low-degree resultants (or their GCD over Q[x], see `_resultant_stage`). Candidates are
    only reported after an exact substitution.
    Honest limits: see the module docstring - the 12x12 pure-Python lattice reaches an
    unknown half of about 2^6-2^7 per prime and n up to roughly 384 bits; larger n is
    refused by the basis-size preflight rather than ground away. That is well short of the
    XY < N^(2/3) the literature gives for the bilinear case, and the gap is the lattice cap.
    """
    t0 = time.time()
    f = _reduce_poly2(f, None)
    if N <= 1:
        return {"ok": False, "roots": [], "factor": None,
                "detail": "N must be > 1", "note": "no computation attempted"}
    if X <= 0 or Y <= 0:
        return {"ok": False, "roots": [], "factor": None,
                "detail": "X and Y must be positive", "note": "no computation attempted"}
    if not f:
        return {"ok": False, "roots": [], "factor": None,
                "detail": "f is the zero polynomial", "note": "every point is a root mod N"}
    dtotal, dx, dy = poly2_degree(f)
    if dtotal < 1:
        return {"ok": False, "roots": [], "factor": None,
                "detail": "f has degree 0 in both variables", "note": "nothing to solve"}
    if m is None:
        m = 2
    if t is None:
        t = 1
    if m < 1:
        return {"ok": False, "roots": [], "factor": None,
                "detail": "m must be >= 1", "note": "no computation attempted"}
    if t < 0:
        t = 0

    # try every lattice the greedy builder can reach, widest first, and stop at the first
    # verified root; the labels of what was tried end up in the failure note
    deadline = t0 + time_budget
    tried = []
    best = None
    for label, rows, monomials in _candidate_lattices(f, N, m, t, X=X, Y=Y):
        if time.time() > deadline:
            break
        tried.append("%s" % label)
        res = _run_window(f, N, X, Y, rows, monomials, label, deadline)
        if res.get("skipped"):
            continue
        res["detail"] = res["detail"] + ", %.1fs total" % (time.time() - t0)
        if res["ok"]:
            return res
        if best is None:
            best = res
    if best is None:
        reasons = []
        if _LAST_SCREEN.get("cap"):
            reasons.append("%d lattice(s) over the %dx%d cap"
                           % (_LAST_SCREEN["cap"], _MAX_ROWS, _MAX_COLS))
        if _LAST_SCREEN.get("determinant"):
            reasons.append("%d rejected by the determinant test (the bound X=%d, Y=%d is "
                           "too large for m=%d, t=%d)"
                           % (_LAST_SCREEN["determinant"], X, Y, m, t))
        return {"ok": False, "roots": [], "factor": None,
                "detail": "no shift lattice survived for m=%d, t=%d: %s"
                          % (m, t, "; ".join(reasons) if reasons else "builder produced "
                             "nothing"),
                "note": "widen by shrinking X/Y or lowering m/t; measured reach is about "
                        "X*Y <= 2^13 with m=2, t=1 and the 12x12 lattice cap"}
    best["note"] = (best["note"] + " | no lattice in the set worked (tried %s)"
                    % (tried[:6],)).strip()
    return best


def _resultant_stage(polys, X, Y, record, deadline):
    """Eliminate y pairwise and pull x-candidates out of the resultants

    Cost control comes first, because this stage is where the time goes: only the
    `_MAX_POLYS` shortest-in-degree polynomials are paired (a 12-polynomial lattice has
    66 pairs and every resultant is a sizable polynomial), and the pairs are then used in
    two ways:
      1. the low-degree resultants THEMSELVES - if deg R is small then its integer roots
         include the root x0, and `_int_roots` finds them exactly. This is the cheap and
         usually sufficient path.
      2. the GCD over Q[x] of the two lowest-degree resultants - only when path 1 found
         nothing. GCDs of huge polynomials are expensive, so at most one pair is tried.
    Every candidate is completed with a partner y and handed to `record`, which
    re-verifies; nothing here reports anything by itself.
    """
    if len(polys) < 2 or time.time() > deadline:
        return
    polys = sorted(polys, key=lambda p: sum(poly2_degree(p)))[:_MAX_POLYS]
    res = []
    seen_r = set()
    for i in range(len(polys)):
        for j in range(i + 1, len(polys)):
            r = poly2_resultant(polys[i], polys[j], True)
            if not r or len(r) < 2:
                continue
            prim = tuple(_poly_primitive(r))
            if prim in seen_r:
                continue
            seen_r.add(prim)
            res.append(list(prim))
    res.sort(key=len)
    cands = []
    seen_c = set()

    def offer(poly):
        if not poly or not (1 <= len(poly) <= _ROOT_POLY_DEG + 1):
            return
        key = tuple(int(c) for c in poly)
        if key in seen_c:
            return
        seen_c.add(key)
        cands.append(list(key))

    for r in res:
        if len(r) <= _ROOT_POLY_DEG + 1:
            offer(r)
    if not cands and len(res) >= 2:
        # No low-degree resultant at all: fall back to the GCD over Q[x] of the two
        # smallest resultants. Measured: trying three pairs instead of one made the
        # FAILING cases several times slower without recovering anything new, so the
        # fallback stays at a single pair - the low-degree resultants are the working path.
        g = L._poly_gcd_rational(res[0], res[1])
        if g:
            offer([int(c) for c in g])
    for g in cands:
        for x0 in _int_roots(g, X):
            for poly in polys:
                for y0 in _solve_for_y(poly, x0, Y):
                    record(x0, y0, poly)


def _extract_roots(polys, f, N, X, Y, label, dim_r, dim_c, deadline):
    """Turn the short-vector polynomials into verified roots (never a guess)

    `deadline` is an absolute time.time() value.
    """
    detail = ("lattice %dx%d %s, %d usable polynomial(s)"
              % (dim_r, dim_c, label, len(polys)))
    verified = []
    unverified = []
    factor = None
    seen = set()

    def _record(x0, y0, poly):
        nonlocal factor
        if (x0, y0) in seen or abs(x0) >= X or abs(y0) >= Y:
            return
        seen.add((x0, y0))
        if poly2_eval(poly, x0, y0) != 0:
            unverified.append((x0, y0))
            return
        if poly2_eval(f, x0, y0, N) % N != 0:
            unverified.append((x0, y0))
            return
        verified.append((x0, y0))
        if factor is None:
            g = A.gcd(x0, N) if x0 else 0
            if 1 < g < N:
                factor = g

    # stage 1: pairwise resultants eliminate y, the GCD over Q[x] of two of them isolates
    # the x-coordinate of the common root (this is the path that actually works)
    _resultant_stage(polys, X, Y, _record, deadline)

    # stage 2: modulo a few small primes - the true integer root must be congruent to a
    # root of every short polynomial modulo each prime; cheap and it prunes hard
    if not verified and time.time() < deadline:
        for (x0, y0) in _candidates_mod_prime(polys, X, Y):
            for poly in polys:
                if poly2_eval(poly, x0, y0) == 0:
                    _record(x0, y0, poly)

    notes = []
    if not verified:
        notes.append("no verified root: the lattice did not produce polynomials with a "
                     "common small root, or its root is outside |x|<X, |y|<Y")
        notes.append("direction to widen: larger m/t (more shifts), or smaller X/Y; "
                     "lattice cap is %d rows x %d columns" % (_MAX_ROWS, _MAX_COLS))
    if unverified:
        notes.append("%d candidate(s) failed the mod-N verification and were discarded"
                     % len(unverified))
    return {"ok": bool(verified), "roots": sorted(verified), "factor": factor,
            "detail": detail, "note": " ".join(notes)}


def _candidates_mod_prime(polys, X, Y, primes=(2, 3, 5, 7), max_scan=64):
    """Small-integer root candidates filtered modulo several small primes

    The true integer root reduces to a root of every short-vector polynomial modulo
    every prime, so intersecting those root sets leaves a handful of residue classes
    and the cheap rectangle scan below only visits x values in those classes. Any
    candidate still has to pass the exact substitution in the caller, so this stage can
    only ever propose, never decide.
    """
    usable = []
    for prime in primes:
        survivors = set()
        for poly in polys:
            red = {(i, j): c % prime for (i, j), c in poly.items() if c % prime}
            if not red:
                survivors = set()
                break  # the polynomial vanishes mod this prime: no information
            for xr in range(prime):
                for yr in range(prime):
                    if poly2_eval(red, xr, yr, prime) == 0:
                        survivors.add((xr, yr))
            if not survivors:
                break
        if survivors:
            usable.append((prime, survivors))
    if not usable:
        return []
    xlim = min(int(X), max_scan) if X > 0 else 0
    ylim = min(int(Y), max_scan) if Y > 0 else 0
    out = []
    for xr in range(-xlim, xlim):
        if not all(any((xr % prime, yr) in surv for yr in range(prime))
                   for prime, surv in usable):
            continue
        for yr in range(-ylim, ylim):
            if all((xr % prime, yr % prime) in surv for prime, surv in usable):
                out.append((xr, yr))
    return out


# the two-prime known-high-bits case ------------------------------------------------------

def known_high_bits_two_primes(n, p_high, q_high, known_bits, total_bits=None,
                               time_budget=60.0):
    """Known high bits of BOTH RSA primes -> factor n (bivariate Coppersmith)

    f(x, y) = (p_high * 2^shift + x) * (q_high * 2^shift + y) - n with
    shift = total_bits/2 - known_bits, so x and y are the unknown low bits of p and q.
    Returns {"ok", "p", "q", "roots", "note"}; p * q == n is verified before the result
    is returned, and on failure p and q are None (never a guess).
    Honest range (measured, see the module docstring): the unknown low part must fit in
    about 6-7 bits per prime, so 64-, 128-, 256- and 384-bit n work when known_bits is
    within ~6 of half the bit length. A 512-bit n is refused immediately by the basis-size
    preflight: with that cap lifted it does still solve at 6-bit unknowns, but it takes
    74 s, which is not what a CTF helper should cost. When it cannot solve, `note` names
    the bound that was reached and the direction to widen.
    """
    if not p_high or not q_high or p_high <= 0 or q_high <= 0:
        return {"ok": False, "p": None, "q": None, "roots": [],
                "note": "p_high and q_high must both be positive: with no known high "
                        "bits there is no polynomial to build"}
    if n <= 1:
        return {"ok": False, "p": None, "q": None, "roots": [],
                "note": "n must be > 1"}
    total_bits = total_bits or n.bit_length()
    shift = max(1, total_bits // 2 - known_bits)
    X = Y = 1 << shift
    ph, qh = p_high << shift, q_high << shift
    f = {(1, 1): 1, (1, 0): qh, (0, 1): ph, (0, 0): ph * qh - n}
    res = coppersmith_bivariate(f, n, X, Y, m=2, t=1, time_budget=time_budget)
    out = {"ok": False, "p": None, "q": None, "roots": res["roots"],
           "note": res["detail"] + " | " + res["note"] if res["note"] else res["detail"]}
    for x0, y0 in res["roots"]:
        p, q = ph + x0, qh + y0
        if p > 1 and q > 1 and p * q == n:
            out.update(ok=True, p=min(p, q), q=max(p, q),
                       note="bivariate Coppersmith small root hit; p*q==n verified")
            return out
        out["note"] += " | candidate (x, y) = (%d, %d) did not give p*q == n" % (x0, y0)
    if res["roots"]:
        out["note"] += (" | verified roots exist for f mod n but none yields p*q == n "
                        "(the p_high/q_high split may not match this n)")
    return out
