"""Linearization lattice -- the mechanical half of "modular equations + small unknowns".

What this is for: a large family of tasks hands you one or more congruences whose unknowns
are small quantities (the low bits of a prime, two short nonces, leaked products, the two
factors of a known product), and the work between "here are my equations" and "here are the
values" is mechanical: give every MONOMIAL of the system one lattice coordinate, scale each
coordinate by the bound the user knows, LLL-reduce, and read the small quantities back off
the short vectors. Which attack the numbers came from (RSA, ECDSA, LCG, Merkle-Hellman, ...)
stays the caller's decision; this module only does the lattice bookkeeping, and it never
invents a value.

Representation (fixed here, used by every public name in this file):
  * A MONOMIAL is a tuple of variable names, sorted ascending, one entry per power:
    ("x",) = x, ("x", "x", "y") = x^2*y, ("x", "y") = x*y, () = the constant 1. Tuples are
    canonical dict keys, and `parse_monomial("x^2*y")` builds one from a string.
  * An EQUATION is {"terms": {monomial: coefficient}, "mod": m, "rhs": r} and means
    sum(coefficient * monomial) == r (mod m). "mod": 0 (or None) means an exact equality
    over the integers; no modulus row is then put in the lattice.
  * `bounds` maps every monomial that appears in the equations to an upper bound on its
    ABSOLUTE value: {("x",): 2**32, ("x", "y"): N} means |value| <= bound, bound >= 1.
    A bound for a product can also be DERIVED from the single-variable bounds (|x*y| <= X*Y)
    - that is how the automatic shifts stay sound. A bound that is needed and cannot be
    derived is refused with a note, never guessed.
  * An ASSIGNMENT maps variable names to integers; it may additionally carry monomial keys
    ({( "x", "y"): value}), whose value `check_solution` then uses verbatim.

The lattice (one row per monomial, plus one row per modular equation):
    column j       = value of monomial j times the column scale K // X_j, with K the largest
                     bound in play (so a value AT its bound always contributes K, whatever the
                     bound is - that is the "make the coordinates comparable" step, and it
                     also makes the constant column cost K)
    column k+i     = residual of equation i, times a weight W = 8*K (a vector with a non-zero
                     residual is then at least W long, while a solution inside its bounds is
                     at most K*sqrt(k+1) <= 3.6*K for the k <= 12 coordinates allowed here, so
                     the LLL cannot prefer a near-miss over a genuine solution)
    row j          = the column scale in column j, and the coefficient of monomial j in every
                     equation (each equation is homogenised: the constant term -rhs is carried
                     by the monomial (), whose value is pinned to 1 by construction)
    row k+i        = W * m_i, for every equation with modulus m_i >= 2
A lattice vector whose residual columns are all EXACTLY zero is a vector of monomial values
satisfying every congruence: that is the linearisation. `effort` adds shift equations
(each equation multiplied by monomials), which is a strictly stronger relaxation - the true
values always satisfy it too.

Honesty rules enforced in code, not just in prose:
  * A value is read off a reduced vector only when every residual column of that vector is
    exactly zero AND the coordinate divides exactly by its column scale. Nothing is
    interpolated, averaged or guessed.
  * `solution` is reported only after `check_solution` multiplied the variables out for real
    and every equation held. A relaxation artefact (x = 0, y = 0, x*y = c satisfies the
    linearisation but not the equation) is therefore rejected, not reported.
  * A variable is reported either (a) because the congruences PROVE its value - Gauss-Jordan
    over Z/m shows its column is a unit row, so every solution has that value, and the bound
    then leaves exactly one integer - or (b) by exact arithmetic on the proven monomial values
    (x*y = c with x known gives y = c/x; three pairwise products give x = sqrt(xy*xz/yz)), or
    (c) from a verified short vector, and then the free monomial directions of the
    linearisation are probed for a second solution: if one is found the values are declared
    undetermined (ok=False) rather than picked arbitrarily. Failing to find one is reported as
    "not proven unique", never as a proof.
  * When the linearisation pins a monomial but not the individual variables (the classic
    "x*y is known, x and y are not"), the monomial goes into `monomial_values`, `solution`
    stays None and the note says why.
  * Underdetermined systems, bounds too loose, inconsistent equations and lattices past the
    pure-Python LLL cap all return ok=False with the reason and the direction to widen
    (more equations / tighter bounds / more shifts).

What this deliberately does NOT do (measured, not assumed):
  * It is a LINEARISATION tool: a product is a free monomial, so a system whose only link
    between x and y is "x*y == c" (or "x + y == s together with x*y == c") is NOT solved
    here. Measured on x + y == s (mod 2^127-1) with x*y == c and both values known: the
    shortest vectors of the relaxation are the symmetric point x = y = s/2 (which satisfies
    the relaxation but not the product), and the true pair is a large multiple of the kernel
    direction away from it. Such shapes need the polynomial structure: `.bivariate`
    Coppersmith, or a quadratic over the integers when the product is not reduced.
  * Determination is analysed PER MODULUS and the results are glued with CRT. A value that
    only the COMBINATION of two different moduli pins down is therefore not proven here
    (each modulus alone is underdetermined); the verified-candidate path can still find it
    and says "uniqueness is not proven". A single modulus keeps full strength, and scaling
    every equation to a common lcm is deliberately not done: it turns the coefficients into
    non-units and throws the elimination away (measured on two coprime moduli).
  * Smallness of the representative is NOT a licence to pick one: when the bound admits
    several integers congruent to the proven residue (a bound at or above half the modulus),
    the value is reported as "pinned down modulo the modulus" and ok stays False, even though
    a short vector satisfying the equations may be sitting in `vectors`.

Measured range (this machine, CPython 3.11, the pure-Python Fraction LLL of `.lattice`, which
refuses any shape above 12 rows or 12 columns - see the time ceiling below for what that cap
really buys):
  * Fully determined linear system in n unknowns with a known small solution, n equations,
    128-bit and 1024-bit moduli (lattice = (2n-1) x (2n-1)):
      n=2 dim  5 -> 0.01 s      n=3 dim  7 -> 0.09 / 0.12 s     n=4 dim  9 -> 0.55 / 0.70 s
      n=5 dim 11 -> 2.2 / 2.7 s n=6 dim 13 -> refused (over the 12 cap)
  * Overdetermined (n unknowns, n+3 equations, 128-bit modulus):
      dim  8 -> 0.23 s          dim 10 -> 1.2 s                dim 12 -> 3.7 s
      dim 14 -> refused
  * So the honest budget is: <= 12 lattice coordinates (monomials + equations), which in
    practice is 4-5 unknowns with a handful of equations, and a few seconds of LLL. Working
    range for the module as a whole (including the linear analysis) is well below that in
    time; the refusals above the cap come back as ok=False with the reason, never as a
    half-finished reduction.
  * THE CAP IS NOT THE CEILING - TIME IS, and `effort` is what buys it. The same
    "2 variables, 2 equations" system is a 5x5 lattice at effort='light' and a 12x12
    relaxation at effort='normal', and the 12x12 one is what costs minutes (one rung,
    measured through the single-attempt path):
      1024-bit modulus, 64-bit bounds:  light 0.01 s  |  normal  20.7 s
      2048-bit modulus, 64-bit bounds:  light 0.01 s  |  normal  24.4 s
      2048-bit modulus, 128-bit bounds: light 0.02 s  |  normal  66.1 s
      4096-bit modulus, 128-bit bounds: light 0.03 s  |  normal  82.2 s
    A user's shape went further still: the 11x11 `normal` lattice sat on the LLL internal
    step guard for 104 s and returned None, while `light` answered it in 1.4 s. `linearize`
    therefore walks the effort ladder CHEAPEST FIRST and stops at the first verified answer
    (see `_EFFORT_LADDER`), and the note names the level that answered. With the ladder the
    public call on all four rows above returns in 0.01-0.02 s. Numbers are this machine,
    CPython 3.11, no optional accelerators in the path.

Pure standard library; the modulus arithmetic, gcds and the integer roots come from
`.algebra`, the reduction from `.lattice`.

The public surface: `parse_monomial` (spelling), `monomials_of` and `check_solution`
(bookkeeping and the substitution gate), `linearize` (the lattice), `solve_linearized`
(the same plus the caller's verifier), `recover_from_products` (the products shape),
and `separate_variables` (the gcd/root step that turns known monomial values into the
variables themselves).
"""

import math
import time
from fractions import Fraction

from . import algebra as A
from . import lattice as L

__all__ = [
    "linearize", "solve_linearized", "monomials_of", "check_solution",
    "recover_from_products", "separate_variables", "parse_monomial",
]

# `.lattice.lll` refuses more than 12 rows or 12 columns, so the lattice is assembled inside
# that cap: shift equations are added only while the shape still fits, and dropping them is
# reported in the note.
_LLL_MAX_DIM = 12
# Column scaling and the residual weight. A coordinate is value * (K // bound), so a value at
# its bound contributes K whatever the bound is: the coordinates become comparable (which is
# the whole point of the bounds), and the constant column's scale K makes the "multiple of the
# modulus" junk vector - the one unavoidable non-solution of a homogenised system - cost K*m
# instead of m. The residual columns carry W = _WEIGHT_SCALE * K: a vector with a NON-zero
# residual is then at least W long, while a solution inside its bounds is at most K*sqrt(k+1)
# with k <= 12 coordinates, i.e. at most 3.6*K - so the LLL cannot prefer a near-miss over a
# genuine solution. Measured: with W = K the near-misses dominated and nothing was found.
_WEIGHT_SCALE = 8
# How many free monomial directions are probed for a second solution before a candidate that
# was not proven by the linear analysis is reported, and with which multipliers.
_MAX_PROBES = 4
_PROBE_COEFFS = (1, -1, 2, -2)
_EFFORTS = ("light", "normal", "heavy")
# Cheap stage first, applied automatically instead of left to the caller. A `normal` run
# builds a much bigger relaxation than `light` (measured: an 11x11 lattice against a 5x5 one
# on "2 variables, 2 equations"), and that bigger lattice is what eats the time: 85.8 s
# against 0.53 s at a 4096-bit modulus, and a user's shape sat on the LLL step guard for
# 104 s at `normal` while `light` solved it in 1.4 s and returned None. So the ladder runs
# CHEAPEST FIRST and stops at the first verified answer - the same "cheap stage first" order
# as `common_d_attack` - which is what keeps the call at seconds instead of minutes. That
# also means no downward retry is ever needed: a cheaper level has already been tried (and
# its outcome recorded) before a more expensive one is built.
_EFFORT_LADDER = {"light": ("light",),
                  "normal": ("light", "normal"),
                  "heavy": ("light", "normal", "heavy")}
# Failure kinds that the note phrases specially (the shape ones are why the ladder exists).
_HIT_PHRASE = {"cap": "was over the lattice cap",
               "guard": "hit the LLL step guard"}
# The combination of several moduli is done by scaling each equation to the common lcm; if
# that lcm explodes the linear analysis is skipped rather than done with absurd entries.
_MAX_COMMON_MODULUS_BITS = 8192


# ---- monomials ---------------------------------------------------------------------

def parse_monomial(text):
    """Build a monomial from a string: "x" -> ("x",), "x^2*y" -> ("x","x","y"), "" -> ()

    Factors may be repeated ("x*x") or written as powers ("x^2"); the result is always the
    canonical sorted tuple, so parse_monomial("y*x") == parse_monomial("x*y") == ("x","y").
    """
    if text is None:
        return ()
    if not isinstance(text, str):
        raise TypeError("parse_monomial expects a string")
    body = text.strip().replace(" ", "")
    if body in ("", "1"):
        return ()
    out = []
    for factor in body.split("*"):
        if not factor:
            raise ValueError("empty factor in monomial %r" % (text,))
        if "^" in factor:
            name, _, exp = factor.partition("^")
            if not name or not exp.isdigit():
                raise ValueError("bad power in monomial %r" % (text,))
            out.extend([name] * int(exp))
        elif factor != "1":
            out.append(factor)
    return tuple(sorted(out))


def _as_monomial(obj):
    """Accept a canonical monomial tuple/list or its string spelling"""
    if isinstance(obj, str):
        return parse_monomial(obj)
    if isinstance(obj, (tuple, list)):
        names = []
        for name in obj:
            if not isinstance(name, str) or not name:
                raise TypeError("monomial names must be non-empty strings")
            names.append(name)
        return tuple(sorted(names))
    raise TypeError("a monomial must be a tuple of variable names or a string")


def _mono_key(mono):
    """Sort key for monomials: by number of factors, then by names (stable and readable)"""
    return (len(mono), mono)


def _mul_mono(a, b):
    return tuple(sorted(a + b))


def _show_mono(mono):
    """Readable spelling: () -> "1", ("x","x","y") -> "x^2*y" """
    if not mono:
        return "1"
    out = []
    i = 0
    while i < len(mono):
        j = i
        while j < len(mono) and mono[j] == mono[i]:
            j += 1
        count = j - i
        out.append(mono[i] if count == 1 else "%s^%d" % (mono[i], count))
        i = j
    return "*".join(out)


def _show_list(monos):
    return ", ".join(_show_mono(m) for m in monos)


def monomials_of(equations):
    """Every monomial appearing in `equations`, sorted (the constant () included if used)

    This is exactly the set the lattice needs a bound for. Ordering is by (factor count,
    names): (), ("x",), ("y",), ("x","x"), ("x","y").
    """
    eqs = _normalise_equations(equations)
    seen = set()
    for eq in eqs:
        seen.update(eq["terms"])
    return sorted(seen, key=_mono_key)


# ---- input normalisation -----------------------------------------------------------

def _normalise_equations(equations):
    """Validate the {"terms", "mod", "rhs"} shape -> list of canonical dicts (raises on junk)

    Zero coefficients are dropped so that two spellings of one equation compare equal;
    "mod": 0 / None means an exact equality over Z. This raises instead of returning a
    result dict because a malformed equation is a programming error in the caller, and
    `linearize` turns the raise into an ok=False result with the message in the note.
    """
    if equations is None:
        raise TypeError("equations must be a sequence of {terms, mod, rhs} dicts")
    if isinstance(equations, dict):
        equations = [equations]
    out = []
    for idx, eq in enumerate(equations):
        if not isinstance(eq, dict):
            raise TypeError("equation %d is not a dict" % idx)
        terms = eq.get("terms")
        if not isinstance(terms, dict):
            raise TypeError("equation %d has no {monomial: coefficient} 'terms' dict" % idx)
        clean = {}
        for key, val in terms.items():
            mono = _as_monomial(key)
            if not isinstance(val, int) or isinstance(val, bool):
                raise TypeError("equation %d: coefficients must be integers" % idx)
            if val:
                clean[mono] = clean.get(mono, 0) + val
        if not clean:
            raise ValueError("equation %d has no non-zero terms" % idx)
        mod = eq.get("mod", 0)
        if mod is None:
            mod = 0
        if not isinstance(mod, int) or isinstance(mod, bool) or mod < 0:
            raise TypeError("equation %d: 'mod' must be a non-negative integer" % idx)
        if mod == 1:
            raise ValueError("equation %d: modulus 1 makes every value a solution" % idx)
        rhs = eq.get("rhs", 0)
        if not isinstance(rhs, int) or isinstance(rhs, bool):
            raise TypeError("equation %d: 'rhs' must be an integer" % idx)
        out.append({"terms": clean, "mod": mod, "rhs": rhs})
    return out


def _normalise_bounds(bounds):
    """Validate {monomial: bound} (tuples or strings) -> canonical dict, bounds >= 1"""
    if bounds is None:
        return {}
    if not isinstance(bounds, dict):
        raise TypeError("bounds must be a {monomial: bound} dict")
    out = {}
    for key, val in bounds.items():
        mono = _as_monomial(key)
        if not isinstance(val, int) or isinstance(val, bool):
            raise TypeError("bound for %s must be an integer" % _show_mono(mono))
        if val < 1:
            raise ValueError("bound for %s must be >= 1" % _show_mono(mono))
        out[mono] = val
    return out


def _derive_bound(mono, var_bounds):
    """|value| <= bound from the single-variable bounds: |x*y| <= X*Y, |x^2| <= X^2

    This is the only sound derivation available, so a monomial whose variables are not all
    bounded returns None and the caller refuses that shift instead of inventing a bound.
    The empty monomial is the constant 1, so its bound is 1.
    """
    bound = 1
    for name in mono:
        x = var_bounds.get(name)
        if x is None:
            return None
        bound *= x
    return bound


def _int_value(val, what):
    if not isinstance(val, int) or isinstance(val, bool):
        raise TypeError("%s must be an integer" % what)
    return int(val)


# ---- verification ------------------------------------------------------------------

def check_solution(equations, assignment):
    """Substitute an assignment and report every equation that does not hold

    Returns (ok, failures) with failures = [(equation_index, lhs - rhs), ...], the
    difference reduced modulo the equation's modulus (the exact difference when mod is 0).
    lhs is computed by MULTIPLYING the variables out for real - ("x","x","y") is x*x*y -
    which is what makes this the honest gate for a linearised candidate: the relaxation says
    "x*y is some free monomial", this says "x times y".

    `assignment` maps variable names to integers and may additionally carry monomial keys
    (tuples), whose value is then used verbatim for that monomial. An equation mentioning a
    variable the assignment does not have cannot be evaluated: it is reported as a failure
    with a None difference, because an unevaluated equation is not a verified one.
    """
    eqs = _normalise_equations(equations)
    variables = {}
    literal = {}
    for key, val in (assignment or {}).items():
        if isinstance(key, str):
            variables[key] = _int_value(val, "assignment[%s]" % key)
        else:
            literal[_as_monomial(key)] = _int_value(val, "assignment[%s]" % (key,))
    failures = []
    for idx, eq in enumerate(eqs):
        lhs = 0
        evaluable = True
        for mono, coeff in eq["terms"].items():
            if not mono:
                mval = 1
            elif mono in literal:
                mval = literal[mono]
            else:
                mval = 1
                for name in mono:
                    if name not in variables:
                        evaluable = False
                        break
                    mval *= variables[name]
                if not evaluable:
                    break
            lhs += coeff * mval
        if not evaluable:
            failures.append((idx, None))
            continue
        diff = (lhs - eq["rhs"]) % eq["mod"] if eq["mod"] else lhs - eq["rhs"]
        if diff:
            failures.append((idx, diff))
    return (not failures), failures


# ---- the linear analysis over Z/m --------------------------------------------------

def _centre(value, mod):
    """Centred representative of `value` modulo `mod` (None mod means "already exact")"""
    if not mod:
        return value
    v = value % mod
    return v - mod if 2 * v > mod else v


def _analyse(rows, rhs, mod):
    """Which monomial values do the congruences force? (unit-pivot Gauss-Jordan)

    `rows` are the coefficients of the NON-constant monomials, `rhs` the matching right-hand
    sides (the constant term has already been moved there, since the constant is 1), and
    `mod` is the common modulus or None for exact arithmetic over Q.

    Returns (determined, free, consistent) with
      determined = {column: value mod `mod`} for every column whose reduced row is a unit
                   vector - then EVERY solution has that value (sound, because only
                   invertible row operations over Z/m are used: multiply a row by a unit,
                   add an integer multiple of another row)
      free       = the nullspace basis directions of the reduced system, used to probe for a
                   second solution
      consistent = False when a row of zeros has a non-zero right-hand side, i.e. the
                   equations contradict each other

    A column with no unit entry anywhere is left unpivoted and therefore counted as free:
    that can only lose a determination, never invent one.
    """
    nrow = len(rows)
    ncol = len(rows[0]) if nrow else 0
    if mod:
        T = [[v % mod for v in row] + [rhs[i] % mod] for i, row in enumerate(rows)]
    else:
        T = [[Fraction(v) for v in row] + [Fraction(rhs[i])] for i, row in enumerate(rows)]
    pivots = {}
    r = 0
    for c in range(ncol):
        sel = None
        for i in range(r, nrow):
            if mod:
                if T[i][c] % mod and math.gcd(T[i][c] % mod, mod) == 1:
                    sel = i
                    break
            elif T[i][c]:
                sel = i
                break
        if sel is None:
            continue
        T[r], T[sel] = T[sel], T[r]
        if mod:
            inv = A.modinv(T[r][c] % mod, mod)
            T[r] = [(v * inv) % mod for v in T[r]]
        else:
            lead = T[r][c]
            T[r] = [v / lead for v in T[r]]
        for i in range(nrow):
            if i == r or not T[i][c]:
                continue
            f = T[i][c]
            if mod:
                T[i] = [(T[i][k] - f * T[r][k]) % mod for k in range(ncol + 1)]
            else:
                T[i] = [T[i][k] - f * T[r][k] for k in range(ncol + 1)]
        pivots[c] = r
        r += 1
        if r == nrow:
            break
    for i in range(nrow):
        zero_row = all(not T[i][k] for k in range(ncol))
        if zero_row and T[i][ncol]:
            return {}, [], False
    determined = {}
    for c, i in pivots.items():
        if any(T[i][k] for k in range(ncol) if k != c):
            continue                      # expressed through a free monomial: not forced
        val = T[i][ncol]
        if mod:
            determined[c] = int(val % mod)
        elif val.denominator == 1:
            determined[c] = int(val)
    free_cols = [c for c in range(ncol) if c not in pivots]
    directions = []
    for f in free_cols:
        # the reduced row i reads  z_c = rhs_i - sum_f T[i][f] * z_f, so moving the free
        # column f by one moves the pivot column c by -T[i][f]
        d = {}
        for c, i in pivots.items():
            coef = T[i][f]
            if mod:
                d[c] = _centre(-int(coef), mod)
            elif coef.denominator == 1:
                d[c] = -int(coef)
        d[f] = 1
        directions.append(d)
    return determined, directions, True


def _merge_congruences(pairs):
    """CRT merge of [(residue, modulus), ...] with moduli that need not be coprime

    Returns (residue, lcm) or None when the constraints contradict each other. Same
    arithmetic as `modular.crt_general` (which is imported from here on purpose: a
    determination proven modulo two coprime moduli is only useful once they are glued).
    """
    residue, mod = 0, 1
    for a, m in pairs:
        g = math.gcd(mod, m)
        if (a - residue) % g:
            return None
        m_g = m // g
        inv = A.modinv((mod // g) % m_g, m_g)
        if inv is None:
            return None
        t = ((a - residue) // g) * inv % m_g
        residue = (residue + mod * t) % (mod * m_g)
        mod = mod * m_g
    return residue, mod


def _is_null_direction(d, homog, column_of):
    """Is this integer direction in the nullspace of EVERY base equation?

    The per-modulus analysis produces directions that keep one modulus happy; only the
    ones that keep all of them happy describe a second solution of the whole system, so
    the others are dropped instead of being probed (a probe outside the solution set
    proves nothing).
    """
    for eq in homog:
        acc = 0
        for mono, c in eq["terms"].items():
            if mono:
                acc += c * d.get(column_of[mono], 0)
        if eq["mod"]:
            if acc % eq["mod"]:
                return False
        elif acc:
            return False
    return True


def _rational_power_product(pairs, root_order):
    """prod(value_i ** (P_i / root_order)) exactly as an integer, or None

    `pairs` is [(value, P_i)] and `root_order` the common denominator Q of the exponents. The
    powers are combined BEFORE the root is taken - that is the whole point: for the three
    pairwise products the individual square roots are irrational (sqrt(6), sqrt(15)) while
    sqrt(6 * 15 / 10) = 3 is exact, so taking roots factor by factor would always fail. The
    value is num/den = (num * den^(Q-1)) / den^Q, whose Q-th root is exact only when the
    scaled numerator is a perfect Q-th power; otherwise None (never an approximation).
    """
    num, den = 1, 1
    for value, power in pairs:
        if power > 0:
            num *= value ** power
        elif power < 0:
            den *= value ** (-power)
    if den == 0:
        return None
    if root_order > 1:
        scaled = num * den ** (root_order - 1)
        if scaled < 0:
            if root_order % 2 == 0:
                return None
            scaled = -scaled
            root, exact = A.iroot(scaled, root_order)
            if not exact:
                return None
            num = -root
        else:
            root, exact = A.iroot(scaled, root_order)
            if not exact:
                return None
            num = root
    if num % den:
        return None
    return num // den


def _solve_exponents(monos, target, variables):
    """Fractions a_i with sum(a_i * exponent(m_i)) = exponent(target), or None

    Solved over Q (free variables are set to 0). Any solution is a polynomial identity in the
    variables, so it turns the known monomial values into a formula for the target - rational
    powers included, which is exactly how x = sqrt(xy * xz / yz) comes out.
    """
    ncol = len(monos)
    rows = [[Fraction(mono.count(name)) for mono in monos] + [Fraction(target.count(name))]
            for name in variables]
    nrow = len(rows)
    if ncol == 0:
        return None
    pivots = {}
    r = 0
    for c in range(ncol):
        sel = None
        for i in range(r, nrow):
            if rows[i][c]:
                sel = i
                break
        if sel is None:
            continue
        rows[r], rows[sel] = rows[sel], rows[r]
        lead = rows[r][c]
        rows[r] = [x / lead for x in rows[r]]
        for i in range(nrow):
            if i != r and rows[i][c]:
                f = rows[i][c]
                rows[i] = [rows[i][k] - f * rows[r][k] for k in range(ncol + 1)]
        pivots[c] = r
        r += 1
        if r == nrow:
            break
    for i in range(nrow):
        if all(not rows[i][k] for k in range(ncol)) and rows[i][ncol]:
            return None                 # the identity cannot hold
    sol = [Fraction(0)] * ncol
    for c, i in pivots.items():
        sol[c] = rows[i][ncol]
    return sol


def _exact_completion(proven, variables, eqs, bnd):
    """Derive still-unknown variables from determined monomial values, by exact arithmetic

    Runs only when EVERY equation is an exact equality over Z (no modulus): that is where
    rational powers make sense, and it is the classical "I know products of small secrets"
    shape. Two routes, both exact and both re-verified by the caller before anything is
    reported:
      1. a monomial value v * r with r known (r may be the constant 1): the unknown is v = m/r
      2. an exponent combination: sum(a_i * exponent(m_i)) = exponent(v), so
         v = prod(m_i ** a_i); with three pairwise products the a_i are +-1/2 and the route
         is a square root, and it is kept only when the result is an integer.
    Returns (derived, how) where `how` spells out what was used.
    """
    if not proven or any(eq["mod"] for eq in eqs):
        return {}, ""
    known = {mono: val for mono, val in proven.items() if mono and val}
    if not known:
        return {}, ""
    derived, how = {}, []

    def _fits(name, value):
        x = bnd.get((name,))
        return x is None or abs(value) <= x

    for name in variables:
        if name in derived or (name,) in proven:
            continue
        for mono in sorted(known, key=_mono_key):
            if mono.count(name) != 1:
                continue
            rest = list(mono)
            rest.remove(name)
            rest = tuple(sorted(rest))
            if rest and rest not in known:
                continue
            denom = known.get(rest, 1)
            if denom and known[mono] % denom == 0 and _fits(name, known[mono] // denom):
                derived[name] = known[mono] // denom
                how.append("%s = %s/%s" % (name, known[mono], denom))
                break
    monos = sorted(known, key=_mono_key)
    for name in variables:
        if name in derived or (name,) in proven:
            continue
        exps = _solve_exponents(monos, (name,), variables)
        if exps is None:
            continue
        root_order = 1
        for exp in exps:
            root_order = root_order * exp.denominator // math.gcd(root_order,
                                                                exp.denominator)
        pairs = [(known[mono], exp.numerator * (root_order // exp.denominator))
                 for mono, exp in zip(monos, exps) if exp]
        candidate = _rational_power_product(pairs, root_order)
        if candidate is not None and _fits(name, candidate):
            derived[name] = candidate
            how.append("%s = %s" % (name, " * ".join(
                "%s^(%s)" % (_show_mono(mono), exp) for mono, exp in zip(monos, exps)
                if exp)))
    return derived, "; ".join(how)


def _representative(residue, mod, bound):
    """The unique integer in [-bound, bound] congruent to `residue` mod `mod`, or None

    Returns (value, reason) where reason is "" on success and explains the failure otherwise.
    With an exact (mod None) analysis the residue IS the value, so only the bound is checked.
    With a modulus there may be 0, 1 or several representatives inside the bound: several
    means the modulus is too small (or the bound too loose) to fix the integer, and the value
    is then reported as "pinned down modulo the modulus" rather than picked - choosing one of
    the candidates would be exactly the guess this module refuses to make.
    """
    if not mod:
        if abs(residue) <= bound:
            return residue, ""
        return None, "the exact value %d is outside the bound %d" % (residue, bound)
    lo = -bound - residue
    hi = bound - residue
    t_first = -((-lo) // mod)
    t_last = hi // mod
    if t_last < t_first:
        return None, "no value congruent to %d (mod %d) fits the bound %d" % (residue, mod,
                                                                            bound)
    if t_first == t_last:
        return residue + t_first * mod, ""
    return None, ("%d values congruent to %d (mod %d) fit the bound %d, so the integer is "
                  "not pinned down: tighten the bounds" % (t_last - t_first + 1, residue,
                                                          mod, bound))


# ---- the lattice -------------------------------------------------------------------

def _homogenise(eqs):
    """sum(terms) == rhs (mod m)  ->  sum(terms) - rhs * 1 == 0 (mod m)

    After this every equation is homogeneous in the monomials plus the constant (), whose
    value is 1 - the shape the lattice rows and the linear analysis both consume.
    """
    out = []
    for eq in eqs:
        terms = dict(eq["terms"])
        terms[()] = terms.get((), 0) - eq["rhs"]
        terms = {m: c for m, c in terms.items() if c}
        if terms:
            out.append({"terms": terms, "mod": eq["mod"]})
    return out


def _shift_multipliers(variables, extra_monomials, effort):
    """The monomials every equation gets multiplied by: user extras + the effort ladder

    light: no shifts (the base system only).
    normal: the base system plus every equation multiplied by one variable.
    heavy: also multiplied by products of two variables (x^2, x*y, ...).
    """
    mults = [()]
    if effort in ("normal", "heavy"):
        mults += [(name,) for name in variables]
    if effort == "heavy":
        singles = [(name,) for name in variables]
        products = sorted({_mul_mono(a, b) for a in singles for b in singles}, key=_mono_key)
        mults += [m for m in products if m not in mults]
    for m in extra_monomials or []:
        if m not in mults:
            mults.append(m)
    return mults


def _shape(work):
    """(sorted monomials, rows, columns) of a working equation list"""
    monos = {()}
    for eq in work:
        monos.update(eq["terms"])
    monos = sorted(monos, key=_mono_key)
    rows = len(monos) + sum(1 for eq in work if eq["mod"])
    return monos, rows, len(monos) + len(work)


def _assemble(homog, variables, bound_of, var_bounds, extra_monomials, effort):
    """Add shift equations while the lattice still fits, and derive the bounds they need

    Returns (work, bnd, monos, dropped_unbounded, dropped_cap). `work` is the list of
    homogeneous equations actually used; a shift is skipped (and counted) when one of the
    monomials it creates has no bound, or when it would push the shape past the cap.
    """
    base, bnd = [], dict(bound_of)
    for eq in homog:
        base.append(eq)
        for mono in eq["terms"]:
            if mono not in bnd:
                derived = _derive_bound(mono, var_bounds)
                if derived is None:
                    return None, None, None, 0, 0
                bnd[mono] = derived
    _, rows, cols = _shape(base)
    if rows > _LLL_MAX_DIM or cols > _LLL_MAX_DIM:
        return base, bnd, _shape(base)[0], 0, -1
    work = list(base)
    dropped_unbounded = 0
    dropped_cap = 0
    for mult in _shift_multipliers(variables, extra_monomials, effort):
        if not mult:
            continue
        for eq in homog:
            terms = {}
            for mono, coeff in eq["terms"].items():
                shifted = _mul_mono(mono, mult)
                terms[shifted] = terms.get(shifted, 0) + coeff
            terms = {m: c for m, c in terms.items() if c}
            new_bounds = {}
            for mono in terms:
                if mono in bnd:
                    continue
                derived = _derive_bound(mono, var_bounds)
                if derived is None:
                    new_bounds = None
                    break
                new_bounds[mono] = derived
            if new_bounds is None:
                dropped_unbounded += 1
                continue
            trial = work + [{"terms": terms, "mod": eq["mod"]}]
            _, rows, cols = _shape(trial)
            if rows > _LLL_MAX_DIM or cols > _LLL_MAX_DIM:
                dropped_cap += 1
                continue
            work = trial
            bnd.update(new_bounds)
    return work, bnd, _shape(work)[0], dropped_unbounded, dropped_cap


def _scales(monos, bnd):
    """Per-column scale (K // bound) and the residual weight W = _WEIGHT_SCALE * K

    K is the largest bound in play, so the column of the largest-bound monomial and the
    constant column get the scale K and everything else is normalised against it.
    """
    biggest = max(bnd.values())
    scale = [max(1, biggest // bnd[mono]) for mono in monos]
    return scale, _WEIGHT_SCALE * biggest


def _build_rows(work, monos, bnd):
    """Lay the working equations out on the monomial columns and build the lattice rows

    Returns (rows_for_lll, index_of_monomial, coef_matrix, mods, scale, weight) where
    coef_matrix is the homogenised coefficient matrix over ALL monomials (the constant
    included), which the linear analysis consumes as well.
    """
    index = {mono: j for j, mono in enumerate(monos)}
    n_mono = len(monos)
    mods = [eq["mod"] for eq in work]
    coef = []
    for eq in work:
        row = [0] * n_mono
        for mono, c in eq["terms"].items():
            row[index[mono]] += c
        coef.append(row)
    scale, weight = _scales(monos, bnd)
    basis = []
    for j, mono in enumerate(monos):
        row = [0] * (n_mono + len(work))
        row[j] = scale[j]
        for i in range(len(work)):
            row[n_mono + i] = weight * coef[i][j]
        basis.append(row)
    for i, mod in enumerate(mods):
        if mod:
            row = [0] * (n_mono + len(work))
            row[n_mono + i] = weight * mod
            basis.append(row)
    # `.lattice.lll` runs its Gram-Schmidt over a square shape most comfortably; zero rows
    # are inert for the reduction (they are dropped when the vectors are read back).
    while len(basis) < len(monos) + len(work):
        basis.append([0] * (n_mono + len(work)))
    return basis, index, coef, mods, scale, weight


def _read_vector(row, monos, lengths, scale):
    """Read a reduced vector: None when a residual is non-zero, else the monomial values

    Returns (values, reason) where values maps every monomial (constant included) to its
    integer value. The residual columns must be EXACTLY zero and every coordinate must be
    divisible by its column scale - otherwise this vector is not a linearisation of the
    system and nothing is read off it.
    """
    for k in range(lengths, len(row)):
        if row[k]:
            return None, "non-zero residual"
    values = {}
    for j, mono in enumerate(monos):
        v = row[j]
        s = scale[j]
        if v % s:
            return None, "coordinate %d is not a multiple of its scale %d" % (j, s)
        values[mono] = v // s
    return values, ""


def _normalise_constant(values):
    """Scale a candidate so that the constant monomial reads 1, or report why it cannot

    A lattice vector with zero residual is only a SOLUTION of the inhomogeneous system when
    its constant coordinate is non-zero (an all-zero constant part is a homogeneous relation
    between the monomials, not a solution). Multiples of a solution are also in the lattice,
    so a constant coordinate that divides every other coordinate is divided out.
    """
    const = values.get((), 0)
    if const == 0:
        return None, "the constant coordinate is 0: a homogeneous relation, not a solution"
    if const == -1:
        return {m: -v for m, v in values.items()}, ""
    if const == 1:
        return dict(values), ""
    if all(v % const == 0 for v in values.values()):
        return {m: v // const for m, v in values.items()}, "scaled down by the constant"
    return None, "the constant coordinate is %d, which does not divide every coordinate" \
                 % const


def _columns(monos):
    """The non-constant monomials of a coordinate list, in the order the analysis uses"""
    return [m for m in monos if m != ()]


def _assignment_from(values, variables):
    """{variable: value} from the singleton monomials of a candidate, or (None, missing)"""
    out = {}
    missing = []
    for name in variables:
        if (name,) in values:
            out[name] = values[(name,)]
        else:
            missing.append(name)
    return (out, []) if not missing else (None, missing)


def _probe_family(eqs, assignment, directions, columns, bnd):
    """Look for a SECOND small solution along the free directions - a refusal test

    The linear analysis hands over the nullspace directions of the reduced system; a
    direction that touches only single-variable monomials can be applied to an assignment.
    If the shifted assignment still satisfies every equation, the values are NOT determined
    (for instance x + y == s: (x-1, y+1) satisfies it too), so the caller must refuse.

    Only ever used to refuse a report, never to justify one: failing to find a second
    solution is reported as "not proven unique", not as a proof of uniqueness.
    """
    for d in directions[:_MAX_PROBES]:
        pert = {}
        usable = True
        for c, coef in d.items():
            mono = columns[c]
            if len(mono) == 1:
                pert[mono[0]] = pert.get(mono[0], 0) + coef
            elif coef:
                usable = False           # moves a product on its own: not a variable shift
                break
        if not usable or not any(pert.values()):
            continue
        for t in _PROBE_COEFFS:
            cand = {name: assignment[name] + t * pert.get(name, 0) for name in assignment}
            if cand == assignment:
                continue
            if any(bnd.get((name,)) is not None and abs(val) > bnd[(name,)]
                   for name, val in cand.items()):
                continue
            ok, _ = check_solution(eqs, cand)
            if ok:
                return cand
    return None


# ---- the public entry points -------------------------------------------------------

def _linearize_once(equations, bounds, extra_monomials=None, effort="normal"):
    """One attempt at `linearize` with exactly the effort given (see `linearize`)

    Kept separate so the effort ladder in `linearize` can retry cheaper without
    re-validating or re-normalising anything twice.
    """
    t0 = time.time()
    out = {"ok": False, "monomial_values": None, "solution": None, "vectors": [],
           "dimension": 0, "detail": "", "note": "", "seconds": 0.0, "_hit": "other"}

    def _fail(note, detail="", hit="other"):
        out["note"] = note
        if detail:
            out["detail"] = detail
        out["_hit"] = hit
        out["seconds"] = round(time.time() - t0, 3)
        return out

    if effort not in _EFFORTS:
        return _fail("effort must be one of %s" % (", ".join(_EFFORTS),))
    try:
        eqs = _normalise_equations(equations)
        explicit = _normalise_bounds(bounds)
        extra = [_as_monomial(m) for m in extra_monomials] if extra_monomials else []
    except (TypeError, ValueError) as exc:
        return _fail("input rejected: %s" % (exc,))
    if not eqs:
        return _fail("no equations given: there is nothing to linearise")

    variables = sorted({name for eq in eqs for mono in eq["terms"] for name in mono})
    var_bounds = {mono[0]: x for mono, x in explicit.items() if len(mono) == 1}
    bound_of = {(): 1}                     # the constant is 1 by construction, always
    for mono, x in explicit.items():
        bound_of[mono] = x
    needed = set()
    for eq in eqs:
        needed.update(eq["terms"])
    needed.update(extra)
    missing = []
    for mono in sorted(needed, key=_mono_key):
        if mono in bound_of:
            continue
        derived = _derive_bound(mono, var_bounds)
        if derived is None:
            missing.append(mono)
        else:
            bound_of[mono] = derived
    if missing:
        return _fail("no bound for monomial(s) %s: pass them in `bounds` (|value| <= bound) "
                     "or bound the single variables so a product bound can be derived"
                     % (_show_list(missing),))

    homog = _homogenise(eqs)
    if not homog:
        return _fail("every equation is 0 == 0: no information to work with")
    work, bnd, monos, dropped_unbounded, dropped_cap = _assemble(
        homog, variables, bound_of, var_bounds, extra, effort)
    if work is None:
        return _fail("a shifted equation needs a bound that neither `bounds` nor the "
                     "single-variable bounds provide")
    if dropped_cap == -1:
        monos, rows, cols = _shape(work)
        out["dimension"] = cols
        return _fail("the base system alone is %d rows x %d columns, over the pure-Python "
                     "LLL cap of %d: reduce the number of equations or monomials"
                     % (rows, cols, _LLL_MAX_DIM), "base system %dx%d, cap %d"
                     % (rows, cols, _LLL_MAX_DIM), "cap")
    if not work:
        return _fail("no equation carries information after shifts")
    n_mono = len(monos)
    dimension = n_mono + len(work)
    out["dimension"] = dimension
    detail_bits = ["lattice %dx%d" % (_shape(work)[1], dimension),
                   "%d equation(s), %d monomial(s), effort=%s" % (len(work), n_mono, effort)]
    if dropped_cap:
        detail_bits.append("%d shift(s) past the cap" % dropped_cap)
    if dropped_unbounded:
        detail_bits.append("%d shift(s) unbounded" % dropped_unbounded)

    basis, _index, _coef, _mods, scale, _weight = _build_rows(work, monos, bnd)
    red = L.lll(basis, max_dim=_LLL_MAX_DIM)
    lll_seconds = time.time() - t0
    detail_bits.append("LLL %.2fs" % lll_seconds)
    out["detail"] = ", ".join(detail_bits)
    if red is None:
        return _fail("the pure-Python LLL refused the %d x %d lattice (cap %d): lower the "
                     "effort, drop equations or shrink the monomial set"
                     % (len(basis), dimension, _LLL_MAX_DIM),
                     "lattice %dx%d, LLL %.1fs" % (len(basis), dimension, lll_seconds),
                     "guard")

    # ---- read the reduced vectors ------------------------------------------------------
    vectors = []
    candidates = []
    for row in red:
        if not any(row):
            continue
        norm = math.isqrt(sum(v * v for v in row))
        values, why = _read_vector(row, monos, n_mono, scale)
        entry = {"monomial_values": None, "residual_zero": why == "", "norm": norm,
                 "solution": None, "verified": False, "note": why}
        if values is not None:
            scaled, why2 = _normalise_constant(values)
            if scaled is None:
                entry["note"] = why2
            else:
                entry["monomial_values"] = {m: v for m, v in scaled.items() if m != ()}
                if why2:
                    entry["note"] = why2
                assignment, _missing = _assignment_from(scaled, variables)
                if assignment is not None:
                    entry["solution"] = assignment
                    ok, failures = check_solution(eqs, assignment)
                    entry["verified"] = ok
                    if not ok:
                        entry["note"] = ("does not satisfy the equations (%d failed)"
                                         % len(failures))
                candidates.append(entry)
        vectors.append(entry)
    out["vectors"] = vectors
    best = None
    for entry in candidates:
        if entry["verified"]:
            best = entry
            break

    # ---- what the congruences prove ----------------------------------------------------
    proven = {}
    ambiguous = []
    directions = []
    determined = {}
    linear_note = ""
    columns = _columns(monos)
    column_of = {mono: j for j, mono in enumerate(columns)}
    # The analysis runs on the BASE system, never on the shifted relaxation: shifts add
    # monomials of their own, so a shifted system can look determined where the base system
    # is not (x + y == s plus its shift by x hides the free direction (1, -1)). A determined
    # base value is a fact about the problem; a determined shifted value is only a fact about
    # the relaxation the caller asked for. Each modulus is analysed on its own and the
    # results are glued with CRT, because scaling every equation to a common lcm makes the
    # coefficients non-units and throws the elimination away (measured: two coprime moduli
    # gave "nothing determined" before this split).
    groups = {}
    for eq in homog:
        rows, rhs = groups.setdefault(eq["mod"], ([], []))
        row = [0] * len(columns)
        const = 0
        for mono, c in eq["terms"].items():
            if mono:
                row[column_of[mono]] += c
            else:
                const += c
        rows.append(row)
        rhs.append(-const)
    per_group = []
    raw_directions = []
    for mod in sorted(groups):
        if mod and mod.bit_length() > _MAX_COMMON_MODULUS_BITS:
            linear_note = "a modulus is too large to analyse: determination skipped for it"
            continue
        rows, rhs = groups[mod]
        det, dirs, consistent = _analyse(rows, rhs, mod or None)
        if not consistent:
            return _fail("the equations are inconsistent modulo %s: no value can satisfy "
                         "them" % (mod if mod else "the integers (exact equality)"))
        per_group.append((mod, det))
        raw_directions.extend(dirs)
    for c, mono in enumerate(columns):
        exact = [det[c] for mod, det in per_group if not mod and c in det]
        modular = [(det[c], mod) for mod, det in per_group if mod and c in det]
        if exact:
            if len(set(exact)) > 1:
                return _fail("the exact equations disagree about %s" % _show_mono(mono))
            value, why = _representative(exact[0], None, bnd[mono])
        elif modular:
            merged = _merge_congruences(modular)
            if merged is None:
                return _fail("the congruences disagree about %s: %s"
                             % (_show_mono(mono), "no integer can satisfy them together"))
            residue, merged_mod = merged
            value, why = _representative(residue, merged_mod, bnd[mono])
        else:
            continue
        if value is None:
            ambiguous.append("%s: %s" % (_show_mono(mono), why))
        else:
            proven[mono] = value
    directions = [d for d in raw_directions if _is_null_direction(d, homog, column_of)]
    if not linear_note:
        linear_note = ("%d monomial value(s) proven by the congruences" % len(proven)
                       if proven else "the congruences force no monomial value on their own")

    proven_vars = {name: proven[(name,)] for name in variables if (name,) in proven}
    undetermined_vars = [name for name in variables if (name,) not in proven]
    determined = {c for _mod, det in per_group for c in det}
    ambiguous_vars = [name for name in undetermined_vars
                      if column_of.get((name,)) in determined]
    solution = None
    notes = []
    if variables and len(proven_vars) == len(variables):
        ok, failures = check_solution(eqs, proven_vars)
        if ok:
            solution = proven_vars
            notes.append("every variable is forced by the congruences (proven, not fitted)")
        else:
            notes.append("the values the congruences force failed the substitution check "
                         "(%s): reported as unsolved" % _describe_failures(failures))
    if solution is None and proven:
        # exact arithmetic on top of the proven monomial values: x*y = c with x known gives
        # y = c/x, and the three pairwise products give x = sqrt(xy * xz / yz). Only the
        # exact-equation case is attempted (a modulus needs modular roots, a different job).
        derived, how = _exact_completion(proven, variables, eqs, bnd)
        if derived:
            merged = dict(proven_vars)
            merged.update(derived)
            if len(merged) == len(variables):
                ok, failures = check_solution(eqs, merged)
                if ok:
                    solution = merged
                    notes.append("completed by exact arithmetic (%s) and verified" % how)
                else:
                    notes.append("exact arithmetic proposed %s but the substitution check "
                                 "failed (%s)" % (_describe_assignment(merged),
                                                  _describe_failures(failures)))
            else:
                notes.append("exact arithmetic recovered %s but not %s"
                             % (_describe_assignment(derived),
                                ", ".join(n for n in variables if n not in merged)))

    if solution is None and best is not None and not ambiguous_vars:
        candidate = dict(best["solution"])
        conflict = [name for name, val in proven_vars.items() if candidate.get(name) != val]
        if conflict:
            notes.append("the short vector disagrees with the proven value of %s: nothing "
                         "reported" % (", ".join(conflict),))
        else:
            ok, failures = check_solution(eqs, candidate)
            family = _probe_family(eqs, candidate, directions, columns, bnd)
            if not ok:
                notes.append("the shortest usable vector failed the substitution check (%s)"
                             % _describe_failures(failures))
            elif family is not None:
                notes.append("not determined: %s also satisfies every equation, so this "
                             "system does not pin the values down"
                             % _describe_assignment(family))
            else:
                solution = candidate
                notes.append("values verified by substitution; uniqueness is not proven "
                             "(no second solution found along the %d free direction(s) of "
                             "the linearisation)" % len(directions))
    if solution is None and ambiguous_vars:
        notes.append("the short vector is NOT reported: %s cannot be pinned to a single "
                     "integer within the given bounds (see above)" % (", ".join(
                         ambiguous_vars),))

    if solution is None and any(len(mono) > 1 for eq in homog for mono in eq["terms"]):
        notes.append("the relaxation carries a product such as x*y as a free monomial, so "
                     "it never sees x*y as a function of x and y: a system whose only "
                     "coupling is a product needs a polynomial attack (bivariate "
                     "Coppersmith / a quadratic over the integers), not linearisation")

    if solution is not None:
        monomial_values = {}
        for eq in eqs:
            for mono in eq["terms"]:
                monomial_values[mono] = _mono_value(mono, solution)
        out["monomial_values"] = monomial_values
        out["solution"] = {name: solution[name] for name in variables}
        out["ok"] = True
    elif proven:
        monomial_values = dict(proven)
        for eq in eqs:
            for mono in eq["terms"]:
                if mono == () and () not in monomial_values:
                    monomial_values[()] = 1
        out["monomial_values"] = monomial_values
        undetermined = [name for name in variables if name not in proven_vars]
        notes.append("the individual value(s) of %s are not determined by these equations"
                     % (", ".join(undetermined) if undetermined else "the variables"))
    elif ambiguous:
        notes.append("pinned down modulo the modulus but not as an integer: "
                     + "; ".join(ambiguous))

    if solution is None:
        notes.append(_widen(bnd, variables, effort, candidates, dropped_cap,
                            dropped_unbounded))
    out["note"] = " | ".join([linear_note] + [n for n in notes if n])
    out["seconds"] = round(time.time() - t0, 3)
    out["_hit"] = "" if solution is not None else "other"
    return out


def _attempt_line(level, hit, res):
    """One "what this effort hit" fragment for the note"""
    if hit == "other":
        # No shape failure: quote the attempt's own first reason (the lattice detail and
        # the "what to widen" sentence stay in `detail` / the final note).
        return "effort='%s' %s" % (level, (res.get("note")
                                           or "no accepted solution").split(" | ")[0])
    detail = (res.get("detail") or "").strip()
    if len(detail) > 70:
        detail = detail[:67] + "..."
    return "effort='%s' %s%s" % (level, _HIT_PHRASE[hit],
                                 " (%s)" % detail if detail else "")


def linearize(equations, bounds, extra_monomials=None, effort="normal"):
    """Build the linearisation lattice, reduce it, and read the small monomial values off

    Args:
        equations: sequence of {"terms": {monomial: coeff}, "mod": m, "rhs": r}; "mod" 0 or
                   None means an exact equality over Z (see the module docstring for the
                   monomial spelling).
        bounds: {monomial: bound} with |value| <= bound for every monomial of the equations.
                   A product bound may be omitted when the single variables are bounded.
        extra_monomials: additional monomials for the shift set - every equation is also
                   multiplied by each of them (they must be boundable).
        effort: "light" (no shifts), "normal" (x every equation), "heavy" (also products of
                   two variables). Shifts that do not fit the 12x12 pure-Python LLL cap are
                   skipped and the detail says so. `effort` is a CEILING, not a promise: the
                   levels are tried cheapest first and the first verified answer wins
                   (`_EFFORT_LADDER`), because a `normal` relaxation is the expensive one and
                   the cheap one usually carries the information. The note names the level
                   that answered, and on failure what each attempt hit.
    Returns:
        {"ok", "monomial_values", "solution", "vectors", "dimension", "detail", "note",
         "effort", "seconds"}:
          ok            True only when every variable has a value that `check_solution`
                        accepted.
          monomial_values  {monomial: value} - the values the lattice actually read off, the
                        congruences proved, or exact arithmetic derived from them. May be a
                        PARTIAL dict when ok is False (e.g. x*y is known but x and y are
                        not); None when nothing could be read.
          solution      {variable: value} for every variable of the system, else None.
          vectors       one entry per non-zero reduced vector:
                        {"monomial_values", "residual_zero", "norm", "solution",
                         "verified", "note"} - the raw material, so a caller who wants to
                        read the lattice itself still can.
          dimension     number of lattice coordinates (monomial columns + equation columns).
          detail        lattice shape, parameters and timings.
          effort        the effort level that produced this result (the cheap level that
                        answered, which may be below the one requested), or the requested
                        one on a full failure.
          note          why the result is what it is; on failure it names the reason and the
                        direction to widen, plus what each attempt hit. On a cheap-level
                        answer it names the level that worked and what the cheaper attempts
                        before it hit.
          seconds       wall-clock time of the WHOLE call, every attempt included.
        Nothing in this dict is ever a guess: `monomial_values` entries come from a vector
        with exactly zero residuals, from a proven determination, or from exact arithmetic on
        those; every `solution` entry was substituted back through `check_solution`.
        The determination analysis runs PER MODULUS and is glued with CRT, so a value that
        only the combination of two different moduli pins down is not proven here (it can
        still arrive through the verified-candidate path, labelled as not proven unique).

    Measured ceiling (this machine, CPython 3.11, the pure-Python Fraction LLL of
    `.lattice`). The 12-coordinate cap is not the real limit - time is. Raw cost of one
    rung, measured through the single-attempt path on "2 variables, 2 equations, modulus
    M, bound B" (5x5 at effort='light', 12x12 at effort='normal'):

        M 1024-bit, B 2^64:   light  0.01 s  (5x5)  |  normal  20.7 s  (12x12)
        M 2048-bit, B 2^64:   light  0.01 s  (5x5)  |  normal  24.4 s  (12x12)
        M 2048-bit, B 2^128:  light  0.02 s  (5x5)  |  normal  66.1 s  (12x12)
        M 4096-bit, B 2^128:  light  0.03 s  (5x5)  |  normal  82.2 s  (12x12)

    A user hit exactly this: `effort="normal"` built an 11x11 lattice, sat on the LLL
    step guard for 104 s and returned None, while `effort="light"` solved the same shape in
    1.4 s. With the ladder, the public call on all four rows above returns in 0.01-0.02 s,
    because the light rung answers first and the 12x12 relaxation is never built. That is
    the whole point: read `note` for the level that answered and `detail` for the lattice
    actually built.
    """
    if effort not in _EFFORTS:
        res = _linearize_once(equations, bounds, extra_monomials, effort)
        res.pop("_hit", None)
        res["effort"] = effort
        return res
    t0 = time.time()
    attempts = []
    for level in _EFFORT_LADDER[effort]:
        res = _linearize_once(equations, bounds, extra_monomials, level)
        hit = res.pop("_hit", "other")
        attempts.append((level, hit, res))
        res["effort"] = level
        res["seconds"] = round(time.time() - t0, 3)
        if res["ok"]:
            if level != effort:
                # Name the level that answered, and what the cheaper attempts before it
                # hit when there were any (there are none when `level` is the first rung).
                before = ("; before it, " + "; ".join(_attempt_line(lv, h, r)
                                                      for lv, h, r in attempts[:-1])
                          if len(attempts) > 1 else "")
                res["note"] = (res["note"] + " | " if res["note"] else "") + \
                    "solved at effort='%s', below the requested effort='%s'%s" \
                    % (level, effort, before)
            return res
    last = attempts[-1][2]
    last["note"] = (last["note"] + " | " if last["note"] else "") + \
        "efforts tried (cheapest first): " + \
        "; ".join(_attempt_line(lv, h, r) for lv, h, r in attempts)
    return last


def _describe_failures(failures):
    bits = []
    for idx, diff in failures[:3]:
        bits.append("equation %d: %s" % (idx, "cannot be evaluated (missing variable)"
                                         if diff is None else "off by %d" % diff))
    if len(failures) > 3:
        bits.append("%d more" % (len(failures) - 3))
    return "; ".join(bits)


def _describe_assignment(assignment):
    return "(" + ", ".join("%s=%d" % (k, assignment[k]) for k in sorted(assignment)) + ")"


def _widen(bnd, variables, effort, candidates, dropped_cap, dropped_unbounded):
    """The "what to do next" sentence, naming the reason and the direction to widen"""
    biggest = max(bnd.values())
    bits = ["no accepted solution"]
    if candidates:
        satisfied = sum(1 for entry in candidates if entry["verified"])
        bits.append("%d zero-residual vector(s) read, %d of them satisfied every equation"
                    % (len(candidates), satisfied))
    else:
        bits.append("no reduced vector had exactly zero residuals")
    if not variables:
        bits.append("the system has no variables to solve for")
    bits.append("largest bound in play 2^%d" % max(1, biggest.bit_length()))
    widen = ["more equations (an extra relation is usually worth more than a bigger bound)"]
    if biggest > 1:
        widen.append("tighter bounds (the bound enters squared in the vector length)")
    if dropped_cap or dropped_unbounded or effort != "heavy":
        widen.append("more shifts (effort='heavy', or pass extra_monomials)")
    bits.append("direction to widen: " + "; ".join(widen))
    return " | ".join(bits)


def _mono_value(mono, assignment):
    """The value of one monomial under an assignment: variables multiplied out for real"""
    val = 1
    for name in mono:
        val *= assignment[name]
    return val


def _gcd(a: int, b: int) -> int:
    return math.gcd(a, b)


def _iroot(n: int, k: int):
    return A.iroot(n, k)


def separate_variables(monomial_values, variables=None, max_coeff: int = 2):
    """Recover individual variables from known monomial values, by gcd and exact roots

    The shape this exists for (a user's worked CTF example): a lattice hands back
    `x*y^2` and `x^2*y` as its small quantities, and `gcd(x*y^2, x^2*y) = x*y` separates
    them - `x = (x^2*y)/(x*y)`, `y = (x*y^2)/(x*y)`. More generally the input is a pool of
    monomial values, and this function enriches it with the pairwise gcds (which are the
    monomials with the minimum exponents, e.g. `gcd(x^2*y, x*y^2) = x*y`) and then looks
    for an integer combination of the known exponent vectors that equals `k * e_v` for a
    single variable `v`; the value of `v` is the exact `k`-th root of the corresponding
    product.

    Args:
        monomial_values: {monomial: int}. Monomials in any form `parse_monomial`
                         understands (("x","x","y"), "x^2*y", ...). Signs are handled by
                         working with absolute values; a zero value makes its monomial
                         useless and is reported in the note.
        variables: optional list of names to separate; default = every variable that
                   occurs in the monomials.
        max_coeff: how far the search may go in combining known monomials (2 is enough
                   for the canonical pairwise-gcd shapes; larger costs time only).
    Returns:
        `{"ok", "solution", "used", "note"}`; `solution` maps only the variables that
        were separated and verified (`product of the monomials == the known value`).
        A variable that cannot be isolated is listed in the note - never guessed.

    Scope: this step is exact arithmetic over the integers and takes no modulus. The
    values it consumes are the ones a lattice has already proven (`linearize` /
    `recover_from_products` report them, possibly as a partial dict when a product is
    proven without its factors - that partial dict is exactly what belongs here).
    For products that are only known *modulo* something, get them out of the lattice
    first; a congruence never determines the integer product on its own.
    """
    pool = {}
    for mono, value in (monomial_values or {}).items():
        key = _as_monomial(mono)
        try:
            val = abs(int(value))
        except (TypeError, ValueError):
            continue
        if val == 0 or val == 1:
            continue
        pool[key] = val
    notes = []
    if not pool:
        return {"ok": False, "solution": None, "used": {},
                "note": "no usable monomial values: need at least one positive integer"}
    # Pairwise gcds: when two monomials use exactly the same variables, their gcd is the
    # min-exponent monomial - that is what turns (x*y^2, x^2*y) into x*y. Monomials with
    # different variable sets are skipped: their gcd is not a clean sub-monomial of both.
    keys = list(pool)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            if set(keys[i]) != set(keys[j]):
                continue
            g = _gcd(pool[keys[i]], pool[keys[j]])
            if g <= 1:
                continue
            cand = tuple(sorted(v for v in set(keys[i])
                                for _ in range(min(keys[i].count(v), keys[j].count(v)))))
            if not cand:
                continue
            if cand not in pool:
                pool[cand] = g
            elif pool[cand] != g:
                notes.append(f"gcd({_show_mono(keys[i])}, {_show_mono(keys[j])}) = {g} "
                             f"contradicts the given value {pool[cand]} for "
                             f"{_show_mono(cand)}")
    names = list(variables) if variables else sorted({v for mono in pool for v in mono})
    exponents = {mono: {v: mono.count(v) for v in set(mono)} for mono in pool}
    items = list(pool.items())
    # Phase 1: isolate each variable on its own - an integer combination of the known
    # exponent vectors must equal k * e_v for a single variable v (breadth is tiny: a
    # handful of monomials, coefficients within +-max_coeff).
    isolated = {}
    for name in names:
        for k in (1, 2, 3):
            hit = None
            for combo in _coeff_combos(len(items), max_coeff):
                vec = {}
                for coeff, (mono, _val) in zip(combo, items):
                    for v, e in exponents[mono].items():
                        vec[v] = vec.get(v, 0) + coeff * e
                if vec.get(name) != k or any(v != name and e for v, e in vec.items()):
                    continue
                num, den = 1, 1
                for coeff, (mono, val) in zip(combo, items):
                    if coeff > 0:
                        num *= val ** coeff
                    elif coeff < 0:
                        den *= val ** (-coeff)
                if den == 0 or num % den:
                    continue
                root, exact = _iroot(num // den, k)
                if exact and root > 0:
                    hit = (root, vec)
                    break
            if hit is not None:
                isolated[name] = hit
                break
        if name not in isolated:
            notes.append(f"{name}: no integer combination of the known monomials "
                         f"isolates it")
    # Phase 2: verify the whole assignment against every monomial in the pool, once all
    # the variables are in hand (checking earlier would reject valid values simply
    # because their partners had not been separated yet).
    solution = {name: root for name, (root, _vec) in isolated.items()}
    used = {name: vec for name, (_root, vec) in isolated.items()}
    for mono, val in items:
        unknown = [v for v in set(mono) if v not in solution]
        if unknown:
            notes.append(f"{_show_mono(mono)}: not checked (no value for "
                         f"{', '.join(sorted(unknown))})")
            continue
        prod = 1
        for v in set(mono):
            prod *= solution[v] ** mono.count(v)
        if prod != val:
            notes.append(f"{_show_mono(mono)} = {val}, but the separated values give "
                         f"{prod}")
    verified = not any("but the separated values give" in n for n in notes)
    if solution and not verified:
        solution = {}                      # nothing is reported that failed verification
    if not solution:
        return {"ok": False, "solution": None, "used": {},
                "note": "; ".join(notes) or "could not separate any variable"}
    if not notes:
        notes.append(f"separated {len(solution)}/{len(names)} variable(s) from "
                     f"{len(pool)} monomial value(s)")
    return {"ok": len(solution) == len(names), "solution": solution, "used": used,
            "note": "; ".join(notes)}


def _coeff_combos(width: int, max_coeff: int):
    """Integer coefficient tuples of the given width, small |coeff| first"""
    if width == 0:
        yield ()
        return
    order = [0] + [c for n in range(1, max_coeff + 1) for c in (n, -n)]
    for head in order:
        for tail in _coeff_combos(width - 1, max_coeff):
            yield (head,) + tail


def solve_linearized(equations, bounds, variables, verifier=None, effort="normal"):
    """`linearize` plus: derive the named variables, verify them, honour a caller verifier

    Args:
        equations, bounds, effort: as in `linearize`.
        variables: the variable names the caller wants. A name that does not appear in the
                   equations cannot be determined and is reported in the note.
        verifier: optional callable taking the {variable: value} dict and returning a truthy
                   value when it accepts the candidate. It is called only on a candidate that
                   already passed `check_solution`, and a rejection means ok=False - the
                   equations holding is necessary, the caller's own check decides.
    Returns:
        The same dict shape as `linearize`, with `solution` restricted to `variables`.
    """
    res = linearize(equations, bounds, effort=effort)
    req = []
    for name in variables or []:
        if not isinstance(name, str) or not name:
            res = dict(res)
            res.update(ok=False, solution=None,
                       note="solve_linearized: variables must be non-empty strings")
            return res
        req.append(name)
    if res["solution"] is None:
        return res
    full = res["solution"]
    absent = [name for name in req if name not in full]
    if absent:
        res = dict(res)
        res.update(ok=False, solution=None,
                   note=(res["note"] + " | " if res["note"] else "")
                        + "%s do not appear in the equations, so nothing determines them"
                        % (", ".join(absent),))
        return res
    solution = {name: full[name] for name in req}
    # The equations are re-checked here on the FULL assignment, so this function never claims
    # ok on the strength of a subset: the requested variables may be fewer than the system's.
    ok, failures = check_solution(equations, full)
    if not ok:
        res = dict(res)
        res.update(ok=False, solution=None,
                   note=(res["note"] + " | " if res["note"] else "")
                        + "the candidate does not satisfy the equations (%s)"
                        % _describe_failures(failures))
        return res
    note = res["note"]
    if verifier is not None:
        try:
            accepted = bool(verifier(dict(solution)))
        except Exception as exc:                       # a broken verifier is a rejection
            accepted = False
            note = (note + " | " if note else "") + \
                "the verifier raised %s: treated as a rejection" % type(exc).__name__
        if not accepted:
            res = dict(res)
            res.update(ok=False, solution=None,
                       note=(note + " | " if note else "")
                            + "the caller's verifier rejected the candidate (the equations "
                              "alone do hold, so the task's own check is what failed)")
            return res
    res = dict(res)
    res["solution"] = solution
    res["ok"] = True
    return res


def recover_from_products(products, bounds=None, modulus=None, effort="normal"):
    """The "I know products of small secrets" shape, linearised and reduced in one call

    Args:
        products: {monomial: value} or a sequence of (monomial, value) pairs. A value may be
                  an int (1 * monomial == value), a (coefficient, value) pair, or a
                  (coefficient, value, modulus) triple - the last two cover "value times a
                  known constant" and per-product moduli. Monomial keys may be written as
                  strings ("x*y").
        bounds: optional {monomial: bound} the caller already knows; these monomials are also
                  used as shift monomials, so bounding ("x",) lets every equation be shifted
                  by x. Bounds for the products themselves are derived from the values when
                  this is omitted.
        modulus: default modulus for every product (None or 0 = exact equality over Z).
        effort: as in `linearize`.
    Returns:
        The dict shape of `linearize`. A single product such as x*y == c pins the monomial but
        not x and y, so `monomial_values` comes back with ("x","y") and `solution` stays None
        with the reason in the note - the caller decides whether to factor, to add an equation
        or to use a different attack.
    Bounds: an explicit `bounds` entry always wins. For an exact product the bound is derived
    from the value itself (c*mono == rhs gives |mono| = |rhs/c|, rounded up - a fact, not an
    assumption). For a MODULAR product the magnitude is genuinely unknown, so a bound is taken
    from the single-variable bounds when the user gave them (|x*y| <= X*Y, a fact); failing
    that the smallest representative of the residue is used as the bound and the note says so,
    because "the residue is the value" is an assumption about the task, not a proof.
    """
    items = []
    if products is None:
        items = []
    elif isinstance(products, dict):
        items = list(products.items())
    else:
        for item in products:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise TypeError("each product must be a (monomial, value) pair")
            items.append((item[0], item[1]))
    parsed = []
    for key, val in items:
        mono = _as_monomial(key)
        mod = modulus or 0
        if isinstance(val, (list, tuple)):
            if len(val) == 2:
                coeff, rhs = val
            elif len(val) == 3:
                coeff, rhs, mod = val
                mod = mod or 0
            else:
                raise TypeError("a product value must be an int, (coeff, value) or "
                                "(coeff, value, modulus)")
        else:
            coeff, rhs = 1, val
        coeff = _int_value(coeff, "product coefficient")
        rhs = _int_value(rhs, "product value")
        if not coeff:
            raise ValueError("product coefficient 0 makes the equation empty")
        parsed.append((mono, coeff, rhs, mod))
    if not parsed:
        res = dict(linearize([], {}, effort=effort))
        res["note"] = "no products given: nothing to recover"
        return res
    user = _normalise_bounds(bounds)
    var_bounds = {mono[0]: x for mono, x in user.items() if len(mono) == 1}
    auto = {}
    assumed = []
    for mono, coeff, rhs, mod in parsed:
        if mono in user:
            continue
        if not mod:
            auto[mono] = max(1, (abs(rhs) + abs(coeff) - 1) // abs(coeff))
            continue
        derived = _derive_bound(mono, var_bounds)
        if derived is not None:
            auto[mono] = max(1, derived)
            continue
        residue = rhs % mod
        inv = A.modinv(coeff % mod, mod)
        if inv is not None:
            residue = rhs * inv % mod
        auto[mono] = max(1, min(residue, mod - residue))
        assumed.append(mono)
    eqs = [{"terms": {mono: coeff}, "mod": mod, "rhs": rhs}
           for mono, coeff, rhs, mod in parsed]
    merged = dict(auto)
    merged.update(user)
    res = linearize(eqs, merged, extra_monomials=list(user), effort=effort)
    if res["solution"] is None:
        res = dict(res)
        given = ", ".join("%s = %s" % (_show_mono(mono), rhs)
                          for mono, _coeff, rhs, _mod in parsed)
        if len(parsed) == 1:
            advice = ("one product of two secrets does not separate them - factor the "
                      "product, add one more relation, or bound the single variables in "
                      "`bounds` so they enter as shifts")
        else:
            advice = ("one more relation (or a bound on the single variables, which then "
                      "enter as shifts) is what separates the factors")
        bits = [res["note"], "products given: %s; %s" % (given, advice)]
        if assumed:
            bits.append("the magnitude of %s was ASSUMED to be the small representative of "
                        "the residue; pass `bounds` if it can be larger"
                        % (", ".join(_show_mono(m) for m in assumed),))
        res["note"] = " | ".join(b for b in bits if b)
    return res
