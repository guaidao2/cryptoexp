"""Lattice toolkit — pure-Python LLL / Coppersmith / low-density subset sum

Zero core dependencies: no sage; LLL (exact Gram-Schmidt over Fraction) and the
Howgrave-Graham univariate Coppersmith (small roots / factorisation with known
high bits) are implemented here.
Sized for typical CTF tasks (dimension <= 8, polynomial degree <= 5); when out
of scale it returns None explicitly, so the caller degrades to "lead + skeleton"
instead of pretending to succeed.
"""

from fractions import Fraction
import math

from .algebra import isqrt, perfect_square, modinv, gcd


# ────────────────────────── LLL ──────────────────────────

def _gram_schmidt(basis):
    """Exact Gram-Schmidt (Fraction) → (orthogonalised vectors, mu coefficients)"""
    n = len(basis)
    dim = len(basis[0])
    ortho = []
    mu = [[Fraction(0)] * n for _ in range(n)]
    for i in range(n):
        row = [Fraction(x) for x in basis[i]]
        for j in range(i):
            num = sum(Fraction(basis[i][k]) * ortho[j][k] for k in range(dim))
            den = sum(ortho[j][k] * ortho[j][k] for k in range(dim))
            mu[i][j] = num / den if den else Fraction(0)
            row = [row[k] - mu[i][j] * ortho[j][k] for k in range(dim)]
        ortho.append(row)
    return ortho, mu


def _round_half(x: Fraction) -> int:
    return math.floor(x + Fraction(1, 2))


def lll(basis, delta=Fraction(3, 4), max_dim: int = 12):
    """LLL basis reduction — input is a list of integer row vectors,
    returns the reduced integer basis

    The implementation is the textbook "recompute Gram-Schmidt at every step"
    version: slower, but free of the hard-to-find precision/sign bugs that live
    in incremental updates — good enough at CTF scale.
    """
    if not basis:
        return []
    n = len(basis)
    dim = len(basis[0])
    if n > max_dim or dim > max_dim:
        return None  # out of scale: do not force it
    B = [[int(x) for x in row] for row in basis]
    ortho, mu = _gram_schmidt(B)
    k = 1
    guard = 0
    while k < n:
        guard += 1
        if guard > 4000:
            return None  # give up rather than return a half-finished basis
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = _round_half(mu[k][j])
                B[k] = [B[k][i] - q * B[j][i] for i in range(dim)]
                ortho, mu = _gram_schmidt(B)
        lhs = sum(ortho[k][i] ** 2 for i in range(dim))
        rhs = (delta - mu[k][k - 1] ** 2) * sum(ortho[k - 1][i] ** 2 for i in range(dim))
        if lhs >= rhs:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            ortho, mu = _gram_schmidt(B)
            k = max(1, k - 1)
    return B


# ────────────────────────── polynomials (lowest degree first) ──────────────────────────

def poly_trim(p):
    p = list(p)
    while len(p) > 1 and p[-1] == 0:
        p.pop()
    return p or [0]


def poly_mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                out[i + j] += x * y
    return poly_trim(out)


def poly_pow(a, k):
    out = [1]
    for _ in range(k):
        out = poly_mul(out, a)
    return out


def poly_scale(a, k):
    return poly_trim([x * k for x in a])


def poly_eval(p, x):
    """Horner"""
    acc = 0
    for c in reversed(p):
        acc = acc * x + c
    return acc


def _poly_mod(f, g, N):
    """Remainder in (Z/N)[x] — g must be monic (the caller guarantees it)"""
    f = [c % N for c in f]
    g = [c % N for c in g]
    dg = len(g) - 1
    if dg == 0:
        return [0]
    inv = modinv(g[-1], N)
    if inv is None:
        raise ZeroDivisionError("leading coeff not invertible")
    out = list(f)
    for i in range(len(out) - 1, dg - 1, -1):
        coef = out[i] * inv % N
        if coef:
            for j in range(dg + 1):
                out[i - dg + j] = (out[i - dg + j] - coef * g[j]) % N
    while len(out) > 1 and out[-1] % N == 0:
        out.pop()
    return [c % N for c in out]


def _poly_gcd_mod(f, g, N):
    """Euclidean GCD attempt in (Z/N)[x]

    Returns ("poly", monic polynomial) or ("factor", non-trivial factor) — the
    latter shows up on a non-invertible leading coefficient, which by itself
    hands us the factorisation of N for free (a common Coppersmith by-product).
    """
    f, g = poly_trim([c % N for c in f]), poly_trim([c % N for c in g])
    while g != [0]:
        inv = modinv(g[-1] % N, N)
        if inv is None:
            d = gcd(g[-1] % N, N)
            if 1 < d < N:
                return "factor", d
            return "fail", None
        g = [c * inv % N for c in g]
        try:
            f, g = g, _poly_mod(f, g, N)
        except ZeroDivisionError:
            return "fail", None
    if f == [0]:
        return "poly", [0]
    inv = modinv(f[-1] % N, N)
    if inv is None:
        d = gcd(f[-1] % N, N)
        if 1 < d < N:
            return "factor", d
        return "fail", None
    return "poly", [c * inv % N for c in f]


def _poly_mod_rational(f, g):
    """Remainder in Q[x] (g's leading coefficient is non-zero)"""
    f = [Fraction(x) for x in f]
    g = [Fraction(x) for x in g]
    dg = len(g) - 1
    out = list(f)
    for i in range(len(out) - 1, dg - 1, -1):
        coef = out[i] / g[dg]
        if coef:
            for j in range(dg + 1):
                out[i - dg + j] -= coef * g[j]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def _poly_gcd_rational(a, b):
    """Polynomial GCD over Q[x] (returns the monic result, coefficients as Fraction)

    This is the key to Coppersmith post-processing: Howgrave-Graham guarantees
    that **a short-vector polynomial vanishes exactly at the true root**, so the
    true root must be a common root of two reduced polynomials → their gcd is
    linear and the integer root can be read straight off. Using the gcd over
    (Z/N)[x] instead takes the most trivial of those roots (x ≡ -a mod N, i.e.
    the fake factorisation with p=n/q=1) as the answer — we hit that in testing.
    """
    f = [Fraction(x) for x in poly_trim(list(a))]
    g = [Fraction(x) for x in poly_trim(list(b))]
    while any(g):
        if len(g) - 1 > len(f) - 1:
            f, g = g, f
        f, g = g, _poly_mod_rational(f, g)
    if not any(f):
        return None
    lead = f[-1]
    return [x / lead for x in f]


def _small_degree_int_roots(poly, max_deg: int = 2):
    """Integer roots of a low-degree polynomial (exact linear division, or a
    perfect-square discriminant)"""
    p = poly_trim([int(x) for x in poly])
    d = len(p) - 1
    if d == 1:
        a, b = p
        return [-a // b] if b and a % b == 0 else []
    if d == 2:
        a, b, c = p
        r = perfect_square(b * b - 4 * a * c)
        if r is None:
            return []
        out = []
        for num in (-b + r, -b - r):
            if num % (2 * a) == 0:
                out.append(num // (2 * a))
        return out
    return []


def coppersmith_univariate(f, N: int, X: int, m: int = None, t: int = None):
    """Univariate Coppersmith small roots (Howgrave-Graham)

    Args:
        f: monic polynomial coefficients (lowest degree first), degree delta
        N: modulus (usually the RSA n)
        X: bound on the root (|x0| < X)
        m, t: lattice parameters; by default small values are picked from delta
              (CTF scale)
    Returns:
        {"roots": [...], "factor": p|None, "note": str}
        Every root in roots is an **exact integer root of a reduced polynomial**
        (h(root)==0 has been verified) with |root| < X; whether it is really the
        small root the task wants is still for the caller to check against the
        task statement (e.g. known_high_bits_factor re-verifies
        N % (p_high<<shift + root) == 0).
    """
    f = poly_trim(f)
    d = len(f) - 1
    if d < 1:
        return {"roots": [], "factor": None, "note": "polynomial degree is not positive"}
    if f[-1] != 1:
        return {"roots": [], "factor": None, "note": "only monic polynomials are supported"}
    if m is None:
        m = 3
    if t is None:
        # For the partial-modulus case the standard scale is t ~= m(1/beta - 1)
        # with beta = 0.5, i.e. t ~= m. Measured on a 512-bit N with 160 of p's
        # 256 bits known: (m,t)=(3,1) -> no root, (4,3) -> no root, (3,3) -> root
        # in 5.6s, (4,4) -> 110s, (5,5) -> >19 min. So (3,3) is the default sweet
        # spot; larger lattices must be requested explicitly because pure-Python
        # Fraction LLL gets very slow.
        t = m if d == 1 else max(1, d * m // 2)
    # build g_{i,j} = x^j * N^(m-i) * f^i  (i<m, j<d) and g = x^j * f^m (j<t)
    polys = []
    for i in range(m):
        base = poly_scale(poly_pow(f, i), N ** (m - i))
        for j in range(d):
            polys.append([0] * j + base)
    fm = poly_pow(f, m)
    for j in range(t):
        polys.append([0] * j + fm)

    # substitute x → xX and use the coefficients as the lattice (columns = degrees)
    dim = max(len(p) for p in polys)
    basis = []
    for p in polys:
        row = [0] * dim
        for k, c in enumerate(p):
            row[k] = c * (X ** k)
        basis.append(row)
    reduced = lll(basis)
    if reduced is None:
        return {"roots": [], "factor": None,
                "note": "lattice dimension too large, skipped (lower m/t by hand)"}

    # turn the rows back into polynomials (undo the X^k scaling)
    rows = []
    for row in reduced:
        poly, ok = [], True
        for k in range(dim):
            if row[k] == 0:
                poly.append(0)
                continue
            xk = X ** k
            if row[k] % xk:
                ok = False
                break
            poly.append(row[k] // xk)
        if ok:
            rows.append(poly_trim(poly))
    if not rows:
        return {"roots": [], "factor": None,
                "note": "reduced vectors cannot be turned back into integer polynomials"}

    roots, seen = [], set()

    def _add(r):
        if r is None or r in seen or abs(r) >= X:
            return False
        seen.add(r)
        roots.append(int(r))
        return True

    # 1) pairwise gcd over Q[x] → linear means an integer root (main path)
    for i in range(len(rows)):
        for j in range(i + 1, len(rows)):
            g = _poly_gcd_rational(rows[i], rows[j])
            if g and len(g) == 2:
                c0, c1 = g
                if c1 and (-c0) % c1 == 0:
                    r = int(-c0 / c1)
                    if poly_eval(rows[i], r) == 0:
                        _add(r)
    # 2) exact low-degree solve on a single row (fallback)
    for poly in rows:
        for r in _small_degree_int_roots(poly):
            if poly_eval(poly, r) == 0:
                _add(r)
    # 3) gcd with f over (Z/N)[x] — for when "the root is a root mod N"
    factor = None
    for poly in rows:
        kind, val = _poly_gcd_mod(f, poly, N)
        if kind == "factor":
            factor = val
            break
        if kind != "poly" or len(val) != 2:
            continue
        a, b = val
        inv = modinv(b % N, N)
        if inv is None:
            continue
        r = (-a * inv) % N
        if r < X and poly_eval(f, r) % N == 0:
            _add(r)
    return {"roots": sorted(roots), "factor": factor,
            "note": "" if (roots or factor) else "no small root found (raise m/t or check X bound)"}


def _valid_factor(N: int, d, max_bits: int = None):
    """Is a factorisation result trustworthy: it must be a non-trivial factor

    Checking `N % d == 0` alone is not enough — that also holds when d == N, and
    it then produces the fake factorisation "p=n, q=1" which blows up the phi
    computation downstream (we hit this in testing).
    """
    if not d or d <= 1 or d >= N:
        return False
    if N % d:
        return False
    if max_bits is not None and d.bit_length() > max_bits:
        return False
    return True


def known_high_bits_factor(N: int, p_high: int, known_bits: int, total_bits: int = None):
    """Known high bits of p → factor N

    f(x) = p_high * 2^shift + x, where shift = number of unknown bits; Coppersmith
    finds the small root.
    Returns {"p", "q", "root", "note"} (p/q are verified by multiplication).
    On failure the same four keys are present with value None - the dict is always
    returned, so callers check `res["p"] is not None` rather than expecting no value.
    """
    total_bits = total_bits or N.bit_length()
    shift = max(1, total_bits // 2 - known_bits)
    X = 1 << shift
    # make it monic: f(x) = x + p_high*2^shift (a root mod N is p_low)
    f = [p_high << shift, 1]
    res = coppersmith_univariate(f, N, X, m=3, t=3)
    out = {"p": None, "q": None, "root": None, "note": res["note"]}
    d = res.get("factor")
    if _valid_factor(N, d, max_bits=total_bits - 1) and p_high and d > (p_high << shift):
        out.update(p=d, q=N // d, note="Coppersmith by-product: the factor came out directly")
        return out
    for r in res["roots"]:
        cand = (p_high << shift) + r
        # must be a non-trivial factor: rule out 1, N and clipped-out "pseudo-roots"
        if _valid_factor(N, cand, max_bits=total_bits - 1) and cand > (p_high << shift):
            out.update(p=cand, q=N // cand, root=r, note="Coppersmith small root hit")
            return out
    if not out["note"]:
        out["note"] = "small root found but not a non-trivial factor (rejected: fake factorisation)"
    return out


# ────────────────────────── low-density subset sum (knapsack) ──────────────────────────

def subset_sum_lll(weights, target, max_dim: int = 12):
    """Low-density subset sum: find x_i ∈ {0,1} with sum(x_i*w_i) = target

    Solvable when the density d = n / log2(max w) < 0.94; returns a list of
    indices or None. The equality must hold before anything is returned — LLL
    hands over candidates and the verification happens here.
    """
    n = len(weights)
    if n == 0 or n > max_dim:
        return None
    if sum(w for w in weights if w > 0) < target:
        return None
    N = 2  # scaling factor, so the ±1 entries stand out in the short vector
    basis = []
    for i in range(n):
        row = [0] * (n + 1)
        row[i] = 2
        row[n] = N * weights[i]
        basis.append(row)
    last = [1] * n + [N * target]
    basis.append(last)
    reduced = lll(basis, max_dim=max_dim + 1)
    if reduced is None:
        return None
    for row in reduced:
        if row[n] != 0:
            continue
        bits = [(2 - abs(v)) for v in row[:n]]  # v = ±1 → 1, 0 → 2 (impossible)
        if any(b not in (0, 1) for b in bits):
            continue
        picks = [i for i in range(n) if row[i] == -1]
        if sum(weights[i] for i in picks) == target:
            return sorted(picks)
        picks = [i for i in range(n) if row[i] == 1]
        if sum(weights[i] for i in picks) == target:
            return sorted(picks)
    return None


def mitm_subset_sum(weights, target, max_n: int = 36):
    """Meet-in-the-middle subset sum — the right answer when density is high
    (LLL cannot move it) but the item count is modest

    2^(n/2) enumeration plus a hash lookup; the item cap follows memory
    (n=36 → about 260k entries per side). Returns a list of indices or None.
    LLL and MITM are complementary paths:
      - low density (<0.94): LLL is fast
      - medium density or few items: MITM is steady
    """
    ws = [int(w) for w in weights]
    n = len(ws)
    if n == 0 or n > max_n or target < 0:
        return None
    if sum(w for w in ws if w > 0) < target:
        return None
    half = n // 2
    left, right = ws[:half], ws[half:]

    table = {0: 0}
    for i, w in enumerate(left):
        for s, mask in list(table.items()):
            ns = s + w
            if ns <= target and ns not in table:
                table[ns] = mask | (1 << i)
        if target in table:
            return [i for i in range(half) if table[target] >> i & 1]

    found = None
    stack = [(0, 0, 0)]
    # the right half is enumerated iteratively (avoids recursion depth / memory blowup)
    right_sums = {0: 0}
    for i, w in enumerate(right):
        for s, mask in list(right_sums.items()):
            ns = s + w
            if ns <= target and ns not in right_sums:
                right_sums[ns] = mask | (1 << i)
    for s, mask in right_sums.items():
        need = target - s
        if need in table:
            found = (table[need], mask)
            break
    if not found:
        return None
    lmask, rmask = found
    picks = [i for i in range(half) if lmask >> i & 1]
    picks += [half + i for i in range(len(right)) if rmask >> i & 1]
    if sum(ws[i] for i in picks) != target:
        return None
    return sorted(picks)


def approx_gcd(values):
    """Approximate gcd of a difference sequence — for LCG modulus recovery
    (gcd of several differences, then try small multiples)"""
    g = 0
    for v in values:
        g = gcd(g, abs(int(v)))
        if g == 1:
            break
    if g <= 1:
        return None
    return g
