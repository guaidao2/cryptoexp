"""RSA attack extensions - the lattice and oracle attacks that rsa_ops does not carry

    from cryptoexp.utils import rsa_attacks as RA
    RA.franklin_reiter(n, e, c1, c2, a, b)      # related messages m2 = a*m1 + b
    RA.hastad_padded(3, [(n1, c1, pad1), ...])  # Hstad with linear padding
    RA.stereotyped_message(n, e, c, b"flag{")   # partially known plaintext
    RA.parity_oracle_attack(n, e, c, oracle)    # LSB / parity oracle

Same convention as rsa_ops - every attack returns
    {"ok": bool, "plaintext": bytes|None, "detail": str,
     "factors": (p, q)|None, "d": int|None, "note": str}
so the analyser and the solve generator can consume it unchanged.

Honest failure is part of the contract: when an attack needs a parameter the
challenge does not give, it returns ok=False with a note that names exactly what
is missing. A guess is never reported as a success - every candidate plaintext
is confirmed by re-encryption (pow(m, e, n) == c) before it is returned.

Deliberately NOT duplicated here (already in rsa_ops, one implementation only):
    common_modulus_attack, wiener_attack (the small-d attack),
    broadcast_attack, small_e_attack, fermat_attack, shared_prime_attack,
    dp_leak_attack, phi_leak_attack, known_high_bits_attack.
"""

import time
from fractions import Fraction

from . import algebra as A
from . import lattice as L
from . import rsa_ops as R


# -------------------------- polynomial / packing helpers --------------------------

# lattice.lll refuses bases above this dimension, so every parameter ladder below
# stays inside it (a larger lattice would silently return no root).
_LATTICE_MAX_DIM = 12


def _poly_sub(a, b, mod=None):
    """Polynomial a - b (coefficient lists, lowest degree first)

    lattice carries the polynomial primitives (poly_mul / poly_pow / poly_trim);
    subtraction is the one operation it does not expose, so it lives here.
    """
    n = max(len(a), len(b))
    out = []
    for i in range(n):
        x = a[i] if i < len(a) else 0
        y = b[i] if i < len(b) else 0
        out.append((x - y) % mod if mod else x - y)
    return L.poly_trim(out)


def _binom(n: int, k: int) -> int:
    """Binomial coefficient (kept local so the module stays self-contained)"""
    if k < 0 or k > n:
        return 0
    k = min(k, n - k)
    num = 1
    for i in range(k):
        num = num * (n - i) // (i + 1)
    return num


def _as_bytes(x):
    """bytes-like or str -> bytes (str is utf-8 encoded)"""
    if isinstance(x, str):
        return x.encode("utf-8")
    return bytes(x)


def _parameter_ladder(degree: int, max_dim: int = _LATTICE_MAX_DIM):
    """Coppersmith (m, t) pairs, cheapest lattice first

    The lattice for a degree-d polynomial with parameters (m, t) has dimension
    d*m + t; lattice.lll gives up above max_dim without saying so loudly, hence
    the ordering: start with the smallest dimension that can plausibly work and
    only spend time on bigger lattices when the cheap ones found nothing.
    """
    combos = []
    for m in (2, 3, 4, 5, 6):
        for t in (1, 2, 3, 4, 5, 6):
            if degree * m + t <= max_dim:
                combos.append((m, t))
    combos.sort(key=lambda mt: (degree * mt[0] + mt[1], mt[0]))
    return combos


def _lattice_capacity(N: int, degree: int, m: int, t: int, margin_bits: int = 4) -> int:
    """Largest root bound the (m, t) Howgrave-Graham lattice can be expected to reach

    The lattice dimension is degree*m + t. From the standard determinant estimate
    the reachable bound is X ~ N^((2t + d*m - d) / (d*(d*m + t))); the margin
    absorbs the 2^((n-1)/4) * sqrt(n) constants of the LLL bound. Measured on a
    381-bit N with degree 3: (2,1) predicts 2^91 and 2^41 / 2^86 / 2^90 all found
    the root, while (2,2) predicts 2^111 and 2^41 missed but 2^107 / 2^111 hit -
    a bound far *below* the capacity is not more reliable, because the lattice
    scaling and the pairwise-gcd extraction both expect X near the root scale.
    """
    num = 2 * t + degree * m - degree
    den = degree * (degree * m + t)
    if num <= 0 or den <= 0:
        return 0
    cap = A.iroot(N ** num, den)[0]
    return cap >> margin_bits


def _coppersmith_attempts(poly, N: int, degree: int, root_bound: int = None,
                          time_budget=None, dim_ceiling: int = 11):
    """Try the (m, t) ladder, cheapest lattice first, until a root or factor shows up

    Args:
        root_bound: the caller's exclusive upper bound on the root. Dimensions
            whose capacity is below it are skipped (they cannot reach it), and
            within a usable dimension X = capacity is tried first with
            X = root_bound as the fallback.
    Returns:
        (result|None, info) with info = {"used": (m, t), "X": X, "attempts": n,
        "dims": [...], "note": str}
    """
    deadline = time.monotonic() + float(time_budget) if time_budget else None
    ladder = _parameter_ladder(degree, max_dim=dim_ceiling)
    dims_tried, last_note, skipped = [], "", 0
    attempts = 0
    for (m, t) in ladder:
        cap = _lattice_capacity(N, degree, m, t)
        if cap < 2:
            continue
        if root_bound is not None and cap < root_bound:
            skipped += 1
            continue
        xs = [cap]
        if root_bound and 2 <= root_bound < cap:
            # cap first: measurements show the near-capacity scale is the more
            # reliable one, and a hit on the first attempt is also the cheapest
            # overall even though a single big-X lattice costs more than a small-X one
            xs.append(int(root_bound))
        for X in xs:
            if deadline is not None and time.monotonic() > deadline:
                return None, {"used": None, "X": None, "attempts": attempts,
                              "dims": dims_tried,
                              "note": f"time budget {time_budget}s spent after "
                                      f"{attempts} lattice attempt(s)"}
            attempts += 1
            dims_tried.append(f"dim{degree * m + t}/X=2^{X.bit_length() - 1}")
            res = L.coppersmith_univariate(poly, N, X, m=m, t=t)
            if res.get("roots") or res.get("factor"):
                return res, {"used": (m, t), "X": X, "attempts": attempts,
                             "dims": dims_tried, "note": res.get("note", "")}
            last_note = res.get("note") or ""
    if skipped and root_bound is not None and ladder:
        top_m, top_t = ladder[-1]
        top_cap = _lattice_capacity(N, degree, top_m, top_t)
        last_note += (f"; {skipped} cheaper dimension(s) were too small to reach the "
                      f"bound {root_bound}, the largest usable one reaches about "
                      f"{top_cap.bit_length()} bits")
    return None, {"used": None, "X": None, "attempts": attempts, "dims": dims_tried,
                  "note": last_note or "no lattice parameter produced a small root"}


def _root_in_range(res, N: int):
    """Small roots from a Coppersmith result, plus the free factor when the
    lattice handed one over (a non-invertible coefficient factors N - the usual
    lucky by-product of Coppersmith on an RSA modulus)"""
    roots = [int(r) for r in (res.get("roots") or []) if 0 <= int(r) < N]
    factor = res.get("factor")
    if factor and 1 < factor < N and N % factor == 0:
        return roots, (factor, N // factor)
    return roots, None


# -------------------------- related-message attacks --------------------------

def franklin_reiter(n, e, c1, c2, a, b, max_degree: int = 12):
    """Franklin-Reiter related-message attack: m2 = a*m1 + b (mod n), so

        g1(x) = x^e - c1
        g2(x) = (a*x + b)^e - c2        (mod n)

    share the root x = m1. Their gcd over (Z/n)[x] is generically linear and the
    root can be read straight off it; the result is then confirmed by
    re-encryption. A non-invertible leading coefficient in the Euclidean chain
    returns a non-trivial factor of n instead, which is just as good a win.
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    n, e, c1, c2, a, b = int(n), int(e), int(c1), int(c2), int(a), int(b)
    if e < 2:
        return R._res(False, note=f"e={e} is not a valid public exponent")
    if e > max_degree:
        return R._res(False, note=f"polynomial degree e={e} is beyond the lattice "
                                  f"budget (max_degree={max_degree})")
    if n < 3 or n % 2 == 0:
        return R._res(False, note="n is even or degenerate - not an RSA modulus")

    # a shares a factor with n: factor n straight away, no polynomial gcd needed
    g = A.gcd(a % n, n)
    if 1 < g < n:
        p, q = g, n // g
        r = R.decrypt_with_factors(n, e, c1, p, q)
        if r["ok"]:
            r["detail"] = "franklin_reiter: gcd(a, n) is non-trivial, n factored directly"
            return r
        return R._res(False, factors=(p, q),
                      note="gcd(a, n) factors n, but e and phi are not coprime")

    g1 = [0] * (e + 1)
    g1[0] = (-c1) % n
    g1[e] = 1
    lin = [b % n, a % n]
    g2 = _poly_sub(L.poly_pow(lin, e), [c2 % n], n)

    kind, val = L._poly_gcd_mod(g1, g2, n)
    if kind == "factor":
        p = val
        q = n // p
        r = R.decrypt_with_factors(n, e, c1, p, q)
        if r["ok"]:
            r["detail"] = ("franklin_reiter: a non-invertible leading coefficient "
                           "in the polynomial gcd factored n")
            return r
        return R._res(False, factors=(p, q),
                      note="the polynomial gcd factors n, but e and phi are not "
                           "coprime - needs the special decoding case")
    if kind != "poly" or not val:
        return R._res(False, note="polynomial gcd failed in (Z/n)[x] "
                                  "(a coefficient is not invertible mod n)")

    if len(val) == 2:
        inv = A.modinv(val[1] % n, n)
        if inv is not None:
            m = (-val[0] * inv) % n
            if R.reencrypt_check(m, e, n, c1):
                note = "linear gcd root"
                m2 = (a * m + b) % n
                if R.reencrypt_check(m2, e, n, c2):
                    note = "linear gcd root, both ciphertexts re-encryption checked"
                return R._res(True, plaintext=R.itob(m),
                              detail=f"franklin_reiter: gcd(x^e - c1, (a*x+b)^e - c2) "
                                     f"is linear, m recovered (a={a}, b={b})",
                              note=note)
    if len(val) > 2:
        # Rare, but a higher-degree gcd can still carry an exact integer root
        for r in L._small_degree_int_roots(val):
            if 0 <= r < n and R.reencrypt_check(r, e, n, c1):
                return R._res(True, plaintext=R.itob(r),
                              detail=f"franklin_reiter: degree-{len(val) - 1} gcd, "
                                     f"integer root recovered")
    return R._res(False, note="gcd found but no root passed the re-encryption check "
                              "- check that m2 = a*m1 + b with these exact a, b and "
                              "that c1, c2 belong to the same modulus")


def hastad_padded(e, triples, bound=None, time_budget: float = 60.0):
    """Hstad broadcast with linear padding: c_i = (m + pad_i)^e mod n_i

    Args:
        e: public exponent (3 is the usual case; e triples are needed)
        triples: [(n_i, c_i, pad_i), ...]; pad_i is an int or bytes offset
        bound: exclusive upper bound on m; by default the theoretical
               floor(N^(1/e)) where N = prod(n_i)
        time_budget: seconds spent across the lattice parameter ladder

    How it works: CRT the coefficient vectors of the polynomials
    f_i(x) = (x + pad_i)^e - c_i (mod n_i) into one monic polynomial
    P(x) mod N = prod(n_i). Every f_i vanishes at x = m, so P(m) = 0 mod N and m
    is a small root of P. Coppersmith (Howgrave-Graham) finds roots below
    N^(1/e). The recovered m is accepted only when it satisfies every original
    congruence (pow(m + pad_i, e, n_i) == c_i) - the re-encryption check.
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    if e is None or int(e) < 2:
        return R._res(False, note=f"e={e} is not a valid public exponent")
    e = int(e)
    items = []
    for t in (triples or []):
        if len(t) != 3:
            return R._res(False, note="every triple must be (n_i, c_i, pad_i)")
        n_i, c_i, pad_i = t
        items.append((int(n_i), int(c_i),
                      R.btoi(_as_bytes(pad_i)) if isinstance(pad_i, (bytes, bytearray, str))
                      else int(pad_i)))
    if len(items) < e:
        return R._res(False, note=f"needs at least e={e} (n_i, c_i, pad_i) triples, "
                                  f"only {len(items)} given")
    items = items[:e]
    for n_i, _, _ in items:
        if n_i < 3 or n_i % 2 == 0:
            return R._res(False, note="one of the moduli is even or degenerate "
                                      "- not an RSA modulus")
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if A.gcd(items[i][0], items[j][0]) != 1:
                return R._res(False, note=f"n{i + 1} and n{j + 1} are not coprime: the "
                                          f"CRT step is undefined - use "
                                          f"rsa_ops.shared_prime_attack instead")

    N = 1
    for n_i, _, _ in items:
        N *= n_i

    # Cheap exact path first: if m + pad_i stays below every modulus there is no
    # modular reduction to undo, so c_i is an exact e-th power and m is an integer
    # root. That is the common CTF shape (a short message under big moduli) and it
    # costs one integer root per triple, so try it before any lattice work.
    for n_i, c_i, pad_i in items:
        root, exact = A.iroot(c_i, e)
        if not exact:
            break
        candidate = root - pad_i
        if candidate <= 0 or candidate >= n_i:
            break
        if all(pow(candidate + p, e, nn) == cc for nn, cc, p in items):
            return R._res(True, plaintext=R.itob(candidate), factors=None,
                          detail=f"Hastad (e={e}): no reduction mod n_i happened, so "
                                 f"the message is an exact integer {e}-th root; "
                                 f"verified against all {len(items)} congruences",
                          note="re-encryption checked against every c_i")

    # CRT the coefficients: coefficient k of (x + pad)^e - c is C(e,k)*pad^(e-k)
    coeffs = []
    for k in range(e + 1):
        residues = []
        for n_i, c_i, pad_i in items:
            if k == 0:
                v = (pow(pad_i, e, n_i) - c_i) % n_i
            else:
                v = (_binom(e, k) * pow(pad_i, e - k, n_i)) % n_i
            residues.append((v, n_i))
        crt = A.crt(residues)
        if not crt:
            return R._res(False, note="coefficient CRT failed (moduli not pairwise coprime)")
        coeffs.append(crt[0])
    poly = L.poly_trim([c % N for c in coeffs])
    if len(poly) != e + 1 or poly[-1] != 1:
        return R._res(False, note="the combined polynomial did not come out monic "
                                  f"(leading coefficient {poly[-1] if poly else 0})")

    # Coppersmith ladder. The bound is what makes or breaks this: the lattice has
    # to be scaled near the root magnitude, so when the caller gives no bound each
    # dimension is tried at its own computed capacity (_lattice_capacity) instead
    # of the useless theoretical floor(N^(1/e)) - measured on a 767-bit N with a
    # 64-bit root, X = floor(N^(1/e)) failed at every dimension the pure-Python
    # LLL can afford, while X near the capacity found it.
    res, info = _coppersmith_attempts(poly, N, e, root_bound=bound,
                                      time_budget=time_budget)
    if res is None:
        return R._res(False,
                      note=f"no small root found after {info['attempts']} lattice "
                           f"attempt(s) [{', '.join(info['dims']) or 'none'}]; "
                           f"{info['note']}. The pure-Python lattice (dimension <= 11) "
                           f"reaches roughly {A.iroot(N, e)[0].bit_length()} bits at "
                           f"most for this N; the message must be small enough that "
                           f"m + pad_i stays below n_i, and a wrong pad_i breaks it "
                           f"silently - pass bound=<exact message bound> to spend the "
                           f"budget on the right scale")
    roots, factor = _root_in_range(res, N)
    for r in roots:
        if all(pow(r + pad_i, e, n_i) == c_i % n_i for n_i, c_i, pad_i in items):
            detail = (f"hastad_padded: {e} padded congruences CRT'd into one monic "
                      f"degree-{e} polynomial mod {N.bit_length()}-bit N, small root "
                      f"recovered by Coppersmith (lattice (m,t)={info['used']}, "
                      f"X=2^{info['X'].bit_length() - 1})")
            if factor:
                detail += "; the lattice also factored one modulus"
            return R._res(True, plaintext=R.itob(r), detail=detail,
                          factors=factor, note="all e congruences re-checked")
    if factor:
        return R._res(False, factors=factor,
                      note="the lattice produced a non-trivial factor of one modulus, "
                           "but no verified padded root - feed the factor to "
                           "rsa_ops.decrypt_with_factors")
    return R._res(False,
                  note=f"the lattice returned {len(roots)} candidate root(s) in "
                       f"{info['attempts']} attempt(s), none satisfying "
                       f"(m + pad_i)^e == c_i mod n_i for all i; check that the pads "
                       f"really are the offsets used for encryption")


def stereotyped_message(n, e, c, known_prefix, known_suffix=b"", bound=None,
                        max_unknown_bytes: int = 8, time_budget: float = 60.0):
    """Coppersmith for a partially known plaintext

        m = known_prefix || x || known_suffix     (x is the unknown field)

    With y = x * 2^(8*len(known_suffix)) the message becomes m = A + y with
    A = prefix << (8*(L + len(suffix))) + suffix, so

        f(y) = (y + A)^e - c   (mod n)

    is monic of degree e and has the small root y0 = x << shift. Coppersmith
    finds y0 when y0 < n^(1/e); the plaintext is accepted only after
    pow(m, e, n) == c, i.e. a re-encryption check, never on the polynomial
    alone.

    Args:
        known_prefix: bytes (or str) preceding the unknown field
        known_suffix: bytes (or str) following the unknown field
        bound: exclusive upper bound on the unknown integer x. Also fixes the
               width L of the unknown field: L = ceil(bit_length(bound)/8)
               (pass bound=256**L for an exactly L-byte field).
               When None, L is searched from 1 to max_unknown_bytes with
               bound = 1 << (8*L).
        max_unknown_bytes: only used when bound is None
        time_budget: seconds spent across all attempts
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    try:
        n, e, c = int(n), int(e), int(c)
    except (TypeError, ValueError):
        return R._res(False, note="n, e, c must be integers")
    prefix = _as_bytes(known_prefix)
    suffix = _as_bytes(known_suffix)
    if e < 2:
        return R._res(False, note=f"e={e} is not a valid public exponent")
    if n < 3 or n % 2 == 0:
        return R._res(False, note="n is even or degenerate - not an RSA modulus")

    if bound is not None:
        X0 = int(bound)
        if X0 < 2:
            return R._res(False, note=f"bound={bound} is too small to hold an unknown field")
        attempts_list = [(X0, max(1, (X0.bit_length() + 7) // 8))]
    else:
        attempts_list = [(1 << (8 * span), span)
                         for span in range(1, max(1, int(max_unknown_bytes)) + 1)]

    deadline = time.monotonic() + float(time_budget) if time_budget else None
    shift = 8 * len(suffix)
    suffix_int = R.btoi(suffix)
    prefix_int = R.btoi(prefix)

    # Cheap exact path first: when the whole candidate plaintext stays below n there
    # is no modular reduction to undo, so c is an exact e-th power and the unknown
    # field comes straight out of an integer root. This is the usual CTF shape
    # (short message, big modulus) and it is instant - no lattice required.
    # Every candidate width is tried, not just the one the bound implies: a caller
    # passing an over-generous bound must not lose the short unknown field.
    max_span = (max(1, (int(bound).bit_length() + 7) // 8) if bound is not None
                else max(1, int(max_unknown_bytes)))
    for span in range(1, max_span + 1):
        width = 1 << (8 * span)
        X = min(width, int(bound)) if bound is not None else width
        # A_ places the unknown field at its shifted position: the message is
        # m = A_ + (x << shift) with x < X, so the bound applies *before* the shift.
        # NB: the shift needs its own parentheses -- `a << n + b` parses as
        # `a << (n + b)`, which silently builds a gigantic constant instead.
        A_ = (prefix_int << (8 * (span + len(suffix)))) + suffix_int
        top = A_ + (X << shift)
        if pow(top, e) >= n:
            continue
        root, exact = A.iroot(c, e)
        if not exact or root < A_ or root >= top:
            continue
        out = R.itob(root)
        if len(out) != len(prefix) + span + len(suffix):
            continue
        if out.startswith(prefix) and out.endswith(suffix):
            return R._res(True, plaintext=out, factors=None,
                          detail=f"stereotyped_message: no reduction mod n happened, so "
                                 f"the plaintext is an exact integer {e}-th root "
                                 f"(unknown field {span} byte(s), no lattice needed)",
                          note="re-encryption checked against c")

    tried, lattice_notes = [], []
    # NB: the loop variable must not be called `L` -- `L` is the lattice module alias
    # here, and shadowing it made `L.poly_pow` raise AttributeError on every call.
    for (X, span) in attempts_list:
        A_ = prefix_int << (8 * (span + len(suffix)))
        constant = A_ + suffix_int
        Y = X << shift
        tried.append(f"span={span} (bound={X})")
        if Y >= n:
            lattice_notes.append(f"span={span}: bound {Y.bit_length()} bits >= n, impossible")
            continue
        if deadline is not None and time.monotonic() > deadline:
            break
        remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
        f = _poly_sub(L.poly_pow([constant % n, 1], e), [c % n], n)
        res, info = _coppersmith_attempts(f, n, e, root_bound=Y, time_budget=remaining)
        if res is None:
            lattice_notes.append(f"span={span}: {info['note']}")
            continue
        used = info["used"]
        roots, factor = _root_in_range(res, n)
        for r in roots:
            if shift and r % (1 << shift):
                continue
            x = r >> shift
            if x >= X:
                continue
            m = constant + r
            if m <= 0 or m >= n or not R.reencrypt_check(m, e, n, c):
                continue
            out = R.itob(m)
            if suffix and not out.endswith(suffix):
                continue
            detail = (f"stereotyped_message: unknown field of {span} byte(s) recovered by "
                      f"Coppersmith (lattice (m,t)={used}); prefix "
                      f"{len(prefix)}B + unknown {span}B + suffix {len(suffix)}B")
            if factor:
                detail += "; the lattice also produced a factor of n"
            return R._res(True, plaintext=out, detail=detail, factors=factor,
                          note="re-encryption checked against c")
        lattice_notes.append(f"span={span}: {res.get('note') or 'no root'}")
        if factor:
            return R._res(False, factors=factor,
                          note="Coppersmith factored n, but no verified plaintext came "
                               "out - use rsa_ops.decrypt_with_factors with this factor")

    # Nothing verified: say exactly what was assumed and what is missing
    top_m, top_t = _parameter_ladder(e, max_dim=11)[-1]
    reach = _lattice_capacity(n, e, top_m, top_t).bit_length()
    return R._res(False,
                  note=f"no verified plaintext; tried [{' | '.join(tried)}]. "
                       f"The unknown field sits {shift} bits above the suffix, so the "
                       f"lattice root is bounded by the dimension capacity, not by "
                       f"n^(1/e): the pure-Python LLL (dimension <= 11) reaches about "
                       f"{reach} bits here, and the prefix/suffix must be byte-exact; "
                       f"lattice details: "
                       f"{'; '.join(lattice_notes[-3:]) or 'no attempt completed'}")


# -------------------------- oracle attacks --------------------------

def parity_oracle_attack(n, e, c, oracle, max_iter: int = None):
    """LSB / parity oracle attack - a mechanical, fully bounded attack

    oracle(ciphertext_int) -> the least significant bit of the decrypted
    plaintext. The attack never needs d: multiplying the ciphertext by 2^e mod n
    makes the plaintext 2*m mod n, whose parity is the next bit of m/n. The
    intervals [lo, hi) halve each query, so after about n.bit_length() queries
    only m remains.

    Args:
        max_iter: query cap; defaults to n.bit_length() + 2 (and is hard-capped
                  at 8192 so a hostile oracle cannot spin forever)

    The result is confirmed by re-encryption; an oracle that answers for a
    padded plaintext, for the wrong ciphertext, or inconsistently yields
    ok=False with a note saying so.
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    n, e, c = int(n), int(e), int(c)
    if e < 1:
        return R._res(False, note=f"e={e} is not a valid public exponent")
    if n < 3 or n % 2 == 0:
        return R._res(False, note="n is even or degenerate - a parity oracle over an "
                                  "even modulus has no RSA structure")
    if not callable(oracle):
        return R._res(False, note="oracle must be callable: oracle(ciphertext_int) -> LSB bit")
    steps = int(max_iter) if max_iter else n.bit_length() + 2
    if steps < 1:
        return R._res(False, note=f"max_iter={max_iter} leaves no query budget")
    if steps > 8192:
        steps = 8192

    # The interval has to be exact: with integer midpoints the floor bias accumulates
    # (measured: the interval drifted off the true plaintext by a few units after
    # ~250 queries and the attack then failed on a 256-bit modulus). Fractions keep
    # the halves exact, so the observed parity bits always bisect correctly.
    lo, hi = Fraction(0), Fraction(n)
    cur = c % n
    two_e = pow(2, e, n)
    queries = 0
    try:
        for _ in range(steps):
            cur = cur * two_e % n
            bit = 1 if oracle(cur) else 0
            queries += 1
            mid = (lo + hi) / 2
            if bit:
                lo = mid
            else:
                hi = mid
            if hi - lo <= 1:
                break
    except Exception as exc:  # an oracle that dies is an honest failure, not a crash
        return R._res(False, note=f"the oracle raised {type(exc).__name__}: {exc} "
                                  f"(after {queries} queries)")

    candidates = []
    for m in (-(-lo.numerator // lo.denominator), hi.numerator // hi.denominator,
              -(-lo.numerator // lo.denominator) + 1, lo.numerator // lo.denominator):
        if 0 <= m < n and m not in candidates:
            candidates.append(int(m))
    for m in candidates:
        if R.reencrypt_check(m, e, n, c):
            return R._res(True, plaintext=R.itob(m),
                          detail=f"parity/LSB oracle: {queries} queries, interval "
                                 f"shrunk to [{lo}, {hi}]",
                          note="re-encryption checked against c")
    return R._res(False,
                  note=f"{queries} queries left [{lo}, {hi}] with no candidate that "
                       f"re-encrypts to c; the oracle must be the LSB of the "
                       f"decryption of exactly the integer it is handed (a 0/1 "
                       f"answer for a padded plaintext gives a different bit)")


# lsb_oracle_attack is the other common name for the same attack
lsb_oracle_attack = parity_oracle_attack


# -------------------------- documented skeleton --------------------------

def bleichenbacher_note() -> dict:
    """Not an attack - the documented requirements of the Bleichenbacher
    PKCS#1 v1.5 padding-oracle attack, and why this module ships no solver

    A real Bleichenbacher (1998) attack needs a *padding validity oracle*: a
    black box that answers yes/no to "does this ciphertext decrypt to a
    plaintext whose first two bytes are 0x00 0x02". That is a different oracle
    from parity_oracle_attack (which leaks one bit of the plaintext) and it
    cannot be simulated from public parameters alone.

    The attack itself is mechanical but long: roughly 2^16 initial interval
    narrowing queries, then about a thousand further queries per candidate
    interval, plus a search converging on the plaintext; every query is one call
    to a remote service. So it is written as a skeleton - the caller supplies
    the oracle and drives the loop, and this function only records what that
    loop needs. Returning a guess from no oracle would be a lie, hence
    ok=False.

    Returns the standard result dict plus: requires, steps, why_skeleton,
    references (all English strings).
    """
    return R._res(
        False,
        detail="Bleichenbacher PKCS#1 v1.5 padding-oracle attack: documented skeleton only",
        note="no attack was run: this function describes requirements, it does not solve",
        **{
            "is_attack": False,
            "name": "bleichenbacher_pkcs1_v1_5_padding_oracle",
            "requires": [
                "the RSA public key (n, e) and the target ciphertext c",
                "a padding oracle: validity of the PKCS#1 v1.5 block 0x00 0x02 ... "
                "after decryption, answering for ciphertexts of the caller's choosing",
                "a query budget (thousands to tens of thousands of adaptive queries) "
                "and, for the final phase, a candidate plaintext ordering",
                "the modulus must be at least 11 bytes shorter than the message slot "
                "(k >= 11) for the padding block to exist at all",
            ],
            "steps": [
                "1. find s_1 with c * s_1^e mod n accepted by the oracle (about 2^16 tries)",
                "2. narrow the interval [a, b] for m * s mod n using the accepted range "
                "of PKCS#1 conforming products",
                "3. search the next s_i that keeps the interval consistent (about 1e3 "
                "queries per turn)",
                "4. repeat until a == b, then m = a * s_i^-1 mod n",
                "5. confirm by re-encryption: pow(m, e, n) == c",
            ],
            "why_skeleton": [
                "nothing in the ciphertext, (n, e) or the padding scheme reveals "
                "whether a decryption was PKCS#1 conforming - the oracle lives in the "
                "target (a server, a timing channel, a decryption log)",
                "the loop is adaptive and query-driven: every step depends on the "
                "oracle's previous answer, so it cannot be precomputed offline",
                "a full implementation is only testable against a simulated oracle, "
                "which would verify the simulation and not the target",
                "Manger's attack (OAEP, oracle 'is the plaintext >= 2^(k-1)') has the "
                "same shape and the same requirement: one oracle call per step",
            ],
            "references": [
                "Bleichenbacher, 'Chosen Ciphertext Attacks Against Protocols Based on "
                "the RSA Encryption Standard PKCS #1', CRYPTO 1998",
                "RFC 8017 (PKCS#1 v2.2), section 7.2.2 for the EME-PKCS1-v1_5 layout",
                "Manger, 'A Chosen Ciphertext Attack on RSA Optimal Asymmetric "
                "Encryption Padding (OAEP)', CRYPTO 2001",
            ],
        })


# -------------------------- key-material helper --------------------------

def rsa_recover_d_from_factors(n, e, p, q):
    """d from the factorisation: d = e^-1 mod phi(n), or None when it does not exist

    phi = (p-1)(q-1); for the degenerate n = p^2 case phi = p(p-1). The factors
    are validated (p*q == n, both > 1) before anything is computed, and None is
    returned - never a made-up exponent - when gcd(e, phi) != 1.
    """
    n, e, p, q = int(n), int(e), int(p), int(q)
    if p <= 1 or q <= 1 or p * q != n:
        return None
    if p == q:
        phi = p * (p - 1)
    else:
        phi = (p - 1) * (q - 1)
    return A.modinv(e, phi)


__all__ = [
    "franklin_reiter",
    "hastad_padded",
    "stereotyped_message",
    "parity_oracle_attack",
    "lsb_oracle_attack",
    "bleichenbacher_note",
    "rsa_recover_d_from_factors",
]
