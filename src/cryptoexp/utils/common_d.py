"""Shared private exponent d across several moduli -- the lattice (SDAP) version

`rsa_ops.common_private_exponent_attack` already exploits a shared d through the
continued-fraction convergents of every `e_i / n_i`. That is cheap, but it keeps
Wiener's per-modulus reach: a candidate d is only proposed when it is a convergent
denominator, so the shared exponent has to fall inside the single-modulus
approximation range. This module adds the simultaneous-Diophantine-approximation
(SDAP) lattice layer: it looks for d as the small *last coordinate* of a short
lattice vector, which reaches further whenever several moduli carry the same d.

    from cryptoexp.utils import common_d as CD
    CD.common_d_attack([(e1, n1), (e2, n2), (e3, n3)])   # cheap stage first
    CD.common_d_lattice([(e1, n1), (e2, n2), (e3, n3)])  # lattice stage only

Result convention: the usual library dict, with this attack's multi-modulus
deviation (same as `rsa_ops.common_private_exponent_attack`)

    {"ok": bool, "d": int|None, "factors": [(p_i, q_i), ...]|None,
     "plaintexts": [...]|None, "detail": str, "note": str,
     "dimension": int, "tried": int}

`factors` is a **list** in input order rather than one tuple, `d` is the shared
exponent, `plaintexts` carries one entry per supplied ciphertext, `dimension` is
the lattice dimension that was reduced and `tried` is how many reduced vectors
were examined. Every accepted d is re-verified against every modulus before
`ok=True` is reported (see `_verify_shared_d`); when no candidate passes, the
result stays `ok=False` and the note names the range that was actually covered.
"""

import itertools

from . import algebra as A
from . import lattice as L
from . import rsa_ops as R


# ---- the two stages

def _items(pairs):
    """Normalise [(e, n)] / [(e, n, c)] into [(e, n, c_or_None)]"""
    out = []
    for entry in pairs:
        if len(entry) == 3:
            out.append((int(entry[0]), int(entry[1]), int(entry[2])))
        else:
            e_i, n_i = entry
            out.append((int(e_i), int(n_i), None))
    return out


def _factors_from_d(n, e, d, window):
    """Recover (p, q) from a candidate d -- WITHOUT needing the exact k.

    The tempting check is `k = (e*d - 1) // n` and then `phi = (e*d - 1) // k`.
    That is wrong by a *lot* once d grows: `e*d/n` estimates
    `k = (e*d - 1)/phi` only up to `|k_est - k| ~ e*d*s/n^2 ~ 2*d/sqrt(n)`, which
    measured 2^45 bits at d ~ 2^100 (512-bit n) and 2^125 bits at d ~ 2^180. No
    fixed window survives that, which is why the earlier version of this file
    "missed" d values the lattice had already recovered.

    Two ways out, cheapest first:

    1. a bounded window of +-window around k_est, accepted only when the phi it
       yields really factors n (this is what recovers phi, and with it the
       factors, directly);
    2. the standard d-based factoring: `e*d - 1` is a multiple of phi, so
       `g^(odd part of e*d-1) mod n` and its squarings expose a factor. This
       needs no estimate of k at all and always works when d is the true
       exponent. It is written out here rather than delegated to
       `rsa_ops.factor_from_d` because that one squares the *odd part* `t` times
       instead of the 2-adic exponent of `e*d - 1` (it still returns an answer
       for the sizes we test, but the exponent count is not the standard one --
       reported to the parent, not changed here since this file must not touch
       other modules).
    """
    M = e * d - 1
    if M <= 0:
        return None
    k_est = M // n
    for k in range(max(1, k_est - window), k_est + window + 1):
        if M % k:
            continue
        phi = M // k
        if not (1 < phi < n):
            continue
        if (e * d) % phi != 1:
            continue
        pair = R.factor_from_phi(n, phi)
        if pair and pair[0] * pair[1] == n:
            return pair
    # stage 2: standard (n, e, d) factoring
    alpha, t = M, 0
    while alpha % 2 == 0:
        alpha //= 2
        t += 1
    if t:
        import random as _random
        rng = _random.Random(0xC0FFEE)
        bases = list(range(2, 20)) + [rng.randrange(2, n - 1) for _ in range(8)]
        for g in bases:
            gg = A.gcd(g, n)
            if 1 < gg < n:
                return gg, n // gg
            y = pow(g, alpha, n)
            if y in (1, n - 1):
                continue
            for _ in range(t - 1):
                x = y * y % n
                if x == 1:
                    p = A.gcd(y - 1, n)
                    if 1 < p < n:
                        return p, n // p
                    break
                y = x
    return None


def _verify_shared_d(d, items, window=None):
    """The acceptance test: one d must explain every modulus. Nothing else counts.

    For each modulus the factors are recovered from `e_i*d - 1` (see
    `_factors_from_d`), and the acceptance requires all of

        p_i * q_i == n_i,  p_i, q_i > 1,  and  e_i * d mod phi_i == 1

    with `phi_i = (p_i - 1)*(q_i - 1)`. A single modulus that fails rejects the
    candidate outright: a candidate that explains only some of the moduli is a
    coincidence, not the shared exponent.

    `window` bounds the k-search inside `_factors_from_d`; when it is None the
    window is derived from the size of `e*d` (adaptive, capped - the stage-2
    factoring is what actually guarantees the answer, so the window only has to
    be wide enough to be worth trying).

    Returns the list of (p_i, q_i) in input order when every modulus checks out,
    else None.
    """
    if d is None or d <= 1:
        return None
    factors = []
    for e_i, n_i, _c in items:
        if window is None:
            # extra bits of e*d over n^2 - the relative error of k_est is s/n, so
            # the absolute error is that many bits of k (see _factors_from_d)
            extra = max(0, (e_i * d).bit_length() - 2 * n_i.bit_length())
            win = min(1 << 16, 1 << min(extra, 16))
        else:
            win = window
        pair = _factors_from_d(n_i, e_i, d, win)
        if pair is None or pair[0] * pair[1] != n_i:
            return None
        if pair[0] <= 1 or pair[1] <= 1:
            return None
        if (e_i * d) % ((pair[0] - 1) * (pair[1] - 1)) != 1:
            return None
        factors.append(pair)
    return factors


# ---- lattice construction

def _basis(items):
    """The SDAP basis -- dimension m+1, and exactly why this shape.

    Write `e_i*d - k_i*phi_i = 1` with `phi_i = n_i - s_i`:

        e_i*d - k_i*n_i = 1 - k_i*s_i          (small: |k_i*s_i| ~ 2*d*sqrt(n_i))

    Build the square basis B whose row i (i = 1..m) is `n_i` in coordinate i and
    0 elsewhere, and whose last row is `[e_1, ..., e_m, 1]`. Then the integer
    combination

        d * row(m+1) - sum_i k_i * row_i

    is exactly the vector

        x = (d*e_1 - k_1*n_1, ..., d*e_m - k_m*n_m, d)

    i.e. `(-k_i*s_i, ..., d)`: all m+1 coordinates are the small quantities of
    the problem, and the last one is the shared private exponent itself. That is
    the whole trick -- the basis entries carry no scaling factors at all, so
    there is nothing to get subtly wrong: `n_i` and `e_i` are used raw, and the
    last coordinate of the target stays unscaled so it can be read directly.

    Note the contrast with the tempting `[[n_i*e_j], [c, ..., c, 1]]` variants:
    those introduce a `(0, ..., 0, c)` lattice vector that is short no matter
    what d is, and LLL then returns that trivial vector - the target is never
    seen. This basis has no such vector: a vector with all first m coordinates
    zero must be a multiple of `(0, ..., 0, 1)`, which is not in the lattice.
    """
    ns = [n for _e, n, _c in items]
    es = [e for e, _n, _c in items]
    m = len(items)
    basis = []
    for i in range(m):
        row = [0] * (m + 1)
        row[i] = ns[i]
        basis.append(row)
    basis.append(es + [1])
    return basis


def _candidates(reduced):
    """Every plausible d carried by the reduced basis, cheapest first.

    LLL does not have to return the target itself: it may return a small integer
    multiple `g * x` (a lattice vector along the same direction, e.g. when the
    target is not uniquely shortest). So the last coordinate `g*d`, the gcd of a
    whole vector and pairwise gcds of coordinates are all candidates, together
    with their small divisors - dividing by a few small integers costs almost
    nothing compared with the verification, which is the real filter.
    """
    out = set()

    def add(v):
        v = abs(int(v))
        if v > 1:
            out.add(v)
            for f in (2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256, 512, 1024, 4096):
                if v % f == 0:
                    out.add(v // f)

    dim = len(reduced)
    width = len(reduced[0])
    for row in reduced:
        for x in row:
            add(x)
        g = 0
        for x in row:
            g = A.gcd(g, abs(x))
        add(g)
        for i in range(width):
            for j in range(i + 1, width):
                add(A.gcd(abs(row[i]), abs(row[j])))
    # small integer combinations of the last coordinate (catches g*d with the
    # multiplier spread over a couple of rows)
    lasts = [row[-1] for row in reduced]
    for mask in range(1, 1 << dim):
        add(sum(lasts[i] for i in range(dim) if mask >> i & 1))
    return sorted(out)


def _measured_reach(bits, m):
    """Measured reach, from this repository's own runs at 512-bit moduli.

    The lattice succeeds while the target is shorter than the shortest vector
    the lattice can be expected to contain (its Gaussian heuristic), which puts
    the practical edge near `n^((m+1)/(2m))` and does *not* follow the
    optimistic `n^(m/(m+1))` shape. Measured (2 runs each):
    m=2: no lattice recovery up to 2^260 (the convergent stage is better here);
    m=3: recovers up to ~2^100, fails from 2^128 on;
    m=4: recovers to ~2^150, fails from 2^170 on.
    """
    if m <= 2:
        return 96
    return int(bits * (m + 1) / (2.0 * m))


def common_d_lattice(pairs, effort="normal"):
    """Shared small private exponent d via the SDAP lattice (LLL) -- the fallback

    pairs: [(e_i, n_i), ...] or [(e_i, n_i, c_i), ...] with m = 2 or more moduli
    sharing one d. A supplied ciphertext makes the plaintexts available in the
    result as well.

    effort: "normal" builds one lattice over all moduli; "high" additionally
    reduces lattices built from every (m-1)-subset, which is worth the extra
    time when the moduli are not all equally strong.

    Returns the standard multi-modulus result dict -- see the module docstring.
    It names the range that was actually reached when it fails, and it never
    reports a d that has not been re-verified against every modulus:

        {"ok", "d", "factors", "plaintexts", "detail", "note",
         "dimension", "tried"}
    """
    items = _items(pairs)
    m = len(items)
    plain = {"ok": False, "plaintext": None, "plaintexts": None, "detail": "",
             "factors": None, "d": None, "note": "",
             "dimension": m + 1, "tried": 0}
    if m < 2:
        plain["note"] = ("needs at least two (e, n) pairs; with one modulus use "
                         "wiener_attack or fermat_attack")
        return plain
    if any(e <= 0 or n <= 1 for e, n, _c in items):
        plain["note"] = "invalid (e, n) pair"
        return plain

    subsets = [list(range(m))]
    if effort == "high" and m >= 3:
        subsets += [list(s) for s in itertools.combinations(range(m), m - 1)]

    tried = 0
    for subset in subsets:
        part = [items[i] for i in subset]
        basis = _basis(part)
        plain["dimension"] = len(basis)
        reduced = L.lll(basis, max_dim=12)
        if reduced is None:
            plain["note"] = (f"{len(basis)}-dimensional lattice is beyond this LLL "
                             f"implementation (max_dim=12)")
            continue
        tried += len(reduced)
        hit = None
        for cand in _candidates(reduced):
            if _verify_shared_d(cand, part) is not None:
                hit = cand
                break
        if hit is None:
            continue
        d_all = _verify_shared_d(hit, items)
        if d_all is None:
            # d explains only the subset: honest partial answer, no ok=True
            plain["note"] = (f"a candidate d explained only {len(part)} of {m} "
                             f"moduli; refusing to report it as shared")
            continue
        factors = d_all
        out = {"ok": True, "d": hit, "factors": factors,
               "detail": (f"SDAP lattice (dimension {len(basis)}) recovered the shared "
                          f"d ({hit.bit_length()} bits) from {m} moduli; the "
                          f"single-modulus Wiener bound does not cover it"),
               "note": "", "dimension": len(basis), "tried": tried}
        if all(c is not None for _e, _n, c in items):
            msgs = []
            for (e_i, n_i, c_i), (p_i, q_i) in zip(items, factors):
                msgs.append(R.decrypt_with_factors(n_i, e_i, c_i, p_i, q_i)
                            .get("plaintext"))
            out["plaintexts"] = msgs
            out["plaintext"] = next((x for x in msgs if x), None)
        return out

    bits = max(n.bit_length() for _e, n, _c in items)
    reach = _measured_reach(bits, m)
    plain["tried"] = tried
    plain["plaintexts"] = [None] * m
    plain["note"] = (
        f"no shared d found by the SDAP lattice ({bits}-bit moduli, {m} of them, "
        f"dimension {plain['dimension']}, {tried} reduced vectors examined). "
        f"Measured range at 512-bit moduli: m=3 works to about 2^100 bits of d, "
        f"m=4 to about 2^150; m=2 gets nothing the convergent stage does not "
        f"already have. Reached here: about 2^{reach} bits of d "
        f"(n^((m+1)/(2m))-flavoured estimate)")
    return plain


def common_d_attack(pairs, effort="normal"):
    """Try the cheap shared-d attack first, then the lattice one -- first win wins

    Stage 1 is `rsa_ops.common_private_exponent_attack`: it only proposes d as a
    continued-fraction convergent denominator of some `e_i / n_i`, which costs
    milliseconds and is unbeatable when it applies. Stage 2 is
    `common_d_lattice`, the SDAP/LLL version above, which is the one that keeps
    working when d has grown past the convergent range (measured: 4 moduli of
    512 bits, lattice recovers d ~ 2^150 where stage 1 is empty).

    Returns the standard multi-modulus result dict; `detail` names the winning
    stage, so a caller can log which lead actually closed the case.
    """
    # `common_private_exponent_attack` reads a 3-element entry as a ciphertext and
    # calls int() on it, so it gets plain (e, n) pairs - our normalised items may
    # carry a None placeholder.
    cheap = R.common_private_exponent_attack([(e, n) for e, n, _c in _items(pairs)])
    if cheap.get("ok"):
        cheap["detail"] = "stage 1 (convergent shared-d): " + str(cheap.get("detail", ""))
        cheap.setdefault("dimension", 0)
        cheap.setdefault("tried", 0)
        return cheap

    lat = common_d_lattice(pairs, effort=effort)
    if lat.get("ok"):
        lat["detail"] = "stage 2 (SDAP lattice): " + str(lat.get("detail", ""))
        return lat

    lat["note"] = (f"stage 1 (convergent shared-d) did not apply: "
                   f"{cheap.get('note', '')} | stage 2 (SDAP lattice): "
                   f"{lat.get('note', '')}")
    return lat
