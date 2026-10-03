"""RSA primitives and attack library — importable directly as infrastructure

    from cryptoexp import rsa_ops as R
    k = R.keygen(1024)
    R.decrypt(c, k['d'], k['n'])   # decrypt(c, d, n) - the ciphertext comes first
    R.wiener_attack(e, n)          # → result dict

Convention: every attack_* returns the same structure
    {"ok": bool, "plaintext": bytes|None, "detail": str,
     "factors": (p, q)|None, "d": int|None, "note": str}
Both the analyser and the solve generator consume this structure — one
implementation, two consumers.

Every public attack repeats that contract in its own docstring, because `help(fn)`
shows only the function's docstring and never this module header (a user hit exactly
that: the returned dict was mistaken for the plaintext).
"""

import random

from . import algebra as A
from . import lattice as L


_RESULT_KEYS = '{"ok", "plaintext", "detail", "factors", "d", "note"}'

_MIXUP_HINT = (
    " If this value came from an attack function, it is the result dict: read "
    "result['plaintext'] (bytes), or result['factors']/result['d'] for the "
    "factor-based attacks. Contract: " + _RESULT_KEYS
)


def itob(x: int) -> bytes:
    """int → big-endian bytes (0 → b'\\x00')

    Attack functions return the standard result dict, not an integer, so handing one
    of those here is a common mix-up. It is rejected with a message that names the
    fix, instead of failing later inside `x.to_bytes` with an opaque type error
    (reported by a user solving RSA tasks, 2026-10-03).
    """
    if isinstance(x, bool) or not isinstance(x, int):
        raise TypeError(f"itob/long_to_bytes expects an int, got {type(x).__name__}."
                        + _MIXUP_HINT)
    if x < 0:
        raise ValueError("negative number")
    return b'\x00' if x == 0 else x.to_bytes((x.bit_length() + 7) // 8, 'big')


def btoi(b: bytes) -> int:
    """bytes → big-endian int (the inverse of `itob`)"""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        raise TypeError(f"btoi/bytes_to_long expects bytes, got {type(b).__name__}."
                        + _MIXUP_HINT)
    return int.from_bytes(bytes(b), 'big')


# pwntools-style aliases, so code can be moved over as it is
long_to_bytes = itob
bytes_to_long = btoi


def _res(ok=False, **kw):
    """Build the standard result structure every attack returns

    The contract, in one place so it cannot drift:

        {"ok": bool,              # did the attack succeed
         "plaintext": bytes|None, # the answer, when the attack yields plaintext
         "detail": str,           # how it was obtained
         "factors": (p, q)|None,  # factor-based attacks
         "d": int|None,           # key-recovery attacks
         "note": str}             # why it failed / what is missing

    Both the analyzer and the solve generator consume this structure - one
    implementation, two consumers - so a new attack fills it rather than returning a
    bare int or bytes. Private on purpose: callers meet the contract through the
    public attack functions, each of which documents it in its own `help()`.
    """
    out = {"ok": ok, "plaintext": None, "detail": "", "factors": None,
           "d": None, "note": ""}
    out.update(kw)
    return out


# ────────────────────────── basic operations ──────────────────────────

def keygen(bits: int = 1024, e: int = 65537, rng: random.Random = None):
    """Generate an RSA key (for tests / target ranges) → dict(n, e, d, p, q, phi)"""
    rng = rng or random
    half = bits // 2
    while True:
        p = A.next_prime(rng.getrandbits(half) | (1 << (half - 1)))
        q = A.next_prime(rng.getrandbits(half) | (1 << (half - 1)))
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        d = A.modinv(e, phi)
        if d is None:
            continue
        return {"n": p * q, "e": e, "d": d, "p": p, "q": q, "phi": phi}


def encrypt(m, e: int, n: int) -> int:
    """m may be an int or bytes"""
    if isinstance(m, (bytes, bytearray)):
        m = btoi(bytes(m))
    return pow(m, e, n)


def decrypt(c: int, d: int, n: int):
    """Returns an int (converting to bytes is the caller's decision — this avoids
    the leading-zero ambiguity)"""
    return pow(c, d, n)


def crt_decrypt(n, e, c, p, q, dp=None, dq=None):
    """CRT-accelerated decryption (faster with dp/dq; falls back to d)

    `n` must equal p*q: the factors are validated first, because handing over
    mismatched values used to produce a silently wrong plaintext.
    Returns: int normally, and **None** when e is not invertible mod phi (an earlier
    version returned 0, which is indistinguishable from the plaintext 0 - it decrypts
    to b'\\x00' and looks like a real answer).
    """
    if p <= 1 or q <= 1 or p * q != n:
        return None
    if dp is not None and dq is not None:
        m1 = pow(c % p, dp, p)
        m2 = pow(c % q, dq, q)
    else:
        d = A.modinv(e, (p - 1) * (q - 1))
        if d is None:
            return None
        m1, m2 = pow(c, d, p), pow(c, d, q)
    qinv = A.modinv(q, p)
    if qinv is None:
        return None
    h = (qinv * (m1 - m2)) % p
    return m2 + h * q


def reencrypt_check(m: int, e: int, n: int, c: int) -> bool:
    """Re-encryption check: pow(m, e, n) == c — the criterion that upgrades a
    claim from "looks like plaintext" to "mathematically correct"."""
    return pow(m, e, n) == c % n


# ────────────────────────── factorisation attacks ──────────────────────────

def factor_from_phi(n: int, phi: int):
    """Recover p, q from phi: p+q = n-phi+1, then solve the quadratic"""
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    r = A.perfect_square(disc)
    if r is None or (s + r) % 2:
        return None
    p, q = (s + r) // 2, (s - r) // 2
    return (p, q) if p * q == n and p > 1 and q > 1 else None


def factor_from_d(n: int, e: int, d: int):
    """Factor n from (n, e, d) — the standard random-base algorithm"""
    k = e * d - 1
    if k <= 0 or k % 2:
        return None
    t = 0
    while k % 2 == 0:
        k //= 2
        t += 1
    for g in list(range(2, 20)) + [random.randrange(2, max(3, n - 1)) for _ in range(8)]:
        y = pow(g, k, n)
        if y in (1, n - 1):
            continue
        for _ in range(t):
            x = pow(y, 2, n)
            if x == 1:
                p = A.gcd(y - 1, n)
                if 1 < p < n:
                    return p, n // p
                break
            y = x
    return None


def decrypt_with_factors(n, e, c, p, q):
    """Known p, q → decrypt (the factors are validated first; invalid ones are
    rejected at once)
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    if not p or not q or p <= 1 or q <= 1 or p * q != n:
        return _res(False, note=f"invalid factors (p×q {'=' if p and q else '?'} n), refusing")
    d = A.modinv(e, (p - 1) * (q - 1))
    if d is None:
        return _res(False, note="e and phi are not coprime (needs special handling)")
    m = pow(c, d, n)
    return _res(True, plaintext=itob(m), d=d, factors=(p, q),
                detail="known p/q → d → decryption")


# ────────────────────────── attacks ──────────────────────────

def small_e_attack(n, e, c):
    """Small e with no padding: m^e = c (no modular reduction) → integer root
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    root, exact = A.iroot(c, e)
    if exact and pow(root, e) == c and root < n:
        return _res(True, plaintext=itob(root), detail=f"exact {e}-th power → integer root")
    return _res(False, note=f"c is not an exact {e}-th power (try broadcast attack)")


def broadcast_attack(e: int, pairs):
    """Håstad broadcast: same e, e pairs (n_i, c_i) with pairwise coprime moduli
    → CRT then integer root
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    # Input pairs are (n_i, c_i) - the same order `rsa_attacks.hastad_padded`
    # documents. The order used to be reversed here while the docstring said
    # (n_i, c_i), so code written from the docs failed with a misleading
    # "moduli are not coprime". A.crt wants (residue, modulus), hence the swap.
    pairs = [(int(c), int(n)) for n, c in pairs][:e]
    if len(pairs) < e:
        return _res(False, note=f"needs {e} pairs, only {len(pairs)} given")
    res = A.crt(pairs)
    if not res:
        return _res(False, note="moduli are not coprime (switch to the shared-factor attack); "
                               "pairs must be given as (n_i, c_i)")
    root, exact = A.iroot(res[0], e)
    if not exact:
        return _res(False, note="CRT result is not an exact e-th power (padded plaintext?)")
    return _res(True, plaintext=itob(root), detail=f"{e} pairs CRT'd, integer root succeeded")


def common_modulus_attack(n, e1, c1, e2, c2):
    """Same modulus, different exponents (gcd(e1,e2)=1): m = c1^a * c2^b mod n

    The recovered message is delivered as result["plaintext"] (bytes), not as the
    integer m - reading the line above as "returns an int" is a known trap.
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    g, a, b = A.egcd(e1, e2)
    if g != 1:
        return _res(False, note=f"gcd(e1,e2)={g} ≠ 1, needs factorisation first")
    if a < 0:
        inv = A.modinv(c1, n)
        if inv is None:
            return _res(False, note="c1 is not coprime with n — a plain gcd factors n")
        part1 = pow(inv, -a, n)
    else:
        part1 = pow(c1, a, n)
    part2 = pow(c2, b, n) if b >= 0 else pow(A.modinv(c2, n), -b, n)
    m = part1 * part2 % n
    if not reencrypt_check(m, e1, n, c1):
        return _res(False, note="recovered m failed the re-encryption check")
    return _res(True, plaintext=itob(m), detail="common modulus attack")


def shared_prime_attack(pairs):
    """Several (n, c) pairs: find a shared prime factor → decrypt (the king of
    give-away CTF tasks)

    Returns: the result dict, with plaintext being the first message decrypted
    successfully; every result is in results
    """
    items = [(int(n), int(c)) for n, c in pairs]
    outs = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            n1, c1 = items[i]
            n2, _ = items[j]
            g = A.gcd(n1, n2)
            if 1 < g < min(n1, n2):
                p = A.gcd(n1, g)
                q = n1 // p
                if p * q != n1:
                    continue
                outs.append((n1, c1, p, q))
                p2 = A.gcd(n2, g)
                if 1 < p2 < n2:
                    outs.append((n2, items[j][1], p2, n2 // p2))
                break
        if outs:
            break
    if not outs:
        return _res(False, note="no shared prime factor found")
    results = []
    for n, c, p, q in outs:
        e = 65537
        r = decrypt_with_factors(n, e, c, p, q)
        if r["ok"]:
            results.append({"n": n, "p": p, "q": q, "plaintext": r["plaintext"]})
    if not results:
        return _res(False, note="factorisation worked but decryption failed (e not 65537?)")
    return _res(True, plaintext=results[0]["plaintext"], factors=(results[0]["p"], results[0]["q"]),
                detail=f"shared-factor factorisation, {len(results)} pairs decrypted",
                note=str(len(results)),
                **{"results": results})


def wiener_attack(e, n, c=None):
    """d too small → recover d from the continued-fraction convergents
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    hit = A.wiener_attack(e, n)
    if not hit:
        return _res(False, note="d does not meet the Wiener condition (d > n^0.25/3)")
    d, p, q = hit
    out = _res(True, factors=(p, q), d=d, detail=f"Wiener recovered d ({d.bit_length()} bits)")
    if c is not None:
        m = pow(c, d, n)
        out["plaintext"] = itob(m)
        out["note"] = "re-encryption check" if reencrypt_check(m, e, n, c) else ""
    return out


def common_private_exponent_attack(pairs, max_candidates: int = 400):
    """Several moduli sharing one small private exponent d — the Wiener follow-up

    When the same d is used across moduli, `e_i*d - k_i*phi_i = 1` gives
    `k_i/d ~ e_i/n_i`, so d is a denominator of a continued-fraction convergent of
    `e_i/n_i` for **every** modulus. Wiener on one modulus needs d < n^0.25/3; the
    shared d survives well past that, because a candidate d is only accepted when it
    explains *all* the moduli at once (k_i = round(e_i*d/n_i) must be exact and the
    resulting phi_i must factor n_i). That is the "small-denominator rational
    approximation across two moduli" lead: run it when `wiener_attack` comes back empty
    and more than one (e, n) pair is on the table.

    pairs: [(e_i, n_i), ...] or [(e_i, n_i, c_i), ...] — ciphertexts are optional.
    Returns: the standard result dict, with one deviation for this multi-modulus
             attack: result["factors"] is a **list** of (p_i, q_i) in input order
             instead of the usual single tuple, result["d"] is the shared exponent, and
             result["plaintexts"] carries the decrypted messages when ciphertexts were
             supplied. Every factor pair is checked by multiplication before it is
             reported.

    MEASURED RANGE, stated because it is narrower than the name suggests: this
    convergent-based version stays inside the per-modulus continued-fraction reach, so
    with three 512-bit moduli it succeeds at d = 100/120/126 bits - where single-modulus
    `wiener_attack` *also* already succeeds - and fails at d = 130/140 bits, exactly
    where Wiener fails. It is a cheap extra lead, not a widened bound. Recovering a
    genuinely larger shared d needs the simultaneous-Diophantine-approximation lattice
    (the `common_d` module), which is the fallback to use when this returns ok=False.
    """
    items = []
    for entry in pairs:
        if len(entry) == 3:
            items.append((int(entry[0]), int(entry[1]), int(entry[2])))
        else:
            e_i, n_i = entry
            items.append((int(e_i), int(n_i), None))
    if len(items) < 2:
        return _res(False, note="needs at least two (e, n) pairs; with one modulus use "
                               "wiener_attack or fermat_attack")
    if any(e_i <= 0 or n_i <= 1 for e_i, n_i, _ in items):
        return _res(False, note="invalid (e, n) pair")

    # Candidate shared exponents: the convergent denominators of every e_i/n_i
    candidates = set()
    for e_i, n_i, _ in items:
        for _k, d in A.convergents(A.continued_fraction(e_i, n_i)):
            if 0 < d:
                candidates.add(d)
    candidates = sorted(candidates)[:max_candidates]
    if not candidates:
        return _res(False, note="no continued-fraction denominators to test")

    for d in candidates:
        factors = []
        phis = []
        ok = True
        for e_i, n_i, _c in items:
            k_est = (e_i * d) // n_i
            found = None
            for k in (k_est - 1, k_est, k_est + 1, k_est + 2):
                if k <= 0 or (e_i * d - 1) % k:
                    continue
                phi = (e_i * d - 1) // k
                if not (1 < phi < n_i):
                    continue
                pair = factor_from_phi(n_i, phi)
                if pair and pair[0] * pair[1] == n_i:
                    found = (pair, phi)
                    break
            if found is None:
                ok = False
                break
            factors.append(found[0])
            phis.append(found[1])
        if not ok:
            continue
        # Independent verification: every modulus must satisfy e_i*d ≡ 1 mod phi_i
        if any((e_i * d) % phis[idx] != 1 for idx, (e_i, _n, _c) in enumerate(items)):
            continue
        out = _res(True, d=d, factors=factors,
                   detail=f"shared private exponent d recovered ({d.bit_length()} bits) "
                          f"from {len(items)} moduli; single-modulus Wiener did not "
                          f"apply")
        if all(c is not None for _e, _n, c in items):
            msgs = []
            for idx, (e_i, n_i, c_i) in enumerate(items):
                p_i, q_i = factors[idx]
                m = decrypt_with_factors(n_i, e_i, c_i, p_i, q_i)
                msgs.append(m.get("plaintext"))
            out["plaintexts"] = msgs
            out["plaintext"] = next((m for m in msgs if m), None)
        return out
    return _res(False, note=f"no shared d among {len(candidates)} convergent "
                           f"denominator candidate(s); the exponent is probably not "
                           f"common to these moduli (or it exceeds the approximation "
                           f"range)")


def fermat_attack(n, e=65537, c=None, max_iter: int = 1000000):
    """p and q close → Fermat factorisation
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    f = A.fermat_factor(n, max_iter=max_iter)
    if not f:
        return _res(False, note=f"not factored in {max_iter} rounds (p, q not close enough)")
    p, q = f
    r = decrypt_with_factors(n, e, c, p, q) if c is not None else \
        _res(True, factors=(p, q), detail="Fermat factorisation succeeded")
    r["factors"] = (p, q)
    if c is not None and r["ok"]:
        r["detail"] = "Fermat factorisation → decrypt"
    return r


def pollard_attack(n, e=65537, c=None, max_steps: int = 1000000):
    """Bounded Pollard rho factorisation (when n is not too large)
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    fac = A.factor_limited(n, max_steps=max_steps)
    if not fac or len(fac) < 2:
        return _res(False, note=f"not factored within {max_steps} steps")
    ks = list(fac)
    p, q = ks[0], n // ks[0]
    if c is None:
        return _res(True, factors=(p, q), detail="Pollard rho factorisation succeeded")
    r = decrypt_with_factors(n, e, c, p, q)
    r["factors"] = (p, q)
    if r["ok"]:
        r["detail"] = "Pollard rho factorisation → decrypt"
    return r


def dp_leak_attack(n, e, dp, c=None):
    """dp = d mod (p-1) leaked → gcd(2^(e*dp) - 2, n) = p
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    try:
        p = A.gcd(pow(2, e * dp, n) - 2, n)
    except Exception:
        p = 1
    if not (1 < p < n):
        return _res(False, note="gcd gave no non-trivial factor (dp/e may be wrong)")
    q = n // p
    if c is None:
        return _res(True, factors=(p, q), detail="dp leak → factorisation succeeded")
    r = decrypt_with_factors(n, e, c, p, q)
    r["factors"] = (p, q)
    if r["ok"]:
        r["detail"] = "dp leak → factorisation → decryption"
    return r


def phi_leak_attack(n, e, phi, c=None):
    """phi leaked → recover p, q
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    f = factor_from_phi(n, phi)
    if not f:
        return _res(False, note="phi → p, q recovery failed (is phi an Euler totient?)")
    p, q = f
    if c is None:
        return _res(True, factors=(p, q), detail="phi leak → factorisation succeeded")
    return decrypt_with_factors(n, e, c, p, q)


def known_high_bits_attack(n, p_high, known_bits, e=None, c=None, total_bits=None):
    """Known high bits of p → Coppersmith (LLL small roots)
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    res = L.known_high_bits_factor(n, p_high, known_bits, total_bits)
    if res.get("factor"):
        p, q = res["factor"], n // res["factor"]
    elif res.get("p"):
        p, q = res["p"], res["q"]
    else:
        return _res(False, note=res.get("note", "small root not hit"))
    if c is not None and e:
        r = decrypt_with_factors(n, e, c, p, q)
        r["factors"] = (p, q)
        if r["ok"]:
            r["detail"] = "Coppersmith high-bits factorisation → decryption"
        return r
    return _res(True, factors=(p, q), detail="Coppersmith high-bits factorisation succeeded")


# ────────────────────────── convenience wrapper (try everything) ──────────────────────────

def auto_attack(n, e=65537, c=None, pairs=None, p=None, q=None, d=None,
                phi=None, dp=None, max_steps: int = 500000):
    """Try the common attacks automatically, cheapest first → the first success

    pairs: [(n_i, c_i), ...] used for shared-factor / broadcast checks when
    several sets are available
    Returns: the standard result dict - {"ok", "plaintext", "detail", "factors",
             "d", "note"}; the answer, when there is one, is result["plaintext"]
             (bytes), or result["factors"] / result["d"] for the factor attacks.
    """
    if p and q and p * q == n:
        return decrypt_with_factors(n, e, c, p, q) if c is not None else \
            _res(True, factors=(p, q), detail="known p, q")
    if d:
        out = _res(True, d=d, detail="known d")
        if c is not None:
            m = pow(c, d, n)
            out["plaintext"] = itob(m)
        return out
    if phi:
        r = phi_leak_attack(n, e, phi, c)
        if r["ok"]:
            return r
    if dp:
        r = dp_leak_attack(n, e, dp, c)
        if r["ok"]:
            return r
    if pairs:
        r = shared_prime_attack([(nn, cc) for nn, cc in pairs])
        if r["ok"]:
            return r
        if e <= 17:
            r = broadcast_attack(e, [(nn, cc) for nn, cc in pairs])
            if r["ok"]:
                return r
    if e <= 17 and c is not None:
        r = small_e_attack(n, e, c)
        if r["ok"]:
            return r
    r = wiener_attack(e, n, c)
    if r["ok"]:
        return r
    # Wiener failed: if more than one modulus is on the table, the small private
    # exponent may be *shared* rather than small per modulus - the follow-up lead a user
    # asked for. Cheap (continued fractions only), so it goes right after Wiener.
    if pairs and len(pairs) >= 2:
        r = common_private_exponent_attack(list(pairs))
        if r["ok"]:
            r["detail"] = "auto_attack: " + r.get("detail", "")
            return r
        # Three or more moduli: the SDAP lattice reaches a larger shared d than any
        # convergent can (measured: m=4 with 512-bit moduli recovered a 151-bit d that
        # no single-modulus Wiener touched). It costs seconds and adds nothing for two
        # moduli, hence the length guard. Imported here to keep the module import cheap.
        if len(pairs) >= 3:
            try:
                from .common_d import common_d_lattice
                r = common_d_lattice(list(pairs))
            except Exception:
                r = {"ok": False}
            if r.get("ok"):
                r["detail"] = "auto_attack: " + str(r.get("detail", ""))
                return r
    r = fermat_attack(n, e, c)
    if r["ok"]:
        return r
    r = pollard_attack(n, e, c, max_steps=max_steps)
    if r["ok"]:
        return r
    return _res(False, note="auto_attack: none of the common attack surfaces apply")
