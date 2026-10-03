"""Signature attacks — the mechanical half of DSA/ECDSA/RSA signature CTF tasks.

The single most common signature challenge is **nonce reuse**: two signatures that
share the random k leak the private key algebraically. That is pure bookkeeping, so
it belongs in an infrastructure library rather than in every solver script.

Result convention matches rsa_ops: {"ok", "plaintext", "detail", "factors", "d", "note"}
(here `d` carries the recovered private key / nonce where applicable).
"""

import hashlib

from . import algebra as A


def _res(ok=False, **kw):
    out = {"ok": False, "plaintext": None, "detail": "", "factors": None,
           "d": None, "note": ""}
    out["ok"] = ok
    out.update(kw)
    return out


def hash_to_int(data, algorithm: str = "sha256") -> int:
    """Hash arbitrary data to an integer (defaults to SHA-256, the ECDSA norm)"""
    if isinstance(data, str):
        data = data.encode()
    h = hashlib.new(algorithm, data).digest()
    return int.from_bytes(h, 'big')


# ────────────────────────── ECDSA / DSA ──────────────────────────

def ecdsa_nonce_reuse(n, r, s1, s2, h1, h2):
    """Recover the private key when two signatures reused the same nonce k

    k = (h1 - h2) / (s1 - s2) mod n, then d = (s1*k - h1) / r mod n.

    What this cannot do (stated because an earlier docstring claimed otherwise): the
    two signature equations are satisfied by the derived (k, d) *by construction*, for
    any input, so there is no algebraic self-check that would detect "the nonces were
    not actually reused". With unrelated signatures the function still returns a
    (k, d) pair that reproduces them - the pair is simply not the signer's key.
    Verify against the signer's public key (d*G == Q) before trusting the result;
    `dsa_nonce_reuse` can do that check when it is given `y`, this one has no curve
    parameter.
    Returns: the standard result dict; the recovered private key is result["d"] and
             the nonce is result["meta"]["k"].
    """
    denom = (s1 - s2) % n
    inv = A.modinv(denom, n)
    if inv is None:
        return _res(False, note="s1 - s2 is not invertible mod n; check the inputs")
    k = (h1 - h2) * inv % n
    r_inv = A.modinv(r, n)
    if r_inv is None:
        return _res(False, note="r is not invertible mod n")
    d = (s1 * k - h1) * r_inv % n
    return _res(True, d=d, meta={"k": k, "verified": False},
                detail=f"nonce k recovered, private key d = {d}; the equations hold by "
                       f"construction, so confirm d against the public key")


def dsa_nonce_reuse(p, q, g, y, r, s1, s2, h1, h2):
    """Same attack for DSA; `y` is the public key (verification uses it)

    Returns the private key x and the reused nonce k.
    Returns: the standard result dict; the recovered private key is
             result["d"] and the reused nonce is result["meta"]["k"].
    """
    denom = (s1 - s2) % q
    inv = A.modinv(denom, q)
    if inv is None:
        return _res(False, note="s1 - s2 not invertible mod q")
    k = (h1 - h2) * inv % q
    r_inv = A.modinv(r, q)
    if r_inv is None:
        return _res(False, note="r not invertible mod q")
    x = (s1 * k - h1) * r_inv % q
    # verify: the public key must match g^x
    if y is not None and pow(g, x, p) != y % p:
        return _res(False, note="recovered x does not reproduce the public key y")
    return _res(True, d=x, meta={"k": k, "verified": y is not None},
                detail=f"private key x = {x}")


def ecdsa_recover_k(n, r, s, h, d):
    """Recover the nonce k of a signature whose private key d is known

    From s = k^-1 (h + r*d) mod n it follows that

        k = (h + r*d) / s  mod n

    (dividing by **s**, not by r - an early version divided by r, which returned a
    plausible-looking wrong nonce for every input; the parameter s was silently
    unused, which is the kind of bug that survives a test suite that never calls the
    function). Returns None when s is not invertible mod n.
    Returns: int or None (an int, not a result dict - this is a helper, not an attack).
    """
    s_inv = A.modinv(s % n, n)
    if s_inv is None:
        return None
    return (h + r * d) * s_inv % n


def ecdsa_verify(px, py, a, b, p, gx, gy, r, s, h):
    """Minimal ECDSA verification (affine arithmetic) — for checking attacks

    Deliberately small: enough to confirm a recovered key/nonce on toy curves.
    """
    def inv_mod(x, m):
        return A.modinv(x % m, m)

    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            lam = (3 * x1 * x1 + a) * inv_mod(2 * y1, p) % p
        else:
            lam = (y2 - y1) * inv_mod(x2 - x1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return x3, (lam * (x1 - x3) - y1) % p

    def mul(k, P):
        R = None
        while k:
            if k & 1:
                R = add(R, P)
            P = add(P, P)
            k >>= 1
        return R

    if not (1 <= r < p and 1 <= s < p):
        return False
    w = A.modinv(s, p)
    if w is None:
        return False
    u1, u2 = h * w % p, r * w % p
    point = add(mul(u1, (gx, gy)), mul(u2, (px, py)))
    if point is None:
        return False
    return point[0] % p % p == r % p


# ────────────────────────── RSA signatures ──────────────────────────

def rsa_e3_signature_forge(n, digest_info: bytes, tail_bits: int = 32,
                           max_tries: int = 64):
    """Bleichenbacher-style e = 3 signature forgery.

    Condition (must be stated honestly): the verifier reads the *leading* bytes of
    sig^3 mod n and tolerates trailing garbage behind the DigestInfo. Under that
    condition we can pick any s whose cube starts with the expected block:

        s = ceil( cuberoot(digest_info || 0...0) )   ->   s^3 = digest_info||0...0 + delta

    We search over the number of trailing zero bits until the cube starts exactly
    with the expected DigestInfo, and we verify that prefix before returning.

    Returns: the standard result dict. Where the pieces live: the forged signature is
             result["d"] (an int, so it can be fed straight to a verification routine)
             and the bytes sig^3 mod n that matched are result["meta"]["recovered"].
             An earlier docstring claimed fresh keys named "signature"/"recovered",
             which raised KeyError for anyone who trusted `help()`.
    """
    if isinstance(digest_info, str):
        digest_info = digest_info.encode()
    target = int.from_bytes(digest_info, 'big')
    for extra in range(0, max_tries):
        t = tail_bits + extra * 8
        candidate = target << t
        if candidate >= n:
            break
        s, exact = A.iroot(candidate, 3)
        if not exact:
            s += 1                      # take the ceiling: s^3 > candidate
        cube = pow(s, 3)
        if cube % n != cube:
            continue                    # cube must stay below n, else the prefix wraps
        got = cube.to_bytes((cube.bit_length() + 7) // 8, 'big')
        if got.startswith(digest_info):
            return _res(True, d=s, meta={"recovered": got},
                        detail=f"forged e=3 signature with {t} tail bits: "
                               f"sig^3 starts with the expected DigestInfo")
    return _res(False, note="no prefix-preserving cube found; the verifier is probably strict")


def pkcs1_v15_pad(message, key_len: int, block_type: int = 1) -> bytes:
    """PKCS#1 v1.5 padding: 0x00 || 0x01/0x02 || PS || 0x00 || message

    block_type 1 = signing, 2 = encryption. PS bytes are 0xFF for type 1 (and are
    generated from a fixed PRNG for type 2 so the result stays reproducible).
    """
    if block_type not in (1, 2):
        raise ValueError("block_type must be 1 (sign) or 2 (encrypt)")
    if isinstance(message, str):
        message = message.encode()
    ps_len = key_len - len(message) - 3
    if ps_len < 8:
        raise ValueError("message too long for this key length")
    if block_type == 1:
        ps = b"\xff" * ps_len
    else:
        prng = __import__("random").Random(0xC0FFEE)
        ps = bytes(prng.randrange(1, 256) for _ in range(ps_len))
    return b"\x00" + bytes([block_type]) + ps + b"\x00" + message


def pkcs1_v15_unpad(block: bytes):
    """Strip PKCS#1 v1.5 padding → (block_type, message) or None when malformed"""
    if len(block) < 11 or block[0] != 0 or block[1] not in (1, 2):
        return None
    idx = block.find(b"\x00", 2)
    if idx < 10:
        return None
    return block[1], block[idx + 1:]


def dsa_sign(p, q, g, x, h, k):
    """Reference signer (tests / local oracles): r = (g^k mod p) mod q, s = k^-1 (h + x r) mod q"""
    r = pow(g, k, p) % q
    k_inv = A.modinv(k, q)
    if k_inv is None:
        return None
    s = k_inv * (h + x * r) % q
    return r, s


def ecdsa_sign(n, gx, gy, a, p, d, h, k):
    """Reference ECDSA signer over a prime field, using the affine verifier above"""
    def inv_mod(x, m):
        return A.modinv(x % m, m)

    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            lam = (3 * x1 * x1 + a) * inv_mod(2 * y1, p) % p
        else:
            lam = (y2 - y1) * inv_mod(x2 - x1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        return x3, (lam * (x1 - x3) - y1) % p

    def mul(k, P):
        R = None
        while k:
            if k & 1:
                R = add(R, P)
            P = add(P, P)
            k >>= 1
        return R

    point = mul(k, (gx, gy))
    if point is None:
        return None
    r = point[0] % n
    k_inv = A.modinv(k, n)
    if k_inv is None:
        return None
    s = k_inv * (h + d * r) % n
    return r, s
