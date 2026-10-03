"""Pure-Python hashes — SHA-256 / SHA-1 / MD5 plus the length-extension primitive

Why not just call hashlib: hashlib only offers one-shot hashing. Length extension
needs the *internal state*, and the whole point of the attack is that
H(secret||data) together with len(secret) is enough to keep walking the
Merkle-Damgard chain and forge H(secret||data||glue||extra) without ever learning
the secret. The standard library exposes no "resume from a digest" API, so the
compression functions live here and `HashState` wraps them into something that can
be stopped, inspected and continued.

Same rule as aes.py: derive constants instead of transcribing them. SHA-256's round
constants are the fractional parts of the cube roots of the first 64 primes and its
initial state the fractional parts of their square roots; both are computed with
exact integer arithmetic (`_iroot`), because one mistyped magic number is a hash
that is quietly wrong. MD5's T table comes from sin(i + 1) as RFC 1321 defines it.

What is verified: the published FIPS 180-4 / RFC 1321 vectors, a byte-for-byte
comparison against hashlib for every plain digest, and — the strongest check — the
forged message of a length extension is fed back through hashlib.sha256/hashlib.md5.
If the glue padding were one byte off, that equality would break immediately.

Cost: pure Python runs at roughly 1 MB/s, so this is for CTF-sized inputs. When no
state is needed, hashlib is still the right tool.

Recipe (the two useful call shapes, spelled out because the naive one is wrong):

    # 1) you know data and the digest the server gave you -> forge a suffix
    r = length_extension(h1, len(data), b"&admin=1", "sha256", secret_len=5)
    send(data + r["forged_message"])           # ...and the server now sees admin=1

    # 2) split one long message into resumable chunks (chunked == one-shot)
    st = sha256_state(b"first half", 0)
    assert st.extend(b"second half").digest() == sha256(b"first halfsecond half")
"""

import math as _math
import struct as _struct

_MASK32 = 0xffffffff
_BLOCK = 64


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _iroot(n: int, k: int) -> int:
    """Exact floor(n ** (1/k)) — integer Newton iteration, no floating point

    Used only to derive SHA-2 constants. A float cube root could land on the wrong
    side of the floor for a value that sits extremely close to an integer, and that
    failure would be invisible until some hash somewhere disagrees.
    """
    if n < 0 or k < 1:
        raise ValueError("iroot needs n >= 0 and k >= 1")
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            return x
        x = y


def _frac_root(p: int, k: int) -> int:
    """floor(frac(p ** (1/k)) * 2**32) computed exactly

    p ** (1/k) * 2**32 == (p * 2**(32k)) ** (1/k), so scaling before taking the
    root turns the fractional part into an integer problem: subtract the whole part
    and the floor is exact.
    """
    return _iroot(p << (32 * k), k) - (_iroot(p, k) << 32)


def _first_primes(count: int):
    out = []
    cand = 2
    while len(out) < count:
        if all(cand % p for p in out if p * p <= cand):
            out.append(cand)
        cand += 1
    return out


_PRIMES = _first_primes(64)
_K256 = tuple(_frac_root(p, 3) for p in _PRIMES)
_H256 = tuple(_frac_root(p, 2) for p in _PRIMES[:8])
# SHA-1 and MD5 share the same "nothing up my sleeve" IV; SHA-1 adds a fifth word.
_HMD5 = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
_HSHA1 = _HMD5 + (0xc3d2e1f0,)
_MD5_K = tuple(int(abs(_math.sin(i + 1)) * (1 << 32)) & _MASK32 for i in range(64))
_MD5_S = (7, 12, 17, 22) * 4 + (5, 9, 14, 20) * 4 + (4, 11, 16, 23) * 4 \
    + (6, 10, 15, 21) * 4


def _sha256_compress(h, block: bytes):
    w = list(_struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & _MASK32)
    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        big1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        choose = g ^ (e & (f ^ g))          # Ch(e,f,g), written without complement
        t1 = (hh + big1 + choose + _K256[i] + w[i]) & _MASK32
        big0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big0 + majority) & _MASK32
        hh, g, f, e = g, f, e, (d + t1) & _MASK32
        d, c, b, a = c, b, a, (t1 + t2) & _MASK32
    return [(x + y) & _MASK32 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]


def _sha1_compress(h, block: bytes):
    w = list(_struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
    a, b, c, d, e = h
    for i in range(80):
        if i < 20:
            f = d ^ (b & (c ^ d))           # Ch(b,c,d)
            k = 0x5a827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ed9eba1
        elif i < 60:
            f = (b & c) ^ (b & d) ^ (c & d)  # Maj(b,c,d)
            k = 0x8f1bbcdc
        else:
            f = b ^ c ^ d
            k = 0xca62c1d6
        tmp = (_rotl(a, 5) + f + e + k + w[i]) & _MASK32
        e, d, c, b, a = d, c, _rotl(b, 30), a, tmp
    return [(x + y) & _MASK32 for x, y in zip(h, (a, b, c, d, e))]


def _md5_compress(h, block: bytes):
    m = list(_struct.unpack("<16I", block))
    a, b, c, d = h
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & _MASK32 & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & _MASK32 & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d & _MASK32))
            g = (7 * i) % 16
        mixed = (f + a + _MD5_K[i] + m[g]) & _MASK32
        a, d, c, b = d, c, b, (b + _rotl(mixed, _MD5_S[i])) & _MASK32
    return [(x + y) & _MASK32 for x, y in zip(h, (a, b, c, d))]


_SPECS = {
    "sha256": {"name": "sha256", "digest_size": 32, "word_endian": "big",
               "len_endian": "big", "init": _H256, "compress": _sha256_compress},
    "sha1": {"name": "sha1", "digest_size": 20, "word_endian": "big",
             "len_endian": "big", "init": _HSHA1, "compress": _sha1_compress},
    "md5": {"name": "md5", "digest_size": 16, "word_endian": "little",
            "len_endian": "little", "init": _HMD5, "compress": _md5_compress},
}


def _spec(algorithm):
    """Normalise an algorithm name ("SHA-256", "sha_1", ...) to its parameter table"""
    name = str(algorithm).lower().replace("-", "").replace("_", "")
    if name not in _SPECS:
        raise ValueError(f"unsupported algorithm {algorithm!r}; expected one of "
                         f"{sorted(_SPECS)}")
    return _SPECS[name]


def _padding(length: int, spec) -> bytes:
    """Merkle-Damgard padding for a message of `length` bytes

    Same 0x80 + zeros + 64-bit bit-length scheme for all three algorithms; only the
    byte order of the trailing length differs (SHA-1/SHA-256 big-endian, MD5
    little-endian), which is why the endianness lives in the spec table.
    """
    bits = length * 8
    if bits >= (1 << 64):
        raise ValueError("message too long for the 64-bit length field (>= 2**61 bytes)")
    zeros = (-(length + 9)) % _BLOCK
    return b"\x80" + b"\x00" * zeros + bits.to_bytes(8, spec["len_endian"])


class HashState:
    """Resumable Merkle-Damgard state — the raw material for length extension

    A state holds the chaining value, the bytes not yet compressed and the total
    message length. `extend` continues hashing and returns a *new* state (the
    original is left alone), so a captured state can be branched in several
    directions, which is handy when probing what a server will accept.

    For a forgery the chaining value has to come from the digest the server handed
    out — an unknown secret cannot be reconstructed. `HashState.from_digest` does
    exactly that: it adopts the digest words and moves the length counter past the
    padding the original hash applied, so the caller has to paste those padding
    bytes (`glue()`) into the forged message but must *not* hash them again (they
    were already compressed as part of the original digest).
    """

    __slots__ = ("algorithm", "_spec", "_h", "_buf", "_length", "_glue")

    def __init__(self, algorithm="sha256", state=None, buffer=b"", length=0, glue=b""):
        spec = _spec(algorithm)
        self.algorithm = spec["name"]
        self._spec = spec
        self._h = list(spec["init"]) if state is None else [w & _MASK32 for w in state]
        if len(self._h) != len(spec["init"]):
            raise ValueError(f"{spec['name']} state needs {len(spec['init'])} words, "
                             f"got {len(self._h)}")
        self._buf = bytes(buffer)
        self._length = int(length)
        self._glue = bytes(glue)
        if self._length < 0:
            raise ValueError("length must not be negative")
        if len(self._buf) >= _BLOCK:
            raise ValueError("buffer must hold less than one block")

    # ------------------------------------------------------------------ internals

    def _absorb(self, data: bytes) -> None:
        buf = self._buf + data
        keep = len(buf) % _BLOCK
        for off in range(0, len(buf) - keep, _BLOCK):
            self._h = self._spec["compress"](self._h, buf[off:off + _BLOCK])
        self._buf = buf[len(buf) - keep:]
        self._length += len(data)

    # -------------------------------------------------------------------- queries

    @property
    def length(self) -> int:
        """Total message bytes accounted for (the secret prefix counts)"""
        return self._length

    def glue(self) -> bytes:
        """Padding bytes the original hash appended (empty for a state built from data)

        These belong in the *message* of a forgery, never in the hash input.
        """
        return self._glue

    def padding(self) -> bytes:
        """Padding this state would append for the message hashed so far

        Under length extension this is the glue: the server's message plus these
        bytes reaches the digest that was handed to you.
        """
        return _padding(self._length, self._spec)

    def copy(self) -> "HashState":
        return HashState(self.algorithm, self._h, self._buf, self._length, self._glue)

    # ------------------------------------------------------------- transformations

    @classmethod
    def from_digest(cls, digest, message_len: int, algorithm="sha256") -> "HashState":
        """Rebuild the state behind `digest` for a message of `message_len` bytes

        `message_len` is the length of the *whole* hashed message, secret included
        (that is the number an attacker knows because they know the secret's length).
        The result sits just after the original padding: `glue()` returns those
        padding bytes and `extend(extra)` hashes only `extra`, giving the forged
        digest H(message || glue || extra). Digesting the state as-is instead gives
        the digest of the padded message, which is a different (usually useless)
        value — read `glue()` first.
        """
        spec = _spec(algorithm)
        digest = bytes(digest)
        if len(digest) != spec["digest_size"]:
            raise ValueError(f"{spec['name']} digest must be {spec['digest_size']} bytes, "
                             f"got {len(digest)}")
        words = [int.from_bytes(digest[i:i + 4], spec["word_endian"])
                 for i in range(0, len(digest), 4)]
        glue = _padding(message_len, spec)
        return cls(spec["name"], words, b"", message_len + len(glue), glue)

    def extend(self, extra: bytes) -> "HashState":
        """Continue hashing `extra` from this state; returns a new state"""
        new = self.copy()
        new._absorb(bytes(extra))
        return new

    def digest(self) -> bytes:
        """Digest of the message this state accounts for (self is not modified)"""
        final = self.copy()
        final._absorb(final.padding())
        return b"".join(w.to_bytes(4, final._spec["word_endian"]) for w in final._h)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def __repr__(self) -> str:
        return (f"<HashState {self.algorithm} len={self._length} "
                f"pending={len(self._buf)}>")


def _state_from_data(algorithm: str, data: bytes, secret_len: int = 0) -> HashState:
    """State of `data` with `secret_len` bytes credited to the message length"""
    if secret_len < 0:
        raise ValueError("secret_len must not be negative")
    st = HashState(algorithm, None, b"", secret_len)
    st._absorb(bytes(data))
    return st


def _feed(algorithm: str, data: bytes) -> bytes:
    st = HashState(algorithm)
    st._absorb(bytes(data))
    return st.digest()


# ------------------------------------------------------------------ one-shot API

def sha256(data: bytes) -> bytes:
    """SHA-256 (FIPS 180-4), pure Python"""
    return _feed("sha256", data)


def sha1(data: bytes) -> bytes:
    """SHA-1 (FIPS 180-4), pure Python — broken by collisions, still everywhere in CTFs"""
    return _feed("sha1", data)


def md5(data: bytes) -> bytes:
    """MD5 (RFC 1321), pure Python — likewise collision-broken, still very common"""
    return _feed("md5", data)


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def sha1_hex(data: bytes) -> str:
    return sha1(data).hex()


def md5_hex(data: bytes) -> str:
    return md5(data).hex()


# --------------------------------------------------------------- resumable states

def sha256_state(data: bytes, secret_len: int = 0, digest=None) -> HashState:
    """SHA-256 state for `data`, optionally with a secret prefix or a known digest

    Without `digest` only the length accounting is usable: `padding()` is the glue
    for H(secret||data) and `length` is that total, but the chaining value covers
    `data` alone — with an unknown secret, `digest()` here is a self-consistent yet
    *wrong* value for H(secret||data), so do not send it anywhere.

    Pass the digest the server gave you (`digest=H(secret||data)`) and the state
    becomes fully correct for forgery: `glue()` is the padding to paste and
    `extend(extra).digest()` is H(secret||data||glue||extra). `length_extension`
    is this same computation with the bookkeeping done for you.
    """
    if digest is None:
        return _state_from_data("sha256", data, secret_len)
    return HashState.from_digest(digest, secret_len + len(bytes(data)), "sha256")


def sha1_state(data: bytes, secret_len: int = 0, digest=None) -> HashState:
    """SHA-1 state — see `sha256_state` for the meaning of the two modes"""
    if digest is None:
        return _state_from_data("sha1", data, secret_len)
    return HashState.from_digest(digest, secret_len + len(bytes(data)), "sha1")


def md5_state(data: bytes, secret_len: int = 0, digest=None) -> HashState:
    """MD5 state — see `sha256_state` for the meaning of the two modes"""
    if digest is None:
        return _state_from_data("md5", data, secret_len)
    return HashState.from_digest(digest, secret_len + len(bytes(data)), "md5")


# -------------------------------------------------------------------------- HMAC

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256 (RFC 2104) over our own sha256

    Stdlib hmac would be allowed, but building it from two sha256 calls keeps the
    module on a single hash implementation and makes the construction visible.
    """
    key, msg = bytes(key), bytes(msg)
    if len(key) > _BLOCK:
        key = sha256(key)
    key = key + b"\x00" * (_BLOCK - len(key))
    inner = bytes(b ^ 0x36 for b in key)
    outer = bytes(b ^ 0x5c for b in key)
    return sha256(outer + sha256(inner + msg))


# ------------------------------------------------------------- length extension

def length_extension(orig_digest, orig_len: int, extra: bytes,
                     algorithm: str = "sha256", secret_len: int = None) -> dict:
    """Forge H(secret || data || glue || extra) from H(secret || data) and len(secret)

    `orig_len` is the length of the *data* part (what follows the secret), so
    `secret_len + orig_len` is the length of the message that produced `orig_digest`.

    Returns:
        digest          bytes  the forged digest, H(secret||data||glue||extra)
        hexdigest       str    the same in hex
        forged_message  bytes  `glue + extra` — append this after the original
                              `data` when sending; the unknown `secret || data`
                              prefix is already in the server's message and is
                              *not* included here (the secret is never learned).
                              Full forged message = secret + data + forged_message.
        glue            bytes  the padding bytes on their own
        total_len       int    length of the complete forged message
                              (secret + data + glue + extra)
        prefix_len      int    secret_len + orig_len, the original message length
        secret_len      int
        algorithm       str

    `secret_len` cannot be guessed here: the glue is `padding(secret_len + orig_len)`,
    so a wrong guess produces a wrong message and a wrong digest. With several
    ciphertexts-length hints, try each candidate and let the server's reply decide.
    """
    if secret_len is None:
        raise ValueError("secret_len is required: the glue length follows from the total "
                         "message length, which is secret_len + orig_len")
    if secret_len < 0 or orig_len < 0:
        raise ValueError("lengths must not be negative")
    extra = bytes(extra)
    prefix_len = secret_len + orig_len
    st = HashState.from_digest(orig_digest, prefix_len, algorithm)
    glue = st.glue()
    forged = st.extend(extra)
    return {
        "digest": forged.digest(),
        "hexdigest": forged.hexdigest(),
        "forged_message": glue + extra,
        "glue": glue,
        "total_len": prefix_len + len(glue) + len(extra),
        "prefix_len": prefix_len,
        "secret_len": secret_len,
        "algorithm": forged.algorithm,
    }
