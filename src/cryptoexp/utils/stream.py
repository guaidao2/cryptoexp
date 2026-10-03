"""Stream ciphers + keystream-reuse attacks — RC4, ChaCha20, AES-CTR, crib drag

Stream ciphers have one cardinal sin: reusing a (key, nonce) pair. Under reuse
c1 ^ c2 == p1 ^ p2, so two ciphertexts already leak plaintext structure, and one
known plaintext recovers the whole keystream and decrypts every other message.
That is why the ciphers and the attacks they enable share a file: the misuse is
half the primitive.

Verified against public vectors where they exist — RC4 "Key"/"Plaintext" and the
RFC 8439 section 2.4.2 ChaCha20 block. AES-CTR is verified for round-trip and for
self-consistency with an independent AES-ECB keystream construction, plus the NIST
SP 800-38A F.5.1 counter blocks fed one at a time through `initial_value`: that
vector counts the whole 128-bit block big-endian, while this module counts a
little-endian field (see `_ctr_blocks`), so a per-block check is the honest one.

Deliberately absent: LFSR/stream-cipher state recovery — another module owns LFSR.
"""

import struct as _struct

from .aes import MODE_ECB, new as _aes_new
from .encoding import printable_ratio
from .pad import xor as _xor

_MASK32 = 0xffffffff


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & _MASK32


# ───────────────────────────────────── RC4 ─────────────────────────────────────

def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 — KSA then PRGA; encryption and decryption are the same call

    RC4 is thoroughly broken in TLS (its keystream biases leak plaintext through
    many ciphertexts), but it still shows up in CTF challenges and in older
    firmware, and the biases are exactly what those challenges test.
    """
    if not key:
        raise ValueError("RC4 key must not be empty")
    key, data = bytes(key), bytes(data)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for k, byte in enumerate(data):
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out[k] = byte ^ s[(s[i] + s[j]) & 0xff]
    return bytes(out)


def rc4_keystream(key: bytes, length: int) -> bytes:
    """Raw RC4 keystream (encrypting zeros yields it) — useful for reuse attacks

    With a fixed key and no nonce, every message shares this keystream, so having
    it explicitly makes the "same key twice" failure obvious.
    """
    if length < 0:
        raise ValueError("length must not be negative")
    return rc4(key, b"\x00" * length)


# ─────────────────────────────────── ChaCha20 ──────────────────────────────────

_CHACHA_CONST = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
_CHACHA_ROUNDS = 10          # 10 double rounds == the 20 rounds of the name


def _qr(x, a: int, b: int, c: int, d: int) -> None:
    """ChaCha quarter round, in place on the 16-word state"""
    x[a] = (x[a] + x[b]) & _MASK32
    x[d] = _rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & _MASK32
    x[b] = _rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & _MASK32
    x[d] = _rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & _MASK32
    x[b] = _rotl32(x[b] ^ x[c], 7)


def _chacha20_state(key: bytes, nonce: bytes, counter: int):
    """The 16 input words: constants | key | counter | nonce"""
    if len(key) != 32:
        raise ValueError(f"ChaCha20 needs a 32-byte key, got {len(key)}")
    words = list(_CHACHA_CONST) + list(_struct.unpack("<8I", bytes(key)))
    if len(nonce) == 12:
        # RFC 8439 (IETF): 32-bit block counter, 96-bit nonce
        words += [counter & _MASK32] + list(_struct.unpack("<3I", bytes(nonce)))
    elif len(nonce) == 8:
        # Original djb layout: 64-bit block counter, 64-bit nonce
        wide = counter & 0xffffffffffffffff
        words += [wide & _MASK32, (wide >> 32) & _MASK32]
        words += list(_struct.unpack("<2I", bytes(nonce)))
    else:
        raise ValueError(f"ChaCha20 nonce must be 8 bytes (djb) or 12 bytes (RFC 8439), "
                         f"got {len(nonce)}")
    return words


def chacha20_block(key: bytes, nonce: bytes, counter: int = 0) -> bytes:
    """One 64-byte ChaCha20 keystream block (the raw block function, no data)"""
    state = _chacha20_state(key, nonce, counter)
    x = list(state)
    for _ in range(_CHACHA_ROUNDS):
        _qr(x, 0, 4, 8, 12)
        _qr(x, 1, 5, 9, 13)
        _qr(x, 2, 6, 10, 14)
        _qr(x, 3, 7, 11, 15)
        _qr(x, 0, 5, 10, 15)
        _qr(x, 1, 6, 11, 12)
        _qr(x, 2, 7, 8, 13)
        _qr(x, 3, 4, 9, 14)
    return _struct.pack("<16I", *[(x[i] + state[i]) & _MASK32 for i in range(16)])


class ChaCha20:
    """ChaCha20 keystream object — encryption and decryption are the same XOR

    `counter` is the starting block counter. RFC 8439 starts at 1 when block 0 is
    spent on a Poly1305 key; plain encryption starts at 0. The counter lives on the
    object and advances as blocks are consumed, so a partially used object keeps
    producing the right keystream.
    """

    block_size = 64

    def __init__(self, key: bytes, nonce: bytes, counter: int = 0):
        key, nonce = bytes(key), bytes(nonce)
        _chacha20_state(key, nonce, counter)      # validate up front, not per block
        self.key = key
        self.nonce = nonce
        self.counter = int(counter)
        self._pending = b""                       # keystream generated but not used

    def keystream(self, n: int) -> bytes:
        """Next `n` keystream bytes (state advances; repeat calls continue the stream)"""
        if n < 0:
            raise ValueError("n must not be negative")
        while len(self._pending) < n:
            self._pending += chacha20_block(self.key, self.nonce, self.counter)
            self.counter += 1
        out, self._pending = self._pending[:n], self._pending[n:]
        return out

    def encrypt(self, data: bytes) -> bytes:
        return _xor(bytes(data), self.keystream(len(data)))

    def decrypt(self, data: bytes) -> bytes:
        """Identical to `encrypt` — a stream cipher XORs the same keystream"""
        return self.encrypt(data)

    def __repr__(self) -> str:
        return f"<ChaCha20 counter={self.counter} pending={len(self._pending)}>"


def chacha20(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """One-shot ChaCha20 (encrypt == decrypt)"""
    return ChaCha20(key, nonce, counter).encrypt(data)


# ─────────────────────────────────── AES-CTR ───────────────────────────────────

_CTR_BLOCK = 16


def _ctr_blocks(key: bytes, nonce: bytes, counter: int, initial_value=None):
    """Generator of AES-CTR counter blocks, following the convention below

        block = nonce || counter_field

    `counter_field` is the remaining (16 - len(nonce)) bytes, **little-endian**,
    starting at `counter` and incremented by one per block, wrapping modulo the
    field width.

    Little-endian is the choice because that is what a challenge author gets from
    struct.pack("<Q", i), which is the most common way CTR-style challenges are
    built. It is *not* pycryptodome's default (that one counts big-endian), so a
    target built with pycryptodome needs its counter block passed in explicitly
    through `initial_value`; guessing wrong here yields plausible garbage rather
    than an error, which is exactly the failure mode worth documenting.

    `initial_value` as bytes is a full 16-byte first counter block: its leading
    `len(nonce)` bytes replace the nonce and its tail is read as the counter field.
    """
    nonce = bytes(nonce)
    if len(nonce) > 12:
        raise ValueError("nonce must be at most 12 bytes so the counter field keeps at "
                         "least 32 bits; pass the counter through initial_value instead")
    width = _CTR_BLOCK - len(nonce)
    limit = 1 << (8 * width)

    if isinstance(initial_value, int):
        if counter not in (0, initial_value):
            raise ValueError("counter and initial_value disagree; pass only one of them")
        counter = initial_value
    elif initial_value is not None:
        raw = bytes(initial_value)
        if len(raw) != _CTR_BLOCK:
            raise ValueError(f"initial_value bytes must be a full 16-byte counter block, "
                             f"got {len(raw)}")
        if counter:
            raise ValueError("pass either counter or a full initial_value block, not both")
        prefix = raw[:len(nonce)]
        value = int.from_bytes(raw[len(nonce):], "little")
        while True:
            yield prefix + (value % limit).to_bytes(width, "little")
            value += 1
        return

    prefix = nonce
    value = int(counter)
    while True:
        yield prefix + (value % limit).to_bytes(width, "little")
        value += 1


def aes_ctr_keystream(key: bytes, nonce: bytes, length: int, counter: int = 0,
                      initial_value=None) -> bytes:
    """Raw AES-CTR keystream of `length` bytes (encrypt/decrypt by XORing it in)"""
    if length < 0:
        raise ValueError("length must not be negative")
    if length == 0:
        return b""
    blocks = _ctr_blocks(key, nonce, counter, initial_value)
    enc = _aes_new(bytes(key), MODE_ECB)
    out = bytearray()
    while len(out) < length:
        out += enc.encrypt(next(blocks))
    return bytes(out[:length])


def aes_ctr(key: bytes, nonce: bytes, data: bytes, counter: int = 0,
            initial_value=None) -> bytes:
    """AES-CTR encrypt/decrypt (the same call does both)

    Counter convention: `nonce || little-endian counter`, see `_ctr_blocks`. The
    block cipher comes from `cryptoexp.utils.aes`, so this stays dependency-free.
    """
    data = bytes(data)
    return _xor(data, aes_ctr_keystream(key, nonce, len(data), counter, initial_value))


# ──────────────────────── keystream reuse (the actual attacks) ─────────────────

def keystream_xor(c1: bytes, c2: bytes) -> bytes:
    """c1 ^ c2 under keystream reuse == p1 ^ p2 — the leak the attacks below use

    Truncates to the shorter ciphertext, which is the only part where both
    plaintexts exist.
    """
    return _xor(bytes(c1), bytes(c2))


def crib_drag(c1: bytes, c2: bytes, crib: bytes):
    """Slide a guessed plaintext through two same-keystream ciphertexts

    Since c1 ^ c2 == p1 ^ p2, placing `crib` at offset i inside p1 forces p2 to be
    `crib ^ (c1 ^ c2)[i:i+n]`. Returns *every* offset as a candidate
    {"position", "plaintext1", "plaintext2", "printable2"} in offset order, with
    `printable2` the printability of the implied p2 — no candidate is silently
    dropped, because filtering on printability hides the real offset when the
    plaintext is binary or the crib is only part of a word. Sort by `printable2`
    when the plaintext is known to be text, and read the offsets by hand otherwise.
    """
    c1, c2, crib = bytes(c1), bytes(c2), bytes(crib)
    if not crib:
        raise ValueError("crib must not be empty")
    leak = keystream_xor(c1, c2)
    out = []
    for i in range(max(0, len(leak) - len(crib) + 1)):
        p2 = _xor(crib, leak[i:i + len(crib)])
        out.append({"position": i, "plaintext1": crib, "plaintext2": p2,
                    "printable2": printable_ratio(p2)})
    return out


def fixed_nonce_reuse_recover(ciphertexts, known_plaintext: bytes, index: int = 0) -> dict:
    """One known plaintext breaks every message sharing the keystream

    `known_plaintext` is (a prefix of) the plaintext of `ciphertexts[index]`; the
    keystream recovered from it decrypts all the others. Only
    `min(len(known_plaintext), len(ciphertexts[index]))` keystream bytes are
    derivable, so longer ciphertexts are truncated honestly — their tail stays
    unknown rather than being padded with a guess.

    Returns {"ok", "keystream", "plaintexts", "plaintext", "index",
    "keystream_len", "detail"}.
    """
    cts = [bytes(c) for c in ciphertexts]
    if not cts:
        raise ValueError("need at least one ciphertext")
    if not 0 <= index < len(cts):
        raise ValueError(f"index {index} out of range for {len(cts)} ciphertexts")
    known = bytes(known_plaintext)
    if not known:
        raise ValueError("known_plaintext must not be empty")
    n = min(len(known), len(cts[index]))
    keystream = _xor(cts[index][:n], known[:n])
    plaintexts = [_xor(ct[:n], keystream) for ct in cts]
    return {
        "ok": True,
        "keystream": keystream,
        "keystream_len": n,
        "plaintexts": plaintexts,
        "plaintext": plaintexts[index],
        "index": index,
        "detail": (f"recovered {n} keystream bytes from ciphertext {index}; "
                   f"{sum(1 for ct in cts if len(ct) > n)} ciphertext(s) truncated"),
    }
