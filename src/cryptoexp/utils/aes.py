"""Pure-Python AES (ECB/CBC) — zero dependencies, API mirrors pycryptodome

Why write our own: cryptoexp is positioned as "infrastructure", and requiring
pycryptodome would cost portability; oracle-style attacks (ECB byte-at-a-time /
padding oracle) also need a **locally reproducible** symmetric primitive to
write tests against.

Usage (identical to pycryptodome, so the import swaps cleanly):
    from cryptoexp.utils.aes import AES, MODE_ECB, MODE_CBC
    c = AES.new(key, MODE_ECB)
    ct = c.encrypt(b'\\x00' * 16)
    pt = AES.new(key, MODE_ECB).decrypt(ct)

The S-box is **computed** from GF(2^8) inversion plus the affine transform
rather than transcribed as 256 bytes of constants — one mis-copied byte is a
disaster in a cipher implementation, so compute whatever can be computed.
Verified against the official FIPS-197 / SP800-38A vectors.
"""

MODE_ECB = 1
MODE_CBC = 2

_BLOCK = 16
_SBOX = None
_INV_SBOX = None


def _gmul(a: int, b: int) -> int:
    """GF(2^8) multiplication (modulo x^8+x^4+x^3+x+1)"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _tables():
    global _SBOX, _INV_SBOX
    if _SBOX is not None:
        return _SBOX, _INV_SBOX
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if _gmul(i, j) == 1:
                inv[i] = j
                break
    sbox = [0] * 256
    for i in range(256):
        x = inv[i]
        y = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 0xff
            y ^= x
        sbox[i] = y ^ 0x63
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    _SBOX, _INV_SBOX = sbox, inv_sbox
    return _SBOX, _INV_SBOX


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


def _expand_key(key: bytes):
    """AES key expansion → list of round keys (16 bytes each)"""
    sbox, _ = _tables()
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key length must be 16/24/32 bytes")
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [sbox[b] for b in temp]
            temp[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = [sbox[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return [bytes(sum((w[4 * r + c] for c in range(4)), [])) for r in range(nr + 1)], nr


def _add_round_key(state, rk):
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state, sbox):
    for i in range(16):
        state[i] = sbox[state[i]]


def _shift_rows(state):
    # state is column-major: state[r + 4c]
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            state[r + 4 * c] = row[c]


def _inv_shift_rows(state):
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            state[r + 4 * c] = row[c]


def _mix_columns(state):
    for c in range(4):
        i = 4 * c
        a = state[i:i + 4]
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        state[i] ^= t ^ _xtime(a[0] ^ a[1])
        state[i + 1] ^= t ^ _xtime(a[1] ^ a[2])
        state[i + 2] ^= t ^ _xtime(a[2] ^ a[3])
        state[i + 3] ^= t ^ _xtime(a[3] ^ a[0])


def _inv_mix_columns(state):
    for c in range(4):
        i = 4 * c
        a = state[i:i + 4]
        state[i] = _gmul(a[0], 14) ^ _gmul(a[1], 11) ^ _gmul(a[2], 13) ^ _gmul(a[3], 9)
        state[i + 1] = _gmul(a[0], 9) ^ _gmul(a[1], 14) ^ _gmul(a[2], 11) ^ _gmul(a[3], 13)
        state[i + 2] = _gmul(a[0], 13) ^ _gmul(a[1], 9) ^ _gmul(a[2], 14) ^ _gmul(a[3], 11)
        state[i + 3] = _gmul(a[0], 11) ^ _gmul(a[1], 13) ^ _gmul(a[2], 9) ^ _gmul(a[3], 14)


def _encrypt_block(block: bytes, rkeys, nr: int) -> bytes:
    sbox, _ = _tables()
    state = list(block)
    _add_round_key(state, rkeys[0])
    for rnd in range(1, nr):
        _sub_bytes(state, sbox)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, rkeys[rnd])
    _sub_bytes(state, sbox)
    _shift_rows(state)
    _add_round_key(state, rkeys[nr])
    return bytes(state)


def _decrypt_block(block: bytes, rkeys, nr: int) -> bytes:
    _, inv_sbox = _tables()
    state = list(block)
    _add_round_key(state, rkeys[nr])
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(state)
        _sub_bytes(state, inv_sbox)
        _add_round_key(state, rkeys[rnd])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _sub_bytes(state, inv_sbox)
    _add_round_key(state, rkeys[0])
    return bytes(state)


class _AESCipher:
    """AES cipher object — encrypt/decrypt do not pad automatically (as in pycryptodome)"""

    block_size = _BLOCK

    def __init__(self, key: bytes, mode: int, iv: bytes = None):
        if len(key) not in (16, 24, 32):
            raise ValueError("key length must be 16/24/32 bytes")
        self.key = bytes(key)
        self.mode = mode
        self.iv = bytes(iv) if iv is not None else None
        if mode == MODE_CBC and self.iv is None:
            raise ValueError("CBC needs an iv")
        self._rkeys, self._nr = _expand_key(self.key)

    def encrypt(self, data: bytes) -> bytes:
        if len(data) % _BLOCK:
            raise ValueError("encrypt needs block-aligned input (use pad.pkcs7_pad first)")
        out = bytearray()
        prev = self.iv
        for i in range(0, len(data), _BLOCK):
            blk = data[i:i + _BLOCK]
            if self.mode == MODE_CBC:
                blk = bytes(a ^ b for a, b in zip(blk, prev))
            enc = _encrypt_block(blk, self._rkeys, self._nr)
            out += enc
            prev = enc
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        if len(data) % _BLOCK:
            raise ValueError("decrypt needs block-aligned input")
        out = bytearray()
        prev = self.iv
        for i in range(0, len(data), _BLOCK):
            blk = data[i:i + _BLOCK]
            dec = _decrypt_block(blk, self._rkeys, self._nr)
            if self.mode == MODE_CBC:
                dec = bytes(a ^ b for a, b in zip(dec, prev))
                prev = blk
            out += dec
        return bytes(out)


def new(key: bytes, mode: int = MODE_ECB, iv: bytes = None) -> _AESCipher:
    """AES.new(key, MODE_ECB/MODE_CBC, iv=None) — same name and meaning as pycryptodome"""
    return _AESCipher(key, mode, iv)


def encrypt_ecb(key: bytes, data: bytes) -> bytes:
    return new(key, MODE_ECB).encrypt(data)


def decrypt_ecb(key: bytes, data: bytes) -> bytes:
    return new(key, MODE_ECB).decrypt(data)


def encrypt_cbc(key: bytes, data: bytes, iv: bytes) -> bytes:
    return new(key, MODE_CBC, iv).encrypt(data)


def decrypt_cbc(key: bytes, data: bytes, iv: bytes) -> bytes:
    return new(key, MODE_CBC, iv).decrypt(data)
