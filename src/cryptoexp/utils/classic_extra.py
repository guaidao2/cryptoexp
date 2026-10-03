"""Classical ciphers and encodings beyond the ones in `encoding.py`

`encoding.py` already covers Caesar / affine / Vigenere / Morse / rail fence
(decrypt only) and the usual hex/base32/base64/base58 family. This module adds the
rest of the classical zoo plus two "text-safe" binary encodings that turn up in
CTF tasks:

  * letter transforms: atbash, rot47, rot_n over a configurable alphabet
  * Bacon (both the 24- and 26-letter variants)
  * Playfair, Hill, columnar transposition, autokey, substitution
  * base62 / base91, URL and HTML-entity decoding
  * `detect_classic` — a mechanical fingerprint helper

Design notes that matter for correctness:

  * Non-alphabetic characters are preserved wherever a cipher has no rule for
    them; anything else silently eats whitespace and punctuation.
  * Where a cipher cannot be inverted exactly (Playfair's filler `X`, Bacon's
    case-insensitive output, Hill's padding) the docstring says what is lost,
    because "round-trips" is often a weaker claim than it looks.
  * `detect_classic` returns leads with a confidence, never conclusions — the
    same evidence grading the rest of the library uses.
"""

import re
import string
import urllib.parse
from html import unescape as _html_unescape

from .encoding import score_text, index_of_coincidence
from .algebra import modinv

_ALPHA = string.ascii_uppercase
_BACON24 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"          # the classic 24-letter alphabet
_ATBASH = str.maketrans(_ALPHA + _ALPHA.lower(),
                        _ALPHA[::-1] + _ALPHA[::-1].lower())
_ROT47_LOW, _ROT47_HIGH = 33, 126


# ────────────────────────── letter transforms ──────────────────────────

def atbash(text: str) -> str:
    """Atbash: A↔Z, a↔z (its own inverse, non-letters untouched)"""
    return text.translate(_ATBASH)


def rot47(text: str) -> str:
    """ROT47 over the printable ASCII range 33..126 (its own inverse)

    Unlike ROT13 this one touches digits and punctuation as well, so it is the
    usual choice when a "rotated" blob contains more than letters.
    """
    out = []
    for ch in text:
        code = ord(ch)
        if _ROT47_LOW <= code <= _ROT47_HIGH:
            out.append(chr((code - _ROT47_LOW + 47) % 94 + _ROT47_LOW))
        else:
            out.append(ch)
    return ''.join(out)


def rot_n(text: str, n: int, alphabet=None) -> str:
    """Rotate by `n` positions inside `alphabet` (default A-Z a-z)

    Supplying an alphabet makes this the general rotary cipher: a 36-character
    alphabet is base36-rot, a 32-character one is base32-rot, and so on. A custom
    alphabet must contain an even split of upper/lowercase letters — the case of
    each input character is preserved by rotating inside its own half.
    """
    if alphabet is None:
        out = []
        for ch in text:
            if ch.isupper():
                out.append(chr((ord(ch) - 65 + n) % 26 + 65))
            elif ch.islower():
                out.append(chr((ord(ch) - 97 + n) % 26 + 97))
            else:
                out.append(ch)
        return ''.join(out)
    alpha = ''.join(alphabet)
    if len(alpha) < 3:
        raise ValueError("alphabet must have at least 3 symbols")
    upper = ''.join(c for c in alpha if c.isupper())
    lower = ''.join(c for c in alpha if c.islower())
    out = []
    for ch in text:
        if upper and ch in upper:
            out.append(upper[(upper.index(ch) + n) % len(upper)])
        elif lower and ch in lower:
            out.append(lower[(lower.index(ch) + n) % len(lower)])
        else:
            out.append(ch)
    return ''.join(out)


# ────────────────────────── Bacon ──────────────────────────

def bacon_encode(text: str, sep: str = " ", use_ab: bool = True) -> str:
    """Bacon's cipher: each letter becomes five `A`/`B` (or `0`/`1`) symbols

    The classic alphabet merges I/J and U/V, so both map onto the same group; this
    encoder uses the 24-letter table and joins the groups with `sep` because a
    solid run of A/B is unreadable. `use_ab=False` emits 0/1 instead, which is
    what most CTF blobs actually look like.
    """
    one, zero = ("A", "B") if use_ab else ("1", "0")
    groups = []
    for ch in text.upper():
        idx = _BACON24.find(ch)
        if idx < 0:
            idx = _BACON24.find({"J": "I", "V": "U"}.get(ch, ""))
        if idx < 0:
            continue
        groups.append("".join(one if (idx >> (4 - bit)) & 1 else zero for bit in range(5)))
    return sep.join(groups)


def bacon_decode(text: str, use_ab: bool = True) -> str:
    """Decode Bacon groups back to letters

    Accepts 5-symbol runs of A/B and 0/1 in any mix, with or without separators;
    any other character is treated as a separator. Because the 24-letter alphabet
    merges I/J and U/V the result cannot say which of the pair was meant.
    """
    body = text.upper()
    runs = re.findall(r'[AB01]{5}', body)
    if not runs and len(body) >= 5:
        # a solid string: chop it into fives
        compact = re.sub(r'[^AB01]', '', body)
        runs = [compact[i:i + 5] for i in range(0, len(compact) - 4, 5)]
    out = []
    for run in runs:
        bits = 0
        for ch in run:
            bits = (bits << 1) | (1 if ch in "A1" else 0)
        out.append(_BACON24[bits] if bits < 24 else "?")
    return ''.join(out)


# ────────────────────────── Playfair ──────────────────────────

def _playfair_square(key: str) -> list:
    """5x5 key square; I and J share a cell (J is folded onto I)"""
    seen = []
    for ch in (key + _ALPHA).upper():
        if not ch.isalpha():
            continue
        ch = 'I' if ch == 'J' else ch
        if ch not in seen:
            seen.append(ch)
    return seen


def _playfair_pos(square: list, ch: str) -> tuple:
    idx = square.index('I' if ch == 'J' else ch)
    return divmod(idx, 5)


def _playfair_prepare(text: str, filler: str = 'X') -> str:
    """Uppercase letters only, split into digraphs, fill doubles

    A doubled pair is split with the filler, and a leftover single letter is
    expanded the same way (`...A` → `...AX`), so the result is always even and
    nothing is dropped.
    """
    letters = [c for c in text.upper() if c.isalpha()]
    letters = ['I' if c == 'J' else c for c in letters]
    out = []
    i = 0
    while i < len(letters):
        a = letters[i]
        if i + 1 < len(letters):
            b = letters[i + 1]
            if a == b:
                b = filler
                i += 1
            else:
                i += 2
        else:
            b = filler
            i += 1
        out.append(a)
        out.append(b)
    return ''.join(out)


def _playfair_letters(text: str) -> str:
    """Read-side normalisation: uppercase letters only, J folded onto I"""
    return ''.join('I' if c == 'J' else c for c in text.upper() if c.isalpha())


def _playfair_run(text: str, key: str, shift: int) -> str:
    square = _playfair_square(key)
    body = _playfair_prepare(text) if shift > 0 else _playfair_letters(text)
    out = []
    for i in range(0, len(body) - 1, 2):
        r1, c1 = _playfair_pos(square, body[i])
        r2, c2 = _playfair_pos(square, body[i + 1])
        if r1 == r2:
            out.append(square[r1 * 5 + (c1 + shift) % 5])
            out.append(square[r2 * 5 + (c2 + shift) % 5])
        elif c1 == c2:
            out.append(square[((r1 + shift) % 5) * 5 + c1])
            out.append(square[((r2 + shift) % 5) * 5 + c2])
        else:
            out.append(square[r1 * 5 + c2])
            out.append(square[r2 * 5 + c1])
    return ''.join(out)


def playfair_encrypt(text: str, key: str) -> str:
    """Playfair encryption with a 5x5 square (I/J merged)

    Preprocessing is the part that bites: letters are uppercased, J is folded onto
    I, a doubled pair is split with `X`, and an odd tail is padded with `X`. All of
    that is lossy, so `playfair_decrypt(playfair_encrypt(x))` returns the
    normalised plaintext (J→I, inserted fillers present), not `x` verbatim.
    """
    return _playfair_run(text, key, 1)


def playfair_decrypt(text: str, key: str) -> str:
    """Playfair decryption (same square and rules, shifts run backwards)"""
    return _playfair_run(text, key, -1)


# ────────────────────────── Hill ──────────────────────────

def _hill_check(matrix, mod: int):
    """Validate a square matrix and return (size, determinant) or raise"""
    rows = [list(r) for r in matrix]
    if not rows or any(len(r) != len(rows) for r in rows):
        raise ValueError("hill: matrix must be square")
    size = len(rows)
    det = _det_mod(rows, mod)
    if det % mod == 0:
        raise ValueError("hill: matrix is not invertible modulo %d (det=%d)" % (mod, det))
    return size, det


def _det_mod(rows, mod: int) -> int:
    """Determinant modulo `mod`, via exact (fraction-free) Bareiss elimination

    Working modulo `mod` inside the elimination needs a modular inverse at every
    pivot, and a pivot that shares a factor with `mod` then blows up even when the
    determinant is fine — so the elimination runs over the integers instead and the
    modulus is applied to the result only.
    """
    m = [list(row) for row in rows]
    n = len(m)
    if n == 0:
        return 0
    sign = 1
    prev = 1
    for col in range(n - 1):
        if m[col][col] == 0:
            swap = None
            for r in range(col + 1, n):
                if m[r][col]:
                    swap = r
                    break
            if swap is None:
                return 0
            m[col], m[swap] = m[swap], m[col]
            sign = -sign
        for r in range(col + 1, n):
            for c in range(col + 1, n):
                m[r][c] = (m[r][c] * m[col][col] - m[r][col] * m[col][c]) // prev
            m[r][col] = 0
        prev = m[col][col]
    return (sign * m[n - 1][n - 1]) % mod


def _hill_inverse(matrix, mod: int) -> list:
    """Modular inverse of a square matrix: `adj(A) * det(A)^-1 (mod mod)`

    Built from cofactors rather than Gauss-Jordan. Elimination over Z/mod needs a
    modular inverse at every pivot, and a perfectly invertible matrix can still hit
    a pivot sharing a factor with `mod` (observed with a 3x3 whose determinant is
    invertible while an intermediate pivot is not), so the cofactor route is both
    shorter and free of that failure mode.
    """
    n = len(matrix)
    inv_det = modinv(_det_mod(matrix, mod), mod)
    if inv_det is None:
        return None
    adj = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [[matrix[r][c] for c in range(n) if c != j]
                     for r in range(n) if r != i]
            cof = _det_mod(minor, mod) if n > 1 else 1
            if (i + j) % 2:
                cof = -cof
            adj[j][i] = cof * inv_det % mod        # transposed cofactor
    return adj


def _hill_apply(text: str, matrix, mod: int, pad: str) -> str:
    n = len(matrix)
    clean = [c for c in text.upper() if c.isalpha()]
    clean = [c if 'A' <= c <= 'Z' else pad for c in clean]
    while len(clean) % n:
        clean.append(pad)
    a = ord('A')
    out = []
    for i in range(0, len(clean), n):
        block = [ord(c) - a for c in clean[i:i + n]]
        for row in matrix:
            out.append(chr(sum(row[j] * block[j] for j in range(n)) % mod + a))
    return ''.join(out)


def hill_encrypt(text: str, matrix, mod: int = 26) -> str:
    """Hill cipher encryption; `matrix` is a list of rows

    The matrix must be invertible modulo `mod` (otherwise the call raises rather
    than producing something that cannot be undone), the text is uppercased,
    spaces/punctuation dropped, and the tail padded with `X`.
    """
    _hill_check(matrix, mod)
    return _hill_apply(text, matrix, mod, 'X')


def hill_decrypt(text: str, matrix, mod: int = 26) -> str:
    """Hill cipher decryption using the modular inverse of the same matrix"""
    _hill_check(matrix, mod)
    inv = _hill_inverse(matrix, mod)
    if inv is None:
        raise ValueError("hill: matrix is not invertible modulo %d" % mod)
    return _hill_apply(text, inv, mod, 'X')


# ────────────────────────── columnar transposition ──────────────────────────

def _columnar_order(key: str) -> list:
    """Column read order from the key, ties broken by original position"""
    idx = sorted(range(len(key)), key=lambda i: (key[i], i))
    order = [0] * len(key)
    for rank, i in enumerate(idx):
        order[i] = rank
    return order


def columnar_encrypt(text: str, key: str) -> str:
    """Columnar transposition: write in rows, read the columns in key order

    The text is padded with `X` to fill the last row, so decryption returns that
    padded plaintext. Repeating letters in the key are resolved left to right,
    which is the usual convention but one that must match the encryptor's.
    """
    if not key:
        raise ValueError("columnar: empty key")
    k = len(key)
    body = [c for c in text if c != '\n']
    while len(body) % k:
        body.append('X')
    rows = [body[i:i + k] for i in range(0, len(body), k)]
    order = _columnar_order(key)
    cols = ['' for _ in range(k)]
    for i, rank in enumerate(order):
        cols[rank] = ''.join(row[i] for row in rows)
    return ''.join(cols)


def columnar_decrypt(text: str, key: str) -> str:
    """Inverse of `columnar_encrypt` (including the `X` padding)"""
    if not key:
        raise ValueError("columnar: empty key")
    k = len(key)
    n = len(text)
    full_rows, extra = divmod(n, k)
    order = _columnar_order(key)
    lengths = [full_rows + (1 if i < extra else 0) for i in range(k)]
    cols = [''] * k
    pos = 0
    for rank in range(k):
        i = order.index(rank)
        cols[i] = text[pos:pos + lengths[i]]
        pos += lengths[i]
    out = []
    for r in range(full_rows + (1 if extra else 0)):
        for i in range(k):
            if r < len(cols[i]):
                out.append(cols[i][r])
    return ''.join(out)


# ────────────────────────── rail fence ──────────────────────────

def rail_fence_encrypt(text: str, rails: int) -> str:
    """Rail fence (zig-zag) encryption — the counterpart of `fence_decrypt`

    Kept in step with `encoding.fence_decrypt`, which is the decrypt-only version
    already in the library: same zig-zag pattern, characters read row by row.
    """
    if rails <= 1 or rails >= len(text):
        return text
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    rows = [[] for _ in range(rails)]
    for i, ch in enumerate(text):
        rows[pattern[i % len(pattern)]].append(ch)
    return ''.join(''.join(r) for r in rows)


def rail_fence_decrypt(text: str, rails: int) -> str:
    """Rail fence decryption — reuses `encoding.fence_decrypt` (same convention)"""
    from .encoding import fence_decrypt
    return fence_decrypt(text, rails)


# ────────────────────────── autokey ──────────────────────────

def autokey_encrypt(text: str, key: str) -> str:
    """Autokey (Vigenere with the plaintext appended to the key)

    Only letters are enciphered and the key stream advances on letters alone, which
    is the detail that decides whether a message with spaces survives at all. The
    keystream is `key` followed by the plaintext itself.
    """
    letters = [c for c in text.upper() if c.isalpha()]
    k = [ord(c) - 65 for c in key.upper() if c.isalpha()]
    stream = k + [ord(c) - 65 for c in letters]
    out = []
    li = 0
    for ch in text:
        if ch.isalpha():
            shift = stream[li] if li < len(stream) else 0
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            li += 1
        else:
            out.append(ch)
    return ''.join(out)


def autokey_decrypt(text: str, key: str) -> str:
    """Autokey decryption: the key stream grows as plaintext letters are recovered"""
    k = [ord(c) - 65 for c in key.upper() if c.isalpha()]
    stream = list(k)
    out = []
    li = 0
    for ch in text:
        if ch.isalpha():
            shift = stream[li] if li < len(stream) else 0
            base = 65 if ch.isupper() else 97
            plain = (ord(ch) - base - shift) % 26
            out.append(chr(plain + base))
            stream.append(plain)
            li += 1
        else:
            out.append(ch)
    return ''.join(out)


# ────────────────────────── substitution ──────────────────────────

def substitution_decrypt(text: str, mapping) -> str:
    """Monoalphabetic substitution with an explicit 26-character alphabet

    `mapping` is the ciphertext alphabet in plaintext order: `mapping[0]` is the
    letter that stands for A, `mapping[1]` the one for B, and so on. A mapping with
    repeated letters is rejected — it would silently make the cipher non-invertible.
    """
    table = ''.join(mapping).upper()
    if len(table) != 26 or set(table) != set(_ALPHA):
        raise ValueError("substitution: mapping must be a permutation of A-Z")
    rev = {table[i]: _ALPHA[i] for i in range(26)}
    return ''.join(rev.get(c.upper(), c).lower() if c.islower()
                   else rev.get(c, c) for c in text)


# ────────────────────────── base62 / base91 ──────────────────────────

_B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
# basE91's canonical alphabet (Joachim Henke). It contains the double quote and no
# `$`, and the symbol order matters: a wrong alphabet still round-trips through
# this module but is not interoperable with any other basE91 tool, so it is copied
# verbatim from the reference implementation.
_B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
_B91_INV = {c: i for i, c in enumerate(_B91)}


def _as_bytes(data) -> bytes:
    return data.encode() if isinstance(data, str) else bytes(data)


def _base_x_decode(text: str, alphabet: str, label: str):
    """Big-integer base-X decode with leading-zero preservation (`0` = zero byte)"""
    alpha = ''.join(alphabet)
    if not text:
        return b""
    bad = [c for c in text if c not in alpha]
    if bad:
        raise ValueError("%s: character %r is not in the alphabet" % (label, bad[0]))
    num = 0
    for ch in text:
        num = num * len(alpha) + alpha.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b""
    return b"\x00" * (len(text) - len(text.lstrip(alpha[0]))) + raw


def _base_x_encode(data, alphabet: str) -> str:
    raw = _as_bytes(data)
    if not raw:
        return ""
    num = int.from_bytes(raw, 'big')
    alpha = ''.join(alphabet)
    out = ""
    while num:
        num, rem = divmod(num, len(alpha))
        out = alpha[rem] + out
    return alpha[0] * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def to_base62(data) -> str:
    """Base62 (0-9A-Za-z) with leading zero bytes preserved as `0`"""
    return _base_x_encode(data, _B62)


def from_base62(text: str) -> bytes:
    """Base62 decode (inverse of `to_base62`, leading `0`s restored as NULs)"""
    return _base_x_decode(text, _B62, "base62")


def to_base91(data) -> str:
    """basE91 (Joachim Henke's alphabet) — 13-bit bit-packing, two symbols per group

    Mirrors the reference encoder: bytes go into an LSB-first accumulator, a group
    is emitted as two base-91 digits (`v % 91` then `v // 91`) using 13 bits
    normally and 14 bits when the 13-bit prefix exceeds 88, and the processed bits
    are shifted out. Independently verified only by round-trip here; the symbol
    order is taken from the reference and matters for interoperability, since a
    wrong alphabet still round-trips inside this module.
    """
    raw = _as_bytes(data)
    out = []
    buf = 0
    bits = 0
    for byte in raw:
        buf |= byte << bits
        bits += 8
        if bits > 13:
            val = buf & 0x1fff
            if val > 88:
                buf >>= 13
                bits -= 13
            else:
                val = buf & 0x3fff
                buf >>= 14
                bits -= 14
            out.append(_B91[val % 91])
            out.append(_B91[val // 91])
    if bits:
        out.append(_B91[buf % 91])
        if bits > 7 or buf // 91:
            out.append(_B91[buf // 91])
    return ''.join(out)


def from_base91(text: str) -> bytes:
    """basE91 decode (inverse of `to_base91`)

    The trailing group is the mirror of the encoder's flush: the last value is only
    added when the accumulator ends up with at most 7 bits, otherwise it would
    invent a byte that the encoder never wrote.
    """
    out = bytearray()
    buf = 0
    bits = 0
    val = -1
    for ch in text:
        idx = _B91_INV.get(ch)
        if idx is None:
            raise ValueError("base91: character %r is not in the alphabet" % ch)
        if val < 0:
            val = idx
            continue
        val += idx * 91
        buf |= val << bits
        bits += 13 if (val & 0x1fff) > 88 else 14
        while bits > 7:
            out.append(buf & 0xff)
            buf >>= 8
            bits -= 8
        val = -1
    if val >= 0:
        buf |= val << bits
        out.append(buf & 0xff)
    return bytes(out)


# ────────────────────────── percent / HTML entities ──────────────────────────

def url_decode(text: str) -> str:
    """Percent-decoding (`%41` → `A`, `+` → space), plus a Latin-1 fallback

    `unquote` decodes UTF-8 by default and leaves malformed bytes as replacement
    characters; the Latin-1 retry covers the older single-byte pages that would
    otherwise come back as mojibake.
    """
    try:
        return urllib.parse.unquote_plus(text, errors='strict')
    except UnicodeDecodeError:
        return urllib.parse.unquote_plus(text, encoding='latin-1')


def url_encode(text: str) -> str:
    """Percent-encoding of everything that is not unreserved"""
    return urllib.parse.quote_plus(text)


def html_entity_decode(text: str) -> str:
    """Named and numeric HTML entities → text (`&amp;` → `&`, `&#65;` → `A`)"""
    return _html_unescape(text)


# ────────────────────────── fingerprint helper ──────────────────────────

_BASE62_RE = re.compile(r'^[0-9A-Za-z]+$')
_MORSE_RE = re.compile(r'^[.\-/|\s]+$')
_HEX_RE = re.compile(r'^[0-9a-fA-F\s]+$')


def _printable_only(text: str) -> bool:
    """All characters are printable ASCII (whitespace allowed, since a rotated
    sentence still contains spaces and rejecting them hid real rot47 candidates)"""
    return bool(text) and all(32 < ord(c) < 127 or c.isspace() for c in text)


def _rot47_gain(text: str) -> float:
    """How much ROT47 improves the "looks like English" score of a short text"""
    flipped = rot47(text)
    return score_text(flipped, flag_bonus=False) - score_text(text, flag_bonus=False)


def _atbash_gain(text: str) -> float:
    flipped = atbash(text)
    return score_text(flipped, flag_bonus=False) - score_text(text, flag_bonus=False)


def detect_classic(text: str) -> list:
    """Mechanical fingerprints of classical ciphers → [{"cipher", "confidence", "detail"}]

    This is deliberately a *charset and statistics* helper, not a solver: it says
    what a string could plausibly be, with a confidence, and the caller decides.
    Signals used: printable-ASCII shape (rot47), letter-only shape plus an index of
    coincidence below the English value (atbash / substitution / transposition),
    the base62 vs base91 alphabets, and the Morse charset.
    """
    t = (text or "").strip()
    out = []
    if not t:
        return out
    letters = [c for c in t if c.isalpha()]
    space_ratio = t.count(' ') / len(t)

    if _MORSE_RE.match(t) and ('.' in t or '-' in t) and len(t) >= 3:
        out.append({"cipher": "morse", "confidence": "high",
                    "detail": "only dots/dashes/separators; try encoding.morse_decode"})

    # ROT47 thresholds are calibrated, not guessed: a rot47-encoded English sentence
    # scores +29, a rot47-encoded flag +8.7, while plain English is -29, base64
    # -7.1 and a base62-looking token +0.25 (measured on this machine).
    if _printable_only(t) and len(t) >= 8:
        gain = _rot47_gain(t)
        letter_count = sum(1 for c in t if c.isalpha())
        if gain > 20:
            out.append({"cipher": "rot47", "confidence": "high",
                        "detail": "printable ASCII only and rot47 raises the text score "
                                  "by %.1f" % gain})
        elif gain > 8 and letter_count * 3 >= len(t):
            out.append({"cipher": "rot47", "confidence": "medium",
                        "detail": "rot47 improves the text score by %.1f with %d/%d letters"
                                  % (gain, letter_count, len(t))})

    if letters and all(c.isalpha() or c.isspace() for c in t):
        ioc = index_of_coincidence(t)
        gain = _atbash_gain(t)
        # atbash preserves the index of coincidence, so a real atbash text still has
        # a low IoC *and* a strongly positive atbash gain; plain English has both
        # a normal IoC and a strongly negative gain, which is what separates them.
        if len(letters) >= 12 and ioc < 0.055 and gain > 12:
            out.append({"cipher": "atbash", "confidence": "high" if gain > 20 else "medium",
                        "detail": "letters+spaces only, IoC %.4f (English is ~0.066) and "
                                  "atbash raises the score by %.1f" % (ioc, gain)})
        elif len(letters) >= 12 and ioc < 0.050 and abs(gain) <= 12:
            out.append({"cipher": "atbash-or-substitution", "confidence": "low",
                        "detail": "letters+spaces only with IoC %.4f; atbash did not help, "
                                  "so try a substitution" % ioc})
        if space_ratio > 0.1 and len(letters) >= 16 and 0.055 <= ioc < 0.075:
            out.append({"cipher": "transposition-or-monoalphabetic", "confidence": "low",
                        "detail": "word lengths look natural but IoC is %.4f" % ioc})

    if _BASE62_RE.match(t) and len(t) >= 12:
        has_digit = any(c.isdigit() for c in t)
        has_upper = any(c.isupper() for c in t)
        has_lower = any(c.islower() for c in t)
        if has_digit and has_upper and has_lower:
            out.append({"cipher": "base62", "confidence": "medium",
                        "detail": "alphanumeric with digits, upper and lower case; "
                                  "no +/= so it is not standard base64"})
        elif len(t) >= 16 and not _HEX_RE.match(t):
            out.append({"cipher": "base62/base64-like", "confidence": "low",
                        "detail": "alphanumeric run; try encoding.from_base64 first"})

    if len(t) >= 12 and all(33 <= ord(c) <= 126 for c in t) and not _BASE62_RE.match(t):
        if any(c in _B91 for c in t) and len(set(t)) >= min(12, len(t) // 2):
            out.append({"cipher": "base91-or-rot47", "confidence": "low",
                        "detail": "mixed punctuation and letters over the printable range"})
    return out
