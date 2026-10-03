"""ADFGX / ADFGVX fractionating transposition ciphers (German field ciphers, 1918)

Both ciphers are two layers stacked: a *fractionating* substitution that turns every
plaintext symbol into a two-letter coordinate pair, and a *columnar transposition* of
the resulting pair stream. Historical descriptions disagree on almost every detail, so
the conventions are pinned down here once, at the top of the module, and every function
below implements exactly these:

  * labels: ADFGX uses ("A", "D", "F", "G", "X"), ADFGVX uses
    ("A", "D", "F", "G", "V", "X"), in that order, labelling rows then columns.
  * square layout: row-major, built from a keyword the same way `classic_extra` builds
    the Playfair square - the keyword's unique symbols first, then the rest of the
    alphabet in order. ADFGX's alphabet is `classic_extra`'s 25-letter one (A-Z with J
    merged onto I, so a J in the keyword or the plaintext is folded onto I); ADFGVX's is
    A-Z followed by 0-9. `square[r][c]` holds one plaintext symbol and its coordinate
    pair is `labels[r] + labels[c]`; with the unkeyed square that makes A -> "AA",
    B -> "AD", F -> "DA", and the last cell of the ADFGVX square (9) -> "XX".
  * transposition: the pair stream is written row by row into a grid `len(key)` columns
    wide and read out column by column, columns ordered by their key letter with ties
    broken left to right - the same order `classic_extra.columnar_encrypt` uses. The
    grid is NOT padded: the last row may be short. That is what makes
    `decrypt(encrypt(x)) == x` exact instead of "exact up to a run of fillers". A
    ciphertext written by a tool that *does* pad still decrypts, with the filler
    symbols visible in the output.
  * digits: ADFGVX carries 0-9 in its square, so digits pass through untouched by
    default. The older habit of substituting digits with letters first ("0-9 -> the
    keyword's unique letters") is the explicit `digit_substitution=` parameter, never a
    hidden default. ADFGX has nowhere to put a digit and raises instead of dropping it;
    whitespace and punctuation are dropped (and the docstrings say so, since that makes
    a round trip lossy).

Losses that are not bugs (they are properties of the cipher):
  * ADFGX merges I and J, so a decrypted "I" may originally have been "J".
  * with `digit_substitution=` a letter that is also a digit substitute is read back as
    that digit - the substitution is not invertible when the plaintext uses those same
    letters as letters.
  * a transposition key is only ever recovered up to its *relative letter order*: every
    keyword that sorts the columns the same way decrypts identically.

`adfgvx_crack` is the search helper. It follows the library's result convention
`{"ok", "key", "plaintext", "square", "note", "score"}` (plus `variant`, `order`,
`keylen`, `seconds`) and every answer it reports is verified by re-encrypting the
plaintext with the recovered key and square and comparing against the input. Two honest
limits are built in and repeated in the results' `note`:

  * starting from a supplied square, only the column order is unknown, and that is a
    solved problem (all `k!` orders are enumerated for short keys, simulated annealing
    above that). But in a pure transposition *every* order reproduces the ciphertext, so
    the verification only rejects invalid candidates - it is the English score that
    selects the answer, and a very short ciphertext can therefore still give the wrong
    key.
  * starting without a square there are two unknowns and one message. Any bijection from
    the coordinate pairs to plaintext symbols *is* a legal square, so "the square is not
    recoverable from a single message" is the truthful answer in general. What this
    module does instead of pretending: it sweeps keyword guesses (whether a challenge
    statement names one) and, for ADFGX, runs a joint order/grid hill climb - and then
    only reports an answer that also passes a word-evidence gate, because a fitted grid
    can raise the letter score on noise. When nothing passes, the result says so and
    keeps the best round trip in `hypothesis` rather than calling it the plaintext.

Search objective: `encoding.score_text(..., flag_bonus=False)` only. A flag-shaped match
never contributes to the score (that is what makes a hill climb fabricate flags); any
flag found in a recovered plaintext is reported as a by-product in `note`.

Standard library only. Scratch/verification lives outside this module.
"""

import itertools
import math
import random
import string
import time

from .encoding import flag_candidates, loose_flag_candidates, score_text
# `_WORDLIST` is private to `encoding`, and deliberately so: it is used here only as a
# source of *keyword guesses* (the same way `bivariate` reuses a private lattice
# helper), never as a scoring table - the scoring call is the public `score_text`.
from .encoding import _WORDLIST

__all__ = [
    "adfgx_square", "adfgvx_square",
    "adfgx_encrypt", "adfgx_decrypt", "adfgvx_encrypt", "adfgvx_decrypt",
    "adfgvx_detect", "adfgvx_crack",
]

_ALPHA5 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"          # 25 symbols: A-Z with J merged onto I
_ALPHA6 = string.ascii_uppercase + string.digits
_LABELS5 = ("A", "D", "F", "G", "X")
_LABELS6 = ("A", "D", "F", "G", "V", "X")

# English letter order with J dropped, so it lines up with the 25 ADFGX cells. Used only
# as the *starting* point of the joint grid fit, which then hill-climbs away from it.
_EN_ORDER25 = "ETAOINSHRDLCUMWFGYPBVKXQZ"

# Square-keyword guesses for the no-square path: the identity square first (a lazy
# encryptor's square), then words a statement or a challenge title plausibly uses.
_SQUARE_KEY_GUESSES = (
    "", "KEY", "KEYWORD", "SECRET", "CIPHER", "CRYPTO", "PASSWORD", "ADFGX", "ADFGVX",
    "SQUARE", "MATRIX", "ALPHABET", "GERMAN", "ZEBRA", "QWERTY", "CODE", "FLAG", "CTF",
    "ATTACK", "MESSAGE", "ENIGMA", "FIELD", "RADIO", "WIRE", "TRENCH", "PHONE",
    "HIDDEN", "PLAIN", "SIMPLE", "WORLD", "HELLO", "BATTLE", "NORTH", "SOUTH", "EAST",
    "WEST", "SPY", "ARMY", "TANK", "SHELL",
)

_EFFORT = {
    "quick": {"budget": 3.0, "exact_max": 6, "square_exact_max": 5, "restarts": 1,
              "iters": 400, "t0": 3.0, "t1": 0.05, "wordlist_keys": False,
              "joint": False, "joint_rounds": 1, "joint_passes": 1,
              "joint_max_keylen": 6, "joint_min": 120, "penalty": 1.0,
              "seed": 0x41444647},
    "normal": {"budget": 15.0, "exact_max": 7, "square_exact_max": 6, "restarts": 3,
               "iters": 2000, "t0": 4.0, "t1": 0.02, "wordlist_keys": True,
               "joint": True, "joint_rounds": 2, "joint_passes": 2,
               "joint_max_keylen": 8, "joint_min": 120, "penalty": 1.0,
               "seed": 0x41444647},
    "deep": {"budget": 60.0, "exact_max": 8, "square_exact_max": 7, "restarts": 8,
             "iters": 8000, "t0": 6.0, "t1": 0.01, "wordlist_keys": True,
             "joint": True, "joint_rounds": 4, "joint_passes": 3,
             "joint_max_keylen": 10, "joint_min": 120, "penalty": 1.0,
             "seed": 0x41444647},
}


# ────────────────────────── small normalisation helpers ──────────────────────────

def _norm_key(key) -> str:
    """A keyword reduced to the symbols that can order columns (uppercase alnum)"""
    return "".join(c for c in str(key).upper() if c.isalnum())


def _fold(ch: str, alphabet) -> str:
    """J -> I when the square keeps only 25 letters (the ADFGX convention)"""
    if ch == "J" and "J" not in alphabet and "I" in alphabet:
        return "I"
    return ch


def _read_order(key) -> list:
    """Columns of the transposition grid in the order they are read

    `order[r]` is the index of the column read at rank r. Sorting is by (letter, index),
    so a repeated key letter is resolved left to right, matching
    `classic_extra.columnar_encrypt`.
    """
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def _canonical_key(read_order) -> str:
    """The alphabetically first keyword that produces this read order

    Column i is read at rank r, so giving column i the letter for rank r makes the
    keyword sort into exactly that order. "BAC" is the canonical key for the order that
    "KEY" produces; any other keyword with the same relative order decrypts identically.
    """
    rank = [0] * len(read_order)
    for r, col in enumerate(read_order):
        rank[col] = r
    return "".join(chr(ord("A") + r) for r in rank)


def _build_square(key, alphabet, labels) -> list:
    """Key square as a list of row strings, row-major (see the module docstring)"""
    size = len(labels)
    alpha = "".join(alphabet).upper()
    if len(alpha) != size * size:
        raise ValueError("adfgx: alphabet for a %dx%d square needs %d symbols, got %d"
                         % (size, size, size * size, len(alpha)))
    if len(set(alpha)) != len(alpha):
        raise ValueError("adfgx: alphabet must not repeat a symbol")
    for ch in alpha:
        if not ch.isalnum():
            raise ValueError("adfgx: alphabet symbols must be letters or digits, got %r"
                             % ch)
    seen = []
    for ch in _norm_key(key):
        ch = _fold(ch, alpha)
        if ch in alpha and ch not in seen:
            seen.append(ch)
    for ch in alpha:
        if ch not in seen:
            seen.append(ch)
    return ["".join(seen[r * size:(r + 1) * size]) for r in range(size)]


def _square_size_hint(square):
    """5 or 6 when the *shape* of `square` already fixes the variant, else None"""
    if square is None or isinstance(square, str):
        return None
    if not isinstance(square, (list, tuple)):
        return None
    seq = list(square)
    if (len(seq) == 2 and isinstance(seq[0], (list, tuple))
            and isinstance(seq[1], (list, tuple))):
        return len(seq[1])
    return len(seq)


def _normalize_square(square, size, alphabet, labels):
    """Any accepted `square` spelling -> (rows, labels)

    Accepted: None (the unkeyed square over `alphabet`), a keyword string (build the
    square from it), the `(rows, labels)` tuple that `adfgx_square`/`adfgvx_square`
    return, or a raw list of rows (its own symbols then define the alphabet, which is
    what lets a *recovered* grid be fed back in). A raw grid is checked for shape, for
    alphanumeric cells and for distinctness - a repeated cell would make the coordinate
    mapping non-invertible.
    """
    if square is None or isinstance(square, str):
        return _build_square(square or "", alphabet, labels), tuple(labels)
    seq = list(square)
    if (len(seq) == 2 and isinstance(seq[0], (list, tuple))
            and isinstance(seq[1], (list, tuple)) and len(seq[0]) == size):
        rows = ["".join(r) for r in seq[0]]
        got = tuple("".join(x) for x in seq[1])
        if len(got) != size:
            raise ValueError("adfgx: %d labels given for a %dx%d square"
                             % (len(labels), size, size))
        labels = got
    else:
        rows = ["".join(r) for r in seq]
    if len(rows) != size or any(len(r) != size for r in rows):
        raise ValueError("adfgx: square must be %d rows of %d symbols, got %s"
                         % (size, size, [len(r) for r in rows]))
    cells = "".join(rows)
    if len(set(cells)) != size * size:
        raise ValueError("adfgx: square cells must be distinct (it is a substitution)")
    for ch in cells:
        if not ch.isalnum():
            raise ValueError("adfgx: square cells must be letters or digits, got %r" % ch)
    return rows, tuple(labels)


def _plaintext_symbols(text, rows, size, digit_map) -> str:
    """Uppercase alnum symbols that have a square cell; punctuation/space is dropped

    A digit with no cell (ADFGX, or a custom 25-symbol alphabet) raises rather than
    being dropped: it cannot be undone, and silently losing it is how a "round trip"
    claim turns out to be false.
    """
    alpha = set("".join(rows))
    out = []
    for ch in str(text).upper():
        ch = _fold(ch, alpha)
        if digit_map is not None and ch.isdigit():
            ch = digit_map[int(ch)]
        if ch in alpha:
            out.append(ch)
        elif ch.isalnum():
            raise ValueError("adfgx: %r has no cell in this %dx%d square (digits need "
                             "digit_substitution= or the ADFGVX square)" % (ch, size, size))
    return "".join(out)


def _encode_pairs(body, rows, labels) -> str:
    """Plaintext symbols -> label pairs (`AX` for the symbol at row 0, column 4)"""
    size = len(labels)
    pos = {ch: divmod(idx, size) for idx, ch in enumerate("".join(rows))}
    return "".join(labels[pos[ch][0]] + labels[pos[ch][1]] for ch in body)


def _decode_pairs(stream, rows, labels) -> str:
    """Label pairs -> plaintext symbols (the inverse of `_encode_pairs`)"""
    if len(stream) % 2:
        raise ValueError("adfgx: %d coordinate symbols cannot be paired" % len(stream))
    return _make_decoder(rows, labels)(stream)


def _make_decoder(rows, labels):
    """A closure turning a coordinate stream into plaintext (the search hot path)

    No dict of pairs is needed: the row-major square *is* the lookup table, with
    `square[r][c]` at flat index `r*size + c`, so decoding costs one list index per pair.
    """
    size = len(labels)
    pos = {ch: i for i, ch in enumerate(labels)}
    flat = [ch for row in rows for ch in row]

    def decode(stream):
        return "".join(flat[pos[a] * size + pos[b]]
                       for a, b in zip(stream[0::2], stream[1::2]))

    return decode


def _ciphertext_stream(text, labels) -> str:
    """Ciphertext -> the coordinate stream (whitespace separators tolerated)

    Anything that is not a label is a ValueError: a wrong symbol means the caller has
    the wrong variant or the wrong square, and guessing around it hides that.
    """
    out = []
    for ch in str(text).upper():
        if ch.isspace():
            continue
        if ch not in labels:
            raise ValueError("adfgx: ciphertext symbol %r is not one of %s"
                             % (ch, "".join(labels)))
        out.append(ch)
    return "".join(out)


def _strip_ws(text) -> str:
    """Uppercase with whitespace removed (the cracker's view of the ciphertext)"""
    return "".join(ch for ch in str(text).upper() if not ch.isspace())


# ────────────────────────── transposition ──────────────────────────

def _fractionate(stream, key) -> str:
    """Write the pair stream in rows of `len(key)` and read the columns in key order"""
    k = len(key)
    if k <= 1:
        return stream
    rows = [stream[i:i + k] for i in range(0, len(stream), k)]
    out = []
    for col in _read_order(key):
        out.append("".join(row[col] for row in rows if col < len(row)))
    return "".join(out)


def _defractionate(text, key) -> str:
    """Inverse of `_fractionate` for a keyword (keyword -> read order -> grid)"""
    return _detranspose(text, _read_order(_norm_key(key)))


def _detranspose(text, read_order) -> str:
    """Inverse of `_fractionate` given the column read order

    Column j holds one symbol more than the others when j < len(text) % width, because
    the grid is filled left to right; that single line is all the ragged-row arithmetic
    there is.
    """
    k = len(read_order)
    if k <= 1:
        return text
    full, extra = divmod(len(text), k)
    lengths = [full + (1 if j < extra else 0) for j in range(k)]
    cols = [""] * k
    pos = 0
    for col in read_order:
        cols[col] = text[pos:pos + lengths[col]]
        pos += lengths[col]
    out = []
    for start in range(0, len(text), k):
        row = start // k
        for col in range(k):
            if start + col < len(text):
                out.append(cols[col][row])
    return "".join(out)


# ────────────────────────── digit substitution (ADFGVX) ──────────────────────────

def _digit_map(spec):
    """`digit_substitution=` -> a 10-letter string (index i is the stand-in for digit i)

    Three accepted spellings, in precedence order: None (no substitution - the 6x6
    square holds the digits itself), a 10-symbol string of distinct letters (an explicit
    mapping), or a longer keyword whose unique letters supply the mapping. A keyword with
    fewer than 10 unique letters is refused instead of being padded with invented
    letters, because "0-9 -> the keyword's unique letters" is only well defined when the
    keyword has ten of them.
    """
    if spec is None:
        return None
    if isinstance(spec, str):
        body = spec.upper()
    else:
        body = "".join(str(x) for x in spec).upper()
    chars = [c for c in body if c.isalnum()]
    if len(chars) == 10 and len(set(chars)) == 10 and all(c.isalpha() for c in chars):
        return "".join(chars)
    uniq = []
    for c in chars:
        if c.isalpha() and c not in uniq:
            uniq.append(c)
    if len(uniq) < 10:
        raise ValueError("digit_substitution: need 10 distinct letters (an explicit "
                         "10-letter mapping, or a keyword with >= 10 unique letters); "
                         "%r supplies %d" % (spec, len(uniq)))
    return "".join(uniq[:10])


def _undo_digits(text, digit_map) -> str:
    """Map the digit stand-ins back to digits (lossy where plaintext letters collide)"""
    if not digit_map:
        return text
    rev = {ch: str(i) for i, ch in enumerate(digit_map)}
    return "".join(rev.get(ch, ch) for ch in text)


# ────────────────────────── public: squares ──────────────────────────

def adfgx_square(key="", alphabet=None):
    """ADFGX key square -> (square, labels)

    `square` is a list of 5 row strings of 5 symbols each, row-major; `labels` is the
    tuple ("A", "D", "F", "G", "X"). `square[r][c]` is the plaintext symbol whose
    coordinate pair is `labels[r] + labels[c]`. The square is the keyword's unique
    letters followed by the rest of `alphabet` (default A-Z with J merged onto I, so a
    J in `key` is folded onto I).
    """
    labels = _LABELS5
    return _build_square(key, alphabet or _ALPHA5, labels), labels


def adfgvx_square(key="", alphabet=None):
    """ADFGVX key square -> (square, labels)

    Same shape as `adfgx_square` but 6x6 over `alphabet` (default A-Z followed by 0-9)
    with the labels ("A", "D", "F", "G", "V", "X").
    """
    labels = _LABELS6
    return _build_square(key, alphabet or _ALPHA6, labels), labels


# ────────────────────────── public: encrypt / decrypt ──────────────────────────

def _run_encrypt(plaintext, key, rows, labels, digit_map) -> str:
    body = _plaintext_symbols(plaintext, rows, len(labels), digit_map)
    return _fractionate(_encode_pairs(body, rows, labels), _norm_key(key))


def _run_decrypt(ciphertext, key, rows, labels, digit_map) -> str:
    stream = _ciphertext_stream(ciphertext, set(labels))
    if len(stream) % 2:
        raise ValueError("adfgx: %d coordinate symbols cannot be paired" % len(stream))
    body = _defractionate(stream, key)
    return _undo_digits(_decode_pairs(body, rows, labels), digit_map)


def adfgx_encrypt(plaintext, key="", square=None, alphabet=None, labels=None):
    """ADFGX encryption -> the ciphertext string (label letters only, no separators)

    `key` is the *transposition* keyword; `square` is the square, and `square=None`
    means the unkeyed square over `alphabet` (build a keyed one with
    `adfgx_square("KEYWORD")` and pass the tuple, or pass just the keyword string). An
    empty `key` skips the transposition and returns the plain coordinate stream.

    Lossy by design: punctuation and whitespace are dropped and J is folded onto I, so
    `adfgx_decrypt(adfgx_encrypt(x))` returns the normalised plaintext, not `x`. A digit
    is a ValueError - the 5x5 square has no cell for one.
    """
    rows, labels = _normalize_square(square, 5, alphabet or _ALPHA5, labels or _LABELS5)
    return _run_encrypt(plaintext, key, rows, labels, None)


def adfgx_decrypt(ciphertext, key="", square=None, alphabet=None, labels=None):
    """ADFGX decryption -> the plaintext string (spaces/punctuation are not restored)"""
    rows, labels = _normalize_square(square, 5, alphabet or _ALPHA5, labels or _LABELS5)
    return _run_decrypt(ciphertext, key, rows, labels, None)


def adfgvx_encrypt(plaintext, key="", square=None, digit_substitution=None,
                   alphabet=None, labels=None):
    """ADFGVX encryption -> the ciphertext string

    `key` is the transposition keyword and `square` works exactly as in `adfgx_encrypt`
    (6x6 here). `digit_substitution=None` (the default) sends digits through the square
    as themselves; anything else names the 0-9 -> letters mapping, applied to the
    plaintext before fractionation (see `_digit_map` for the accepted spellings: an
    explicit 10-letter mapping, or a keyword with at least ten unique letters).
    """
    rows, labels = _normalize_square(square, 6, alphabet or _ALPHA6, labels or _LABELS6)
    return _run_encrypt(plaintext, key, rows, labels, _digit_map(digit_substitution))


def adfgvx_decrypt(ciphertext, key="", square=None, digit_substitution=None,
                   alphabet=None, labels=None):
    """ADFGVX decryption -> the plaintext string

    Pass the same `digit_substitution` used to encrypt. Digits substituted before
    encryption come back as the stand-in letters were writable both ways: a plaintext
    letter equal to a stand-in is read as the digit, which is inherent to the scheme and
    is why the parameter is never applied by default.
    """
    rows, labels = _normalize_square(square, 6, alphabet or _ALPHA6, labels or _LABELS6)
    return _run_decrypt(ciphertext, key, rows, labels, _digit_map(digit_substitution))


# ────────────────────────── public: detection ──────────────────────────

def _uniform_note(text, labels) -> str:
    """Evidence line: the per-label counts and how flat they are"""
    counts = [text.count(c) for c in labels]
    lo = min(counts)
    ratio = (max(counts) / lo) if lo else float("inf")
    return ("counts %s = %s (max/min %.2f; a fractionated coordinate stream is close to "
            "flat, English over the same labels is not)"
            % ("/".join(labels), "/".join(str(c) for c in counts), ratio))


def adfgvx_detect(text):
    """Does this look like an ADFGX / ADFGVX ciphertext? -> dict of evidence

    Returns {"is_adfgvx": bool, "labels": tuple, "variant": "adfgx"|"adfgvx"|None,
    "why": str}. `is_adfgvx` is True for either variant of the family (the caller reads
    `variant` to tell them apart); on a miss it is False, `labels` is () and `variant`
    is None, with `why` naming the symbols that are outside both label sets.

    The decision, and why it is nearly free of false positives: a fractionated
    ciphertext is built from five (ADFGX) or six (ADFGVX) symbols and nothing else. So
    "every character is one of A/D/F/G/X" is the ADFGX signature (a 5-symbol alphabet);
    "every character is one of A/D/F/G/V/X, the text contains a V, and the length is
    even" is the ADFGVX signature - ADFGVX needs the parity test because 0-9 and the
    other 21 letters leave the alphabet in pairs, while an all-ADFGX text is reported as
    ADFGX even when its length is odd (the length is then mentioned as a caveat, because
    such a stream cannot be paired). Whitespace is treated as a group separator and
    ignored. Everything else - including ordinary English, which contains letters outside
    both sets - is a miss. Shortest accepted length is 4 symbols; below that the charset
    test matches a 2-letter word by chance and the function says so instead of guessing.
    """
    t = _strip_ws(text)
    if not t:
        return {"is_adfgvx": False, "labels": (), "variant": None,
                "why": "empty input"}
    chars = set(t)
    odd = len(t) % 2
    if chars <= set(_LABELS5):
        variant, labels = "adfgx", _LABELS5
    elif chars <= set(_LABELS6) and not odd and "V" in chars:
        variant, labels = "adfgvx", _LABELS6
    else:
        outside = sorted(chars - set(_LABELS6))
        if outside:
            why = ("%d symbol(s) are outside both label sets (%s), so it is not a "
                   "fractionated ADFGX/ADFGVX stream"
                   % (len(outside), ", ".join(outside[:8])))
        else:
            why = ("only the ADFGVX labels are used but the length is odd (%d), so the "
                   "coordinate pairs cannot be formed" % len(t))
        return {"is_adfgvx": False, "labels": (), "variant": None, "why": why}
    if len(t) < 4:
        return {"is_adfgvx": False, "labels": (), "variant": None,
                "why": ("only %d label character(s): the %d-symbol alphabet matches a "
                        "short ordinary string by chance, so this is not evidence"
                        % (len(t), len(labels)))}
    why = ("every character is one of the %d %s labels (%s); %s"
           % (len(labels), variant.upper(), "".join(labels), _uniform_note(t, labels)))
    if variant == "adfgx" and odd:
        why += ("; length %d is odd, so this cannot be paired - check for a truncated "
                "or padded copy" % len(t))
    if variant == "adfgvx":
        why += "; length %d is even, as coordinate pairs require" % len(t)
    if len(t) < 8:
        why += "; short (%d symbols), so treat it as a lead rather than a signature" % len(t)
    return {"is_adfgvx": True, "labels": labels, "variant": variant, "why": why}


# ────────────────────────── cracker: search primitives ──────────────────────────

def _effort(effort, time_budget=None) -> dict:
    cfg = _EFFORT.get(str(effort).lower())
    if cfg is None:
        raise ValueError("adfgvx_crack: effort must be one of %s"
                         % ", ".join(sorted(_EFFORT)))
    out = dict(cfg)
    if time_budget is not None:
        out["budget"] = max(0.1, float(time_budget))
    return out


def _search_order(k, evaluate, cfg, deadline, rng):
    """Best column read order for one key length -> (score, order, complete)

    Exhaustive over all k! orders up to `cfg["exact_max"]` (that is the honest answer
    for short keys), simulated annealing above it. `complete` is False when the deadline
    cut the scan short, so the caller can say so instead of implying full coverage.
    """
    if k <= 1:
        order = (0,)
        return evaluate(order), order, True
    if k <= cfg["exact_max"]:
        best_sc, best_order = None, None
        for perm in itertools.permutations(range(k)):
            if time.monotonic() > deadline:
                return best_sc, best_order, False
            sc = evaluate(perm)
            if best_sc is None or sc > best_sc:
                best_sc, best_order = sc, perm
        return best_sc, best_order, True
    best_sc, best_order = None, None
    iters = cfg["iters"]
    for restart in range(cfg["restarts"]):
        order = list(range(k))
        if restart:
            rng.shuffle(order)
        cur_sc = evaluate(order)
        if best_sc is None or cur_sc > best_sc:
            best_sc, best_order = cur_sc, tuple(order)
        for step in range(iters):
            if not (step & 15) and time.monotonic() > deadline:
                return best_sc, best_order, False
            temp = cfg["t0"] * (cfg["t1"] / cfg["t0"]) ** (step / float(iters))
            i, j = rng.randrange(k), rng.randrange(k)
            while j == i:
                j = rng.randrange(k)
            order[i], order[j] = order[j], order[i]
            sc = evaluate(order)
            delta = sc - cur_sc
            if delta >= 0 or rng.random() < math.exp(delta / max(temp, 1e-9)):
                cur_sc = sc
                if sc > best_sc:
                    best_sc, best_order = sc, tuple(order)
            else:
                order[i], order[j] = order[j], order[i]
        if time.monotonic() > deadline:
            return best_sc, best_order, False
    return best_sc, best_order, True


def _order_scorer(stream, decode):
    """evaluate(read_order) = language score of the plaintext that order produces"""
    def evaluate(order):
        return score_text(decode(_detranspose(stream, order)), flag_bonus=False)
    return evaluate


def _search_all_lengths(stream, decode, max_keylen, cfg, deadline, rng):
    """Search every key length 1..min(max_keylen, 26, len(stream)) for the best order

    Returns None when nothing at all could be evaluated, otherwise a dict with the
    winning `order`, its `keylen` and raw `score`, whether its scan was `complete`, and
    the per-length list (so the caller can report the coverage). Lengths are ranked by
    `score - penalty * keylen`: a longer key has more free parameters and can score well
    by luck, which is the same overfitting charge `encoding.vigenere_recover` makes.
    """
    evaluate = _order_scorer(stream, decode)
    cap = max(1, min(int(max_keylen), 26, len(stream)))
    per_k = []
    for k in range(1, cap + 1):
        if time.monotonic() > deadline:
            break
        sc, order, complete = _search_order(k, evaluate, cfg, deadline, rng)
        if order is None:
            break
        per_k.append((sc - cfg["penalty"] * k, sc, order, k, complete))
    if not per_k:
        return None
    per_k.sort(key=lambda item: item[0], reverse=True)
    _, sc, order, k, complete = per_k[0]
    return {"order": order, "keylen": k, "score": sc, "complete": complete,
            "lengths": sorted(item[3] for item in per_k),
            "incomplete": sorted(item[3] for item in per_k if not item[4])}


# ────────────────────────── cracker: the square-unknown path ──────────────────────────

# Word-evidence gate for the no-square path. Spaces are gone once a plaintext has been
# fractionated, so a word-list word is looked for as a substring. Measured on this
# machine over a 93-letter sample: real English plaintext 21 hits (density 0.23), the
# joint grid fit's best junk 5 hits (0.05), a random 93-letter string 0-1 hits (0.01).
# This is what decides whether an answer whose *square* was guessed may be reported: the
# joint fit optimises the letter/word score and can always raise it on noise, while the
# word count separates the two by a wide margin. The score never uses this.
_WORDS = tuple(sorted(w for w in _WORDLIST if len(w) >= 3))
_EVIDENCE_MIN_HITS = 2
_EVIDENCE_MIN_DENSITY = 0.12


def _word_evidence(plaintext):
    """(hits, density) of word-list words appearing inside a plaintext"""
    low = plaintext.lower()
    hits = sum(1 for w in _WORDS if w in low)
    return hits, (hits / len(low) if low else 0.0)


def _has_evidence(plaintext) -> bool:
    """Does this plaintext carry word-level evidence (see the thresholds above)?"""
    hits, density = _word_evidence(plaintext)
    return hits >= _EVIDENCE_MIN_HITS and density >= _EVIDENCE_MIN_DENSITY


def _flat_score(ids, flat) -> float:
    """Language score of a grid (flat letter list) applied to a pair-id sequence"""
    return score_text("".join(flat[i] for i in ids), flag_bonus=False)


def _freq_flat(ids) -> list:
    """Starting grid for the joint fit: commonest pair -> commonest English letter"""
    counts = {}
    for i in ids:
        counts[i] = counts.get(i, 0) + 1
    order = sorted(range(25), key=lambda i: (-counts.get(i, 0), i))
    flat = [""] * 25
    for rank, cell in enumerate(order):
        flat[cell] = _EN_ORDER25[rank]
    return flat


def _fit_flat(ids, flat, passes, deadline):
    """Greedy hill climb on the 25-cell grid: try every pair swap, keep what helps

    Scored on the whole text, never per symbol: a per-symbol or per-column fit has
    nothing to say about a 25-symbol alphabet, which is exactly why this is the slow
    whole-text version.
    """
    cur = list(flat)
    cur_sc = _flat_score(ids, cur)
    for _ in range(max(1, passes)):
        improved = False
        for i in range(len(cur)):
            for j in range(i + 1, len(cur)):
                if time.monotonic() > deadline:
                    return cur
                cur[i], cur[j] = cur[j], cur[i]
                sc = _flat_score(ids, cur)
                if sc > cur_sc + 0.01:
                    cur_sc, improved = sc, True
                else:
                    cur[i], cur[j] = cur[j], cur[i]
        if not improved:
            break
    return cur


def _joint_search(stream, max_keylen, cfg, deadline, rng):
    """ADFGX: recover read order and 25-cell grid together -> a candidate dict or None

    With the square unknown there are two unknowns and one message, and the honest
    position is that one message does not determine the square: every bijection from the
    25 coordinate pairs to 25 letters *is* a legal square, so "recovered the square" can
    only ever mean "found a grid that scores well as English". This alternates the two
    sub-problems - fit the 25-letter assignment by pair swaps on the whole-text score,
    then re-search the read order with that assignment fixed - and keeps the best grid it
    reached. Short ciphertexts (< cfg["joint_min"] symbols) are refused outright: on
    those the objective can be driven up while the text is still noise.
    """
    size = 5
    labels = _LABELS5
    lidx = {ch: i for i, ch in enumerate(labels)}
    if len(stream) < cfg["joint_min"]:
        return None

    def ids_for(order):
        s = _detranspose(stream, order)
        return [lidx[a] * size + lidx[b] for a, b in zip(s[0::2], s[1::2])]

    def scorer_for(flat):
        def evaluate(order):
            return _flat_score(ids_for(order), flat)
        return evaluate

    best = None
    cap = max(1, min(int(max_keylen), cfg["joint_max_keylen"], len(stream)))
    for k in range(1, cap + 1):
        if time.monotonic() > deadline:
            break
        order = tuple(range(k))
        flat = _freq_flat(ids_for(order))
        complete = True
        for _ in range(max(1, cfg["joint_rounds"])):
            ids = ids_for(order)
            flat = _fit_flat(ids, flat, cfg["joint_passes"], deadline)
            sc, new_order, complete = _search_order(k, scorer_for(flat), cfg, deadline,
                                                    rng)
            if new_order is None:
                break
            order = new_order
            if not complete:
                break
        ids = ids_for(order)
        flat = _fit_flat(ids, flat, 1, deadline)
        sc = _flat_score(ids, flat)
        if best is None or sc - cfg["penalty"] * k > best[0]:
            rows = ["".join(flat[r * size:(r + 1) * size]) for r in range(size)]
            best = (sc - cfg["penalty"] * k, sc, order, k, rows, complete)
    if best is None:
        return None
    _, sc, order, k, rows, complete = best
    return {"order": order, "keylen": k, "score": sc, "rows": rows, "square_key": None,
            "source": "joint order+grid search", "complete": complete}


def _square_key_guesses(cfg) -> list:
    """Keyword guesses for the square, in the order they are tried"""
    out = list(_SQUARE_KEY_GUESSES)
    if cfg["wordlist_keys"]:
        for word in sorted(_WORDLIST):
            kw = word.upper()
            if kw not in out:
                out.append(kw)
    return out


def _sweep_square_keys(stream, size, max_keylen, cfg, deadline, rng, guesses, keep=5):
    """Try every square keyword: build the square, then search the read order

    Each guess gets an equal slice of what is left of the budget, so a long guess list
    costs depth per guess rather than silently dropping the tail (a cut-short scan is
    reported through `complete`). Returns `{"cands": [...], "tried": n, "total": m}`
    with several candidates, best-ranked first: the caller re-ranks them with its
    word-evidence gate, so throwing away everything but the winner would lose a correct
    keyword whenever the top-ranked guess is junk.
    """
    labels = _LABELS6 if size == 6 else _LABELS5
    alpha = _ALPHA6 if size == 6 else _ALPHA5
    sub = dict(cfg, exact_max=cfg["square_exact_max"])
    out = []
    tried = 0
    for idx, kw in enumerate(guesses):
        now = time.monotonic()
        if now >= deadline:
            break
        per = max(0.05, (deadline - now) / max(1, len(guesses) - idx))
        rows = _build_square(kw, alpha, labels)
        decode = _make_decoder(rows, labels)
        got = _search_all_lengths(stream, decode, max_keylen, sub,
                                  min(deadline, now + per), rng)
        tried += 1
        if got is None:
            continue
        out.append({"order": got["order"], "keylen": got["keylen"], "score": got["score"],
                    "rows": rows, "square_key": kw, "complete": got["complete"],
                    "source": ("square keyword %r" % kw) if kw else "unkeyed square"})
    out.sort(key=lambda c: c["score"] - cfg["penalty"] * c["keylen"], reverse=True)
    return {"cands": out[:keep], "tried": tried, "total": len(guesses)}


# ────────────────────────── cracker: public ──────────────────────────

def _blank(note, variant=None, t0=None) -> dict:
    """A failed result in the library's shape (never a fabricated plaintext)"""
    return {"ok": False, "key": None, "plaintext": None, "square": None,
            "note": note, "score": -999.0, "variant": variant, "order": None,
            "keylen": None, "hypothesis": None, "word_hits": 0, "word_density": 0.0,
            "seconds": round(time.monotonic() - t0, 3) if t0 else 0.0}


def _hypothesis(cand, hits, bits, variant, t0) -> dict:
    """A no-square candidate that did NOT pass the word-evidence gate

    It is a verified round trip - re-encryption reproduces the ciphertext - but it shows
    no language, which is exactly what the joint grid fit produces on noise. So it is
    not reported as the answer (`ok` stays False, `plaintext` stays None); it is kept in
    `hypothesis` so a caller can still look at it.
    """
    bits = list(bits) + [
        "no candidate showed word-level evidence (best hypothesis: %d word-list hits "
        "over %d symbols), and a single message does not determine the square - any "
        "bijection from the coordinate pairs to plaintext symbols is a legal square, so "
        "nothing is reported as an answer here. Supply the square (or its keyword) and "
        "the transposition alone is solvable" % (hits, len(cand["plaintext"]))]
    out = _blank(". ".join(bits), variant, t0)
    out["hypothesis"] = {"key": _canonical_key(cand["order"]),
                         "square": list(cand["rows"]),
                         "plaintext": cand["plaintext"],
                         "score": round(cand["score"], 2),
                         "source": cand["source"],
                         "word_hits": hits}
    return out


def _encrypt_with(variant, plaintext, key, rows, labels) -> str:
    """Re-encrypt a candidate (the verification step)"""
    if variant == "adfgvx":
        return adfgvx_encrypt(plaintext, key=key, square=(rows, labels))
    return adfgx_encrypt(plaintext, key=key, square=(rows, labels))


def _flag_byproduct(plaintext) -> str:
    """Any flag-shaped string in a recovered plaintext - reported, never scored"""
    strict = flag_candidates(plaintext)
    loose = [f for f in loose_flag_candidates(plaintext) if f not in strict]
    bits = []
    if strict:
        bits.append("strict flag shape found as a by-product (not used for scoring): %s"
                    % ", ".join(sorted(set(strict))[:3]))
    if loose:
        bits.append("loose flag-shaped candidates (leads only): %s"
                    % ", ".join(sorted(set(loose))[:3]))
    return "; ".join(bits)


def adfgvx_crack(ciphertext, square=None, max_keylen=12, effort="normal",
                 square_keys=None, time_budget=None):
    """Recover the transposition key (and, when it can, the square) of an ADFGX/ADFGVX text

    Args:
        ciphertext: the coordinate stream, with or without whitespace separators.
        square: the known square - the `(rows, labels)` tuple from `adfgx_square` /
            `adfgvx_square`, a raw list of rows, or a keyword string. Passing it turns
            this into a pure transposition problem (the honest "solve the column order").
            `square=None` also attempts to recover the square (see the limits below).
        max_keylen: longest transposition keyword to consider (capped at 26 and at the
            ciphertext length).
        effort: "quick" (3 s) / "normal" (15 s) / "deep" (60 s); it scales the exhaustive
            key-length limit, the number of annealing restarts and whether the keyword
            word list is swept. An unknown name is a ValueError.
        square_keys: explicit square-keyword guesses for the no-square path (replaces the
            built-in list, which is the identity square plus common words plus, for
            normal/deep, the library's word list).
        time_budget: seconds; overrides the effort's own budget.

    Returns:
        {"ok": bool,               # a plaintext was produced AND re-encrypted back
         "key": str|None,          # canonical keyword for the read order (see below)
         "plaintext": str|None,
         "square": [str, ...]|None,   # 5 or 6 row strings, as `adfgx_square` returns
         "note": str,              # what was solved, what was not, and the coverage
         "score": float,           # language score of the plaintext (no flag bonus)
         "variant": "adfgx"|"adfgvx"|None,
         "order": [int, ...]|None, # column read order (order[r] = column read at rank r)
         "keylen": int|None,
         "hypothesis": dict|None,  # a no-square candidate that failed the evidence gate
         "word_hits": int,         # word-list words found in the plaintext (evidence)
         "word_density": float,    # word_hits / len(plaintext)
         "seconds": float}

    Verification: the reported plaintext is re-encrypted with `key` and the reported
    square and must equal the input exactly; a candidate that fails is not reported
    (ok=False, plaintext=None). Two caveats are spelled out in `note` because they matter
    more than the flag:

      * with a supplied square, EVERY read order reproduces the ciphertext, so the check
        only rejects invalid candidates - the English score is what selects the answer.
      * `key` is the canonical keyword for the recovered order ("BAC" for the order that
        "KEY" produces); any keyword with the same relative order decrypts identically,
        and the original keyword is not recoverable from the ciphertext.

    Without a square, both the square and the order are unknown, and an answer is only
    reported when it passes a word-evidence gate (>= 2 word-list words and a density of
    >= 0.12; measured here: real English 0.23, the joint grid fit's best junk 0.05,
    random letters 0.01). The gate exists because the joint order/grid hill climb can
    always drive the letter/word score up on noise, so `score` alone cannot distinguish a
    real decryption from a fitted one. When nothing passes, the result is ok=False with
    the best verified round trip in `hypothesis` and a `note` saying that a single message
    does not determine the square. That is the honest answer, not a failure to try.
    """
    t0 = time.monotonic()
    cfg = _effort(effort, time_budget)
    deadline = t0 + cfg["budget"]
    det = adfgvx_detect(ciphertext)
    if not det["is_adfgvx"]:
        return _blank("not an ADFGX/ADFGVX ciphertext: " + det["why"], None, t0)
    text = _strip_ws(ciphertext)
    variant = det["variant"]
    size = 6 if variant == "adfgvx" else 5
    hint = _square_size_hint(square)
    if hint is not None:
        if hint not in (5, 6):
            return _blank("square must be 5x5 or 6x6, got %dx%d - refusing to guess which "
                          "variant was meant" % (hint, hint), variant, t0)
        size = hint
        variant = "adfgvx" if size == 6 else "adfgx"
    alpha = _ALPHA6 if size == 6 else _ALPHA5
    labels = _LABELS6 if size == 6 else _LABELS5
    try:
        rows, labels = _normalize_square(square, size, alpha, labels)
    except (ValueError, TypeError) as exc:
        return _blank("square rejected: %s" % exc, variant, t0)
    outside = sorted({c for c in text if c not in set(labels)})
    if outside:
        return _blank("ciphertext has %d symbol(s) that are not %s labels: %s"
                      % (len(outside), variant, ", ".join(outside[:8])), variant, t0)
    if len(text) % 2:
        return _blank("odd number of coordinate symbols (%d): a fractionated stream is "
                      "made of pairs" % len(text), variant, t0)
    rng = random.Random(cfg["seed"])
    decode = _make_decoder(rows, labels)

    if square is not None:
        got = _search_all_lengths(text, decode, max_keylen, cfg, deadline, rng)
        if got is None:
            return _blank("no read order could be scored within the %.1fs budget"
                          % cfg["budget"], variant, t0)
        order, klen, sc = got["order"], got["keylen"], got["score"]
        if klen <= cfg["exact_max"]:
            how = "exhaustively (%d! read orders)" % klen
        else:
            how = ("by simulated annealing (%d! orders is above the exact-enumeration "
                   "limit of %d)" % (klen, cfg["exact_max"]))
        bits = ["square supplied, so only the transposition was solved: key length %d "
                "recovered %s" % (klen, how),
                "coverage: key lengths %s of 1..%d were scored"
                % (", ".join(str(x) for x in got["lengths"]), max_keylen)]
        if got["incomplete"]:
            bits.append("key length(s) %s were cut short by the %.1fs budget"
                        % (", ".join(str(x) for x in got["incomplete"]), cfg["budget"]))
        bits.append("the English score is what chose between read orders: in a pure "
                    "transposition every order re-encrypts to the same ciphertext, so "
                    "the round-trip check rejects invalid candidates but cannot confirm "
                    "the key - a short ciphertext can still give the wrong order")
    else:
        guesses = (list(square_keys) if square_keys is not None
                   else _square_key_guesses(cfg))
        sweep = _sweep_square_keys(text, size, max_keylen, cfg, deadline, rng, guesses)
        joint = (_joint_search(text, max_keylen, cfg, deadline, rng)
                 if cfg["joint"] and size == 5 else None)
        pool = list(sweep["cands"])
        if joint is not None:
            pool.append(joint)
        if not pool:
            return _blank("no square candidate could be scored within the %.1fs budget"
                          % cfg["budget"], variant, t0)
        for cand in pool:
            cand["plaintext"] = _make_decoder(cand["rows"], labels)(
                _detranspose(text, cand["order"]))
            cand["score"] = score_text(cand["plaintext"], flag_bonus=False)
            cand["rank"] = cand["score"] - cfg["penalty"] * cand["keylen"]
        pool.sort(key=lambda c: c["rank"], reverse=True)
        winner = None
        for cand in pool:
            if _has_evidence(cand["plaintext"]):
                winner = cand
                break
        bits = ["no square supplied, so the square was searched as well: %d of %d "
                "keyword guesses scored (best-ranked %s)"
                % (sweep["tried"], sweep["total"], pool[0]["source"])]
        if joint is not None:
            bits.append("the joint order+grid hill climb (ADFGX only) also ran: it fits "
                        "the 25-cell grid to the text, so it can always produce *some* "
                        "grid - its square is a hypothesis, not an identified key")
        elif size == 6:
            bits.append("the joint grid fit is ADFGX-only (36 cells leave an arbitrary "
                        "grid too unconstrained to be worth reporting)")
        if winner is None:
            hyp_hits, _ = _word_evidence(pool[0]["plaintext"])
            return _hypothesis(pool[0], hyp_hits, bits, variant, t0)
        order, klen, sc, rows = (winner["order"], winner["keylen"], winner["score"],
                                 winner["rows"])
        hits, density = _word_evidence(winner["plaintext"])
        if winner is not pool[0]:
            bits.append("the top-ranked candidate was rejected by the word-evidence gate "
                        "(it scored higher but showed no language), so the best candidate "
                        "that did show language is the one reported")
        bits.append("word evidence: %d word-list hits over %d symbols (density %.3f; "
                    "measured here: real English ~0.20, grid-fit junk ~0.05)"
                    % (hits, len(winner["plaintext"]), density))
        bits.append("a single message does not determine the square: any bijection from "
                    "the coordinate pairs to plaintext symbols is a legal square, so "
                    "unless the right keyword was among the guesses the square is not "
                    "identified - only *a* square that round-trips was found")
        decode = _make_decoder(rows, labels)

    plaintext = decode(_detranspose(text, order))
    sc = score_text(plaintext, flag_bonus=False)
    key = _canonical_key(order)
    if square is not None:
        hits, density = _word_evidence(plaintext)
        bits.append("word evidence: %d word-list hits over %d symbols (density %.3f)"
                    % (hits, len(plaintext), density))
        if len(plaintext) < 30:
            bits.append("the plaintext is only %d symbols, far below the ~50 this score "
                        "needs to tell a real order from noise, so the recovered order "
                        "carries almost no information and may be arbitrary"
                        % len(plaintext))
    try:
        again = _encrypt_with(variant, plaintext, key, rows, labels)
    except (ValueError, TypeError) as exc:
        return _blank("candidate rejected: re-encryption raised %s: %s"
                      % (type(exc).__name__, exc), variant, t0)
    if again != text:
        return _blank("candidate rejected: re-encrypting the plaintext with key %r gave "
                      "%r, not the input (%.40s...)"
                      % (key, again[:40], text), variant, t0)

    note = ". ".join(bits)
    note += (". Verified: re-encrypting the plaintext with key %r and this square "
             "reproduces the ciphertext exactly. score %.2f (no flag bonus in the "
             "search)" % (key, sc))
    flags = _flag_byproduct(plaintext)
    if flags:
        note += ". " + flags
    return {"ok": True, "key": key, "plaintext": plaintext, "square": list(rows),
            "note": note, "score": round(sc, 2), "variant": variant,
            "order": list(order), "keylen": klen, "hypothesis": None,
            "word_hits": hits, "word_density": round(density, 4),
            "seconds": round(time.monotonic() - t0, 3)}
