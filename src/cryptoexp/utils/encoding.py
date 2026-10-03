"""Encoding layer — encoding detection/decoding chains + plaintext scoring + XOR/classical cracking

Design trade-off: this layer **draws no conclusions**; it only produces
"candidates + scores + confidence". The same string often looks like both hex
and base64, so the call rests on "does the decoded plaintext score high", not
on hard charset matching — the same evidence-grading idea as intelpwn.

Flag shapes are **configurable**, because "what a flag looks like" is a property of
the engagement, not of the library: a CTF event may use `DH{...}`, an internal
red-team job may look for `corp_<hex>{...}`, and a researcher may want a custom
regex. Three layers, in order of precedence:

    flag_candidates(data, prefixes=["DH"])        # per call, explicit (library use)
    set_flag_prefixes(["DH"])                     # process default (scripts, notebooks)
    CRYPTOEXP_FLAG_PREFIXES=DH,corp_              # environment (CLI, CI)

A custom `pattern=` regex replaces the prefix list entirely, so any marker format
works. Nothing here decides "this is the flag": strict matches stay evidence, and
the loose pattern is still a lead only.
"""

import base64
import binascii
import contextvars
import os
import re
import string

# ────────────────────────── plaintext scoring ──────────────────────────

# English single-letter frequencies (percent, for chi-square / scoring)
_EN_FREQ = {
    'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75,
    's': 6.33, 'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
    'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97,
    'p': 1.93, 'b': 1.29, 'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
    'q': 0.10, 'z': 0.07,
}
_COMMON_WORDS = (b'the', b'and', b'flag', b'ctf', b'key', b'this', b'that',
                 b'with', b'you', b'for', b'not', b'are', b'have', b'from',
                 b'shell', b'pass', b'secret', b'congrat')
# Word list for the word-level score term. Frequency-only scoring rewards
# "THE KUKDD TDKWN FOR JWNIK ARER" as much as real English, which let a longer
# Vigenere key overfit the objective (a real failure). Few hundred words is enough
# to separate real text from letter-shaped noise.
_WORDLIST = frozenset("""
the be to of and a in that have i it for not on with he as you do at this but his by
from they we say her she or an will my one all would there their what so up out if about
who get which go me when make can like time no just him know take people into year your
good some could them see other than then now look only come its over think also back after
use two how our work first well way even new want because any these give day most us is are
was were been has had do does did doing done make made making take took taken come came get
got give gave find found tell told think thought see saw know knew want wanted use used
work worked call called try tried ask asked need needed feel felt become became leave left
put mean meant keep kept let begin began seem seemed help helped talk talked turn turned
start started show showed hear heard play played run ran move moved live lived believe
bring brought happen happened write wrote provide provided sit sat stand stood lose lost
pay paid meet met include included continue continued set learn learned change changed lead
led understand understood watch watched follow followed stop stopped create created speak
spoke read allow allowed add added spend spent grow grew open opened walk walked win won
offer offered remember remembered love loved consider considered appear appeared buy bought
wait waited serve served die died send sent expect expected build built stay stayed fall
fell cut reach reached kill killed remain remained
quick brown fox jumps over lazy dog message secret hidden inside long text
flag key cipher crypto cryptoexp plaintext encryption decrypt decrypts block stream hash
salt nonce oracle padding attack attacker secure security signature verify recover
recovered repeating hamming distance xor vigenere caesar affine morse fence substitution
rsa lattice coppersmith modulus prime factor leak leaky bits random seed predict clone
one two three four five six seven eight nine ten
""".split())


def _word_shape_score(data: bytes) -> float:
    """Word-level term: dictionary hits plus a shape penalty for junk tokens

    This is what keeps the search honest: a heuristic built only on letter
    frequency cannot tell "THE QUICK BROWN FOX" from "THE KUKDD TDKWN FOR".
    """
    tokens = [t.lower() for t in re.findall(rb'[A-Za-z]+', data)]
    if not tokens:
        return 0.0
    score = 0.0
    for t in tokens:
        w = t.decode('ascii', errors='ignore')
        if len(w) >= 3 and w in _WORDLIST:
            score += 1.5
        elif len(w) >= 4:
            # A long token with no vowel, or a 4+ consonant run, is not a word
            if not any(v in w for v in 'aeiouy'):
                score -= 1.5
            elif re.search(r'[^aeiouy]{4}', w):
                score -= 1.0
        if len(w) == 1:
            score -= 0.5
        elif len(w) > 14:
            score -= 0.5
    return score
# Strict flag: the prefix must be a *known* prefix — used for "confirmed" and as a
# scoring bonus.
# (a loose match treats XOR residue shaped like `f_lURic{EEv}` as a flag; we hit
# this in testing: it both mis-reported a confirmation and skewed the ranking.
# Note the loose pattern needs 2+ prefix chars, so a 1-char token does not match)
DEFAULT_FLAG_PREFIXES = (
    "flag", "ctf", "picoctf", "htb", "nite", "sekai", "corctf", "idek", "ductf",
    "actf", "ictf", "lactf", "buckeye", "justctf", "uiuctf", "dice", "grey", "hxp",
    "asis", "0ctf", "rwctf", "hitcon", "tjctf", "angstromctf", "shellctf", "wctf",
    "csaw", "rialto", "vsctf", "maple", "amuctf", "sctf", "n1ctf",
)
_BODY = (rb'\{(?=[^}\x00-\x1f]{0,120}\})(?=[^}\x00-\x1f]*[A-Za-z0-9])'
         rb'[^}\x00-\x1f]{2,120}\}')
_STRICT_FLAG_PAT = re.compile(
    rb'(?i)(?:' + b'|'.join(re.escape(p.encode()) for p in DEFAULT_FLAG_PREFIXES)
    + rb'|flag_[a-z0-9]+|ctf_[a-z0-9]+)' + _BODY)
# Built from DEFAULT_FLAG_PREFIXES above on purpose. The alternation used to be typed
# out a second time, so editing the tuple silently changed nothing for the default path
# (the literal pattern was what actually ran) - a maintenance trap, not a bug with a
# symptom. The two `prefix_xxx` variants stay explicit: they are not in the tuple.
# Loose flag: any token{...} — a "candidate" lead only, never a confirmation basis.
# The body must contain at least one alphanumeric character: `DH{...}` in a statement
# describing the format is a placeholder, not a flag, and treating it as one made the
# statement itself "confirm" once custom prefixes were configured.
_LOOSE_FLAG_PAT = re.compile(
    rb'[A-Za-z0-9_]{2,20}\{(?=[^}\x00-\x1f]{0,80}\})'
    rb'(?=[^}\x00-\x1f]*[A-Za-z0-9])[^}\x00-\x1f]{2,80}\}')
_PRINTABLE = set(bytes(string.printable, 'ascii'))

# Process-wide default: what `flag_candidates(data)` uses when no argument is given.
# Explicit arguments always win, so library callers never depend on this state.
_CONFIGURED_PREFIXES = None       # None = the built-in DEFAULT_FLAG_PREFIXES
_CONFIGURED_PATTERN = None        # a compiled regex that replaces the prefixes
# Per-run override (analyze_all scopes its flag config here). A ContextVar, not a
# global: one analyze_all call must not change what another caller sees, which a
# plain module global did (caught by the test that runs the same sample with and
# without --flag-prefix).
_RUN_FLAG_CONFIG = contextvars.ContextVar("cryptoexp_flag_config", default=None)


def push_flag_config(prefixes=None, pattern=None):
    """Scope a flag configuration to the current context; returns a token

    Pair with `pop_flag_config(token)` in a finally block. This is how `analyze_all`
    applies its `flag_prefixes=` argument without leaking it into the process.
    """
    compiled = pattern
    if pattern is not None and not hasattr(pattern, "finditer"):
        compiled = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
    return _RUN_FLAG_CONFIG.set((prefixes, compiled))


def pop_flag_config(token):
    """Undo `push_flag_config`"""
    _RUN_FLAG_CONFIG.reset(token)


def _env_prefixes():
    """Prefixes from CRYPTOEXP_FLAG_PREFIXES (comma separated), or None"""
    raw = os.environ.get("CRYPTOEXP_FLAG_PREFIXES")
    if not raw:
        return None
    items = [p.strip() for p in raw.split(",") if p.strip()]
    return items or None


def set_flag_prefixes(prefixes=None, pattern=None, merge=False):
    """Set the process-wide flag shape (returns the previous configuration)

    prefixes: iterable of literal prefix names, e.g. ["DH", "corp_"]; matching is
              case-insensitive and `{...}` is appended, so "DH" matches DH{...}
    pattern:  a regex that *replaces* the prefix list entirely, for markers that are
              not `prefix{body}` at all, e.g. r"[A-Z]{3}-\\d{4}-[a-z0-9]{16}"
    merge:    add to the current prefixes instead of replacing them

    Library callers who want no hidden state should pass `prefixes=`/`pattern=` to
    `flag_candidates` directly; this is for scripts, notebooks and the CLI.
    """
    global _CONFIGURED_PREFIXES, _CONFIGURED_PATTERN
    previous = (_CONFIGURED_PREFIXES, _CONFIGURED_PATTERN)
    if pattern is not None:
        _CONFIGURED_PATTERN = re.compile(pattern.encode() if isinstance(pattern, str)
                                         else pattern)
    if prefixes is not None:
        items = list(prefixes)
        if merge:
            # Merge with the prefixes actually in force (explicit config, env var or the
            # built-ins). The old code merged only with the explicit config, which is
            # None in a fresh process - so `set_flag_prefixes(["DH"], merge=True)` left
            # the list as ("DH",) and dropped `flag`, contradicting the README's
            # "DH plus the built-ins" and quietly breaking flag{...} detection.
            current = list(get_flag_prefixes())
            items = current + [p for p in items if p not in current]
        _CONFIGURED_PREFIXES = items
    return previous


def get_flag_prefixes():
    """The prefixes currently in force (explicit config, env, or the built-ins)"""
    if _CONFIGURED_PREFIXES is not None:
        return tuple(_CONFIGURED_PREFIXES)
    return tuple(_env_prefixes() or DEFAULT_FLAG_PREFIXES)


def reset_flag_prefixes():
    """Drop the process-wide configuration (back to env var, then built-ins)"""
    global _CONFIGURED_PREFIXES, _CONFIGURED_PATTERN
    _CONFIGURED_PREFIXES = None
    _CONFIGURED_PATTERN = None


def build_flag_pattern(prefixes=None, pattern=None):
    """Compile the strict flag regex for these prefixes/pattern

    Precedence: explicit `pattern` → explicit `prefixes` → per-run context (set by
    `analyze_all`) → process-wide `set_flag_prefixes` → `CRYPTOEXP_FLAG_PREFIXES`
    → the built-in event list. Prefixes are escaped and joined, so a prefix
    containing regex metacharacters is matched literally.
    """
    if pattern is not None:
        if hasattr(pattern, "finditer"):
            return pattern
        return re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
    run_prefixes, run_pattern = _RUN_FLAG_CONFIG.get() or (None, None)
    if prefixes is None and run_pattern is not None:
        return run_pattern
    if prefixes is None and run_prefixes is not None:
        prefixes = run_prefixes
    if prefixes is None and _CONFIGURED_PATTERN is not None:
        return _CONFIGURED_PATTERN
    if prefixes is None:
        if _CONFIGURED_PREFIXES is None and _env_prefixes() is None:
            return _STRICT_FLAG_PAT
        prefixes = get_flag_prefixes()
    items = [p for p in prefixes if p]
    if not items:
        return _STRICT_FLAG_PAT
    body = b'|'.join(re.escape(p.encode() if isinstance(p, str) else p) for p in items)
    return re.compile(rb'(?i)(?:' + body + rb')' + _BODY)


def flag_candidates(data, prefixes=None, pattern=None):
    """Strict flag shape → matches (strongest evidence for a confirmation)

    Strict means "the marker format is one we were told to expect": the built-in
    event list, the configured prefixes, the per-run context, or a caller-supplied
    regex. An empty list means "no expected marker found", not "no flag exists" —
    use `loose_flag_candidates` when the format is unknown.

        flag_candidates(payload, prefixes=["DH", "corp_"])
        flag_candidates(payload, pattern=r"ACME-\\d{4}-[a-z0-9]{8}")
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    return [m.group(0).decode('utf-8', errors='replace')
            for m in build_flag_pattern(prefixes, pattern).finditer(data)]


def loose_flag_candidates(data, prefixes=None, pattern=None):
    """Loose flag shape (may be a flag, may be noise that happens to match) → candidate only"""
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    strict = set(flag_candidates(data, prefixes=prefixes, pattern=pattern))
    return [m.group(0).decode('utf-8', errors='replace')
            for m in _LOOSE_FLAG_PAT.finditer(data)
            if m.group(0).decode('utf-8', errors='replace') not in strict]


def find_flags(data, prefixes=None, pattern=None, include_loose=True):
    """Every marker-shaped string in `data`, labelled strict or loose

    This is the function to reach for outside CTF: point it at a memory dump, a
    config file, a transcript or a log line and it answers "where does something
    look like a credential/flag marker", with the strict ones being the ones that
    matched an expected format.

    Returns [{"match": str, "kind": "strict"|"loose", "offset": int}].
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    out, seen = [], set()
    for kind, pat in (("strict", None), ("loose", _LOOSE_FLAG_PAT)):
        if kind == "loose" and not include_loose:
            continue
        regex = build_flag_pattern(prefixes, pattern) if kind == "strict" else pat
        for m in regex.finditer(data):
            text = m.group(0).decode('utf-8', errors='replace')
            if (kind, text) in seen:
                continue
            seen.add((kind, text))
            out.append({"match": text, "kind": kind, "offset": m.start()})
    out.sort(key=lambda item: (item["offset"], item["kind"] != "strict"))
    return out


_PRINT_TAB = bytes(1 if b in _PRINTABLE else 0 for b in range(256))


def printable_ratio(data: bytes) -> float:
    """Printable ratio (translate goes through the C layer — this is a scoring hot spot)"""
    if not data:
        return 0.0
    return sum(data.translate(_PRINT_TAB)) / len(data)


def score_text(data, flag_bonus: bool = True) -> float:
    """Plaintext score (higher = more like plaintext): printability + English
    letter frequency + common words + flag shape

    Deliberately a sum of several signals rather than one metric: a single
    metric is extremely noisy on short strings.

    `flag_bonus=False` is what every search loop must use. When the flag bonus is
    part of the objective, hill climbing over multi-byte keys can *fabricate* a
    flag-shaped string because that maximizes the score (observed on RSA parameter
    blobs). Ranking results may still use the bonus; the search must not.
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')
    if not data:
        return -999.0
    n = len(data)
    pr = printable_ratio(data)
    score = pr * 60.0
    if pr < 0.7:
        score -= 40.0
    low = data.lower()
    letters = [b for b in low if 97 <= b <= 122]
    if letters:
        freq_score = 0.0
        ln = len(letters)
        for c, pct in _EN_FREQ.items():
            obs = low.count(ord(c)) / ln * 100.0
            freq_score -= abs(obs - pct) / 100.0
        score += 30.0 + freq_score * 10.0
    for w in _COMMON_WORDS:
        if w in low:
            score += 6.0
    # Word-level term (dictionary hits + junk-shape penalty). This is what keeps
    # the search honest: letter frequency alone cannot tell "THE QUICK BROWN FOX"
    # from "THE KUKDD TDKWN FOR".
    score += _word_shape_score(data)
    if flag_bonus and build_flag_pattern().search(data):
        score += 60.0
    # Chinese UTF-8 also counts as plaintext: only try decoding when non-ASCII
    # bytes are present (saves a decode in the hot path)
    if any(b > 127 for b in data):
        try:
            txt = data.decode('utf-8')
            if any('\u4e00' <= ch <= '\u9fff' for ch in txt):
                score += 25.0
        except UnicodeDecodeError:
            pass
    if n >= 8 and len(set(data)) <= 2:
        score -= 25.0  # a single repeated byte, i.e. padding/noise
    return score


def confidence_of(score: float, has_flag: bool = False) -> str:
    if has_flag:
        return "high"
    if score >= 85:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


# ────────────────────────── single-layer decoders ──────────────────────────

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def from_hex(s: str):
    t = re.sub(r'\s|0x', '', s)
    if len(t) % 2 or not re.fullmatch(r'[0-9a-fA-F]+', t or ''):
        return None
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


def from_base64(s: str):
    t = re.sub(r'\s', '', s)
    if not re.fullmatch(r'[A-Za-z0-9+/=_-]+', t or '') or len(t) < 4:
        return None
    t = t.replace('-', '+').replace('_', '/')
    t += '=' * (-len(t) % 4)
    try:
        return base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None


def from_base32(s: str):
    t = re.sub(r'\s', '', s).upper()
    if not re.fullmatch(r'[A-Z2-7=]+', t or '') or len(t) < 4:
        return None
    t += '=' * (-len(t) % 8)
    try:
        return base64.b32decode(t, casefold=True)
    except (binascii.Error, ValueError):
        return None


def from_base58(s: str):
    t = re.sub(r'\s', '', s)
    if not t or any(c not in _B58_ALPHABET for c in t):
        return None
    num = 0
    for ch in t:
        num = num * 58 + _B58_ALPHABET.index(ch)
    raw = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num else b''
    pad = len(t) - len(t.lstrip('1'))
    return b'\x00' * pad + raw


def from_binary_string(s: str):
    t = re.sub(r'\s', '', s)
    if not t or not re.fullmatch(r'[01]+', t) or len(t) % 8:
        return None
    return bytes(int(t[i:i + 8], 2) for i in range(0, len(t), 8))


def from_base85(s: str):
    t = re.sub(r'\s', '', s)
    try:
        return base64.b85decode(t)
    except Exception:
        try:
            return base64.a85decode(t)
        except Exception:
            return None


def caesar(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr((ord(ch) - 65 - shift) % 26 + 65))
        elif ch.islower():
            out.append(chr((ord(ch) - 97 - shift) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out)


def rot13(text: str) -> str:
    return caesar(text, 13)


def affine_decrypt(text: str, a: int, b: int) -> str:
    from .algebra import modinv
    inv = modinv(a, 26)
    if inv is None:
        return ""
    out = []
    for ch in text:
        if ch.isupper():
            out.append(chr(((ord(ch) - 65 - b) * inv) % 26 + 65))
        elif ch.islower():
            out.append(chr(((ord(ch) - 97 - b) * inv) % 26 + 97))
        else:
            out.append(ch)
    return ''.join(out)


_MORSE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W',
    '-..-': 'X', '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1',
    '..---': '2', '...--': '3', '....-': '4', '.....': '5',
    '-....': '6', '--...': '7', '---..': '8', '----.': '9',
}


def morse_decode(text: str):
    """Morse decoding (tolerates / as well as plain space separators)"""
    if not re.fullmatch(r'[.\-/|\s]+', text or ''):
        return None
    body = text.replace('/', ' | ')
    words = [w for w in re.split(r'\s*\|\s*|\s{2,}', body.strip()) if w]
    out_words = []
    for w in words:
        letters = []
        for token in w.split():
            letters.append(_MORSE.get(token, '?'))
        out_words.append(''.join(letters))
    result = ' '.join(out_words)
    return None if '?' in result and result.count('?') > len(result) * 0.3 else result


def fence_decrypt(text: str, rails: int) -> str:
    """Rail fence cipher decryption"""
    if rails <= 1 or rails >= len(text):
        return text
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    idx = [pattern[i % len(pattern)] for i in range(len(text))]
    counts = [idx.count(r) for r in range(rails)]
    chunks, pos = [], 0
    for c in counts:
        chunks.append(list(text[pos:pos + c]))
        pos += c
    out, cursor = [], [0] * rails
    for r in idx:
        out.append(chunks[r][cursor[r]])
        cursor[r] += 1
    return ''.join(out)


# ────────────────────────── automatic decode chain ──────────────────────────

_DECODERS = (
    ("hex", from_hex),
    ("base64", from_base64),
    ("base32", from_base32),
    ("base85", from_base85),
    ("base58", from_base58),
    ("binary", from_binary_string),
)


def decode_chain(blob: str, max_layers: int = 3, min_score: float = 55.0):
    """Try decoders layer by layer, return candidates sorted by score

    Each layer keeps applying decoders to the "current best result"; whether to
    go on is decided by score rather than charset matching — this stops random
    hex from being decoded as base64 all the way down into garbage.
    """
    results = []
    frontier = [(blob, [])]
    seen = set()
    for _ in range(max_layers):
        nxt = []
        for text, steps in frontier:
            for name, fn in _DECODERS:
                try:
                    out = fn(text)
                except Exception:
                    out = None
                if not out or out in seen:
                    continue
                seen.add(out)
                sc = score_text(out)
                flags = flag_candidates(out)
                results.append({
                    "steps": steps + [name],
                    "data": out,
                    "text": out.decode('utf-8', errors='replace'),
                    "score": round(sc, 2),
                    "flags": flags,
                    "confidence": confidence_of(sc, bool(flags)),
                })
                if sc >= min_score:
                    try:
                        nxt.append((out.decode('ascii'), steps + [name]))
                    except UnicodeDecodeError:
                        pass
        frontier = nxt
        if not frontier:
            break
    results.sort(key=lambda r: r["score"], reverse=True)
    return results


# ────────────────────────── XOR ──────────────────────────

def single_byte_xor(data: bytes, top: int = 5):
    """Single-byte XOR brute force → top candidates sorted by plaintext score"""
    out = []
    for k in range(256):
        pt = bytes(b ^ k for b in data)
        sc = score_text(pt)
        out.append({"key": k, "plaintext": pt, "score": round(sc, 2),
                    "flags": flag_candidates(pt)})
    out.sort(key=lambda r: (bool(r["flags"]), r["score"]), reverse=True)
    for r in out[:top]:
        r["confidence"] = confidence_of(r["score"], bool(r["flags"]))
    return out[:top]


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def _key_plaintext(data: bytes, key: bytes) -> bytes:
    """Fast decryption (bytes.translate via the C layer — coordinate ascent
    calls this hundreds of thousands of times)"""
    ks = len(key)
    out = bytearray(len(data))
    for i in range(ks):
        table = bytes(b ^ key[i] for b in range(256))
        out[i::ks] = data[i::ks].translate(table)
    return bytes(out)


def _refine_key(data: bytes, key: bytes, cand_lists=None, passes: int = 2,
                restarts: int = 2, seed: int = 0x43525950):
    """Coordinate-ascent key search: re-pick every column's byte using the
    **score of the whole plaintext**

    Why it has to work this way: scoring one column on its own sees only a few
    bytes and frequently picks wrong on short ciphertexts, whereas the signal
    that really separates right from wrong is "does the whole plaintext read
    like language".

    The search space is all 256 bytes by default — we once searched only a
    column's top 8 for speed, and the correct byte was not among those 8, so the
    challenge would not fall at all (we hit this in testing). So we would rather
    spend the compute here, and save time by stopping early on a strict flag hit
    instead of trimming the space with a candidate list.
    """
    import random
    rng = random.Random(seed)
    ks = len(key)
    space = cand_lists or [range(256)] * ks

    starts = [bytes(key)]
    for _ in range(max(0, restarts - 1)):
        starts.append(bytes(rng.choice(list(space[i])) for i in range(ks)))

    best_key = bytes(key)
    best_score = score_text(_key_plaintext(data, best_key), flag_bonus=False)
    for start in starts:
        cur = bytearray(start)
        cur_score = score_text(_key_plaintext(data, bytes(cur)), flag_bonus=False)
        for _ in range(passes):
            changed = False
            for i in range(ks):
                orig = cur[i]
                local_best, local_score = orig, cur_score
                for g in space[i]:
                    if g == orig:
                        continue
                    cur[i] = g
                    sc = score_text(_key_plaintext(data, bytes(cur)), flag_bonus=False)
                    if sc > local_score + 0.01:
                        local_best, local_score = g, sc
                cur[i] = local_best
                if local_best != orig:
                    cur_score, changed = local_score, True
            if not changed:
                break
        if cur_score > best_score + 0.01:
            best_key, best_score = bytes(cur), cur_score
    return best_key, best_score


def repeating_key_xor(data: bytes, min_ks: int = 2, max_ks: int = 40,
                      top_keysizes: int = 4, top: int = 5,
                      restarts: int = 2, passes: int = 2,
                      dist_slack: float = 0.75, early_stop: bool = True):
    """Repeating-key XOR: Hamming shortlist → per-column brute force → whole-text
    score hill climb → rank by score

    All four steps produce candidates first and verify after; no single
    heuristic draws the conclusion:
      1) key length: take a **shortlist** by normalised Hamming distance (not
         only the winner — the correct length often ranks 4th in practice, and
         taking just top1 gets it wrong)
      2) initial key: per-column single-byte brute force
      3) refinement: multi-start hill climb on the whole-plaintext score (full
         256 space)
      4) ranking / early stop: a strict flag hit comes first, then the
         whole-text score; once one hits, no other length is tried
    """
    if len(data) < min_ks * 4:
        return []
    scored = []
    for ks in range(min_ks, min(max_ks, len(data) // 2) + 1):
        blocks = [data[i * ks:(i + 1) * ks] for i in range(min(8, len(data) // ks))]
        if len(blocks) < 2:
            continue
        dists = [_hamming(blocks[i], blocks[i + 1]) / ks for i in range(len(blocks) - 1)]
        scored.append((sum(dists) / len(dists), ks))
    if not scored:
        return []
    scored.sort()
    limit = scored[0][0] + dist_slack
    shortlist = [ks for d, ks in scored if d <= limit][:top_keysizes]
    for d, ks in scored:  # top the shortlist up when it is not full
        if len(shortlist) >= min(top_keysizes, len(scored)):
            break
        if ks not in shortlist:
            shortlist.append(ks)

    out = []
    for ks in shortlist:
        dist = next(d for d, k in scored if k == ks)
        key = bytearray()
        cand_lists = []
        for col in range(ks):
            column = bytes(data[i] for i in range(col, len(data), ks))
            tops = single_byte_xor(column, top=8)
            cand_lists.append([t["key"] for t in tops])
            key.append(tops[0]["key"])
        # try the fast "top 8 per column" pass first; only if that fails, open
        # up the full 256 space (saves time without losing solutions)
        for space in (cand_lists, None):
            k, sc = _refine_key(data, bytes(key), space, passes=passes,
                                restarts=restarts if space is None else 1)
            pt = _key_plaintext(data, k)
            flags = flag_candidates(pt)
            out.append({"keysize": ks, "key": k, "plaintext": pt,
                        "distance": round(dist, 4), "score": round(sc, 2),
                        "flags": flags,
                        "confidence": confidence_of(sc, bool(flags)),
                        "search": "local candidates" if space else "full space"})
            if flags:
                break
        if early_stop and any(r["flags"] for r in out):
            break
    out.sort(key=lambda r: (bool(r["flags"]), r["score"]), reverse=True)
    return out[:top]


# ────────────────────────── classical cipher brute force ──────────────────────────

def caesar_candidates(text: str, top: int = 5):
    out = []
    for shift in range(1, 26):
        pt = caesar(text, shift)
        sc = score_text(pt)
        out.append({"shift": shift, "plaintext": pt, "score": round(sc, 2),
                    "flags": flag_candidates(pt.encode()),
                    "confidence": confidence_of(sc, bool(flag_candidates(pt.encode())))})
    out.sort(key=lambda r: (bool(r["flags"]), r["score"]), reverse=True)
    return out[:top]


def affine_candidates(text: str, top: int = 5):
    from .algebra import modinv
    out = []
    for a in range(1, 26):
        if modinv(a, 26) is None:
            continue
        for b in range(26):
            pt = affine_decrypt(text, a, b)
            sc = score_text(pt)
            flags = flag_candidates(pt.encode())
            out.append({"a": a, "b": b, "plaintext": pt, "score": round(sc, 2),
                        "flags": flags,
                        "confidence": confidence_of(sc, bool(flags))})
    out.sort(key=lambda r: (bool(r["flags"]), r["score"]), reverse=True)
    return out[:top]


def index_of_coincidence(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = {}
    for c in letters:
        counts[c] = counts.get(c, 0) + 1
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))


def _minimal_period(key: str) -> str:
    """Smallest repeating unit of a recovered Vigenere key

    A key of length 2k yields a redundant answer ("SECRETSECRET"); reducing it to
    the minimal period makes candidates comparable and the statistics stronger.
    """
    for p in range(1, len(key) + 1):
        if len(key) % p == 0 and key == key[:p] * (len(key) // p):
            return key[:p]
    return key


def _vigenere_decrypt(text: str, shifts, ) -> str:
    """Decrypt with a shift list; the key stream advances on LETTERS only"""
    period = len(shifts)
    out, li = [], 0
    for ch in text:
        if ch.isalpha():
            out.append(caesar(ch, shifts[li % period]))
            li += 1
        else:
            out.append(ch)
    return ''.join(out)


def _refine_shifts(text: str, shifts, passes: int = 3):
    """Coordinate ascent over per-column shifts, scored on the WHOLE plaintext

    Chi-square per column is unreliable on short columns (20 letters): on a real
    sample it turned the true key "secret" into "yecnrt". Scoring the whole
    decrypted text fixes it, and the search space (26 x keylen) is tiny.
    """
    shifts = list(shifts)
    best = score_text(_vigenere_decrypt(text, shifts), flag_bonus=False)
    for _ in range(passes):
        changed = False
        for i in range(len(shifts)):
            orig = shifts[i]
            local_best, local_score = orig, best
            for s in range(26):
                if s == orig:
                    continue
                shifts[i] = s
                sc = score_text(_vigenere_decrypt(text, shifts), flag_bonus=False)
                if sc > local_score + 0.01:
                    local_best, local_score = s, sc
            shifts[i] = local_best
            if local_best != orig:
                best, changed = local_score, True
        if not changed:
            break
    return shifts, best


def vigenere_recover(text: str, max_keylen: int = 20, top: int = 5):
    """Recover a Vigenere key: length scan -> chi-square seed -> whole-text refinement

    Two real bugs are encoded in this history: the key stream must advance on
    letters only (indexing it by character misaligns at the first space), and
    per-column chi-square alone is too weak on short columns, so every candidate
    is refined against the score of the full plaintext.
    """
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 20:
        return []
    out = []
    for kl in range(1, min(max_keylen, len(letters) // 3) + 1):
        cols = [''.join(letters[i::kl]) for i in range(kl)]
        ioc = sum(index_of_coincidence(c) for c in cols) / kl
        shifts = []
        for col in cols:
            best_shift, best_chi = 0, None
            for s in range(26):
                shifted = ''.join(chr((ord(c.lower()) - 97 - s) % 26 + 97) for c in col)
                chi = 0.0
                for c, pct in _EN_FREQ.items():
                    obs = shifted.count(c) / max(1, len(shifted)) * 100.0
                    chi += (obs - pct) ** 2 / pct
                if best_chi is None or chi < best_chi:
                    best_shift, best_chi = s, chi
            shifts.append(best_shift)
        shifts, sc = _refine_shifts(text, shifts)
        key = _minimal_period(''.join(chr(s + 97) for s in shifts))
        # Refine once more at the reduced period (a redundant key decrypts the same,
        # but its minimal form is what a human wants to see)
        if len(key) < len(shifts):
            reduced = [ord(c) - 97 for c in key]
            reduced, sc = _refine_shifts(text, reduced)
            key = ''.join(chr(s + 97) for s in reduced)
        period = len(key)
        pt = _vigenere_decrypt(text, [ord(c) - 97 for c in key])
        flags = flag_candidates(pt.encode())
        out.append({"key": key, "keylen": period, "ioc": round(ioc, 4),
                    "plaintext": pt, "score": round(sc, 2), "flags": flags,
                    "confidence": confidence_of(sc, bool(flags))})
    seen, uniq = set(), []
    # Rank by (strict flag, score, then SHORTEST key). A longer key has more free
    # parameters and can overfit the heuristic score, so key length is charged for.
    ranked = sorted(out, key=lambda r: (bool(r["flags"]), r["score"] - 1.0 * r["keylen"]),
                    reverse=True)
    for r in ranked:
        if r["key"] in seen:
            continue
        seen.add(r["key"])
        uniq.append(r)
    return uniq[:top]


def fence_candidates(text: str, max_rails: int = 8, top: int = 5):
    out = []
    for rails in range(2, max_rails + 1):
        pt = fence_decrypt(text, rails)
        sc = score_text(pt)
        flags = flag_candidates(pt.encode())
        out.append({"rails": rails, "plaintext": pt, "score": round(sc, 2),
                    "flags": flags,
                    "confidence": confidence_of(sc, bool(flags))})
    out.sort(key=lambda r: (bool(r["flags"]), r["score"]), reverse=True)
    return out[:top]


# ────────────────────────── encoding detection (for the analyser) ──────────────────────────

_HEX_RE = re.compile(r'^[0-9a-fA-F\s]+$')
_B64_RE = re.compile(r'^[A-Za-z0-9+/=_\-\s]+$')
_B32_RE = re.compile(r'^[A-Z2-7=\s]+$')
_MORSE_RE = re.compile(r'^[.\-/|\s]+$')
_BIN_RE = re.compile(r'^[01\s]+$')


def guess_kinds(blob: str):
    """Fast charset check (only says what it looks like, never what it is; the
    score from decode_chain decides that)"""
    t = blob.strip()
    kinds = []
    if _HEX_RE.match(t) and len(re.sub(r'\s', '', t)) % 2 == 0:
        kinds.append("hex")
    if _BIN_RE.match(t) and len(re.sub(r'\s', '', t)) % 8 == 0 and len(re.sub(r'\s', '', t)) >= 8:
        kinds.append("binary")
    if _B32_RE.match(t) and len(t) >= 8:
        kinds.append("base32")
    if _B64_RE.match(t) and len(t) >= 8:
        kinds.append("base64")
    if _MORSE_RE.match(t) and ('.' in t or '-' in t):
        kinds.append("morse")
    if all(c in _B58_ALPHABET for c in t) and len(t) >= 8:
        kinds.append("base58")
    return kinds


# ────────────────────────── encoding side (for the infrastructure) ──────────────────────────

def _as_bytes(data) -> bytes:
    return data.encode() if isinstance(data, str) else bytes(data)


def to_hex(data) -> str:
    return _as_bytes(data).hex()


def to_base64(data) -> str:
    return base64.b64encode(_as_bytes(data)).decode()


def to_base32(data) -> str:
    return base64.b32encode(_as_bytes(data)).decode()


def to_base58(data) -> str:
    raw = _as_bytes(data)
    pad = len(raw) - len(raw.lstrip(b'\x00'))
    num = int.from_bytes(raw, 'big') if raw else 0
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    return "1" * pad + (out or ("" if raw else ""))


_MORSE_REV = {v: k for k, v in _MORSE.items()}


def morse_encode(text: str, sep: str = " ") -> str:
    """Text → Morse (letters/digits; words separated by /)"""
    words = []
    for word in text.upper().split():
        words.append(sep.join(_MORSE_REV.get(ch, "?") for ch in word))
    return " / ".join(words)


# pwntools-style short aliases — let people type a bit less
enhex = to_hex
unhex = from_hex
b64e = to_base64
b64d = from_base64
b32e = to_base32
b32d = from_base32
b58e = to_base58
b58d = from_base58
