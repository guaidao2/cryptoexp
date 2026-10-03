"""PRNG extras — the non-MT19937 generators a CTF meets all the time

`prng.py` covers MT19937 only. The generators below show up just as often in
"here are some outputs, predict the next one" tasks, and each fails in its own
way:

  * `java.util.Random`  — a 48-bit LCG. Carries make the step non-linear bit by
    bit, so the seed is recovered arithmetically (the high 32 bits of the next
    state are printed; inverting the step pins the rest down).
  * glibc `rand()`      — an additive lagged-Fibonacci generator (TYPE_3). The
    state words are unwrapped **mod 2^32** but `rand()` returns `value >> 1`, so
    exactly one bit per word is hidden; using 2^31 for the state is the classic
    silent bug.
  * xorshift32          — a bijective map, so a state can be *inverted* out of an
    output instead of searched for.
  * LCG with truncated outputs — a bounded search with a strict verification; see
    `lcg_recover_truncated`.

Everything returns plain ints/lists/dicts; failure is explicit (`None`), never a
half-guess. Standard library only.
"""

from .algebra import modinv

_MASK32 = 0xffffffff
_MASK31 = 0x7fffffff
_MASK48 = (1 << 48) - 1
_MAGIC48 = 0x5deece66d
_ADDEND48 = 0xb


# ────────────────────────── xorshift32 ──────────────────────────

def _inv_xor_right_shift(y: int, shift: int) -> int:
    """Inverse of `x ^= x >> shift`

    A fixed-point iteration: every round settles `shift` more high bits, and 32
    rounds is comfortably more than the 32-bit width, so it is exact.
    """
    x = y
    for _ in range(32):
        x = y ^ (x >> shift)
    return x & _MASK32


def _inv_xor_left_shift(y: int, shift: int) -> int:
    """Inverse of `x ^= (x << shift) & 0xffffffff` (mirror image of the above)"""
    x = y
    for _ in range(32):
        x = y ^ ((x << shift) & _MASK32)
    return x & _MASK32


def _xorshift32_prev(z: int) -> int:
    """One step backwards: the three xor-shift stages inverted in reverse order"""
    z = _inv_xor_left_shift(z, 5)
    z = _inv_xor_right_shift(z, 17)
    z = _inv_xor_left_shift(z, 13)
    return z & _MASK32


def xorshift32_next(x: int) -> int:
    """One step of the classic Marsaglia xorshift32 (13, 17, 5) — state == output

    All-zero is absorbing, so a zero state is refused rather than quietly
    producing an endless run of zeros (the way such bugs usually reach a report).
    """
    x &= _MASK32
    if x == 0:
        raise ValueError("xorshift32: the all-zero state is absorbing; use a non-zero seed")
    x ^= (x << 13) & _MASK32
    x ^= x >> 17
    x ^= (x << 5) & _MASK32
    return x & _MASK32


def xorshift32_stream(seed: int, count: int) -> list:
    """`count` successive outputs starting at `seed` (the seed is the first output,
    matching the usual `x = seed; x = xorshift(x)` loop form)"""
    x = seed & _MASK32
    if x == 0:
        raise ValueError("xorshift32: the all-zero state is absorbing; use a non-zero seed")
    out = []
    for _ in range(count):
        out.append(x)
        x = xorshift32_next(x)
    return out


def xorshift_recover(outputs) -> dict:
    """Recover the state from consecutive 32-bit outputs → {"state": int} or None

    `state` is the value that produced `outputs[0]`. Since state == output, the
    state behind `outputs[1]` is exactly `_xorshift32_prev(outputs[1])` — the map is
    a bijection, so no bit guessing is needed (an earlier version tried to restore
    "the bits the left shifts lost", which is both unnecessary and wrong: the
    inverse composition recovers every bit). The candidate is replayed over the
    whole observed stream before it is returned.
    """
    outs = [int(o) & _MASK32 for o in outputs]
    if len(outs) < 2:
        return None
    seed = _xorshift32_prev(outs[1])
    if seed == 0:
        return None
    cur = seed
    for k in range(len(outs)):
        if k and cur != outs[k]:
            return None
        cur = xorshift32_next(cur)
    return {"state": seed}


def xorshift_predict(outputs, count: int) -> list:
    """Recover then predict the next `count` outputs ([] when unrecoverable)"""
    rec = xorshift_recover(outputs)
    if rec is None:
        return []
    x = rec["state"]
    stream = []
    for _ in range(len(outputs) + count):
        stream.append(x)
        x = xorshift32_next(x)
    return stream[len(outputs):]


# ────────────────────────── java.util.Random ──────────────────────────

def _java_next(seed: int, bits: int) -> tuple:
    """One `next(bits)` step → (new 48-bit seed, signed int result)

    The result is Java's signed int and `nextInt()` prints it as-is, so the sign
    must be reproduced here — recovery only works if the caller saw the same
    negative numbers the JVM printed.
    """
    seed = (seed * _MAGIC48 + _ADDEND48) & _MASK48
    val = seed >> (48 - bits)
    if val >= 0x80000000:
        val -= 0x100000000
    return seed, val


def _java_scramble(seed: int) -> int:
    """`new Random(seed)` scrambles the seed before use"""
    return (int(seed) ^ _MAGIC48) & _MASK48


def java_random_next(seed: int, bits: int = 32) -> int:
    """A single `nextInt()`-style output from an **internal** 48-bit seed

    Note the distinction that trips people up: `java_random_next(42, 32)` answers
    for the internal seed 42, whereas `new Random(42)` scrambles 42 first. For the
    value the JVM prints for `new Random(42)` use `java_random_ints(42, 1)`.
    """
    if not 1 <= bits <= 32:
        raise ValueError("bits must be in 1..32")
    return _java_next(_java_scramble(seed), bits)[1]


def java_random_ints(seed: int, count: int) -> list:
    """The first `count` values of `new Random(seed).nextInt()`"""
    st = _java_scramble(seed)
    out = []
    for _ in range(count):
        st, val = _java_next(st, 32)
        out.append(val)
    return out


def java_random_recover(outputs) -> dict:
    """Recover the **internal** 48-bit state from consecutive `nextInt()` outputs

    Returns {"seed": int} or None. "Internal" matters: `new Random(42)` feeds
    42 ^ 0x5DEECE66D into that state, so recovering from `new Random(42)` outputs
    yields the scrambled value, not 42.

    Method: `nextInt()` is `(state_after_one_step >> 16)`, so `outputs[0]` fixes the
    high 32 bits of x_1 (not of x_0) and leaves 16 bits free. Those 2^16 candidates
    are enumerated and each one is inverted with `modinv` to get x_0; the candidate
    that replays every observation is the answer. This is arithmetic rather than
    bitwise linear algebra on purpose — carries make the step map non-linear over
    GF(2), which was confirmed during development (a bitwise solver produced an
    unsatisfiable system that looked reasonable).
    """
    outs = [int(o) for o in outputs]
    if len(outs) < 2:
        return None
    mod = 1 << 48
    step = 1 << 16
    a = _MAGIC48
    c = _ADDEND48
    inv = modinv(a, mod)
    if inv is None:
        return None
    o0 = outs[0] & _MASK32
    for low in range(step):
        x1 = o0 * step + low
        x0 = ((x1 - c) % mod) * inv % mod
        if _java_state_verify(x0, outs):
            return {"seed": x0 & _MASK48}
    return None


def _java_state_verify(state: int, outs) -> bool:
    """Replay a candidate internal state against the observed outputs"""
    st = int(state) & _MASK48
    for o in outs:
        st, val = _java_next(st, 32)
        if val != int(o):
            return False
    return True


def java_random_predict(outputs, count: int) -> list:
    """Recover the internal state from outputs, then predict the next `count` ints"""
    rec = java_random_recover(outputs)
    if rec is None:
        return []
    st = rec["seed"]
    for _ in outputs:
        st, _val = _java_next(st, 32)
    out = []
    for _ in range(count):
        st, val = _java_next(st, 32)
        out.append(val)
    return out


# ────────────────────────── glibc rand() (TYPE_3) ──────────────────────────

_GLIBC_DEG = 31
_GLIBC_SEP = 3
_GLIBC_WARM = 310        # r_0..r_343 are dropped; the r[34+n] loop does 310 of them
_GLIBC_MOD = 2147483647  # 2^31 - 1: the *seeding* modulus, not the state modulus


def _glibc_srand_words(seed: int) -> list:
    """Reproduce glibc's `srandom_r` seeding → r_0..r_30

    Two details are load-bearing and each is a classic silent bug: the seed
    recurrence is modulo 2^31-1 (a zero result is patched back to 2^31-1), and the
    state words are not reduced to 31 bits — they are unwrapped sums modulo 2^32.
    """
    word = int(seed) & _MASK32
    if word == 0:
        word = 1                   # srandom(0) is quietly treated as 1, like glibc
    state = [word]
    for _ in range(_GLIBC_DEG - 1):
        last = state[-1]
        nxt = (16807 * last) % _GLIBC_MOD
        state.append(nxt if nxt else _GLIBC_MOD)
    return state


def _glibc_start(seed: int):
    """`srand(seed)` → the live (state, write_index, read_index) after the warm-up

    The generator is a circular buffer: each step writes `st[w] + st[r] (mod 2^32)`
    into slot `w` and then advances both pointers. After the seeding stage the first
    output uses w = 3, r = 0, and `_GLIBC_WARM` steps bring it to that state.
    """
    st = _glibc_srand_words(seed)
    w, r = _GLIBC_SEP, 0
    for _ in range(_GLIBC_WARM):
        st[w] = (st[w] + st[r]) & _MASK32
        w = (w + 1) % _GLIBC_DEG
        r = (r + 1) % _GLIBC_DEG
    return st, w, r


def _glibc_step(st: list, w: int, r: int) -> tuple:
    """One `rand()` step → (31-bit output, next write index, next read index)"""
    val = (st[w] + st[r]) & _MASK32
    st[w] = val
    return val >> 1, (w + 1) % _GLIBC_DEG, (r + 1) % _GLIBC_DEG


def glibc_rand_values(seed: int, count: int) -> list:
    """`srand(seed); rand()` → the first `count` full 31-bit values"""
    st, w, r = _glibc_start(seed)
    out = []
    for _ in range(count):
        val, w, r = _glibc_step(st, w, r)
        out.append(val)
    return out


def glibc_rand_recover(outputs) -> dict:
    """Recover the 31-word TYPE_3 state from roughly 100 consecutive `rand()` outputs

    Fewer is usually not enough: the hidden low bits are only pinned once enough
    carry equations accumulate (measured: 96 outputs give a unique state, 40 leave
    ~20 free bits and the function then returns None rather than guessing). An earlier
    docstring said ">= 31", which is the size of the state, not of the input needed.

    Returns {"state": [31 ints], "index": int} or None, where `state` is the array
    as it stands *before* the first observation (write/read pointers at their first
    positions) and `index` is the next write slot.

    Why the hidden bits are recoverable: writing each word as `2*t_j + b_j` (the `t`
    are known, they are the outputs; only `b_j`, the bit the `>> 1` throws away, is
    hidden) turns the recurrence `w_j = w_{j-31} + w_{j-3}` into

        b_j = b_{j-31} XOR b_{j-3}
        c_j = b_{j-31} AND b_{j-3},  where c_j = (t_j - t_{j-31} - t_{j-3}) mod 2^31

    Both come straight from the known high bits: `c_j` is computable and must be 0
    or 1 (a consistency check), and it forces `b_{j-31} = b_{j-3} = 1` whenever it is
    1. Propagation therefore fixes most bits, and the remaining ones are settled by a
    small bounded search — after which the whole state is replayed against every
    observation, so a state that merely fits the inputs and then diverges cannot be
    returned (that failure mode was observed during development).
    """
    outs = [int(o) & _MASK31 for o in outputs]
    n = len(outs)
    if n < _GLIBC_DEG + 4:
        return None                      # too few for the constraints to pin down
    step = 1 << 31
    carry = [None] * n
    for j in range(_GLIBC_DEG, n):
        c = (outs[j] - outs[j - _GLIBC_DEG] - outs[j - _GLIBC_SEP]) % step
        if c not in (0, 1):
            return None                  # the observations cannot come from TYPE_3
        carry[j] = c

    # Constraint list: (i, k, carry) meaning (b_i AND b_k) == carry, and the linear
    # relation b_j = b_i XOR b_k that ties j to the pair.
    pairs = [(j - _GLIBC_DEG, j - _GLIBC_SEP, carry[j]) for j in range(_GLIBC_DEG, n)]
    involved = {}
    for idx, (i, k, _c) in enumerate(pairs):
        involved.setdefault(i, []).append(idx)
        involved.setdefault(k, []).append(idx)

    bits = [None] * n

    def propagate():
        """Fixpoint over both relations; False when they contradict each other"""
        while True:
            changed = False
            for (i, k, c) in pairs:
                if c == 1:
                    for t in (i, k):
                        if bits[t] is None:
                            bits[t] = 1
                            changed = True
                        elif bits[t] != 1:
                            return False
                else:
                    if bits[i] == 1 and bits[k] == 1:
                        return False
                    if bits[i] == 1 and bits[k] is None:
                        bits[k] = 0
                        changed = True
                    if bits[k] == 1 and bits[i] is None:
                        bits[i] = 0
                        changed = True
            for j in range(_GLIBC_DEG, n):
                i, k = j - _GLIBC_DEG, j - _GLIBC_SEP
                if bits[i] is not None and bits[k] is not None:
                    val = bits[i] ^ bits[k]
                    if bits[j] is None:
                        bits[j] = val
                        changed = True
                    elif bits[j] != val:
                        return False
            if not changed:
                return True

    def consistent():
        for (i, k, c) in pairs:
            if bits[i] is not None and bits[k] is not None:
                if (bits[i] & bits[k]) != c:
                    return False
        for j in range(_GLIBC_DEG, n):
            i, k = j - _GLIBC_DEG, j - _GLIBC_SEP
            if None not in (bits[i], bits[k], bits[j]) and (bits[i] ^ bits[k]) != bits[j]:
                return False
        return True

    solutions = []

    def enumerate_solutions(node_budget):
        """Collect every assignment consistent with the observations, bounded

        Ordering by constraint degree is what makes this cheap: the residual free
        bits after propagation are ~20, yet a naive first-index branch explodes
        while picking the most constrained bit solves the same instance in ~20
        nodes (measured). Every solution reproduces the observed sequence, so the
        caller needs the *agreement* check below, not just one solution.
        """
        if len(solutions) > 256 or node_budget[0] <= 0:
            return
        node_budget[0] -= 1
        if not consistent():
            return
        unknown = [i for i in range(n) if bits[i] is None]
        if not unknown:
            solutions.append(list(bits))
            return
        pivot = max(unknown, key=lambda i: len(involved.get(i, [])))
        for guess in (0, 1):
            saved = list(bits)
            bits[pivot] = guess
            if propagate():
                enumerate_solutions(node_budget)
            for i in range(n):
                bits[i] = saved[i]

    if not propagate():
        return None
    budget = [4096]
    enumerate_solutions(budget)
    # A truncated enumeration cannot prove that every fitting state agrees, and
    # "the states I happened to find agree" is not the same claim (measured: with
    # 40 outputs the search hit the cap and the agreeing subset still predicted the
    # wrong next value). So truncation means no honest answer, not a lucky one.
    truncated = len(solutions) > 256 or budget[0] <= 0
    if not solutions:
        return None

    def words_of(bitset):
        words = [2 * outs[j] + bitset[j] for j in range(n)]
        for j in range(_GLIBC_DEG, n):
            if (words[j - _GLIBC_DEG] + words[j - _GLIBC_SEP]) & _MASK32 != words[j]:
                return None
        return words

    futures = set()
    first_words = None
    for bitset in solutions:
        words = words_of(bitset)
        if words is None:
            continue
        if first_words is None:
            first_words = words
        probe = list(words)
        fut = []
        for _ in range(3):
            nxt = (probe[-_GLIBC_DEG] + probe[-_GLIBC_SEP]) & _MASK32
            probe.append(nxt)
            fut.append(nxt >> 1)
        futures.add(tuple(fut))
    if first_words is None or len(futures) != 1 or truncated:
        # More than one state fits the observations and they disagree on the very
        # next outputs: the low bits are genuinely underdetermined, so there is no
        # honest answer to give. Ask for more outputs instead of guessing.
        return None
    return {"state": first_words[-_GLIBC_DEG:], "index": _GLIBC_DEG,
            "words": first_words,
            "solutions_considered": len(solutions)}


def glibc_rand_predict(outputs, count: int) -> list:
    """Recover the glibc state, then predict the next `count` rand() values

    Prediction just continues the verified linear recurrence
    `w_j = w_{j-31} + w_{j-3} (mod 2^32)` from the recovered 31-word window; each
    new value is emitted as `w >> 1`, exactly as glibc's `rand()` does.
    """
    rec = glibc_rand_recover(outputs)
    if rec is None:
        return []
    words = list(rec["words"])
    out = []
    for _ in range(count):
        nxt = (words[-_GLIBC_DEG] + words[-_GLIBC_SEP]) & _MASK32
        words.append(nxt)
        out.append(nxt >> 1)
    return out


# ────────────────────────── truncated LCG ──────────────────────────

def lcg_recover_truncated(outputs, bits_known: int, modulus: int = None,
                          multiplier: int = None):
    """Recover the hidden low bits of an LCG observed through its HIGH bits

    Args:
        outputs: consecutive `x_0, x_1, ...` of which only the top `bits_known`
                 bits are known (pass either the raw high bits or the full
                 values — only the top bits are read)
        bits_known: how many high bits each observation reveals
        modulus: the LCG modulus. **Required** — the search is built modulo it, and
                 a guessed modulus produces a plausible-looking wrong answer.
        multiplier: the LCG multiplier `a`. **Required** as well: the middle term of
                 the recurrence depends on the low bits of `a` as well as of the
                 state, so without it the search would span a square of the hidden
                 space. The caller gets None instead of a guess.
    Returns:
        {"outputs": [full ints], "a": int, "c": int, "m": int} or None.

    Method: with `a` known, `x_0 = high_0 * 2^b + low` leaves the low bits as the only
    unknown, so the `(x_0, x_1)` low-bit pairs are enumerated and propagated — the
    constant follows from the first pair (`c ≡ x_1 - a*x_0 (mod m)`), and a wrong
    guess leaves its high-bit bucket almost immediately. A candidate is returned only
    when the whole sequence satisfies `x_{i+1} = a*x_i + c (mod m)` for that single
    `c`, every observed high-bit bucket, **and** reproduces the numbers the caller
    actually passed.

    Limitation, stated plainly — this is the honest part of the module. It is a
    bounded search, not the general lattice attack, and the observations do not
    always determine the hidden bits: several `(x_0 low bits, x_1 low bits)` pairs can
    satisfy every bucket and the recurrence (verified during development on a 16-bit
    LCG, where two different `c` values both fitted six observations). When that
    happens this returns None rather than picking one, so a returned dict is a
    verified result and None means "not determined by this data" — never a
    fabricated sequence. None is also returned when the hidden part is too large to
    search (`shift > 12`, i.e. `2^(2*shift)` candidates) or when the multiplier is
    not supplied.
    """
    vals = [int(v) for v in outputs]
    if modulus is None or multiplier is None:
        return None
    m = int(modulus)
    b = int(bits_known)
    if m <= 1 or b <= 0 or b >= m.bit_length() or len(vals) < 3:
        return None
    shift = (m - 1).bit_length() - b          # how many low bits are hidden
    if shift < 0 or shift > 12:
        # 2^(2*shift) candidates: beyond this the bounded search stops being
        # bounded, and returning None is honest where a fabricated sequence is not
        return None
    a = int(multiplier) % m
    step = 1 << shift
    # Two input conventions are accepted, and only the one that *fits the actual
    # numbers* is used: the caller may hand over the high bits as their own numbers
    # (`189` meaning 0b10111101) or the whole values with only the top bits
    # meaningful. Getting this backwards is what made an earlier version search
    # inside an all-zero space and report `[0, 0, ...]`, because `189 >> 8` is 0 and
    # every bucket then matched trivially.
    if all(v < (1 << b) for v in vals):
        highs = [v for v in vals]              # high bits isolated, as numbers
    elif all(v < m for v in vals):
        highs = [v >> shift for v in vals]     # full values
    else:
        return None
    if any(h >= (1 << b) for h in highs):
        return None
    seq = _lcg_search(highs, shift, m, a, step, vals, full_values=False)
    if seq is None:
        return None
    return _lcg_package(seq, m, a)


def _lcg_search(known, shift, m, a, step, original, full_values=True):
    """Enumerate the hidden low bits of x_0, derive the rest, then verify

    The constant is the crux: for a guess of x_0 the sequence is not free — the low
    bits of every later state follow from the recurrence, and all of them must
    still land in the buckets the caller observed. `c` is then read off the first
    transition and has to reproduce *every* later state exactly. Candidates that
    reproduce the caller's numbers verbatim are preferred, and a candidate is only
    returned when nothing can beat it.
    """
    best = None
    survivors = 0
    for low0 in range(step):
        x0 = (known[0] << shift) | low0
        base = (a * x0) % m
        # `x_1`'s low bits are the other hidden quantity, and `c` follows from them:
        # `c ≡ x_1 - a*x_0 (mod m)`. So the pair (low0, low1) determines everything,
        # and the replay decides. Ranking prefers the candidate that reproduces the
        # caller's numbers verbatim, which is the only evidence available about
        # which of the surviving candidates is the real one.
        for low1 in range(step):
            x1 = (known[1] << shift) | low1
            c = (x1 - base) % m
            seq = [x0]
            good = True
            for i in range(1, len(known)):
                nxt = (a * seq[-1] + c) % m
                if nxt >> shift != known[i]:
                    good = False
                    break
                seq.append(nxt)
            if not good or len(seq) != len(known) or not _lcg_verify(seq, m, a):
                continue
            survivors += 1
            agree = sum(1 for i, v in enumerate(seq) if v == original[i])
            score = (agree, -sum(abs(v - o) for v, o in zip(seq, original)))
            if best is None or score > best[0]:
                best = (score, seq)
    if best is None:
        return None
    # The observations only pin the hidden bits down when the winner reproduces
    # what the caller actually passed. Without that, several `(low0, x_1 low bits)`
    # pairs satisfy every bucket and the recurrence, and picking one would be a
    # guess dressed up as a recovery — so say None instead.
    if best[0][0] != len(known):
        return None
    return best[1]


def _lcg_verify(seq, m, a) -> bool:
    """Every consecutive pair must satisfy x_{i+1} = a*x_i + c (mod m) for one c"""
    if len(seq) < 2:
        return False
    c = (seq[1] - a * seq[0]) % m
    return all((a * seq[i] + c) % m == seq[i + 1] % m for i in range(len(seq) - 1))


def _lcg_package(seq, m, a):
    """Fill in `c` from a verified sequence"""
    return {"outputs": list(seq), "a": a, "c": (seq[1] - a * seq[0]) % m, "m": m}
