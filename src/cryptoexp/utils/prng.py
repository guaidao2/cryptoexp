"""PRNG infrastructure — MT19937 state cloning / seed cracking (a CTF staple)

Python's random is MT19937: 624 32-bit outputs are enough to clone the state
completely, after which every later output is predictable. These are reusable
primitives rather than a fix for one particular challenge.
"""

import random as _random

_N = 624
_M = 397
_MATRIX_A = 0x9908b0df
_UPPER = 0x80000000
_LOWER = 0x7fffffff
_MASK32 = 0xffffffff


def _temper(y: int) -> int:
    y ^= y >> 11
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 15) & 0xefc60000
    y ^= y >> 18
    return y & _MASK32


def _undo_right_shift_xor(y: int, shift: int) -> int:
    x = y
    for _ in range(32 // max(1, shift) + 1):
        x = y ^ (x >> shift)
    return x & _MASK32


def _undo_left_shift_xor_mask(y: int, shift: int, mask: int) -> int:
    x = y
    for _ in range(32 // max(1, shift) + 1):
        x = y ^ ((x << shift) & mask)
    return x & _MASK32


def untemper(y: int) -> int:
    """Inverse of temper — recover the internal state word from an output"""
    y = _undo_right_shift_xor(y, 18)
    y = _undo_left_shift_xor_mask(y, 15, 0xefc60000)
    y = _undo_left_shift_xor_mask(y, 7, 0x9d2c5680)
    y = _undo_right_shift_xor(y, 11)
    return y & _MASK32


class MT19937:
    """Cloneable MT19937 — for "given outputs, predict the rest" challenges"""

    def __init__(self, state=None, index: int = _N):
        if state is None:
            self.mt = [0] * _N
            self.index = _N
        else:
            if len(state) != _N:
                raise ValueError(f"state must be {_N} words")
            self.mt = [s & _MASK32 for s in state]
            self.index = index

    # ── native algorithm (matches CPython _randommodule.c) ──
    def _generate(self):
        for i in range(_N):
            y = (self.mt[i] & _UPPER) | (self.mt[(i + 1) % _N] & _LOWER)
            v = self.mt[(i + _M) % _N] ^ (y >> 1)
            if y & 1:
                v ^= _MATRIX_A
            self.mt[i] = v & _MASK32
        self.index = 0

    def next32(self) -> int:
        if self.index >= _N:
            self._generate()
        y = self.mt[self.index]
        self.index += 1
        return _temper(y)

    def next_below(self, n: int) -> int:
        """Equivalent to CPython's _randbelow (getrandbits rejection sampling)"""
        k = n.bit_length()
        while True:
            r = self.next32() >> (32 - k)
            if r < n:
                return r

    def next_range(self, a: int, b: int) -> int:
        return a + self.next_below(b - a)


def clone_from_outputs(outputs) -> MT19937:
    """Clone the state from 624 32-bit outputs"""
    outs = [o & _MASK32 for o in outputs]
    if len(outs) < _N:
        raise ValueError(f"at least {_N} 32-bit outputs needed (got {len(outs)})")
    return MT19937([untemper(o) for o in outs[:_N]], index=_N)


def predict_next(outputs, count: int = 3):
    """Given outputs → predict the next count 32-bit values"""
    clone = clone_from_outputs(outputs)
    return [clone.next32() for _ in range(count)]


def clone_python_random(getrandbits32_values) -> _random.Random:
    """Load the cloned MT state back into a random.Random object, so that
    random.randrange works directly"""
    mt = clone_from_outputs(getrandbits32_values)
    rng = _random.Random()
    rng.setstate((3, tuple(mt.mt + [mt.index]), None))
    return rng


def crack_seed(target_output: int, max_seed: int = 2 ** 24, base_seed: int = 0,
               use_getrandbits32: bool = True):
    """Small-seed brute force (common when the seed is time.time())

    target_output: the first output (the result of getrandbits(32) or
    randint(0, 2**32-1))
    Returns the matching seed or None. 2^24 iterations take tens of seconds —
    hence the default cap, with the caller deciding where to set it.
    """
    for seed in range(base_seed, base_seed + max_seed):
        rng = _random.Random(seed)
        val = rng.getrandbits(32) if use_getrandbits32 else rng.randint(0, 2 ** 32 - 1)
        if val == target_output:
            return seed
    return None
