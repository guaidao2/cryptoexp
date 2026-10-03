"""GF(2) linear algebra, LFSR analysis and CRC primitives - pure standard library

Why this module exists
----------------------
Three CTF-frequent families are the same object: a bit that depends linearly (mod 2)
on other bits.

1) GF(2) linear algebra.  A linear map over GF(2) (bit-oriented Hill ciphers, "here is
   the matrix" tasks, CRC parameter recovery, CRC forging) always ends as A*x = b over
   GF(2).  gf.py covers GF(p) with real arithmetic; mod 2 deserves its own code because
   bit-packed rows turn elimination into XOR and shift instead of multiply and inverse.

2) LFSR.  A stream cipher built on a linear feedback shift register leaks the whole
   register: 2L output bits determine the minimal connection polynomial
   (Berlekamp-Massey) and the initial state, so the remaining keystream is computable.

3) CRC.  A CRC is an LFSR with the message XORed into the register, i.e. an affine map
   over GF(2).  That one fact gives both directions: recover unknown parameters from
   samples, and forge an appended block that lands on a chosen CRC without brute force.

Representation - ONE choice, used by every function here
--------------------------------------------------------
* A matrix is a list of Python ints; each int is one bit-packed row.
* Column j of a row is bit j of that int, so column 0 is the least significant bit.
  Rationale: an int carries no width, so the LSB has to be column 0 for the
  representation to work without threading a width through every call.
* A vector (a solution, a null-space basis vector, an LFSR register state) is the same
  thing with a single row: bit j is component j / element j.
* Honest consequences:
    - the column count is max(row.bit_length()) unless you pass `cols=`; a column that
      is zero in every row is invisible.  Pass `cols=` when that matters (the CRC
      forger does, because its matrices have exactly 8*append_len unknown columns).
    - this is NOT gf.py's list-of-lists form.  Convert with
      `[sum(b << j for j, b in enumerate(row)) for row in rows]`.

Bit order of the bit-list helpers (deliberately different from the packing above)
--------------------------------------------------------------------------------
* int_to_bits / bits_to_int are MSB-first, like Python's bin() and int(s, 2):
  int_to_bits(0b110, 3) == [1, 1, 0].
* bytes_to_bits / bits_to_bytes are MSB-first inside each byte too.  That is the
  convention CRC test vectors are defined over ("123456789" is 0x31 0x32 ...), and
  reversing it would be the surprising choice.
* To bridge a bit *list* to a bit-packed row/vector (LSB = column 0), reverse it:
  `vec = bits_to_int(bits[::-1])` and `bits = int_to_bits(vec, n)[::-1]`.

LFSR convention
---------------
A Fibonacci LFSR is described by the exponent list of its characteristic polynomial, and
the leading term IS part of the list:

    taps = [t0, t1, ..., L]        ascending, distinct, L = max(taps)
    C(x) = x^L + sum of x^t over t in taps with t < L
    b[n+L] = b[n+t0] ^ b[n+t1] ^ ...            (the x^L term is not a state bit)

The state is a bit-packed int in the same LSB-first packing: state bit 0 is the next bit
the register emits.  One step is
    `fb = parity(state & tap_mask); state = (state >> 1) | (fb << (L-1))`.

Why include the leading term?  Without it the register width would have to be guessed as
max(taps)+1, which silently yields a *shorter* (therefore wrong) LFSR whenever the real
degree is not itself a tap.  With it, `LFSR(taps, state).width == max(taps)` is
unambiguous and berlekamp_massey's output plugs straight back into the constructor.  The
empty list is reserved for the degenerate zero sequence (L = 0).

CRC convention
--------------
Rocksoft / CRC-RevEng model with every parameter explicit: width, poly (normal form, the
top term is implicit), init, refin, refout, xorout.  So

    crc_compute(b"123456789", 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF)
      == 0xCBF43926                      # the CRC-32 check value, also in crc_known()

refin and refout stay two independent flags rather than one derived from the other,
because parameter sets with refin=True, refout=False do show up in CTF tasks.
"""


# ------------------------------ bit-list helpers ------------------------------

def bytes_to_bits(data):
    """bytes -> list of bits, MSB first inside each byte (0x01 -> 0,0,0,0,0,0,0,1)

    This is the order a CRC engine consumes a message in, and the order the standard
    check value over b"123456789" is defined in.
    """
    out = []
    for byte in bytes(data):
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def bits_to_bytes(bits):
    """Bit list (MSB first inside each byte) -> bytes

    Raises ValueError when len(bits) is not a multiple of 8: what to do with a partial
    trailing byte is a decision for the caller, and padding it here would hide it.
    Non-bit values raise too - masking them to 0/1 would produce plausible garbage.
    """
    b = _bits(bits)
    if len(b) % 8:
        raise ValueError(f"bit count {len(b)} is not a multiple of 8")
    out = bytearray()
    for i in range(0, len(b), 8):
        value = 0
        for bit in b[i:i + 8]:
            value = (value << 1) | bit
        out.append(value)
    return bytes(out)


def int_to_bits(x, width=None):
    """int -> bit list, MSB first (int_to_bits(0b110, 3) == [1, 1, 0])

    width: how many bits to emit; None means the shortest exact form (0 -> []).
    A width that cannot hold x raises ValueError instead of truncating - silently
    truncating a key or a register is exactly the bug this library must not have.
    """
    if not isinstance(x, int) or isinstance(x, bool):
        raise ValueError("int_to_bits: x must be an int")
    if x < 0:
        raise ValueError("int_to_bits: x must be non-negative")
    if width is None:
        width = x.bit_length()
    elif not isinstance(width, int) or width < 0:
        raise ValueError("int_to_bits: width must be a non-negative int")
    elif x.bit_length() > width:
        raise ValueError(f"int_to_bits: {x.bit_length()} bits do not fit in width {width}")
    return [(x >> i) & 1 for i in range(width - 1, -1, -1)]


def bits_to_int(bits):
    """Bit list, MSB first -> int (bits_to_int([1, 1, 0]) == 0b110)

    Only 0/1 (or True/False) are accepted; anything else raises ValueError.
    """
    out = 0
    for b in bits:
        if b is True or b is False:
            out = (out << 1) | int(b)
        elif isinstance(b, int) and b in (0, 1):
            out = (out << 1) | b
        else:
            raise ValueError(f"bits_to_int: {b!r} is not a bit")
    return out


def _bits(seq):
    """Validated copy of a bit sequence; anything that is not 0/1 raises ValueError"""
    out = []
    for b in seq:
        if b is True or b is False:
            out.append(int(b))
        elif isinstance(b, int) and b in (0, 1):
            out.append(b)
        else:
            raise ValueError(f"expected a bit (0/1), got {b!r}")
    return out


def _as_bytes(data, what="data"):
    """Bytes-like -> bytes; a str raises, because the encoding would be a guess"""
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        raise ValueError(f"{what} must be bytes-like, not str (encode it explicitly)")
    try:
        return bytes(data)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{what} is not bytes-like: {exc}") from exc


# ------------------------------ GF(2) linear algebra ------------------------------

def _col_count(mat, cols):
    """Column count: explicit when given, else max(row.bit_length())

    The inferred count cannot see a column that is zero in every row; that is the one
    place where this representation loses information, so `cols` exists.
    """
    if cols is not None:
        if not isinstance(cols, int) or cols < 0:
            raise ValueError("cols must be a non-negative int")
        return cols
    width = 0
    for row in mat:
        if isinstance(row, bool) or not isinstance(row, int):
            raise ValueError("a gf2 matrix is a list of ints (one bit-packed row each)")
        if row < 0:
            raise ValueError("gf2 rows must be non-negative ints")
        if row.bit_length() > width:
            width = row.bit_length()
    return width


def _check_rows(mat):
    """Validate a bit-packed matrix without needing a column count"""
    for row in mat:
        if isinstance(row, bool) or not isinstance(row, int):
            raise ValueError("a gf2 matrix is a list of ints (one bit-packed row each)")
        if row < 0:
            raise ValueError("gf2 rows must be non-negative ints")


def gf2_rref(mat, cols=None):
    """Row-reduced echelon form over GF(2) -> (rref_rows, pivot_cols, rank)

    Args:
        mat:  list of bit-packed row ints (never modified; new rows are returned)
        cols: column count; None = inferred from the highest set bit

    Returns:
        (rows, pivot_cols, rank); pivot_cols is ascending.

    The reduced form over a field is unique, so the pivot list describes the matrix
    itself and not the order in which this loop happened to eliminate.
    """
    width = _col_count(mat, cols)
    rows = [row & ((1 << width) - 1) for row in mat]
    n = len(rows)
    pivots = []
    r = 0
    for c in range(width):
        bit = 1 << c
        pivot_row = -1
        for i in range(r, n):
            if rows[i] & bit:
                pivot_row = i
                break
        if pivot_row < 0:
            continue
        rows[r], rows[pivot_row] = rows[pivot_row], rows[r]
        for i in range(n):
            if i != r and (rows[i] & bit):
                rows[i] ^= rows[r]
        pivots.append(c)
        r += 1
        if r == n:
            break
    return rows, pivots, r


def gf2_rank(mat, cols=None):
    """Rank over GF(2) -> int (see gf2_rref for the representation)"""
    return gf2_rref(mat, cols)[2]


def gf2_solve(mat, rhs, cols=None):
    """Solve mat*x = rhs over GF(2) -> bit-packed x, or None

    x is one solution: bit j of the result is component j of x (LSB-first packing).

    Returns None when the system is inconsistent (a row reads 0 = 1).  There is no
    approximate answer worth returning here, and a wrong "solution" is worse than none.
    When several solutions exist the free variables are set to 0 and one particular
    solution comes back; gf2_nullspace(mat) measures the ambiguity.

    Raises ValueError when len(rhs) != len(mat) or an rhs entry is not a bit.
    """
    width = _col_count(mat, cols)
    if len(rhs) != len(mat):
        raise ValueError("rhs length does not match the number of matrix rows")
    aug = []
    for i, row in enumerate(mat):
        entry = rhs[i]
        if entry is True or entry is False:
            entry = int(entry)
        elif not (isinstance(entry, int) and entry in (0, 1)):
            raise ValueError(f"gf2_solve: rhs[{i}] = {rhs[i]!r} is not a bit")
        aug.append(row | (entry << width))
    rows, pivots, _ = gf2_rref(aug, width + 1)
    solution = 0
    for i, c in enumerate(pivots):
        if c == width:
            # the rhs column became a pivot: some row has only the rhs bit set
            return None
        if rows[i] >> width & 1:
            solution |= 1 << c
    return solution


def gf2_nullspace(mat, cols=None):
    """Null-space basis over GF(2) -> list of bit-packed basis vectors

    len(basis) == cols - gf2_rank(mat, cols), which is the consistency check the test
    suite runs.  An empty list means the null space is {0}.
    """
    width = _col_count(mat, cols)
    rows, pivots, rank = gf2_rref(mat, width)
    pivot_set = set(pivots)
    basis = []
    for fc in range(width):
        if fc in pivot_set:
            continue
        vec = 1 << fc
        for i, pc in enumerate(pivots):
            if rows[i] >> fc & 1:
                vec |= 1 << pc
        basis.append(vec)
    return basis


def gf2_inv(mat):
    """Inverse of a square GF(2) matrix -> list of bit-packed rows, or None

    Returns None when the matrix is singular (rank < n).  A non-square or over-wide
    input raises ValueError: "inverse" is meaningless there, and a rectangular answer
    would be a bug the caller cannot see.
    """
    _check_rows(mat)
    n = len(mat)
    if n == 0:
        raise ValueError("gf2_inv: empty matrix")
    for i, row in enumerate(mat):
        if row.bit_length() > n:
            raise ValueError(f"gf2_inv: row {i} has bits outside a {n}x{n} block")
    aug = [mat[i] | (1 << (n + i)) for i in range(n)]
    rows, pivots, rank = gf2_rref(aug, 2 * n)
    # full rank is not enough: if a pivot landed in the identity block the left block
    # is singular (n pivots spread over 2n columns can all sit on the right)
    if rank < n or pivots[n - 1] >= n:
        return None
    return [row >> n for row in rows]


# ------------------------------ LFSR ------------------------------

def _check_taps(taps):
    """Validate and normalise a tap list (ascending, distinct, non-negative ints)"""
    try:
        items = list(taps)
    except TypeError as exc:
        raise ValueError(f"taps must be an iterable of bit positions: {exc}") from exc
    for t in items:
        if isinstance(t, bool) or not isinstance(t, int):
            raise ValueError(f"taps must be ints, got {t!r}")
        if t < 0:
            raise ValueError("taps must be non-negative bit positions")
    if len(set(items)) != len(items):
        raise ValueError("duplicate taps: they would cancel over GF(2)")
    return sorted(items)


def _state_from_bits(bits):
    """Bit list in emission order -> register int (bit 0 of the register = bits[0])

    Same packing as the GF(2) vectors above (LSB first), which is the reverse of
    bits_to_int's MSB-first order - hence the explicit reversal here.
    """
    return bits_to_int(list(bits)[::-1])


class LFSR:
    """Fibonacci LFSR: connection-polynomial exponents plus an initial register state

    Args:
        taps:  exponents of the characteristic polynomial INCLUDING the degree term,
               e.g. x^16 + x^14 + x^13 + x^11 + 1 -> [0, 11, 13, 14, 16].
               The register width is max(taps) - there is nothing to infer.
        state: bit-packed register; bit 0 is the bit emitted first.  Bits at or above
               the register width raise ValueError (a state wider than the register is
               silent aliasing waiting to happen).
        width: optional explicit width, accepted only if it equals max(taps); it exists
               to catch an omitted leading term early instead of aliasing the register.

    An empty tap list with state 0 is the degenerate "always zero" generator (L = 0);
    an empty tap list with a non-zero state is rejected.
    """

    def __init__(self, taps, state, width=None):
        self.taps = _check_taps(taps)
        if isinstance(state, bool) or not isinstance(state, int):
            raise ValueError("LFSR state must be an int")
        if state < 0:
            raise ValueError("LFSR state must be non-negative")
        if not self.taps:
            if state:
                raise ValueError("empty taps (the zero sequence) require state 0")
            self.width = 0
        else:
            self.width = self.taps[-1]
            if self.width < 1:
                raise ValueError("taps must reach a degree of at least 1 "
                                 "(the leading term belongs in the list)")
        if width is not None and width != self.width:
            raise ValueError(f"width {width} contradicts max(taps) = {self.width}; if you "
                             "omitted the leading term, append the degree to taps")
        if state >> self.width:
            raise ValueError(f"state does not fit in {self.width} bits")
        self.state = state
        # every tap except the leading term is a state bit XORed into the feedback
        self._mask = 0
        for t in self.taps[:-1]:
            self._mask |= 1 << t

    def next_bit(self):
        """Advance one step and return the emitted bit (0 or 1)

        The step is: emit bit 0, shift the register right, shift the feedback parity
        into the top position.
        """
        out = self.state & 1
        if self.width:
            fb = (self.state & self._mask).bit_count() & 1
            self.state = (self.state >> 1) | (fb << (self.width - 1))
        return out

    def keystream(self, n):
        """Next n output bits as a list (the register advances by n steps)"""
        if not isinstance(n, int) or n < 0:
            raise ValueError("keystream length must be a non-negative int")
        return [self.next_bit() for _ in range(n)]

    def next_bytes(self, n):
        """Next n bytes: 8 bits per byte, most significant bit first

        The first bit produced becomes the MSB of the first byte, the same order
        bytes_to_bits uses, so next_bytes(n) == bits_to_bytes(keystream(8*n)).
        """
        if not isinstance(n, int) or n < 0:
            raise ValueError("byte count must be a non-negative int")
        out = bytearray()
        for _ in range(n):
            value = 0
            for _ in range(8):
                value = (value << 1) | self.next_bit()
            out.append(value)
        return bytes(out)

    def __repr__(self):  # keeps debugging output honest and readable
        return f"LFSR(width={self.width}, taps={self.taps}, state=0x{self.state:x})"


def lfsr_from_bits(bits, taps, count=None):
    """Seed an LFSR from state bits and return its keystream as bytes

    bits[:L] (L = max(taps)) becomes the initial register - bit 0 of the register is
    bits[0], the first bit the register emits.  `count` output bits are generated and
    packed 8 bits per byte, MSB first, zero-padded at the end when count is not a
    multiple of 8.

    `count` defaults to len(bits): because the register's first L output bits *are* the
    seed, regenerating the same length would just echo the input, so the default is the
    continuation of the same length.  Pass count explicitly for a fixed length.

    Raises ValueError when len(bits) < L - a truncated seed is not a shorter LFSR, it is
    a different (wrong) one.
    """
    ts = _check_taps(taps)
    b = _bits(bits)
    width = ts[-1] if ts else 0
    if len(b) < width:
        raise ValueError(f"need at least {width} seed bits for these taps, got {len(b)}")
    if count is None:
        count = len(b)
    if not isinstance(count, int) or count < 0:
        raise ValueError("count must be a non-negative int")
    out = LFSR(ts, _state_from_bits(b[:width])).keystream(count)
    out.extend([0] * (-len(out) % 8))
    return bits_to_bytes(out)


def berlekamp_massey(bits):
    """Minimal LFSR connection polynomial for a bit sequence (Massey's algorithm)

    Returns the exponent list of the characteristic polynomial, ascending and INCLUDING
    the degree term (the module docstring defines the convention), so the result is a
    valid `LFSR(taps, state)` argument.  The recovered polynomial reproduces the given
    bits exactly, and - for bits that really came from an LFSR - every bit after them.

    Honest limits:
      * L is the linear complexity *of the bits you passed*.  With fewer than 2L bits it
        is a fit, not a fact; this function returns the smallest polynomial the data
        supports, and only lfsr_recover refuses to guess from too little evidence.
      * The empty list means L = 0, i.e. every input bit was 0.
    """
    s = _bits(bits)
    n = len(s)
    C = [1]
    B = [1]
    L = 0
    m = 1
    for i in range(n):
        if len(C) < L + 1:
            C.extend([0] * (L + 1 - len(C)))
        d = s[i]
        for j in range(1, L + 1):
            if C[j] and s[i - j]:
                d ^= 1
        if d == 0:
            m += 1
            continue
        T = C[:]
        if len(C) < len(B) + m:
            C.extend([0] * (len(B) + m - len(C)))
        for j in range(len(B)):
            if B[j]:
                C[j + m] ^= 1
        if 2 * L <= i:
            L = i + 1 - L
            B = T
            m = 1
        else:
            m += 1
    if len(C) < L + 1:
        C.extend([0] * (L + 1 - len(C)))
    if L == 0:
        return []
    # exponents of C(x) = x^L + sum C[i] x^(L-i): the leading term L comes from C[0] = 1
    return sorted([L] + [L - i for i in range(1, L + 1) if C[i]])


def lfsr_recover(bits):
    """Recover a full LFSR from >= 2L keystream bits -> {"taps": [...], "state": int} or None

    Berlekamp-Massey gives the minimal polynomial; the initial state is simply the first
    L bits, because the recurrence it recovers is exactly "run from those L bits".  The
    candidate is then verified by re-generating the whole input, so a returned dict is
    always a generator that reproduces every bit it was given.

    Returns None when fewer than 2L bits are available (such a polynomial fits noise, and
    predicting from it would be a confident wrong answer) or when re-generation
    mismatches.  The all-zero sequence comes back as {"taps": [], "state": 0}.
    """
    s = _bits(bits)
    taps = berlekamp_massey(s)
    degree = taps[-1] if taps else 0
    if len(s) < 2 * degree:
        return None
    if len(s) < degree:
        return None
    seed = s[:degree]
    if LFSR(taps, _state_from_bits(seed)).keystream(len(s)) != s:
        return None
    return {"taps": taps, "state": _state_from_bits(seed)}


def lfsr_next(bits, count):
    """Predict the next `count` bits of an LFSR sequence -> list of bits, or None

    Runs lfsr_recover (Berlekamp-Massey plus verification) and then advances the
    recovered register past the observed bits - the recovered state is the state at
    time 0, so regenerating without that step would hand back the *beginning* of the
    sequence instead of its continuation.  Returns None rather than extrapolating from
    an unverified polynomial.
    """
    if not isinstance(count, int) or count < 0:
        raise ValueError("count must be a non-negative int")
    s = _bits(bits)
    rec = lfsr_recover(s)
    if rec is None:
        return None
    stream = LFSR(rec["taps"], rec["state"]).keystream(len(s) + count)
    return stream[len(s):]


# ------------------------------ CRC ------------------------------

_REFLECT8 = bytes(int(format(i, "08b")[::-1], 2) for i in range(256))


def _reflect(value, width):
    """Bit-reverse the low `width` bits of value"""
    out = 0
    for _ in range(width):
        out = (out << 1) | (value & 1)
        value >>= 1
    return out


class CRC:
    """A configurable CRC engine (Rocksoft / CRC-RevEng parameter set)

    Args:
        width:  register width in bits, 1..64
        poly:   generator polynomial in normal form, top term implicit
                (0x04C11DB7 for CRC-32, not 0x104C11DB7)
        init:   starting register value (before the first message bit)
        refin:  True = the bits inside each input byte are consumed LSB first
        refout: True = the final register is reflected before xorout
        xorout: XORed into the result last

    refin and refout are independent on purpose: "both true" is the usual reflected
    CRC (CRC-32, CRC-16/ARC), "both false" the usual MSB-first one (CCITT-FALSE), but
    mixed sets occur in the wild and deriving one from the other would quietly
    misinterpret them.

    The engine is bit-at-a-time.  That is about 8x slower than a table-driven one, and
    it is exact for every width in 1..64 with no special cases - which is the right
    trade for CTF-sized inputs and for the parameter recovery below, where correctness
    of the model matters more than throughput.
    """

    def __init__(self, width, poly, init=0, refin=False, refout=False, xorout=0):
        if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= 64:
            raise ValueError("CRC width must be an int in 1..64")
        self.width = width
        self.mask = (1 << width) - 1
        if isinstance(poly, bool) or not isinstance(poly, int) or not 0 <= poly <= self.mask:
            raise ValueError(f"CRC poly must be an int in 0..2**{width}-1 (normal form)")
        for name, value in (("init", init), ("xorout", xorout)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"CRC {name} must be an int")
            if not 0 <= value <= self.mask:
                raise ValueError(f"CRC {name} does not fit in {width} bits")
        self.poly = poly
        self.init = init
        self.refin = bool(refin)
        self.refout = bool(refout)
        self.xorout = xorout

    def compute(self, data):
        """CRC of `data` (bytes-like) -> int in [0, 2**width)

        Raises ValueError for a str, since the encoding of the message decides the
        answer and guessing it would be silently wrong.
        """
        payload = _as_bytes(data)
        crc = self.init
        top = 1 << (self.width - 1)
        for byte in payload:
            if self.refin:
                byte = _REFLECT8[byte]
            for i in range(7, -1, -1):
                crc ^= ((byte >> i) & 1) << (self.width - 1)
                if crc & top:
                    crc = ((crc << 1) ^ self.poly) & self.mask
                else:
                    crc = (crc << 1) & self.mask
        if self.refout:
            crc = _reflect(crc, self.width)
        return crc ^ self.xorout

    def __repr__(self):
        return (f"CRC(width={self.width}, poly=0x{self.poly:x}, init=0x{self.init:x}, "
                f"refin={self.refin}, refout={self.refout}, xorout=0x{self.xorout:x})")


def crc_compute(data, width, poly, init=0, refin=False, refout=False, xorout=0):
    """CRC of data -> int (one-shot form of CRC.compute; see CRC for the parameters)"""
    return CRC(width, poly, init, refin, refout, xorout).compute(data)


def crc_known(width=None):
    """Standard CRC parameter sets, keyed by their CRC-RevEng names

    Args:
        width: restrict to one register width (8, 16, 32, 64); None = the whole catalog

    Returns:
        {name: {"name", "width", "poly", "init", "refin", "refout", "xorout", "check",
                "aliases"}}.  "check" is the CRC of b"123456789", the CRC-RevEng
        convention, and every value in this table is verified against this module's own
        engine by the test suite - a mismatch means the engine is wrong, not the table.

    Several standard algorithms share a width (CRC-16 has CCITT-FALSE, ARC, XMODEM,
    MODBUS, ...), so the result is keyed by name: a flat parameter dict would silently
    drop all but one of them.  An unknown width returns {} rather than inventing a set.

        p = crc_known(16)["CRC-16/ARC"]
        crc_compute(data, p["width"], p["poly"], p["init"], p["refin"], p["refout"],
                    p["xorout"])
    """
    catalog = {}
    for name, w, poly, init, refin, refout, xorout, check, aliases in _CRC_CATALOG:
        if width is not None and w != width:
            continue
        catalog[name] = {
            "name": name, "width": w, "poly": poly, "init": init, "refin": refin,
            "refout": refout, "xorout": xorout, "check": check, "aliases": list(aliases),
        }
    return catalog


# name, width, poly, init, refin, refout, xorout, check over b"123456789", aliases
_CRC_CATALOG = (
    ("CRC-8", 8, 0x07, 0x00, False, False, 0x00, 0xF4, ("CRC-8/SMBUS", "crc8")),
    ("CRC-8/MAXIM-DOW", 8, 0x31, 0x00, True, True, 0x00, 0xA1,
     ("CRC-8/MAXIM", "CRC-8/DALLAS-DOW", "crc8maxim")),
    ("CRC-8/SAE-J1850", 8, 0x1D, 0xFF, False, False, 0xFF, 0x4B, ()),
    ("CRC-16/ARC", 16, 0x8005, 0x0000, True, True, 0x0000, 0xBB3D,
     ("CRC-16/IBM", "crc16", "CRC-16/LHA")),
    ("CRC-16/CCITT-FALSE", 16, 0x1021, 0xFFFF, False, False, 0x0000, 0x29B1,
     ("CRC-16/AUTOSAR", "crc16ccitt")),
    ("CRC-16/XMODEM", 16, 0x1021, 0x0000, False, False, 0x0000, 0x31C3,
     ("CRC-16/ACORN", "CRC-16/ZMODEM")),
    ("CRC-16/KERMIT", 16, 0x1021, 0x0000, True, True, 0x0000, 0x2189,
     ("CRC-16/CCITT", "CRC-16/V-41-LSB")),
    ("CRC-16/MODBUS", 16, 0x8005, 0xFFFF, True, True, 0x0000, 0x4B37, ()),
    ("CRC-16/USB", 16, 0x8005, 0xFFFF, True, True, 0xFFFF, 0xB4C8, ()),
    ("CRC-32/ISO-HDLC", 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xCBF43926,
     ("CRC-32", "crc32", "CRC-32/ADCCP", "CRC-32/V-42", "CRC-32/XZ")),
    ("CRC-32/BZIP2", 32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0xFFFFFFFF, 0xFC891918,
     ("CRC-32/AAL5", "CRC-32/DECT-B")),
    ("CRC-32/MPEG-2", 32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000, 0x0376E6E7,
     ()),
    ("CRC-32/ISCSI", 32, 0x1EDC6F41, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xE3069283,
     ("CRC-32C", "CRC-32/CASTAGNOLI")),
    ("CRC-64/ECMA-182", 64, 0x42F0E1EBA9EA3693, 0x0000000000000000, False, False,
     0x0000000000000000, 0x6C40DF5F0B497347, ()),
)


def _samples_from(data, crc):
    """Normalise crc_reverse_params' input into [(bytes, crc_int), ...]"""
    if crc is None:
        if isinstance(data, (bytes, bytearray, memoryview, str)):
            raise ValueError("a single sample needs its crc: pass (data, crc) or "
                             "[(data, crc), ...]")
        try:
            items = list(data)
        except TypeError as exc:
            raise ValueError(f"data is neither bytes-like nor a list of pairs: {exc}") from exc
        out = []
        for item in items:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise ValueError("each sample must be a (data, crc) pair")
            raw, value = item
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"sample crc must be a non-negative int, got {value!r}")
            out.append((_as_bytes(raw, "sample data"), value))
        if not out:
            raise ValueError("no samples given")
        return out
    if isinstance(crc, bool) or not isinstance(crc, int) or crc < 0:
        raise ValueError(f"crc must be a non-negative int, got {crc!r}")
    return [(_as_bytes(data), crc)]


def _poly_candidates(width, max_tries):
    """Odd polys only: a CRC generator has the x^0 term, which halves the search space

    Returns (candidates, truncated).
    """
    limit = 1 << width
    out = []
    truncated = False
    for poly in range(1, limit, 2):
        if len(out) >= max_tries:
            truncated = True
            break
        out.append(poly)
    return out, truncated


def _solve_candidate(samples, width, poly, refin, refout, known_init, known_xor):
    """One (poly, refin, refout) combination: solve the affine system for init/xorout

    The register is a linear function of init, so for a fixed message the map
    init -> crc is affine; evaluating it on the w basis vectors (plus the constant term)
    is all the information the linear solve needs.

    Returns (parameters, free_variable_count) or None.  Whatever comes back is verified
    against every sample with the engine before it is returned, so an unverified
    parameter set can never escape this function.
    """
    mask = (1 << width) - 1
    free_init = known_init is None
    free_xor = known_xor is None
    xor_offset = width if free_init else 0
    n_cols = (width if free_init else 0) + (width if free_xor else 0)
    sys_rows = []
    sys_rhs = []
    for data, target in samples:
        base = CRC(width, poly, 0 if free_init else known_init, refin, refout, 0).compute(data)
        const = base ^ (0 if free_xor else known_xor)
        columns = []
        if free_init:
            for j in range(width):
                columns.append(CRC(width, poly, 1 << j, refin, refout, 0).compute(data) ^ base)
        for i in range(width):
            row = 0
            for j, col in enumerate(columns):
                if col >> i & 1:
                    row |= 1 << j
            if free_xor:
                row |= 1 << (xor_offset + i)
            sys_rows.append(row)
            sys_rhs.append((target ^ const) >> i & 1)
    if n_cols == 0:
        # nothing to solve: both parameters were given, so this is pure verification
        params = {"width": width, "poly": poly, "init": known_init, "refin": refin,
                  "refout": refout, "xorout": known_xor, "free_parameters": 0}
    else:
        solution = gf2_solve(sys_rows, sys_rhs, cols=n_cols)
        if solution is None:
            return None
        free = n_cols - gf2_rank(sys_rows, n_cols)
        params = {
            "width": width, "poly": poly,
            "init": (solution & mask) if free_init else known_init,
            "refin": refin, "refout": refout,
            "xorout": ((solution >> xor_offset) & mask) if free_xor else known_xor,
            "free_parameters": free,
        }
    engine = CRC(width, poly, params["init"], refin, refout, params["xorout"])
    for data, target in samples:
        if engine.compute(data) != target:
            return None
    return params, params["free_parameters"]


def crc_reverse_params(data, crc=None, width=None, poly=None, init=None, xorout=None,
                       refin=None, refout=None, max_poly_tries=2048, max_candidates=64):
    """Recover unknown CRC parameters from samples -> candidate dict, or None

    Args:
        data:  bytes-like for a single sample, or a list of (data, crc) pairs for
               several.  With one sample and both init and xorout unknown the pair does
               not pin them down (any init has a compensating xorout, 2**w solutions),
               so pass two or more samples of *different* messages to make it a fact.
        crc:   the observed CRC of `data` (must be None when `data` is a pair list)
        width: register width
        poly:  known polynomial; None = brute force the odd polynomials in `width` bits
        init, xorout, refin, refout: pass a value to pin that parameter, leave None to
               have it recovered (refin/refout are always brute forced when unknown:
               four combinations, so that one is cheap and exact)

    Returns:
        {"candidates": [params, ...], "unique": bool, "searched": {...}, "note": str}
        or None when no parameter set reproduces the samples.

        Every candidate is a full parameter dict and every candidate has been verified
        by recomputing all samples, so the list never contains a wrong answer; when the
        samples are too few the list is simply longer than one.  "free_parameters" on a
        candidate counts the dimensions still unconstrained (the returned particular
        solution has those free bits cleared), and "unique" is True only when exactly
        one fully determined candidate was found and the polynomial search was complete.

    Limits, stated plainly:
      * one sample with init and xorout both unknown is underdetermined by construction:
        expect 2**w candidates collapsed into one-per-(poly, refin, refout) with
        free_parameters == w, and pin one of the two if you can;
      * a polynomial divisible by (x+1) - which includes most standard ones (CRC-32,
        CRC-16/ARC, CRC-16/CCITT-FALSE) - has a non-zero register value v with A*v = v
        that the LFSR never moves.  Replacing init by init^v is then exactly compensated
        by replacing xorout with xorout^reflect(v), so (init, xorout) cannot be pinned
        down at all from message/CRC pairs: expect free_parameters >= 1 and read the
        returned pair as one verified representative of a small family, not as "the"
        answer.  The ambiguity is measured rather than hidden - that is what
        free_parameters and `unique` are for;
      * brute-forcing the polynomial costs (w+1) engine passes per candidate, so it is
        practical only for small widths; the search is capped at `max_poly_tries` odd
        polynomials and "searched.polys_truncated" says whether it ran out;
      * a wrong polynomial usually still fits if there are fewer equations than
        unknowns, which is exactly what the verification and the unique flag expose.

    Raises ValueError for malformed input (non-bytes data, crc outside the width,
    bad width/poly).
    """
    if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= 64:
        raise ValueError("width must be an int in 1..64")
    if poly is not None:
        if isinstance(poly, bool) or not isinstance(poly, int) or not 0 <= poly < (1 << width):
            raise ValueError(f"poly must be an int in 0..2**{width}-1")
    for name, value in (("init", init), ("xorout", xorout)):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)
                                  or not 0 <= value < (1 << width)):
            raise ValueError(f"{name} must be an int in 0..2**{width}-1 when given")
    for name, value in (("refin", refin), ("refout", refout)):
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"{name} must be True or False when given")
    samples = _samples_from(data, crc)
    for _, value in samples:
        if value >> width:
            raise ValueError(f"sample crc 0x{value:x} does not fit in {width} bits")

    if poly is not None:
        polys, truncated = [poly], False
    else:
        polys, truncated = _poly_candidates(width, max_poly_tries)
    refins = [refin] if refin is not None else [False, True]
    refouts = [refout] if refout is not None else [False, True]

    candidates = []
    for candidate_poly in polys:
        for candidate_refin in refins:
            for candidate_refout in refouts:
                found = _solve_candidate(samples, width, candidate_poly, candidate_refin,
                                         candidate_refout, init, xorout)
                if found is None:
                    continue
                params, _ = found
                candidates.append(params)
                if len(candidates) >= max_candidates:
                    break
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    if not candidates:
        return None
    unique = (len(candidates) == 1 and candidates[0]["free_parameters"] == 0
              and (poly is not None or not truncated))
    notes = []
    if poly is None:
        notes.append(f"polynomial brute-forced over {len(polys)} odd values"
                     + (" (search truncated, raise max_poly_tries to continue)" if truncated
                        else ""))
    if refin is None or refout is None:
        notes.append("refin/refout were unknown and brute-forced (4 combinations)")
    if init is None and xorout is None and len(samples) < 2:
        notes.append("one sample with init and xorout unknown is underdetermined: every "
                     "candidate is verified but only one of 2**width possible pairs")
    if len(candidates) > 1:
        notes.append(f"{len(candidates)} candidate parameter sets reproduce all samples")
    return {
        "candidates": candidates,
        "unique": unique,
        "searched": {"polys": len(polys), "polys_truncated": truncated,
                     "refin": list(refins), "refout": list(refouts),
                     "samples": len(samples)},
        "note": "; ".join(notes) if notes else "all parameters were given or determined",
    }


def crc_forge_append(prefix, target_crc, width, poly, init=0, refin=False, refout=False,
                     xorout=0, append_len=4):
    """Bytes to append to `prefix` so that crc(prefix + appended) == target_crc

    This is the classic "a CRC is not a MAC" primitive: a CRC is an LFSR with the
    message XORed into it, hence an affine map over GF(2), hence forgeable in one linear
    solve.  Here the appended block is the unknown:

        F(a) = crc(prefix + a) = M*a ^ crc(prefix + 0...)      (affine in the bits of a)

    Evaluating F on the 8*append_len basis vectors (one appended bit set at a time) gives
    M and the constant term, and one solve in gf2_solve inverts it.  Cost: 8*append_len+1
    CRC computations, independent of the target - no search, no luck.

    Args:
        prefix:     bytes already fixed
        target_crc: the CRC value the whole message must end up with (post-xorout)
        width, poly, init, refin, refout, xorout: the CRC parameters being attacked
        append_len: how many bytes to append; the appended block holds 8*append_len
                    unknown bits, so anything >= ceil(width/8) gives a full-rank system
                    (append_len=4 covers CRC-32 and wastes 16 free bits on CRC-16)

    Returns:
        the appended bytes (length append_len), or None when target_crc is unreachable
        for this prefix and parameter set - which can only happen when append_len is too
        small, i.e. when the affine map is not surjective.  With more unknowns than
        equations one particular solution (free bits cleared) is returned; it is one
        valid answer among 2**free, never a wrong one.

    Raises ValueError for a str prefix, append_len < 1, or target_crc outside the width.
    Unknown bit j of the appended block is bit (j % 8) of appended byte j // 8 - an
    arbitrary but consistent labelling, since the block is solved as a whole.
    """
    pre = _as_bytes(prefix, "prefix")
    if isinstance(append_len, bool) or not isinstance(append_len, int) or append_len < 1:
        raise ValueError("append_len must be a positive int")
    if (isinstance(target_crc, bool) or not isinstance(target_crc, int)
            or not 0 <= target_crc < (1 << width)):
        raise ValueError(f"target_crc must be an int in 0..2**{width}-1")
    engine = CRC(width, poly, init, refin, refout, xorout)
    tail = bytes(append_len)
    constant = engine.compute(pre + tail)
    rhs = [(target_crc ^ constant) >> i & 1 for i in range(width)]
    sys_rows = [0] * width
    n_bits = 8 * append_len
    for j in range(n_bits):
        probe = bytearray(tail)
        probe[j // 8] |= 1 << (j % 8)
        column = engine.compute(pre + bytes(probe)) ^ constant
        for i in range(width):
            if column >> i & 1:
                sys_rows[i] |= 1 << j
    solution = gf2_solve(sys_rows, rhs, cols=n_bits)
    if solution is None:
        return None
    appended = bytearray(append_len)
    for j in range(n_bits):
        if solution >> j & 1:
            appended[j // 8] |= 1 << (j % 8)
    appended = bytes(appended)
    if engine.compute(pre + appended) != target_crc:
        # linear algebra makes this unreachable; verified anyway so that a mistake here
        # can never leave this library handing out bytes that do not do what they claim
        return None
    return appended


def crc_solve_unknown(prefix, suffix, target_crc, width, poly, unknown_len,
                      init=0, refin=False, refout=False, xorout=0):
    """Recover bytes hidden *inside* a message so its CRC hits a target

    CRC is affine over GF(2) in the message bits, so a fixed-length unknown field is a
    linear system, not a brute force: this solves the CRC preimage

        CRC(prefix || unknown || suffix) == target_crc
        unknown has exactly `unknown_len` bytes

    by taking the single-bit perturbations of the all-zero unknown as the columns and
    solving over GF(2). Useful when a challenge hands you a partially known plaintext
    plus "the CRC of the flag" and the unknown part is short.

    Returns:
        {"ok", "data": prefix||unknown||suffix, "unknown": bytes,
         "unique": bool, "free_bits": int, "detail"/"note": str}

    `unique` is False when `8 * unknown_len > width` (more unknowns than equations): a
    particular solution is returned with the free bits zeroed, and the CRC is re-checked
    before `ok` is set, so the bytes returned always do reach the target.
    """
    pre = _as_bytes(prefix)
    suf = _as_bytes(suffix)
    if isinstance(unknown_len, bool) or not isinstance(unknown_len, int) or unknown_len < 1:
        raise ValueError("unknown_len must be a positive int")
    if isinstance(target_crc, bool) or not isinstance(target_crc, int) \
            or not 0 <= target_crc < (1 << width):
        raise ValueError(f"target_crc must be an int in 0..2**{width}-1")
    engine = CRC(width, poly, init, refin, refout, xorout)
    n_bits = 8 * unknown_len
    tail = bytes(unknown_len)
    constant = engine.compute(pre + tail + suf)
    rhs = [(target_crc ^ constant) >> i & 1 for i in range(width)]
    sys_rows = [0] * width
    for j in range(n_bits):
        probe = bytearray(tail)
        probe[j // 8] |= 1 << (j % 8)
        column = engine.compute(pre + bytes(probe) + suf) ^ constant
        for i in range(width):
            if column >> i & 1:
                sys_rows[i] |= 1 << j
    solution = gf2_solve(sys_rows, rhs, cols=n_bits)
    if solution is None:
        return {"ok": False, "data": None, "unknown": None, "unique": False,
                "free_bits": None,
                "note": "no assignment of the unknown bytes reaches this CRC "
                        "(the samples are inconsistent with these parameters)"}
    unknown = bytearray(unknown_len)
    for j in range(n_bits):
        if solution >> j & 1:
            unknown[j // 8] |= 1 << (j % 8)
    unknown = bytes(unknown)
    data = pre + unknown + suf
    if engine.compute(data) != target_crc:
        # unreachable if the algebra is right; checked so a bug here can never hand out
        # bytes that do not actually reach the target
        return {"ok": False, "data": None, "unknown": None, "unique": False,
                "free_bits": None, "note": "internal check failed: the solved bytes do "
                                           "not reproduce the target CRC"}
    rank = gf2_rank(sys_rows, cols=n_bits)
    free = n_bits - rank
    return {"ok": True, "data": data, "unknown": unknown,
            "unique": free == 0, "free_bits": free,
            "detail": f"recovered {unknown_len} byte(s) by GF(2) linear algebra "
                      f"({rank}/{n_bits} bits pinned); CRC recomputed and matched"}
