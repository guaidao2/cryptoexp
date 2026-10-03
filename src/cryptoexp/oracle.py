"""Oracle attack layer — depends only on "one callback", not on whether the target
is a local function or a remote service.

This is cryptoexp's most important layer as *infrastructure*: a fixed solve only
cracks that one challenge, while an oracle attack abstracts "being able to ask one
question", so the same code attacks a local target and a remote one.

Usage:
    from cryptoexp import oracle as O

    # 1) ECB byte-at-a-time recovery of an unknown suffix (encrypt oracle: bytes -> bytes)
    secret = O.ecb_byte_at_a_time(enc, block_size=16)

    # 2) padding oracle (valid oracle: bytes -> bool); data = iv + ciphertext
    pt = O.padding_oracle_attack(valid, iv + ct, block_size=16)
"""

from .utils.pad import BLOCK, blocks, pkcs7_pad, pkcs7_unpad, xor

_PRINTABLE = bytes(range(32, 127)) + b'\t\n\r'


# ────────────────────────── structure detection ──────────────────────────

def detect_block_size(oracle, max_bs: int = 64) -> int:
    """Block size probe: grow the input length until the ciphertext length jumps;
    the size of the jump is the block size."""
    base = len(oracle(b''))
    for i in range(1, max_bs + 1):
        n = len(oracle(b'A' * i))
        if n > base:
            return n - base
    raise ValueError("cannot detect block size (oracle output length independent of input?)")


def detect_mode(oracle, block_size: int = BLOCK) -> str:
    """ECB/CBC verdict: feed two or more identical whole plaintext blocks;
    under ECB the ciphertext blocks repeat."""
    ct = oracle(b'A' * (block_size * 3))
    blks = blocks(ct, block_size)
    seen = {}
    for b in blks:
        if b in seen:
            return "ECB"
        seen[b] = True
    return "CBC/other"


def find_prefix_len(oracle, block_size: int = BLOCK) -> int:
    """Unknown prefix length (when the oracle prepends fixed data before our input)

    Cross-check with two different filler letters: only identical blocks that
    **depend on our input** count as alignment evidence. Without this step, a secret
    that repeats internally (say 40 'z' characters) makes its own repeated blocks
    look like an alignment signal — a real bug we hit, hence the guard.
    """
    best = 0
    for pad in range(block_size):
        runs = {}
        for ch in (b'A', b'C'):
            ct = oracle(ch * (pad + 2 * block_size))
            runs[ch] = blocks(ct, block_size)
        a, c = runs[b'A'], runs[b'C']
        n = min(len(a), len(c))
        for j in range(n - 1):
            if a[j] == a[j + 1] and c[j] == c[j + 1] and a[j] != c[j]:
                cand = j * block_size - pad
                if cand > best:
                    best = cand
                break
    return best


# ────────────────────────── ECB byte-at-a-time attack ──────────────────────────

def ecb_byte_at_a_time(oracle, block_size: int = None, prefix_len: int = None,
                       charset: bytes = None, max_len: int = 512,
                       stop_at: bytes = b'}'):
    """ECB byte-at-a-time recovery of the oracle's unknown suffix (classic attack)

    oracle: bytes -> bytes, internally E(prefix || our input || secret)
    returns: the recovered secret (bytes)
    """
    charset = charset or _PRINTABLE
    bs = block_size or detect_block_size(oracle)
    if prefix_len is None:
        prefix_len = find_prefix_len(oracle, bs)
    align = (bs - prefix_len % bs) % bs
    prefix_blocks = (prefix_len + align) // bs

    known = b''
    for i in range(max_len):
        pad = bs - 1 - (i % bs)
        probe = b'A' * (align + pad)
        ct = oracle(probe)
        target_idx = (prefix_len + align + pad + i) // bs
        if (target_idx + 1) * bs > len(ct):
            break
        target = ct[target_idx * bs:(target_idx + 1) * bs]
        # target block = last bs-1 bytes of (A^pad || known plaintext) + byte to guess
        # note: taking known[-(i % bs):] alone is wrong — across a block boundary the
        # block also holds earlier known bytes
        ctx = (b'A' * pad + known)[-(bs - 1):]
        found = None
        for g in charset:
            dict_in = b'A' * align + ctx + bytes([g])
            dct = oracle(dict_in)
            if len(dct) < (prefix_blocks + 1) * bs:
                continue
            if dct[prefix_blocks * bs:(prefix_blocks + 1) * bs] == target:
                found = g
                break
        if found is None:
            break
        known += bytes([found])
        if stop_at and known.endswith(stop_at):
            break
    return known


# ────────────────────────── padding oracle ──────────────────────────

def padding_oracle_attack(oracle, data: bytes, block_size: int = BLOCK,
                          include_iv: bool = True, max_blocks: int = None):
    """CBC padding oracle decryption

    oracle: bytes -> bool   (given iv||ct, returns whether the decrypted padding is valid)
    data:   iv + ciphertext (include_iv=True) or ciphertext only (include_iv=False,
            in which case the first block cannot be attacked — the "previous block"
            we would have to forge is the IV, outside the data we control)
    returns: recovered plaintext (bytes, padding included; unpad it with pkcs7_unpad)

    Both classic mistakes are handled here:
      - forging position: the full block list is [iv] + ct, and the block to modify is
        block bi (the target's "previous block"), not "a block inserted after the iv"
      - pad==1 false positives: flip the second-to-last byte and ask again; only accept
        the byte if that query is still valid
    """
    blks = [data[i:i + block_size] for i in range(0, len(data) - block_size + 1,
                                                 block_size)]
    if include_iv:
        iv, ct_blocks = blks[0], blks[1:]
    else:
        iv, ct_blocks = bytes(block_size), blks
    if max_blocks:
        ct_blocks = ct_blocks[:max_blocks]
    full = [iv] + ct_blocks  # full sequence: target is full[bi+1], we forge full[bi]

    plain = b''
    # Work backwards from the last block — a real oracle only checks the padding of
    # the **last** block, so every query must truncate the ciphertext at the target
    # block (omit this and each query answers True forever)
    for bi in range(len(ct_blocks) - 1, -1, -1):
        if not include_iv and bi == 0:
            plain = b'\x00' * block_size + plain  # IV uncontrollable, block unrecoverable
            continue
        prev = bytearray(full[bi])
        cur = full[bi + 1]
        inter = bytearray(block_size)

        def query(forged_prev: bytes) -> bool:
            tail = full[:bi] + [forged_prev, cur]  # truncate: target block becomes last
            payload = b''.join(tail if include_iv else tail[1:])
            return bool(oracle(payload))

        for pad in range(1, block_size + 1):
            pos = block_size - pad
            hit = None
            for byte in range(256):
                forged = bytearray(prev)
                for k in range(pos + 1, block_size):
                    forged[k] = inter[k] ^ pad
                forged[pos] = byte ^ pad
                if not query(bytes(forged)):
                    continue
                if pad == 1 and pos > 0:
                    # false-positive check: with a real padding length of 1,
                    # flipping the second-to-last byte stays valid
                    probe = bytearray(forged)
                    probe[pos - 1] ^= 0x01
                    if not query(bytes(probe)):
                        continue
                hit = byte
                break
            if hit is None:
                return plain  # return what we recovered; never invent a result
            inter[pos] = hit
        plain = bytes(a ^ b for a, b in zip(inter, prev)) + plain
    return plain


# ────────────────────────── ready-made targets (local self-test) ──────────────────────────

def make_ecb_oracle(key: bytes, secret: bytes, prefix: bytes = b''):
    """Build an ECB oracle (for local reproduction; uses the built-in pure-Python AES)"""
    from .utils import aes

    def oracle(user_input: bytes) -> bytes:
        data = pkcs7_pad(prefix + user_input + secret, 16)
        return aes.encrypt_ecb(key, data)
    return oracle


def make_cbc_oracle(key: bytes, iv: bytes, secret: bytes):
    """Build a CBC oracle (encryption callback)"""
    from .utils import aes

    def oracle(user_input: bytes) -> bytes:
        data = pkcs7_pad(user_input + secret, 16)
        return iv + aes.encrypt_cbc(key, data, iv)
    return oracle


def make_padding_oracle(key: bytes, iv: bytes):
    """Build a padding oracle: input iv||ct → is the padding valid (bool)"""
    from .utils import aes

    def valid(payload: bytes) -> bool:
        if len(payload) < 32 or len(payload) % 16:
            return False
        use_iv, ct = payload[:16], payload[16:]
        try:
            pt = aes.decrypt_cbc(key, ct, use_iv)
            pkcs7_unpad(pt, 16)
            return True
        except Exception:
            return False
    return valid


def ct_equal(a: bytes, b: bytes) -> bool:
    """Constant-time comparison (for the remote oracle case)"""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return xor(a, b)
