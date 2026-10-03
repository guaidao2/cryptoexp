"""Symmetric-mode helpers that work on ciphertext alone (no oracle required).

`oracle.py` attacks a live callback; this module is the static half: decide the mode,
infer the block size, and manipulate CBC blocks by hand. Both are mechanical steps
that every block-cipher challenge starts with.
"""

from .pad import BLOCK, blocks, bitflip_cbc, pkcs7_pad, pkcs7_unpad


def ecb_repeated_blocks(data: bytes, block_size: int = BLOCK):
    """Return {cipher_block: count} for every block that appears more than once

    A non-empty result is hard evidence for ECB: identical plaintext blocks encrypt
    identically, which CBC/CTR never do.
    """
    counts = {}
    for blk in blocks(data, block_size):
        counts[blk] = counts.get(blk, 0) + 1
    return {b: n for b, n in counts.items() if n > 1}


def is_ecb(data: bytes, block_size: int = BLOCK) -> bool:
    return bool(ecb_repeated_blocks(data, block_size))


def infer_block_size(ciphertexts, max_size: int = 64):
    """Infer the block size from ciphertexts of *growing* plaintext lengths

    Pass a list of ciphertexts produced by encrypting inputs of increasing length
    (e.g. 0, 1, 2, ... bytes): the block size is the most common length increment.
    Returns None when the input is too short to tell.

    Named `infer_*` rather than `detect_block_size` on purpose: `oracle.detect_block_size`
    probes a live oracle, and a name collision in the package root silently shadowed
    it (the oracle version must stay reachable as `cryptoexp.detect_block_size`).
    """
    if not ciphertexts or len(ciphertexts) < 2:
        return None
    diffs = {}
    for a, b in zip(ciphertexts, ciphertexts[1:]):
        d = len(b) - len(a)
        if 0 < d <= max_size:
            diffs[d] = diffs.get(d, 0) + 1
    if not diffs:
        return None
    return max(diffs, key=diffs.get)


def block_index(offset: int, block_size: int = BLOCK):
    """(block index, offset inside the block) for a plaintext/ciphertext offset"""
    return offset // block_size, offset % block_size


def cbc_flip_plaintext(ct: bytes, iv: bytes, offset: int, old: bytes, new: bytes,
                       block_size: int = BLOCK):
    """CBC byte flip expressed in plaintext terms (IV handling included)

    Flipping ciphertext byte j in block N changes plaintext byte j in block N+1, so
    the caller can think purely in plaintext offsets. `ct` excludes the IV.

    Returns: a 2-tuple `(new_iv, new_ct)`, ready to feed back into the decryption
             routine. The shape was missing from this docstring, so a caller who
             expected one buffer got `TypeError: unsupported operand type(s) for ^:
             'tuple' and 'bytes'` (utils audit, 2026-10-03).
    """
    if len(old) != len(new):
        raise ValueError("old and new must be the same length")
    idx, off = block_index(offset, block_size)
    carrier = iv + ct                     # the block that XORs into the target block
    target = idx * block_size + off       # index inside `carrier`
    if target + len(old) > idx * block_size + block_size:
        raise ValueError("the flip crosses a block boundary; split it")
    buf = bytearray(carrier)
    for i in range(len(old)):
        buf[target + i] ^= old[i] ^ new[i]
    forged = bytes(buf)
    return forged[:block_size], forged[block_size:]


def cbc_decrypt_blocks(ct: bytes, iv: bytes, decrypt_block):
    """Decrypt CBC using a caller-supplied single-block decryptor

    Handy when only the raw block cipher is available (e.g. an oracle that returns
    exactly one decrypted block).
    """
    out = bytearray()
    prev = iv
    for i in range(0, len(ct) - len(ct) % BLOCK, BLOCK):
        blk = ct[i:i + BLOCK]
        dec = decrypt_block(blk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return bytes(out)


def strip_pkcs7(data: bytes, block_size: int = BLOCK):
    """Convenience wrapper that returns None instead of raising on bad padding"""
    try:
        return pkcs7_unpad(data, block_size)
    except ValueError:
        return None


def pad_pkcs7(data: bytes, block_size: int = BLOCK) -> bytes:
    return pkcs7_pad(data, block_size)


__all__ = [
    "ecb_repeated_blocks", "is_ecb", "infer_block_size", "block_index",
    "cbc_flip_plaintext", "cbc_decrypt_blocks", "strip_pkcs7", "pad_pkcs7",
    "bitflip_cbc", "blocks",
]
