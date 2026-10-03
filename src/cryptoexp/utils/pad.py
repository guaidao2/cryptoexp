"""Padding and byte helpers — pkcs7/zero/pad, xor, block utils (common CTF infrastructure)"""

BLOCK = 16


def pkcs7_pad(data: bytes, block: int = BLOCK) -> bytes:
    """PKCS#7 padding (a whole block is added when already aligned, as the standard says)"""
    if block <= 0 or block > 255:
        raise ValueError("invalid block size")
    n = block - len(data) % block
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block: int = BLOCK) -> bytes:
    """PKCS#7 unpadding; bad padding raises ValueError (this is the padding-oracle oracle)"""
    if not data or block <= 0:
        raise ValueError("empty data")
    n = data[-1]
    if n == 0 or n > block or n > len(data):
        raise ValueError(f"invalid padding length {n}")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("inconsistent padding bytes")
    return data[:-n]


def pkcs7_valid(data: bytes, block: int = BLOCK) -> bool:
    try:
        pkcs7_unpad(data, block)
        return True
    except ValueError:
        return False


def zero_pad(data: bytes, block: int = BLOCK) -> bytes:
    r = len(data) % block
    return data + b'\x00' * (block - r) if r else data


def zero_unpad(data: bytes, block: int = BLOCK) -> bytes:
    return data.rstrip(b'\x00')


def xor(a: bytes, b: bytes) -> bytes:
    """XOR of equal-length buffers (with unequal lengths the shorter one wins,
    matching the common pwntools xor usage)"""
    return bytes(x ^ y for x, y in zip(a, b))


def xor_repeat(a: bytes, key: bytes) -> bytes:
    """Repeating-key XOR (one function for encryption and decryption)"""
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(a))


def blocks(data: bytes, size: int = BLOCK):
    """Split into blocks (a trailing partial block is dropped)"""
    return [data[i:i + size] for i in range(0, len(data) - size + 1, size)]


def bitflip_cbc(ct: bytes, offset: int, old: bytes, new: bytes) -> bytes:
    """CBC byte flip: turn the decrypted bytes at offset from old into new

    Principle: only the corresponding bytes of the previous ciphertext block
    need changing, because P_i = D(C_i) ^ C_{i-1}.
    Returns the new ciphertext (the input object is not modified).
    """
    if len(old) != len(new):
        raise ValueError("old/new must have the same length")
    out = bytearray(ct)
    for i in range(len(old)):
        out[offset + i] ^= old[i] ^ new[i]
    return bytes(out)
