#!/usr/bin/env python3
"""Challenge generator — writes practice samples with known flags.

    python3 challenges/make_challenges.py     # writes/overwrites challenges/*.txt

A fixed RNG seed keeps the corpus reproducible, so tests can assert exact flags.
"""

import os
import random
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))     # src layout, no install needed

from cryptoexp import algebra as A
from cryptoexp.utils import aes, encoding as E, pad as P
from cryptoexp.utils import gf2 as G

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))
RNG = random.Random(20261003)


def _prime(bits: int) -> int:
    while True:
        p = RNG.getrandbits(bits) | (1 << (bits - 1)) | 1
        if A.is_prime(p):
            return p


def _int_bytes(s: str) -> int:
    return int.from_bytes(s.encode(), 'big')


def _write(name: str, text: str):
    path = os.path.join(OUT, name)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text.strip() + "\n")
    print(f"  [+] {name}")


# ---------------------------- RSA ----------------------------

def rsa_small_e():
    flag = "flag{small_e_no_padding}"
    n = _prime(1024) * _prime(1024)
    m = _int_bytes(flag)
    c = m ** 3                      # no modular reduction: m^3 < n
    _write("rsa_small_e.txt", f"""
# RSA - small public exponent, no padding
n = {n}
e = 3
c = {c}
""")


def rsa_wiener():
    flag = "flag{wiener_attack_small_d}"
    p, q = _prime(512), _prime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        d = _prime(70)
        if d < A.iroot(n, 4)[0] // 3 and A.gcd(d, phi) == 1:
            break
    e = A.modinv(d, phi)
    c = pow(_int_bytes(flag), e, n)
    _write("rsa_wiener.txt", f"""
# RSA - tiny private exponent (Wiener attack applies)
n = {n}
e = {e}
c = {c}
""")


def rsa_shared_prime():
    flag = "flag{shared_prime_gcd}"
    p = _prime(256)
    q1, q2 = _prime(256), _prime(256)
    n1, n2 = p * q1, p * q2
    e = 65537
    c1 = pow(_int_bytes(flag), e, n1)
    c2 = pow(_int_bytes(flag), e, n2)
    _write("rsa_shared_prime.txt", f"""
# RSA - two moduli sharing a prime factor
n1 = {n1}
n2 = {n2}
e = {e}
c1 = {c1}
c2 = {c2}
""")


def rsa_fermat():
    flag = "flag{fermat_close_primes}"
    p = _prime(256)
    q = A.next_prime(p + 12)
    n = p * q
    e = 65537
    c = pow(_int_bytes(flag), e, n)
    _write("rsa_fermat.txt", f"""
# RSA - p and q are very close
n = {n}
e = {e}
c = {c}
""")


def rsa_factor():
    """The plaintext must stay below n; otherwise encryption silently reduces it
    modulo n and the decrypted value is not the flag (a real bug we hit)."""
    flag = "flag{pollard_rho_factors}"
    m = _int_bytes(flag)
    p = _prime(34)
    while True:
        q = _prime(220)
        n = p * q
        if n > m:
            break
    e = 65537
    c = pow(m, e, n)
    _write("rsa_factor.txt", f"""
# RSA - modulus small enough to factor
n = {n}
e = {e}
c = {c}
""")


def rsa_dp_leak():
    flag = "flag{dp_leak_factors_n}"
    p, q = _prime(256), _prime(256)
    n = p * q
    e = 65537
    d = A.modinv(e, (p - 1) * (q - 1))
    dp = d % (p - 1)
    c = pow(_int_bytes(flag), e, n)
    _write("rsa_dp_leak.txt", f"""
# RSA - dp leak (d mod p-1)
n = {n}
e = {e}
dp = {dp}
c = {c}
""")


def rsa_high_bits():
    flag = "flag{coppersmith_known_high_bits}"
    known = 160
    p, q = _prime(256), _prime(256)
    n = p * q
    e = 65537
    p_high = p >> (256 - known)
    c = pow(_int_bytes(flag), e, n)
    _write("rsa_high_bits.txt", f"""
# RSA - known high 160 bits of p (Coppersmith small root)
n = {n}
e = {e}
c = {c}
p_high = {p_high}
""")


# ---------------------------- encoding / xor / classical ----------------------------

def xor_single():
    flag = b"flag{single_byte_xor_is_easy}"
    ct = bytes(b ^ 0x5a for b in flag)
    _write("xor_single.txt", f"""
# single byte XOR - ciphertext (hex)
cipher = {ct.hex()}
""")


def xor_repeating():
    flag = b"flag{repeating_key_xor_with_hamming_distance}"
    ct = P.xor_repeat(flag, b"KEY42")
    _write("xor_repeating.txt", f"""
# repeating key XOR - ciphertext (hex)
cipher = {ct.hex()}
""")


def classical_caesar():
    ct = E.caesar("flag{caesar_is_classic}", 3)
    _write("classical_caesar.txt", f"""
# Caesar cipher - ciphertext
{ct}
""")


def classical_custom_prefix():
    """Same cipher, but the engagement's marker is DH{...} instead of flag{...}"""
    ct = E.caesar("DH{caesar_with_custom_prefix}", 3)
    _write("classical_custom_prefix.txt", f"""
# Caesar cipher, non-standard flag format
The event uses DH{{...}} as its flag format.
{ct}
""")


def classical_vigenere():
    flag = "flag{vigenere_key_recovered}"
    plain = ("the quick brown fox jumps over the lazy dog and then reads the "
             "secret message " + flag + " which was hidden inside this long text")
    key = "SECRET"
    # Standard Vigenere: the key stream advances on letters only. Advancing it on
    # spaces/punctuation makes the sample unsolvable (we hit this while generating).
    out, ki = [], 0
    for ch in plain:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            base = 65 if ch.isupper() else 97          # preserve case
            out.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    _write("classical_vigenere.txt", f"""
# Vigenere cipher - ciphertext
{''.join(out)}
""")


def classical_morse():
    """Morse cannot express braces, so the answer is an uppercase plaintext"""
    answer = "THEFLAGISMORSECODED"
    _write("classical_morse.txt", f"""
# Morse code - ciphertext (standard Morse has no braces; decode to uppercase text)
{E.morse_encode(answer)}
""")


def encoding_chain():
    flag = b"flag{multi_layer_encoding_chain}"
    blob = E.to_base64(E.to_hex(flag).encode())
    _write("encoding_chain.txt", f"""
# multi-layer encoding - ciphertext
{blob}
""")


# ---------------------------- block / prng / lattice ----------------------------

def symmetric_ecb():
    key = b"0123456789abcdef"
    unit = b"flag{ecb_mode_1}"          # exactly 16 bytes: repeats must be block aligned
    assert len(unit) == 16
    data = (b"A" * 16) + unit * 3
    ct = aes.encrypt_ecb(key, P.pkcs7_pad(data, 16))
    _write("symmetric_ecb.txt", f"""
# block cipher - ciphertext (hex); identify the mode
cipher = {ct.hex()}
""")


def lcg_challenge():
    m = 2 ** 31
    a, c, s = 1103515245, 12345, 246813579
    outs = []
    for _ in range(8):
        s = (a * s + c) % m
        outs.append(s)
    _write("lcg.txt", f"""
# LCG - consecutive outputs; recover the parameters and predict the next value
outputs: {' '.join(str(x) for x in outs)}
""")


def knapsack_challenge():
    weights = [RNG.randrange(2 ** 20, 2 ** 26) for _ in range(8)]
    picks = sorted(RNG.sample(range(8), 3))
    target = sum(weights[i] for i in picks)
    _write("knapsack.txt", f"""
# low-density subset sum - find the selected indices
weights: {' '.join(str(w) for w in weights)}
s = {target}
""")


def crc_challenge():
    """A 4-byte unknown inside the flag: exactly solvable by GF(2) linear algebra"""
    flag = "flag{lin4}"
    body = flag[5:-1]
    assert len(body) == 4, "keep the unknown field at 4 bytes so the preimage is unique"
    target = G.crc_compute(flag.encode(), 32, 0x04C11DB7, 0xFFFFFFFF, True, True,
                           0xFFFFFFFF)
    _write("crc_preimage.txt", f"""
# CRC-32 preimage - the flag body is unknown, the CRC is given
The flag has the form flag{{????}}: exactly 4 unknown characters.
prefix = "flag{{"
suffix = "}}"
unknown bytes = 4
CRC-32 target = 0x{target:08x}
poly = 0x04C11DB7, init = 0xFFFFFFFF, refin = true, refout = true,
xorout = 0xFFFFFFFF
""")


def lfsr_challenge():
    """64 observed keystream bits + the ciphertext: recover the taps, predict, XOR"""
    flag = b"flag{lfsr_taps}"
    taps, state = [0, 7, 13, 16], 0xACE1
    lfsr = G.LFSR(taps, state)
    observed = [lfsr.next_bit() for _ in range(64)]
    keystream = G.bits_to_bytes([lfsr.next_bit() for _ in range(8 * len(flag))])
    ct = bytes(a ^ b for a, b in zip(flag, keystream))
    _write("lfsr_predict.txt", f"""
# Fibonacci LFSR keystream - recover the taps, predict, then XOR
The register emitted these bits first:
{''.join(str(b) for b in observed)}
The message below was XORed with the next {8 * len(flag)} bits it emitted
(MSB-first, bit for bit), so the plaintext is the flag:
ciphertext = {ct.hex()}
""")


GENERATORS = (
    rsa_small_e, rsa_wiener, rsa_shared_prime, rsa_fermat, rsa_factor,
    rsa_dp_leak, rsa_high_bits, xor_single, xor_repeating, classical_caesar,
    classical_vigenere, classical_morse, encoding_chain, symmetric_ecb,
    lcg_challenge, knapsack_challenge, crc_challenge, lfsr_challenge,
    classical_custom_prefix,
)


def main():
    print(f"[*] writing challenge corpus -> {OUT}")
    for fn in GENERATORS:
        fn()
    print(f"[+] done: {len(GENERATORS)} samples")


if __name__ == "__main__":
    main()
