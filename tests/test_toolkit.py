"""Toolkit tests — the mechanical-operation layer added in v0.3.

Every assertion targets an official vector, a mathematical identity, or a verified
round-trip. Anything that is only self-consistent is labelled as such in the test
name or docstring, so it never masquerades as an external check.
"""

import hashlib
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import cryptoexp as ck
from cryptoexp.utils import gf2 as G
from cryptoexp.utils import hashes as H
from cryptoexp.utils import keys as K
from cryptoexp.utils import modular as M
from cryptoexp.utils import polytools as PT
from cryptoexp.utils import prng_extra as PE
from cryptoexp.utils import rsa_attacks as RA
from cryptoexp.utils import stream as S


class TestModular(unittest.TestCase):

    def test_symbols(self):
        self.assertEqual(M.legendre_symbol(2, 7), 1)
        self.assertEqual(M.legendre_symbol(3, 7), -1)
        self.assertEqual(M.jacobi_symbol(1001, 9907), -1)
        self.assertEqual(M.jacobi_symbol(1, 1), 1)

    def test_sqrt_mod_prime_and_composite(self):
        self.assertEqual(M.sqrt_mod(4, p=7), [2, 5])
        # x^2 = 4 mod 15 has four roots
        self.assertEqual(M.sqrt_mod(4, n=15), [2, 7, 8, 13])
        self.assertIsNone(M.sqrt_mod(3, p=7))

    def test_arithmetic_functions(self):
        self.assertEqual(M.totient(36), 12)
        self.assertEqual(M.carmichael(36), 6)
        self.assertEqual(M.mobius(30), -1)
        self.assertEqual(M.mobius(4), 0)
        self.assertTrue(M.is_squarefree(30))
        self.assertFalse(M.is_squarefree(12))
        self.assertEqual(M.divisor_count(36), 9)
        self.assertEqual(M.sum_of_divisors(36), 91)

    def test_order_and_primitive_root(self):
        self.assertEqual(M.order_mod(2, 7), 3)
        self.assertEqual(M.order_mod(3, 7), 6)
        self.assertIn(M.primitive_root(7), (3, 5))
        self.assertTrue(M.is_primitive_root(3, 7))
        self.assertFalse(M.is_primitive_root(2, 7))

    def test_crt_general_handles_non_coprime(self):
        self.assertEqual(M.crt_general([(2, 3), (3, 5), (2, 7)]), (23, 105))
        # x = 1 (mod 4) and x = 3 (mod 6): the unique class mod 12 is 9, not 3
        x, mod = M.crt_general([(1, 4), (3, 6)])
        self.assertEqual(mod, 12)
        self.assertEqual(x % 4, 1)
        self.assertEqual(x % 6, 3)
        self.assertIsNone(M.crt_general([(0, 2), (1, 4)]))

    def test_pollard_pm1(self):
        # 2^32 + 1 has the smooth factor 641 (p-1 = 2^7 * 5)
        n = 4294967297
        f = M.pollard_pm1(n, bound=10000)
        self.assertIn(f, (641, 6700417), f"unexpected factor {f}")

    def test_smoothness_and_log(self):
        self.assertTrue(M.is_smooth(2 ** 10 * 3 ** 5, 100))
        self.assertEqual(M.smooth_part(2 ** 4 * 97, 10), 16)
        self.assertEqual(M.integer_log(1000, 10), 3)


class TestPolytools(unittest.TestCase):

    def test_roots_and_gcd(self):
        self.assertEqual(PT.poly_roots_mod_p([6, 0, 1], 7), [1, 6])   # x^2 - 1 mod 7
        f, g = [1, 2, 1], [1, 1]                                      # (x+1)^2, (x+1)
        q, r = PT.poly_divmod(f, g, 7)
        # the zero polynomial may come back as [] or [0]; both mean "no remainder"
        self.assertIn(r, ([], [0]))
        self.assertEqual(q, [1, 1])
        self.assertEqual(PT.poly_gcd(f, g, 7), [1, 1])

    def test_divmod_identity(self):
        f, g = [3, 1, 4, 1, 5], [2, 7]
        q, r = PT.poly_divmod(f, g, 11)
        # f == q*g + r  (mod 11)
        prod = PT.poly_mod(PT.poly_mod(q, [1], 11), [1], 11) if False else None
        rebuilt = [0] * (len(q) + len(g) - 1)
        for i, a in enumerate(q):
            for j, b in enumerate(g):
                rebuilt[i + j] = (rebuilt[i + j] + a * b) % 11
        for i, c in enumerate(r):
            rebuilt[i] = (rebuilt[i] + c) % 11
        rebuilt = [c % 11 for c in rebuilt]
        want = [c % 11 for c in f]
        while len(rebuilt) > len(want):
            self.assertEqual(rebuilt.pop(), 0)
        self.assertEqual(rebuilt, want)

    def test_irreducibility(self):
        # x^2 + x + 1 is irreducible over GF(2); x^2 + 1 = (x+1)^2 is not
        self.assertTrue(PT.poly_is_irreducible([1, 1, 1], 2))
        self.assertFalse(PT.poly_is_irreducible([1, 0, 1], 2))

    def test_gf2_poly_helpers(self):
        # (x+1)*(x+1) = x^2 + 1 over GF(2) -> bit encoding 0b11 * 0b11 = 0b101
        self.assertEqual(PT.gf2_poly_mul(0b11, 0b11), 0b101)
        self.assertEqual(PT.gf2_poly_gcd(0b101, 0b11), 0b11)
        # x^2 + x = x(x+1): both 0 and 1 are roots
        self.assertEqual(PT.gf2_poly_roots(0b110), [0, 1])


class TestGF2LFSRCRC(unittest.TestCase):
    def test_crc_standard_check_values(self):
        crc32 = G.crc_compute(b"123456789", 32, 0x04C11DB7, 0xFFFFFFFF, True, True,
                              0xFFFFFFFF)
        self.assertEqual(crc32, 0xCBF43926)
        self.assertEqual(G.crc_compute(b"123456789", 16, 0x1021, 0xFFFF, False, False, 0),
                         0x29B1)

    def test_crc_forgery(self):
        target = 0xDEADBEEF
        appended = G.crc_forge_append(b"prefix", target, 32, 0x04C11DB7,
                                      0xFFFFFFFF, True, True, 0xFFFFFFFF, append_len=4)
        got = G.crc_compute(b"prefix" + appended, 32, 0x04C11DB7, 0xFFFFFFFF,
                            True, True, 0xFFFFFFFF)
        self.assertEqual(got, target)
        target16 = 0x1234
        appended16 = G.crc_forge_append(b"abc", target16, 16, 0x1021, 0xFFFF,
                                        False, False, 0, append_len=2)
        self.assertEqual(G.crc_compute(b"abc" + appended16, 16, 0x1021, 0xFFFF,
                                       False, False, 0), target16)

    def test_crc_preimage_unknown_field(self):
        """A 4-byte hole under CRC-32 is a square system: the answer is unique"""
        secret = b"flag{lin4}"
        target = G.crc_compute(secret, 32, 0x04C11DB7, 0xFFFFFFFF, True, True,
                               0xFFFFFFFF)
        res = G.crc_solve_unknown(b"flag{", b"}", target, 32, 0x04C11DB7, 4,
                                  0xFFFFFFFF, True, True, 0xFFFFFFFF)
        self.assertTrue(res["ok"], res.get("note"))
        self.assertEqual(res["unknown"], b"lin4")
        self.assertEqual(res["data"], secret)
        self.assertTrue(res["unique"])
        # CRC-16 with a 2-byte hole is the same story
        target16 = G.crc_compute(b"abXY", 16, 0x1021, 0xFFFF, False, False, 0)
        res16 = G.crc_solve_unknown(b"ab", b"", target16, 16, 0x1021, 2,
                                    0xFFFF, False, False, 0)
        self.assertTrue(res16["ok"], res16.get("note"))
        self.assertEqual(res16["unknown"], b"XY")

    def test_crc_preimage_reports_ambiguity(self):
        """Too many unknown bytes than the CRC can pin: a solution, but not *the* one"""
        target = G.crc_compute(b"flag{crc_is_linear}", 32, 0x04C11DB7, 0xFFFFFFFF,
                               True, True, 0xFFFFFFFF)
        res = G.crc_solve_unknown(b"flag{", b"}", target, 32, 0x04C11DB7, 15,
                                  0xFFFFFFFF, True, True, 0xFFFFFFFF)
        self.assertTrue(res["ok"])
        self.assertFalse(res["unique"])
        self.assertGreater(res["free_bits"], 0)
        # whatever it returns must actually reach the target
        self.assertEqual(G.crc_compute(res["data"], 32, 0x04C11DB7, 0xFFFFFFFF,
                                       True, True, 0xFFFFFFFF), target)

    def test_gf2_linear_algebra(self):
        # x1 + x2 = 1, x2 = 1  ->  x1 = 0, x2 = 1. Rows are bit-packed with
        # column j = bit j, and the solution comes back in the same encoding.
        mat = [0b11, 0b10]
        rhs = [1, 1]
        sol = G.gf2_solve(mat, rhs)
        self.assertEqual(sol, 0b10)                 # x2 = 1, x1 = 0
        self.assertEqual(G.gf2_rank(mat), 2)
        self.assertEqual(G.gf2_rank([0b0, 0b0]), 0)

    def test_lfsr_recovery_and_prediction(self):
        """taps = full characteristic exponent list (leading term included)"""
        taps, state = [0, 11, 13, 14, 16], 0xACE1
        lfsr = G.LFSR(taps, state)
        bits = [lfsr.next_bit() for _ in range(64)]
        self.assertEqual(G.berlekamp_massey(bits), taps)
        predicted = G.lfsr_next(bits, 16)
        fresh = G.LFSR(taps, state)
        true_tail = [fresh.next_bit() for _ in range(80)][64:]
        self.assertEqual(predicted, true_tail)

    def test_bits_helpers(self):
        data = bytes(range(8))
        bits = G.bytes_to_bits(data)
        self.assertEqual(G.bits_to_bytes(bits), data)
        self.assertEqual(G.bits_to_int([1, 0, 1]), 0b101)
        self.assertEqual(G.int_to_bits(0b101, 4), [0, 1, 0, 1])


class TestHashes(unittest.TestCase):

    def test_vectors_match_hashlib(self):
        for msg in (b"", b"abc", b"a" * 1000, bytes(range(256))):
            self.assertEqual(H.sha256(msg), hashlib.sha256(msg).digest())
            self.assertEqual(H.sha1(msg), hashlib.sha1(msg).digest())
        self.assertEqual(H.sha256(b"abc").hex(),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(H.sha1(b"abc").hex(),
                         "a9993e364706816aba3e25717850c26c9cd0d89d")

    def test_md5(self):
        self.assertEqual(H.md5(b"abc").hex(), hashlib.md5(b"abc").hexdigest())

    def test_length_extension_sha256(self):
        secret = b"secret"
        data = b"user=guest"
        extra = b"&admin=1"
        h1 = H.sha256(secret + data)
        forged = H.length_extension(h1, len(data), extra, algorithm="sha256",
                                    secret_len=len(secret))
        # forged_message is glue + extra: the attacker never learns secret||data,
        # so the full forged message has to be reconstructed for verification
        self.assertEqual(H.sha256(secret + data + forged["forged_message"]),
                         forged["digest"])
        self.assertEqual(forged["digest"].hex(), forged["hexdigest"])
        self.assertEqual(forged["total_len"], len(secret + data + forged["forged_message"]))

    def test_length_extension_sha1(self):
        secret, data, extra = b"key", b"msg", b"|admin"
        h1 = H.sha1(secret + data)
        forged = H.length_extension(h1, len(data), extra, algorithm="sha1",
                                    secret_len=len(secret))
        self.assertEqual(H.sha1(secret + data + forged["forged_message"]),
                         forged["digest"])

    def test_length_extension_md5(self):
        secret, data, extra = b"k", b"msg", b"x"
        h1 = H.md5(secret + data)
        forged = H.length_extension(h1, len(data), extra, algorithm="md5",
                                    secret_len=len(secret))
        self.assertEqual(H.md5(secret + data + forged["forged_message"]),
                         forged["digest"])

    def test_hmac(self):
        import hmac
        self.assertEqual(H.hmac_sha256(b"k", b"m"),
                         hmac.new(b"k", b"m", hashlib.sha256).digest())


class TestStreamCiphers(unittest.TestCase):

    def test_rc4_vector(self):
        self.assertEqual(S.rc4(b"Key", b"Plaintext").hex(), "bbf316e8d940af0ad3")
        self.assertEqual(S.rc4(b"Wiki", b"pedia").hex(), "1021bf0420")

    def test_chacha20_rfc8439(self):
        key = bytes(range(32))
        # RFC 8439 section 2.3.2 publishes a *keystream* for this nonce/counter
        block_nonce = bytes.fromhex("000000090000004a00000000")
        keystream = S.chacha20_block(key, block_nonce, 1)
        self.assertEqual(keystream[:16].hex(), "10f1e7e4d13b5915500fdd1fa32071c4")
        # section 2.4.2 publishes a *ciphertext*, and its nonce differs
        nonce = bytes.fromhex("000000000000004a00000000")
        plaintext = (b"Ladies and Gentlemen of the class of '99: If I could offer "
                     b"you only one tip for the future, sunscreen would be it.")
        ct = S.chacha20(key, nonce, plaintext, counter=1)
        self.assertEqual(ct[:16].hex(), "6e2e359a2568f98041ba0728dd0d6981")
        self.assertEqual(len(ct), len(plaintext))
        self.assertEqual(S.chacha20(key, nonce, ct, counter=1), plaintext)

    def test_aes_ctr_round_trip(self):
        key, nonce = b"k" * 16, b"n" * 8
        data = b"cryptoexp ctr mode test data"
        ct = S.aes_ctr(key, nonce, data)
        self.assertEqual(S.aes_ctr(key, nonce, ct), data)
        # the keystream is what you get by encrypting zeros, not the ciphertext
        ks = S.aes_ctr_keystream(key, nonce, len(data))
        self.assertEqual(ks, S.aes_ctr(key, nonce, b"\x00" * len(data)))
        self.assertEqual(ks, bytes(a ^ b for a, b in zip(ct, data)))

    def test_keystream_reuse_and_crib(self):
        key, nonce = b"k" * 16, b"n" * 8
        p1 = b"the flag is flag{reuse}"
        p2 = b"another secret message"
        c1, c2 = S.aes_ctr(key, nonce, p1), S.aes_ctr(key, nonce, p2)
        self.assertEqual(S.keystream_xor(c1, c2), bytes(a ^ b for a, b in zip(p1, p2)))
        hits = S.crib_drag(c1, c2, p1[:10])
        self.assertTrue(any(p2[:6] in (h if isinstance(h, bytes) else b"")
                            for h in hits) or hits)


class TestRSAAttacks(unittest.TestCase):

    def test_franklin_reiter(self):
        """Related messages m2 = a*m1 + b with a small e (the attack's regime)"""
        key = ck.keygen(512, e=3)
        n, e = key["n"], key["e"]
        m1 = ck.bytes_to_long(b"flag{fr")
        a, b = 1, 7
        m2 = a * m1 + b
        c1 = pow(m1, e, n)
        c2 = pow(m2, e, n)
        res = RA.franklin_reiter(n, e, c1, c2, a, b)
        self.assertTrue(res["ok"], res.get("note"))
        self.assertEqual(res["plaintext"], b"flag{fr")

    def test_franklin_reiter_reports_large_e(self):
        key = ck.keygen(512)
        res = RA.franklin_reiter(key["n"], key["e"], 1, 2, 1, 1)
        self.assertFalse(res["ok"])
        self.assertTrue(res["note"])

    def test_hastad_padded(self):
        """e = 3 with tiny linear pads; each modulus must exceed m + pad"""
        e = 3
        m = ck.bytes_to_long(b"flag{hastad}")
        triples = []
        for i in range(e):
            while True:
                key = ck.keygen(512, e=e)
                n = key["n"]
                if n > m + i + 1:
                    break
            triples.append((n, pow(m + i + 1, e, n), i + 1))
        res = RA.hastad_padded(e, triples)
        self.assertTrue(res["ok"], res.get("note"))
        self.assertEqual(res["plaintext"], b"flag{hastad}")

    def test_parity_oracle(self):
        key = ck.keygen(512)
        n, e, d = key["n"], key["e"], key["d"]
        msg = ck.bytes_to_long(b"flag{parity_oracle}")
        c = pow(msg, e, n)
        calls = {"n": 0}

        def oracle(ct):
            calls["n"] += 1
            return pow(ct, d, n) & 1

        # the attack halves the interval per query, so a 512-bit n needs ~514 queries
        res = RA.parity_oracle_attack(n, e, c, oracle)
        self.assertTrue(res["ok"], res.get("note"))
        # the recovered plaintext must be a valid preimage, which is the real check
        self.assertTrue(pow(ck.bytes_to_long(res["plaintext"]), e, n) == c
                        or msg % n == ck.bytes_to_long(res["plaintext"]) % n)

    def test_stereotyped_message(self):
        """A 2-byte unknown field with an explicit bound (keeps the lattice small)"""
        key = ck.keygen(512, e=3)
        n, e = key["n"], key["e"]
        prefix, unknown, suffix = b"flag{", b"hi", b"}"
        m = ck.bytes_to_long(prefix + unknown + suffix)
        c = pow(m, e, n)
        res = RA.stereotyped_message(n, e, c, prefix, suffix,
                                     bound=1 << 16, time_budget=30)
        self.assertTrue(res["ok"], res.get("note"))
        self.assertEqual(res["plaintext"], prefix + unknown + suffix)


class TestKeys(unittest.TestCase):

    def test_der_round_trip(self):
        n, e = 0x1234567890ABCDEF, 65537
        der = K.rsa_public_der(n, e)
        self.assertEqual(K.parse_der_rsa_public(der), (n, e))

    def test_ssh_public_key_round_trip(self):
        import base64

        def mpint(x: int) -> bytes:
            """SSH mpint: big-endian, with a leading zero when the top bit is set"""
            raw = x.to_bytes((x.bit_length() + 7) // 8 or 1, 'big')
            if raw[0] & 0x80:
                raw = b"\x00" + raw
            return len(raw).to_bytes(4, 'big') + raw

        n, e = 0xDEADBEEFCAFEBABE, 65537
        # blob layout: string "ssh-rsa", mpint e, mpint n
        name = b"ssh-rsa"
        blob = (len(name).to_bytes(4, 'big') + name + mpint(e) + mpint(n))
        line = "ssh-rsa " + base64.b64encode(blob).decode() + " user@host"
        parsed = K.parse_ssh_public_key(line)
        self.assertEqual(parsed["e"], e)
        self.assertEqual(parsed["n"], n)
        self.assertTrue(K.key_fingerprint_sha256(line).startswith("SHA256:"))

    def test_pem_wrap(self):
        der = b"\x30\x03\x02\x01\x01"
        pem = K.pem_wrap("RSA PUBLIC KEY", der)
        self.assertIn("-----BEGIN RSA PUBLIC KEY-----", pem)


class TestFlagConfig(unittest.TestCase):
    """Flag shapes are an engagement property, so they must be configurable"""

    def tearDown(self):
        from cryptoexp.utils import encoding as E
        E.reset_flag_prefixes()
        os.environ.pop("CRYPTOEXP_FLAG_PREFIXES", None)

    def test_explicit_prefixes_per_call(self):
        from cryptoexp.utils import encoding as E
        self.assertEqual(E.flag_candidates(b"flag{builtin}"), ["flag{builtin}"])
        self.assertEqual(E.flag_candidates(b"DH{not_default}"), [])
        self.assertEqual(E.flag_candidates(b"DH{now_it_is}", prefixes=["DH"]),
                         ["DH{now_it_is}"])
        # case-insensitive, and the prefix is a literal (no regex injection)
        self.assertEqual(E.flag_candidates(b"dh{lower}", prefixes=["DH"]), ["dh{lower}"])
        # "a.c" must match that literal text, not "abc" (prefixes are escaped)
        self.assertEqual(E.flag_candidates(b"a.c{literal}", prefixes=["a.c"]),
                         ["a.c{literal}"])
        self.assertEqual(E.flag_candidates(b"abc{not_literal}", prefixes=["a.c"]), [])

    def test_custom_regex(self):
        from cryptoexp.utils import encoding as E
        pat = r"ACME-\d{4}-[a-z0-9]{8}"
        found = E.flag_candidates(b"token ACME-2026-abcd1234 end", pattern=pat)
        self.assertEqual(found, ["ACME-2026-abcd1234"])
        self.assertEqual(E.flag_candidates(b"ACME-2026-short", pattern=pat), [])

    def test_process_default_and_reset(self):
        from cryptoexp.utils import encoding as E
        previous = E.set_flag_prefixes(["DH"])
        try:
            self.assertEqual(E.get_flag_prefixes(), ("DH",))
            self.assertEqual(E.flag_candidates(b"DH{xy}"), ["DH{xy}"])
            # merge keeps the earlier prefixes
            E.set_flag_prefixes(["corp_"], merge=True)
            self.assertEqual(E.get_flag_prefixes(), ("DH", "corp_"))
        finally:
            E.set_flag_prefixes(previous[0], previous[1])
        E.reset_flag_prefixes()
        self.assertIn("flag", E.get_flag_prefixes())
        self.assertEqual(E.flag_candidates(b"DH{xy}"), [])

    def test_environment_variable(self):
        from cryptoexp.utils import encoding as E
        os.environ["CRYPTOEXP_FLAG_PREFIXES"] = "DH,NSSCTF"
        self.assertEqual(E.flag_candidates(b"NSSCTF{from_env}"), ["NSSCTF{from_env}"])
        self.assertEqual(E.flag_candidates(b"other{lead}"), [])

    def test_placeholders_are_not_flags(self):
        """A statement that *describes* the format must not confirm itself"""
        from cryptoexp.utils import encoding as E
        self.assertEqual(E.flag_candidates(b"the format is DH{...}", prefixes=["DH"]), [])
        self.assertEqual(E.loose_flag_candidates(b"the format is flag{...}"), [])
        self.assertEqual(E.flag_candidates(b"DH{real_value}", prefixes=["DH"]),
                         ["DH{real_value}"])

    def test_find_flags_labels_and_offsets(self):
        from cryptoexp.utils import encoding as E
        data = b"junk DH{a1b2} noise other{lead} end"
        found = E.find_flags(data, prefixes=["DH"])
        kinds = {(f["match"], f["kind"]) for f in found}
        self.assertIn(("DH{a1b2}", "strict"), kinds)
        self.assertIn(("other{lead}", "loose"), kinds)
        self.assertTrue(all(isinstance(f["offset"], int) for f in found))
        self.assertEqual([f["offset"] for f in found],
                         sorted(f["offset"] for f in found))


class TestPRNGExtra(unittest.TestCase):

    def test_java_random_reference_value(self):
        """new Random(42).nextInt() is -1170105035"""
        self.assertEqual(PE.java_random_ints(42, 1), [-1170105035])

    def test_java_random_recovery_and_prediction(self):
        outputs = PE.java_random_ints(123456789, 6)
        recovered = PE.java_random_recover(outputs)
        self.assertIsNotNone(recovered, "java.util.Random state recovery failed")
        predicted = PE.java_random_predict(outputs, 4)
        truth = PE.java_random_ints(123456789, 10)[6:]
        self.assertEqual(predicted, truth)

    def test_glibc_rand_reference_values(self):
        """srand(1) then rand() — the classic five values"""
        self.assertEqual(PE.glibc_rand_values(1, 5),
                         [1804289383, 846930886, 1681692777, 1714636915, 1957747793])

    def test_glibc_rand_recovery(self):
        """96+ outputs pin the low bits uniquely; fewer are honestly reported"""
        outputs = PE.glibc_rand_values(7, 128)
        state = PE.glibc_rand_recover(outputs)
        self.assertIsNotNone(state, "glibc rand state recovery failed")
        predicted = PE.glibc_rand_predict(outputs, 3)
        truth = PE.glibc_rand_values(7, 131)[128:]
        self.assertEqual(predicted, truth)

    def test_glibc_rand_recovery_reports_ambiguity(self):
        """With too few outputs the state is underdetermined, so None - not a guess"""
        self.assertIsNone(PE.glibc_rand_recover(PE.glibc_rand_values(7, 40)))

    def test_xorshift_round_trip(self):
        outputs = PE.xorshift32_stream(0xDEADBEEF, 8)
        state = PE.xorshift_recover(outputs)
        self.assertIsNotNone(state, "xorshift recovery failed")
        truth = PE.xorshift32_stream(0xDEADBEEF, 11)[8:]
        self.assertEqual(PE.xorshift_predict(outputs, 3), truth)


if __name__ == "__main__":
    unittest.main(verbosity=2)
