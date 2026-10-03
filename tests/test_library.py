"""Infrastructure unit tests — is the dependency-free core actually trustworthy?

Run: python -m unittest discover -s tests -v
Assertions target official vectors and mathematical identities, never "looks right".
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import cryptoexp as ck
from cryptoexp.utils import aes as A


class TestAES(unittest.TestCase):
    """FIPS-197 / SP800-38A official vectors"""

    def test_ecb_vectors(self):
        pt = bytes.fromhex('00112233445566778899aabbccddeeff')
        vectors = [
            ('000102030405060708090a0b0c0d0e0f',
             '69c4e0d86a7b0430d8cdb78070b4c55a'),
            ('000102030405060708090a0b0c0d0e0f1011121314151617',
             'dda97ca4864cdfe06eaf70a0ec0d7191'),
            ('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
             '8ea2b7ca516745bfeafc49904b496089'),
        ]
        for key_hex, want in vectors:
            key = bytes.fromhex(key_hex)
            ct = A.encrypt_ecb(key, pt)
            self.assertEqual(ct.hex(), want, f"AES-{len(key) * 8} encryption mismatch")
            self.assertEqual(A.decrypt_ecb(key, ct), pt, "decryption did not round-trip")

    def test_cbc_vector(self):
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        pt = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
        ct = A.encrypt_cbc(key, pt, iv)
        self.assertEqual(ct.hex(), '7649abac8119b246cee98e9b12e9197d')
        self.assertEqual(A.decrypt_cbc(key, ct, iv), pt)

    def test_rejects_unaligned(self):
        with self.assertRaises(ValueError):
            A.encrypt_ecb(b'k' * 16, b'short')


class TestAlgebra(unittest.TestCase):

    def test_modinv_crt(self):
        self.assertEqual(ck.modinv(3, 11), 4)
        self.assertIsNone(ck.modinv(2, 4))
        self.assertEqual(ck.crt([(2, 3), (3, 5), (2, 7)])[0], 23)
        self.assertIsNone(ck.crt([(1, 4), (2, 6)]),
                          "non-coprime moduli must return None")

    def test_iroot(self):
        self.assertEqual(ck.iroot(27, 3), (3, True))
        self.assertEqual(ck.iroot(28, 3), (3, False))
        self.assertTrue(ck.iroot(10 ** 60, 3)[1])

    def test_factor_and_prime(self):
        self.assertTrue(ck.is_prime(2 ** 61 - 1))
        self.assertFalse(ck.is_prime(2 ** 61 - 3))
        self.assertEqual(ck.factor(2 ** 64 + 1), {274177: 1, 67280421310721: 1})

    def test_factor_limited_budget(self):
        n = ck.next_prime(2 ** 127) * ck.next_prime(2 ** 128)
        self.assertIsNone(ck.factor_limited(n, max_steps=2000),
                          "budget exhaustion must return None, never run unbounded")

    def test_wiener_and_fermat(self):
        p, q = ck.next_prime(2 ** 255), ck.next_prime(2 ** 255 + 10 ** 40)
        n = p * q
        f = ck.fermat_factor(n, 200000)
        self.assertIsNotNone(f)
        self.assertEqual(f[0] * f[1], n)

        p2, q2 = ck.next_prime(2 ** 254), ck.next_prime(2 ** 255)
        n2 = p2 * q2
        phi = (p2 - 1) * (q2 - 1)
        d = ck.next_prime(2 ** 60)
        while ck.gcd(d, phi) != 1:
            d = ck.next_prime(d + 1)
        e = ck.modinv(d, phi)
        hit = ck.wiener_recover_d(e, n2)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], d)

    def test_lcg(self):
        m, a, c, s = 2 ** 31 - 1, 48271, 12345, 7
        seq = []
        for _ in range(8):
            s = (a * s + c) % m
            seq.append(s)
        self.assertEqual(ck.lcg_recover(seq, m), {"a": a, "c": c, "m": m})

    def test_bsgs_budget(self):
        small = ck.next_prime(2 ** 28)
        x = 1234567
        self.assertEqual(ck.bsgs(5, pow(5, x, small), small), x)
        big = ck.next_prime(2 ** 62)
        self.assertIsNone(ck.bsgs(5, 7, big), "over budget must return None")


class TestLinearAlgebra(unittest.TestCase):
    """GF(p) linear algebra — the generic tool for linear constructions"""

    def test_solve_and_inverse(self):
        p = 101
        m = [[1, 2], [3, 4]]
        rhs = [5, 6]
        sol, info = ck.solve_linear(m, rhs, p)
        self.assertIsNotNone(sol, info)
        self.assertEqual([(m[0][0] * sol[0] + m[0][1] * sol[1]) % p,
                          (m[1][0] * sol[0] + m[1][1] * sol[1]) % p], rhs)
        inv = ck.mat_inv(m, p)
        prod = ck.mat_mul(m, inv, p)
        self.assertEqual(prod, [[1, 0], [0, 1]])

    def test_inconsistent_system(self):
        sol, info = ck.solve_linear([[1, 1], [2, 2]], [1, 3], 7)
        self.assertIsNone(sol)

    def test_recover_linear_map(self):
        # a Hill-cipher style 2x2 map over GF(29)
        p = 29
        M = [[3, 5], [7, 11]]
        inputs = [[1, 2], [3, 4], [5, 6]]
        outputs = [[sum(M[i][k] * v[k] for k in range(2)) % p for i in range(2)]
                   for v in inputs]
        rec, info = ck.recover_linear_map(inputs, outputs, p)
        self.assertIsNotNone(rec, info)
        self.assertEqual(rec, M)

    def test_lcg_via_linear_algebra(self):
        p, a, c, s = 2 ** 61 - 1, 6364136223846793005, 1442695040888963407, 42
        seq = []
        for _ in range(6):
            s = (a * s + c) % p
            seq.append(s)
        # the multiplier is only recoverable modulo p
        self.assertEqual(ck.solve_lcg_params(seq, p)["a"], a % p)


class TestDiscreteLog(unittest.TestCase):

    def test_pohlig_hellman_smooth_order(self):
        # p - 1 = 2^4 * 3^2 * 5 * 7 ... pick a prime with a smooth order
        p = 2 ** 16 * 3 ** 2 * 5 * 7 * 11 + 1
        while not ck.is_prime(p):
            p += 2 ** 16 * 3 ** 2 * 5 * 7 * 11
        g = 2
        x = 12345 % (p - 1)
        h = pow(g, x, p)
        res = ck.discrete_log(g, h, p)
        self.assertEqual(res.get("x"), x, res)

    def test_feasibility_verdict_is_honest(self):
        safe = ck.next_prime(2 ** 127)
        p = 2 * safe + 1
        while not ck.is_prime(p):
            safe = ck.next_prime(safe + 2)
            p = 2 * safe + 1
        verdict = ck.dlog_feasibility(p)
        self.assertFalse(verdict["feasible"])
        self.assertIn("large prime factor", verdict["why"])


class TestLattice(unittest.TestCase):

    def test_lll_reduces(self):
        basis = [[1, 1, 1], [1, 0, 1], [0, 1, 1], [1, 1, 0]]
        red = ck.lll(basis)
        self.assertIsNotNone(red)
        self.assertLessEqual(len(red[0]), 3)

    def test_subset_sum_lll(self):
        rng = random.Random(7)
        w = [rng.randrange(2 ** 20, 2 ** 26) for _ in range(8)]
        picks = sorted(rng.sample(range(8), 3))
        target = sum(w[i] for i in picks)
        got = ck.subset_sum_lll(w, target)
        self.assertIsNotNone(got)
        self.assertEqual(sum(w[i] for i in got), target)

    def test_subset_sum_mitm(self):
        """MITM must stay correct on a denser instance where LLL is not reliable"""
        rng = random.Random(21)
        w = [rng.randrange(2 ** 20, 2 ** 21) for _ in range(28)]  # density ~1.3
        picks = sorted(rng.sample(range(28), 6))
        target = sum(w[i] for i in picks)
        got = ck.mitm_subset_sum(w, target)
        self.assertIsNotNone(got)
        self.assertEqual(sum(w[i] for i in got), target)

    def test_coppersmith_known_high_bits(self):
        rng = random.Random(11)

        def prime(bits):
            while True:
                p = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
                if ck.is_prime(p):
                    return p

        p, q = prime(256), prime(256)
        n = p * q
        p_high = p >> 96
        res = ck.known_high_bits_factor(n, p_high, 160, 512)
        self.assertIsNotNone(res["p"], f"Coppersmith missed the root: {res['note']}")
        self.assertEqual(res["p"] * res["q"], n)

    def test_coppersmith_rejects_trivial_factor(self):
        """A bogus result equal to N (p=n, q=1) must never be reported"""
        N = 101                      # prime: it has no non-trivial factorization
        res = ck.known_high_bits_factor(N, 1, 1, 8)
        p = res["p"]
        self.assertTrue(p is None or 1 < p < N,
                        f"reported a trivial 'factor' {p} for N={N}")

    def test_coppersmith_rejects_nonmonic(self):
        res = ck.coppersmith_univariate([1, 2, 3], 101, 10)
        self.assertEqual(res["roots"], [])


class TestRSAOps(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        rng = random.Random(3)
        cls.k = ck.keygen(512, rng=rng)
        cls.flag = b'flag{rsa_ops_unittest}'
        cls.m = ck.bytes_to_long(cls.flag)
        cls.c = ck.rsa_encrypt(cls.m, cls.k['e'], cls.k['n'])

    def test_roundtrip(self):
        self.assertEqual(ck.rsa_decrypt(self.c, self.k['d'], self.k['n']), self.m)
        self.assertTrue(ck.reencrypt_check(self.m, self.k['e'], self.k['n'], self.c))
        self.assertFalse(ck.reencrypt_check(self.m + 1, self.k['e'], self.k['n'], self.c))

    def test_direct_and_phi(self):
        r = ck.decrypt_with_factors(self.k['n'], self.k['e'], self.c,
                                    self.k['p'], self.k['q'])
        self.assertTrue(r['ok'])
        self.assertEqual(r['plaintext'], self.flag)
        phi = (self.k['p'] - 1) * (self.k['q'] - 1)
        r2 = ck.phi_leak_attack(self.k['n'], self.k['e'], phi, self.c)
        self.assertTrue(r2['ok'])
        self.assertEqual(r2['plaintext'], self.flag)

    def test_rejects_bogus_factors(self):
        """p=n, q=1 previously produced a ZeroDivisionError deep inside phi"""
        bad = ck.decrypt_with_factors(self.k['n'], self.k['e'], self.c,
                                      self.k['n'], 1)
        self.assertFalse(bad['ok'])
        self.assertIn("invalid", bad['note'])

    def test_factor_from_d(self):
        f = ck.factor_from_d(self.k['n'], self.k['e'], self.k['d'])
        self.assertIsNotNone(f)
        self.assertEqual(f[0] * f[1], self.k['n'])

    def test_small_e(self):
        n = ck.next_prime(2 ** 1023) * ck.next_prime(2 ** 1024)
        c = self.m ** 3
        r = ck.small_e_attack(n, 3, c)
        self.assertTrue(r['ok'])
        self.assertEqual(r['plaintext'], self.flag)

    def test_broadcast(self):
        e = 3
        pairs = []
        for i in range(3):
            n = ck.next_prime(2 ** 127 + i * 10 ** 6) * ck.next_prime(2 ** 128 + i * 10 ** 6)
            pairs.append((pow(self.m, e, n), n))
        r = ck.broadcast_attack(e, pairs)
        self.assertTrue(r['ok'], r['note'])
        self.assertEqual(r['plaintext'], self.flag)

    def test_common_modulus(self):
        n = self.k['n']
        e1, e2 = 17, 65537
        g, _a, _b = ck.egcd(e1, e2)
        self.assertEqual(g, 1)
        c1, c2 = pow(self.m, e1, n), pow(self.m, e2, n)
        r = ck.common_modulus_attack(n, e1, c1, e2, c2)
        self.assertTrue(r['ok'], r['note'])
        self.assertEqual(r['plaintext'], self.flag)

    def test_shared_prime(self):
        p = ck.next_prime(2 ** 200)
        q1, q2 = ck.next_prime(2 ** 201), ck.next_prime(2 ** 202)
        n1, n2 = p * q1, p * q2
        e = 65537
        pairs = [(n1, pow(self.m, e, n1)), (n2, pow(self.m, e, n2))]
        r = ck.shared_prime_attack(pairs)
        self.assertTrue(r['ok'], r['note'])
        self.assertEqual(r['plaintext'], self.flag)

    def test_dp_leak(self):
        dp = self.k['d'] % (self.k['p'] - 1)
        r = ck.dp_leak_attack(self.k['n'], self.k['e'], dp, self.c)
        self.assertTrue(r['ok'])
        self.assertEqual(r['plaintext'], self.flag)

    def test_auto_attack_gives_up_honestly(self):
        n = ck.next_prime(2 ** 511) * ck.next_prime(2 ** 512)
        r = ck.auto_attack(n, 65537, 12345)
        self.assertFalse(r['ok'])
        self.assertTrue(r['note'])


class TestPRNG(unittest.TestCase):

    def test_clone_predicts(self):
        rng = random.Random(2024)
        outs = [rng.getrandbits(32) for _ in range(624)]
        want = [rng.getrandbits(32) for _ in range(4)]
        self.assertEqual(ck.predict_next(outs, 4), want)

    def test_untemper_roundtrip(self):
        rng = random.Random(9)
        clone = ck.clone_from_outputs([rng.getrandbits(32) for _ in range(624)])
        self.assertTrue(all(0 <= v < 2 ** 32 for v in [clone.next32() for _ in range(5)]))

    def test_crack_small_seed(self):
        seed = 4242
        target = random.Random(seed).getrandbits(32)
        self.assertEqual(ck.crack_seed(target, max_seed=10000), seed)


class TestOracle(unittest.TestCase):

    def setUp(self):
        self.key = b'0123456789abcdef'
        self.iv = b'abcdefghijklmnop'

    def test_structure_detection(self):
        enc = ck.make_ecb_oracle(self.key, b'z' * 40)
        self.assertEqual(ck.detect_block_size(enc), 16)
        self.assertEqual(ck.detect_mode(enc), "ECB")
        self.assertEqual(
            ck.find_prefix_len(ck.make_ecb_oracle(self.key, b'z' * 40, b'P' * 21)), 21)

    def test_prefix_len_survives_repetitive_secret(self):
        """A secret made of repeated bytes must not fake the alignment signal"""
        enc = ck.make_ecb_oracle(self.key, b'z' * 40, b'P' * 21)
        self.assertEqual(ck.find_prefix_len(enc), 21)

    def test_ecb_byte_at_a_time_no_prefix(self):
        secret = b'flag{ecb_byte_at_a_time_works}'
        enc = ck.make_ecb_oracle(self.key, secret)
        self.assertEqual(ck.ecb_byte_at_a_time(enc), secret)

    def test_ecb_byte_at_a_time_with_prefix(self):
        secret = b'flag{prefix_is_handled_too}'
        enc = ck.make_ecb_oracle(self.key, secret, prefix=b'P' * 11)
        self.assertEqual(ck.ecb_byte_at_a_time(enc), secret)

    def test_ecb_byte_at_a_time_multiblock(self):
        secret = b'A' * 32 + b'flag{multi_block_secret}'
        enc = ck.make_ecb_oracle(self.key, secret)
        self.assertEqual(ck.ecb_byte_at_a_time(enc), secret)

    def test_padding_oracle(self):
        for secret in (b'flag{one_block}', b'flag{padding_oracle_across_two_blocks}',
                       b'x' * 40 + b'!}'):
            valid = ck.make_padding_oracle(self.key, self.iv)
            ct = self.iv + A.encrypt_cbc(self.key, ck.pkcs7_pad(secret), self.iv)
            rec = ck.padding_oracle_attack(valid, ct, 16)
            self.assertEqual(ck.pkcs7_unpad(rec, 16), secret)

    def test_bitflip(self):
        pt = ck.pkcs7_pad(b'admin=0;role=user', 16)
        ct = self.iv + A.encrypt_cbc(self.key, pt, self.iv)
        # byte 6 of plaintext block 0 is the '0' in "admin=0"; it is controlled by
        # the IV, i.e. ciphertext offset 0
        forged = ck.bitflip_cbc(ct, 6, b'0', b'1')
        out = A.decrypt_cbc(self.key, forged[16:], forged[:16])
        self.assertIn(b'admin=1;role=user', out)


class TestEncodingLayer(unittest.TestCase):

    def test_flag_format_is_strict(self):
        self.assertTrue(ck.flag_candidates(b'xx flag{abc_123} yy'))
        self.assertEqual(ck.flag_candidates(b'zz j{vreM\\x7f} qq'), [],
                         "garbage matching token{...} must not count as a flag")
        # the loose pattern needs a 2+ character prefix
        self.assertTrue(ck.loose_flag_candidates(b'zz jv{vreM} qq'))

    def test_round_trips(self):
        data = b'flag{round_trip}'
        self.assertEqual(ck.unhex(ck.enhex(data)), data)
        self.assertEqual(ck.b64d(ck.b64e(data)), data)
        self.assertEqual(ck.b32d(ck.b32e(data)), data)
        self.assertEqual(ck.b58d(ck.b58e(data)), data)
        self.assertEqual(ck.morse_decode(ck.morse_encode("SOS FLAG")), "SOS FLAG")

    def test_single_byte_xor(self):
        ct = bytes(b ^ 0x42 for b in b'flag{single}')
        top = ck.single_byte_xor(ct, top=1)[0]
        self.assertEqual(top['key'], 0x42)
        self.assertEqual(top['plaintext'], b'flag{single}')

    def test_repeating_key_xor_recovers_true_length(self):
        """Hamming ranking alone puts the true length 4th here; the library must
        still recover the key because it scores the whole plaintext."""
        flag = b'flag{repeating_key_xor_with_hamming_distance}'
        ct = ck.xor_repeat(flag, b'KEY42')
        best = ck.repeating_key_xor(ct)[0]
        self.assertEqual(best['plaintext'], flag)
        self.assertEqual(best['key'], b'KEY42')


class TestHypothesisEngine(unittest.TestCase):

    def test_gaps_name_what_is_missing(self):
        from cryptoexp.hypothesis import params_from_ctx, evaluate
        from cryptoexp.core.context import build_context
        ctx = build_context("n = 12345678901234567890123456789012345678901234567890"
                            "1234567890123456789012345678901234567890123456789012345"
                            "67890123456789012345678901234567890123456789012345678901"
                            "234567890123\ne = 65537")
        result = evaluate(params_from_ctx(ctx), budget="list")
        names = {g["name"] for g in result["gaps"]}
        self.assertIn("rsa_known_high_bits", names)
        gap = next(g for g in result["gaps"] if g["name"] == "rsa_known_high_bits")
        self.assertTrue(gap["missing"], "a gap must say what exactly is missing")

    def test_full_run_confirms_a_known_attack(self):
        from cryptoexp.hypothesis import params_from_ctx, evaluate
        from cryptoexp.core.context import build_context
        ctx = build_context(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "challenges", "rsa_wiener.txt"))
        result = evaluate(params_from_ctx(ctx), budget="full")
        rsa_hits = [r for r in result["results"]
                    if r["state"] == "confirmed" and r["name"].startswith("rsa_")]
        self.assertTrue(rsa_hits, f"no confirmed RSA hypothesis: "
                                  f"{[(r['name'], r['state']) for r in result['results']]}")

    def test_every_hypothesis_declares_needs(self):
        from cryptoexp.hypothesis import list_hypotheses
        self.assertGreaterEqual(len(list_hypotheses()), 20)
        for name, domain, cost in list_hypotheses():
            self.assertTrue(name and domain)


class TestWorkbench(unittest.TestCase):

    def test_workbench_is_runnable_and_english(self):
        import ast
        from cryptoexp.core.analysis import analyze_all
        from cryptoexp.lab import build_workbench
        results = analyze_all(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "challenges", "rsa_fermat.txt"))
        src = build_workbench(results)
        ast.parse(src)                      # must be valid Python
        self.assertIn("PARAMS", src)
        self.assertIn("remote_oracle", src)
        # ignore lines carrying absolute paths: the repository lives under a
        # non-ASCII directory in this checkout, and paths are environment data
        prose = "\n".join(line for line in src.splitlines()
                          if "sys.path.insert" not in line and ":\\" not in line)
        self.assertFalse(any('\u4e00' <= ch <= '\u9fff' for ch in prose),
                         "workbench output must be English")

    def test_workbench_lists_gaps(self):
        from cryptoexp.core.analysis import analyze_all
        from cryptoexp.lab import build_workbench
        results = analyze_all(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "challenges", "rsa_high_bits.txt"))
        src = build_workbench(results)
        self.assertIn("[gap]", src)
        self.assertIn("[confirmed]", src)


class TestSignatures(unittest.TestCase):
    """DSA/ECDSA nonce reuse and e=3 signature forgery"""

    def test_dsa_nonce_reuse(self):
        from cryptoexp.utils import signatures as S
        q = ck.next_prime(2 ** 60)
        k = 2
        while True:
            p = k * q + 1
            if ck.is_prime(p):
                break
            k += 1
        g = pow(2, (p - 1) // q, p)
        x = 12345678901234567 % q
        y = pow(g, x, p)
        h1, h2, nonce = 111111111111, 222222222222, 424242424242
        r, s1 = S.dsa_sign(p, q, g, x, h1, nonce)
        _, s2 = S.dsa_sign(p, q, g, x, h2, nonce)
        res = S.dsa_nonce_reuse(p, q, g, y, r, s1, s2, h1, h2)
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["d"], x)

    def test_ecdsa_nonce_reuse_toy_curve(self):
        from cryptoexp.utils import signatures as S
        P, a, b = 97, 2, 3
        G = None
        for x0 in range(1, P):
            y0 = ck.tonelli_shanks((x0 ** 3 + a * x0 + b) % P, P)
            if y0 is not None:
                G = (x0, y0)
                break
        n, d, kk = 5, 3, 4
        h1, h2 = 11, 22
        r, s1 = S.ecdsa_sign(n, G[0], G[1], a, P, d, h1, kk)
        _, s2 = S.ecdsa_sign(n, G[0], G[1], a, P, d, h2, kk)
        res = S.ecdsa_nonce_reuse(n, r, s1, s2, h1, h2)
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["d"] % n, d % n)

    def test_e3_signature_forgery(self):
        from cryptoexp.utils import signatures as S
        key = ck.keygen(1024)
        digest_info = b"\x01\xff\xff\xff\x00" + bytes(range(20))
        res = S.rsa_e3_signature_forge(key["n"], digest_info)
        self.assertTrue(res["ok"], res["note"])
        self.assertTrue(res["meta"]["recovered"].startswith(digest_info))

    def test_pkcs1_v15_round_trip(self):
        from cryptoexp.utils import signatures as S
        block = S.pkcs1_v15_pad(b"hello", 128, 1)
        self.assertEqual(S.pkcs1_v15_unpad(block), (1, b"hello"))
        self.assertIsNone(S.pkcs1_v15_unpad(b"\x00\x02short"))
        with self.assertRaises(ValueError):
            S.pkcs1_v15_pad(b"x" * 200, 128, 1)


class TestSymTools(unittest.TestCase):
    """Static block-cipher helpers (ciphertext only, no oracle)"""

    def test_ecb_detection(self):
        from cryptoexp.utils import symtools as T
        key = b"0123456789abcdef"
        unit = b"flag{ecb_mode_1}"          # exactly 16 bytes
        ct = ck.aes.encrypt_ecb(key, T.pad_pkcs7(b"A" * 16 + unit * 3))
        self.assertTrue(T.is_ecb(ct))
        self.assertEqual(len(T.ecb_repeated_blocks(ct)), 1)
        other = ck.aes.encrypt_cbc(key, T.pad_pkcs7(b"A" * 16 + unit * 3), b"i" * 16)
        self.assertFalse(T.is_ecb(other))

    def test_cbc_flip_plaintext(self):
        from cryptoexp.utils import symtools as T
        key, iv = b"0123456789abcdef", b"abcdefghijklmnop"
        pt = T.pad_pkcs7(b"admin=0;role=user")
        ct = iv + ck.aes.encrypt_cbc(key, pt, iv)
        new_iv, new_ct = T.cbc_flip_plaintext(ct[16:], iv, 6, b"0", b"1")
        out = ck.aes.decrypt_cbc(key, new_ct, new_iv)
        self.assertIn(b"admin=1;role=user", out)

    def test_block_index_and_strip(self):
        from cryptoexp.utils import symtools as T
        self.assertEqual(T.block_index(18, 16), (1, 2))
        self.assertEqual(T.strip_pkcs7(ck.pkcs7_pad(b"data")), b"data")
        self.assertIsNone(T.strip_pkcs7(b"bad padding\x00\x05"))


class TestResultContract(unittest.TestCase):
    """The result-dict contract must be visible from `help(fn)`, not only the module

    A user solving NSSCTF RSA tasks reported the exact failure this guards against:
    the structure is documented in the module docstring, but `help(name)` shows only
    the function's own docstring, so the returned dict was mistaken for the answer and
    the real error surfaced frames later inside `long_to_bytes`.
    """

    # Public functions that hand back the standard result dict (or their own dict)
    DOCUMENTED = (
        "decrypt_with_factors", "small_e_attack", "broadcast_attack",
        "common_modulus_attack", "wiener_attack", "fermat_attack", "pollard_attack",
        "dp_leak_attack", "phi_leak_attack", "known_high_bits_attack", "auto_attack",
        "franklin_reiter", "hastad_padded", "stereotyped_message",
        "parity_oracle_attack", "ecdsa_nonce_reuse", "dsa_nonce_reuse",
        "coppersmith_univariate", "known_high_bits_factor", "discrete_log",
        "pohlig_hellman", "dlog_feasibility", "solve_lcg_params", "length_extension",
        "generate_findings", "context_public", "parse_ssh_public_key", "parse_jwt",
        "audit_rsa_key", "batch_gcd", "detect_weak_prng", "parse_der_signature",
    )

    def test_every_dict_returning_function_documents_its_return(self):
        # two of them are presentation-layer helpers, reachable by path rather than
        # from the package root; they still owe the caller a return description
        from cryptoexp.core.analysis import findings as _findings
        from cryptoexp.core import context as _context
        internal = {"generate_findings": _findings.generate_findings,
                    "context_public": _context.context_public}
        missing = []
        for name in self.DOCUMENTED:
            fn = getattr(ck, name, None) or internal.get(name)
            self.assertIsNotNone(fn, f"{name} is not reachable")
            doc = (fn.__doc__ or "").lower()
            # "documented" means the docstring *states the shape*: either a Returns
            # section or an inline arrow with braces. Each family has its own keys, so
            # the check is about visibility, not about one particular key set.
            has_return = any(marker in doc for marker in
                             ("returns:", "returns {", "return {", "-> {", "-> dict"))
            if not has_return:
                missing.append(name)
        self.assertEqual(missing, [],
                         f"return a dict but never say so in help(): {missing}")

    def test_standard_structure_keys(self):
        """All six keys, always — consumers rely on the shape, not on the attack"""
        key = ck.keygen(256, e=3)
        res = ck.wiener_attack(key["e"], key["n"], c=pow(1234, key["e"], key["n"]))
        self.assertEqual(set(res), {"ok", "plaintext", "detail", "factors", "d", "note"})
        self.assertIsInstance(res["ok"], bool)

    def test_dict_passed_to_long_to_bytes_explains_the_mixup(self):
        """The dict-vs-int mix-up must name the fix, not fail inside to_bytes"""
        with self.assertRaises(TypeError) as ctx:
            ck.long_to_bytes({"ok": True, "plaintext": b"x", "d": 3})
        message = str(ctx.exception)
        self.assertIn("result", message)
        self.assertIn("plaintext", message)
        self.assertIn("dict", message)
        with self.assertRaises(TypeError) as ctx2:
            ck.bytes_to_long({"ok": True})
        self.assertIn("bytes", str(ctx2.exception))
        # the normal path is untouched
        self.assertEqual(ck.long_to_bytes(0x4142), b"AB")
        self.assertEqual(ck.bytes_to_long(b"AB"), 0x4142)


class TestAPI(unittest.TestCase):

    def test_all_exports_resolve(self):
        for name in ck.__all__:
            self.assertTrue(hasattr(ck, name), f"{name} in __all__ does not exist")

    def test_api_map_runs(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            text = ck.api()
        self.assertIn("cryptoexp", text)
        self.assertIn("oracle attacks", text)

    def test_library_is_english(self):
        """English-first: no CJK in user-visible module strings"""
        import cryptoexp.hypothesis as H
        for name, domain, cost in H.list_hypotheses():
            self.assertFalse(any('\u4e00' <= ch <= '\u9fff' for ch in name))

    def test_optional_deps_probe(self):
        env = ck.probe_optional_deps()
        self.assertIn("gmpy2", env)
        self.assertIn("available", env["gmpy2"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
