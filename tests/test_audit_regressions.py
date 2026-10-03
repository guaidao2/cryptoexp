"""Regression tests from the two independent audits (2026-10-03).

Each test here corresponds to a defect that was found, reproduced, fixed and would
otherwise come back: a wrong formula, a documented argument order the code did not
implement, a docstring promising keys that did not exist, and several silent-wrong
paths. Keep them; they are the audit's lasting value.
"""

import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import cryptoexp as ck
from cryptoexp.utils import algebra as A
from cryptoexp.utils import dlp, forensics as F, lattice as L, modular, polytools
from cryptoexp.utils import rsa_ops as R, signatures as S, symtools


class TestSignatureAuditRegressions(unittest.TestCase):

    def test_ecdsa_recover_k_uses_s_not_r(self):
        """H1: the nonce is (h + r*d)/s; the early version divided by r and ignored s"""
        n, d, h, r = 1000003, 12345, 999, 654321
        k_true = 54321
        s = A.modinv(k_true, n) * (h + r * d) % n
        self.assertEqual(S.ecdsa_recover_k(n, r, s, h, d), k_true)
        # s = 0 is not invertible: None, not a wrong number
        self.assertIsNone(S.ecdsa_recover_k(n, r, 0, h, d))

    def test_ecdsa_nonce_reuse_does_not_claim_verification(self):
        """H5: the equations hold by construction, so no self-check is possible"""
        doc = inspect.getdoc(S.ecdsa_nonce_reuse) or ""
        self.assertIn("by construction", doc)
        self.assertNotIn("verified by re-deriving", doc)
        n, d, h, r = 1000003, 12345, 999, 654321
        k = 11111
        s1 = A.modinv(k, n) * (h + r * d) % n
        s2 = A.modinv(k, n) * (h + 5 + r * d) % n
        res = S.ecdsa_nonce_reuse(n, r, s1, s2, h, h + 5)
        self.assertTrue(res["ok"])
        self.assertEqual(res["d"], d)
        self.assertFalse(res["meta"]["verified"])   # the honest flag

    def test_e3_forge_documents_real_keys(self):
        """H4: help() used to promise 'signature'/'recovered', which raised KeyError"""
        doc = inspect.getdoc(S.rsa_e3_signature_forge) or ""
        self.assertIn('result["d"]', doc)
        self.assertIn("meta", doc)
        key = R.keygen(512)
        out = S.rsa_e3_signature_forge(key["n"], b"\x01\xff\x00" + bytes(range(20)))
        self.assertIn("ok", out)
        self.assertNotIn("signature", out)          # never a real key
        if out["ok"]:
            self.assertIsInstance(out["d"], int)
            self.assertIn("recovered", out["meta"])

    def test_dsa_nonce_reuse_flags_whether_y_was_checked(self):
        q = ck.next_prime(2 ** 60)
        k = 2
        while True:
            p = k * q + 1
            if ck.is_prime(p):
                break
            k += 1
        g = pow(2, (p - 1) // q, p)
        x = 123456789 % q
        y = pow(g, x, p)
        h1, h2, nonce = 111, 222, 333
        r, s1 = S.dsa_sign(p, q, g, x, h1, nonce)
        _, s2 = S.dsa_sign(p, q, g, x, h2, nonce)
        self.assertTrue(S.dsa_nonce_reuse(p, q, g, y, r, s1, s2, h1, h2)["meta"]["verified"])
        self.assertFalse(S.dsa_nonce_reuse(p, q, g, None, r, s1, s2, h1, h2)["meta"]["verified"])


class TestRSAOpsAuditRegressions(unittest.TestCase):

    def test_broadcast_pairs_are_n_c(self):
        """H2: the docstring said (n_i, c_i) while the code unpacked (c_i, n_i)"""
        e = 3
        moduli = []
        for i in range(e):
            p = A.next_prime(2 ** 30 + 1000 * i)
            moduli.append(p * A.next_prime(p + 5000 * (i + 1)))
        m = 0x2b3c4d
        cs = [pow(m, e, n) for n in moduli]
        res = R.broadcast_attack(e, list(zip(moduli, cs)))
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["plaintext"], R.itob(m))
        # the analysis layer and the hypothesis engine feed the same order
        doc = inspect.getdoc(R.broadcast_attack) or ""
        self.assertIn("(n_i, c_i)", doc)

    def test_module_example_uses_the_real_signature(self):
        """H3: the module docstring showed decrypt(d, n, c) - the signature is (c, d, n)"""
        doc = R.__doc__ or ""
        self.assertIn("R.decrypt(c, k['d'], k['n'])", doc)
        key = R.keygen(256)
        msg = b"attack at dawn"
        c = R.encrypt(msg, key["e"], key["n"])
        self.assertEqual(R.decrypt(c, key["d"], key["n"]), R.btoi(msg))

    def test_crt_decrypt_returns_none_not_zero(self):
        """M2: a failed CRT decrypt used to return 0, which looks like plaintext 0"""
        self.assertIsNone(R.crt_decrypt(1000036000099, 2, 12345, 1000003, 1000033))
        self.assertIsNone(R.crt_decrypt(1000036000099, 65537, 12345, 1000003, 7))
        key = R.keygen(256)
        c = R.encrypt(b"ok", key["e"], key["n"])
        out = R.crt_decrypt(key["n"], key["e"], c, key["p"], key["q"])
        self.assertEqual(R.itob(out), b"ok")


class TestNumberTheoryAuditRegressions(unittest.TestCase):

    def test_poly_resultant_is_antisymmetric(self):
        """H6: the degree swap dropped (-1)^(m*n), breaking antisymmetry over GF(p)"""
        for (f, g, p) in (([3, 1], [1, 0, 2, 1], 7), ([1, 2], [1, 0, 1, 1], 11)):
            m, n = len(f) - 1, len(g) - 1
            a = polytools.poly_resultant(f, g, p)
            b = polytools.poly_resultant(g, f, p)
            self.assertIsNotNone(a)
            self.assertEqual(b % p, ((-1) ** (m * n) * a) % p,
                             f"antisymmetry violated for {f}, {g} mod {p}")

    def test_poly_resultant_matches_its_integer_path(self):
        f, g, p = [3, 1], [1, 0, 2, 1], 7
        self.assertEqual(polytools.poly_resultant(f, g, p),
                         polytools.poly_resultant(f, g) % p)

    def test_is_smooth_is_a_bool(self):
        """M1: dlp.is_smooth returned a tuple, so `if is_smooth(...)` was always true"""
        semiprime = 1000000007 * 1000000009
        self.assertIs(dlp.is_smooth(semiprime, 1000), False)
        self.assertIsInstance(dlp.is_smooth(2 ** 10 * 3 ** 5, 100), bool)
        smooth, factors = dlp.smooth_with_factors(semiprime, 1000)
        self.assertFalse(smooth)
        self.assertIsInstance(factors, dict)
        # the exported name is the boolean one from modular, not the tuple
        self.assertIs(ck.is_smooth, modular.is_smooth)

    def test_kronecker_agrees_with_jacobi_for_positive_odd_n(self):
        """The extra sign(a) factor belonged to n < 0 only"""
        for a in range(-25, 26):
            for n in (1, 3, 5, 9, 15, 21):
                self.assertEqual(modular.kronecker_symbol(a, n),
                                 modular.jacobi_symbol(a, n),
                                 f"kronecker({a}/{n}) != jacobi")
        self.assertEqual(modular.kronecker_symbol(-1, 1), 1)      # (a/1) = 1
        self.assertEqual(modular.kronecker_symbol(3, -1), 1)      # (a/-1) = sign(a)
        self.assertEqual(modular.kronecker_symbol(-3, -1), -1)
        self.assertEqual(modular.kronecker_symbol(1, 0), 1)
        self.assertEqual(modular.kronecker_symbol(2, 0), 0)


class TestForensicsAuditRegressions(unittest.TestCase):

    def test_duplicate_modulus_is_not_a_shared_prime(self):
        """M4: gcd(n, n) = n was reported as a shared factor (q = n // n = 1)"""
        p = A.next_prime(2 ** 80)
        n = p * A.next_prime(p + 1000)
        res = F.batch_gcd([n, n])
        self.assertEqual(res["pairs"], [])
        self.assertEqual(res["groups"], {})
        self.assertEqual(list(res["duplicates"]), [n])
        self.assertTrue(res["rejected"])
        self.assertIn("duplicate", res["rejected"][0]["reason"])

    def test_mt19937_minimum_length_is_still_weak(self):
        """M3: the textbook 624-word clone reported weak_prng=False"""
        import random
        rnd = random.Random(9)
        words = [rnd.getrandbits(32) for _ in range(624)]
        out = F.detect_weak_prng(words)
        self.assertEqual(out["family"], "mt19937")
        self.assertTrue(out["weak_prng"])

    def test_known_high_bits_without_known_bits_returns_the_dict(self):
        """M6: p_high = 0 raised ZeroDivisionError despite the documented contract"""
        p = A.next_prime(2 ** 80)
        n = p * A.next_prime(p + 1000)
        out = L.known_high_bits_factor(n, 0, 20)
        self.assertEqual(set(out), {"p", "q", "root", "note"})
        self.assertIsNone(out["p"])
        self.assertTrue(out["note"])


class TestDocumentationAuditRegressions(unittest.TestCase):

    def test_cbc_flip_documents_its_tuple(self):
        """M5: the 2-tuple return was invisible in help()"""
        doc = inspect.getdoc(symtools.cbc_flip_plaintext) or ""
        self.assertIn("(new_iv, new_ct)", doc)

    def test_stale_claims_are_gone(self):
        self.assertIn("ZeroDivisionError", inspect.getdoc(A.modinv) or "")
        self.assertIn("100 consecutive", inspect.getdoc(ck.glibc_rand_recover) or "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
