"""Regressions for the user-feedback round of 2026-10-03 (second batch).

Four requests came in from real use: `approx_gcd`'s misleading name, `analyze` running
classical-cipher scoring on Python source, a missing structured-gcd scan, and a
small-denominator rational-approximation follow-up for the shared-private-exponent case.
"""

import inspect
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import cryptoexp as ck
from cryptoexp.core.analysis import analyze_all
from cryptoexp.core.context import looks_like_source
from cryptoexp.utils import algebra as A
from cryptoexp.utils import forensics as F
from cryptoexp.utils import lattice as L
from cryptoexp.utils import rsa_ops as R


class TestApproxGcdNaming(unittest.TestCase):

    def test_scope_is_stated_in_the_first_line(self):
        doc = inspect.getdoc(L.lcg_approx_gcd) or ""
        self.assertIn("sequence", doc.split("\n")[0].lower())
        self.assertIn("common_factor_pairs", doc)      # points at the two-moduli tool

    def test_alias_and_behaviour(self):
        self.assertIs(L.approx_gcd([12, 18, 30]), L.lcg_approx_gcd([12, 18, 30]))
        self.assertEqual(L.lcg_approx_gcd([12, 18, 30]), 6)
        self.assertIsNone(L.lcg_approx_gcd([7, 11, 13]))


class TestSourceCodeIsNotCiphertext(unittest.TestCase):

    CODE = ("import gmpy2\n"
            "from Crypto.Util.number import *\n"
            "\n"
            "def solve(n, e, c):\n"
            "    return pow(c, 65537, n)\n"
            "\n"
            "if __name__ == '__main__':\n"
            "    print(solve(1, 2, 3))\n")

    def test_recognized(self):
        self.assertTrue(looks_like_source(self.CODE))
        self.assertTrue(analyze_all(self.CODE)["_ctx"]["source_like"])

    def test_a_challenge_is_not_mistaken_for_code(self):
        text = open(os.path.join(ROOT, "challenges", "rsa_wiener.txt"),
                    encoding="utf-8").read()
        self.assertFalse(looks_like_source(text))
        self.assertFalse(analyze_all(text)["_ctx"]["source_like"])

    def test_no_classical_candidates_from_a_script(self):
        """`import gmpy2` used to be scored as a caesar shift=6 candidate"""
        result = analyze_all(self.CODE)
        self.assertEqual(result["classical"]["candidates"], [])
        self.assertIn("source code", result["classical"].get("note", "").lower())

    def test_a_py_file_target(self):
        result = analyze_all(os.path.join(ROOT, "cryptoexp_cli.py"))
        self.assertEqual(result["classical"]["candidates"], [])
        notes = [b.get("note", "") for b in result["encoding"]["blobs"]]
        self.assertTrue(any("source-code" in n for n in notes),
                        f"blobs were analysed as ciphertext: {notes[:3]}")


class TestStructuredGcdScan(unittest.TestCase):

    def _distinct_primes(self, count, start=80):
        primes, seen = [], set()
        for i in range(count):
            p = A.next_prime(2 ** (start + i) + 13 * i)
            while p in seen:
                p = A.next_prime(p + 2)
            seen.add(p)
            primes.append(p)
        self.assertEqual(len(set(primes)), count)
        return primes

    def test_shared_prime_is_reported_and_usable(self):
        p, q1, q2 = self._distinct_primes(3)
        n1, n2 = p * q1, p * q2
        out = F.scan_structured_gcd([n1, n2], offsets=(0,))
        found = [x for x in out["pairs"] if x["kind"] == "shared_factor"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["factor"], p)
        self.assertEqual(found[0]["p_i"] * found[0]["q_i"], n1)
        self.assertEqual(found[0]["p_j"] * found[0]["q_j"], n2)

    def test_offset_structure_is_a_lead_not_a_factorisation(self):
        r0, s1, s2 = self._distinct_primes(3, start=70)
        m1, m2 = r0 * s1 + 1, r0 * s2 + 1
        out = F.scan_structured_gcd([m1, m2], offsets=(-1, 1))
        hits = [x for x in out["pairs"] if x["kind"] == "structured"]
        self.assertTrue(hits)
        self.assertEqual(hits[0]["factor"], r0)
        self.assertNotIn("p_i", hits[0])          # never claims to factor the modulus

    def test_duplicates_and_unrelated_moduli_produce_nothing(self):
        p, q1, q2, r1, r2 = self._distinct_primes(5)
        n1, n2 = p * q1, p * q2
        self.assertEqual(F.scan_structured_gcd([n1, n1])["pairs"], [])
        unrelated = F.scan_structured_gcd([r1 * q1, r2 * q2])
        self.assertEqual(unrelated["pairs"], [])
        self.assertGreaterEqual(unrelated["trivial"], 0)

    def test_small_gcd_noise_is_counted_not_reported(self):
        p, q1, q2 = self._distinct_primes(3)
        out = F.scan_structured_gcd([p * q1 + 1, p * q2 + 3], offsets=(1, -1),
                                    min_factor_bits=64)
        self.assertTrue(all(x["factor"].bit_length() >= 64 for x in out["pairs"]))


class TestCommonPrivateExponent(unittest.TestCase):

    def _shared_d_case(self, d_bits, count=3, seed=3):
        rng = random.Random(seed)
        d = A.next_prime(2 ** d_bits)                  # odd on purpose
        items = []
        for _ in range(count):
            for _attempt in range(4000):
                p = A.next_prime(rng.getrandbits(256) | (1 << 255))
                q = A.next_prime(rng.getrandbits(256) | (1 << 255))
                phi = (p - 1) * (q - 1)
                if p != q and A.gcd(d, phi) == 1:
                    items.append((A.modinv(d, phi), p * q, p, q))
                    break
        self.assertEqual(len(items), count)
        return d, items

    def test_recovers_a_shared_d_and_verifies_it(self):
        d, items = self._shared_d_case(100)
        res = R.common_private_exponent_attack([(e, n) for e, n, _p, _q in items])
        self.assertTrue(res["ok"], res.get("note"))
        self.assertEqual(res["d"], d)
        for idx, (p, q) in enumerate(res["factors"]):
            e_i, n_i = items[idx][0], items[idx][1]
            self.assertEqual(p * q, n_i)
            self.assertEqual(e_i * d % ((p - 1) * (q - 1)), 1)

    def test_honest_failure_above_the_measured_range(self):
        """Measured: this convergent-only version dies where Wiener dies (d ~ 2^130)"""
        d, items = self._shared_d_case(170)
        res = R.common_private_exponent_attack([(e, n) for e, n, _p, _q in items])
        self.assertFalse(res["ok"])
        self.assertIsNone(res["d"])
        self.assertIn("no shared d", res["note"])

    def test_single_modulus_is_rejected_with_a_pointer(self):
        d, items = self._shared_d_case(100, count=1)
        res = R.common_private_exponent_attack([(items[0][0], items[0][1])])
        self.assertFalse(res["ok"])
        self.assertIn("wiener_attack", res["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
