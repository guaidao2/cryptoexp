"""Tests for the bivariate polynomial layer and bivariate Coppersmith (2026-10-03).

The two things worth pinning here are the mechanical layer (multiplying bivariate
polynomials and taking a bivariate resultant is what users hand-write and get wrong) and
the convention of `known_high_bits_two_primes`: it takes the *unshifted* high part of each
prime and applies `2^shift` itself. Passing an already-shifted value is the mistake the
first external review made, and it fails without saying why - so the convention is
asserted rather than described.
"""

import os
import random
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import cryptoexp as ck
from cryptoexp.utils import algebra as A
from cryptoexp.utils import bivariate as B
from cryptoexp.utils import polytools as PT


def horner(coeffs, x):
    acc = 0
    for c in reversed(coeffs or []):
        acc = acc * x + c
    return acc


class TestPolynomialLayer(unittest.TestCase):

    def test_multiplication_is_coefficient_exact(self):
        f = B.poly2_from_terms([(1, 1, 0), (1, 0, 1)])          # x + y
        self.assertEqual(B.poly2_mul(f, f), {(2, 0): 1, (1, 1): 2, (0, 2): 1})

    def test_multiplication_agrees_with_evaluation(self):
        f = B.poly2_from_terms([(1, 1, 0), (1, 0, 1)])
        g = B.poly2_from_terms([(3, 2, 1), (-1, 0, 0), (5, 1, 3)])
        product = B.poly2_mul(f, g)
        rng = random.Random(3)
        for _ in range(20):
            a, b = rng.randint(-9, 9), rng.randint(-9, 9)
            self.assertEqual(B.poly2_eval(f, a, b) * B.poly2_eval(g, a, b),
                             B.poly2_eval(product, a, b))

    def test_resultant_matches_the_univariate_implementation(self):
        """Independent route: specialise x and compare with polytools.poly_resultant

        Only away from x where a leading y-coefficient vanishes: at such a degenerate
        point the two quantities genuinely differ (measured: g = 3xy + 1 loses its
        y-degree at x = 0), which is a property of resultants, not a defect.
        """
        cases = [(B.poly2_from_terms([(1, 1, 0), (1, 0, 1)]),
                  B.poly2_from_terms([(1, 2, 0), (1, 1, 1), (-3, 0, 0)])),
                 (B.poly2_from_terms([(1, 2, 0), (-2, 0, 2), (7, 0, 0)]),
                  B.poly2_from_terms([(3, 1, 1), (1, 0, 0)]))]
        for f, g in cases:
            res_y = B.poly2_resultant(f, g, "y")
            for x in (1, 2, 3, -2):
                specialised = []
                for poly in (f, g):
                    coeffs = [0] * 4
                    for (i, j), c in poly.items():
                        if j < 4:
                            coeffs[j] += c * x ** i
                    specialised.append(coeffs)
                self.assertEqual(horner(res_y, x),
                                 PT.poly_resultant(specialised[0], specialised[1]),
                                 f"resultant mismatch at x={x}")


class TestBivariateCoppersmith(unittest.TestCase):

    def test_direct_call_recovers_the_small_roots(self):
        half, shift = 32, 6
        p = A.next_prime(random.Random(1).getrandbits(half) | (1 << (half - 1)))
        q = A.next_prime(random.Random(101).getrandbits(half) | (1 << (half - 1)))
        n = p * q
        ph, qh = p >> shift, q >> shift
        f = B.poly2_from_terms([(1, 1, 1), (qh << shift, 1, 0), (ph << shift, 0, 1),
                                (((ph * qh) << (2 * shift)) - n, 0, 0)])
        res = B.coppersmith_bivariate(f, n, 1 << shift, 1 << shift, m=2, t=1,
                                      time_budget=60.0)
        self.assertTrue(res["ok"], res["note"])
        self.assertTrue(any((ph << shift) + x == p and (qh << shift) + y == q
                            for x, y in res["roots"]), res["roots"])

    def test_wrapper_takes_unshifted_high_bits(self):
        half, known = 32, 26
        shift = half - known
        p = A.next_prime(random.Random(2).getrandbits(half) | (1 << (half - 1)))
        q = A.next_prime(random.Random(102).getrandbits(half) | (1 << (half - 1)))
        n = p * q
        res = B.known_high_bits_two_primes(n, p >> shift, q >> shift, known,
                                           total_bits=2 * half)
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["p"] * res["q"], n)
        self.assertEqual({res["p"], res["q"]}, {p, q})

    def test_out_of_range_window_fails_honestly(self):
        """Measured range is a few bits per prime; a wide window must not fabricate"""
        p = A.next_prime(random.Random(5).getrandbits(32) | (1 << 31))
        q = A.next_prime(random.Random(6).getrandbits(32) | (1 << 31))
        n = p * q
        res = B.known_high_bits_two_primes(n, p >> 16, q >> 16, 16, total_bits=64)
        self.assertFalse(res["ok"])
        self.assertIsNone(res["p"])
        self.assertTrue(res["note"])


class TestExports(unittest.TestCase):

    def test_root_exports(self):
        for name in ("coppersmith_bivariate", "known_high_bits_two_primes",
                     "poly2_mul", "poly2_resultant"):
            self.assertTrue(callable(getattr(ck, name)), name)
            self.assertIn(name, ck.__all__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
