"""Regressions for the reported defects of 2026-10-04, part 2 of 2.

Two real reports are pinned here:
  * `linearize(..., effort="normal")` sat on the LLL step guard for 104 s and returned
    None, while `effort="light"` solved the same shape in 1.4 s. The effort ladder now
    runs cheapest first and the note names the level that answered.
  * `common_modulus_attack` refused `gcd(e1,e2)=2` with "needs factorisation first",
    although Bezout still gives m^g mod n and the exact g-th root is the message when
    m^g < n.
"""

import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from cryptoexp.utils import algebra as A
from cryptoexp.utils import linearize as LIN
from cryptoexp.utils import rsa_ops as R

FLAG = b"flag{common_modulus_gcd_two}"


def _modulus(bits_p, bits_q):
    return A.next_prime(1 << (bits_p - 1)) * A.next_prime(1 << (bits_q - 1))


class TestCommonModulusNonCoprimeExponents(unittest.TestCase):
    """gcd(e1, e2) = 2 with m^2 < n is solvable, not a dead end"""

    def test_gcd_two_small_message_is_solved(self):
        n = _modulus(512, 512)
        m = int.from_bytes(FLAG, "big")
        self.assertLess(m * m, n, "the fixture must keep m^2 below n")
        e1, e2 = 4, 6
        res = R.common_modulus_attack(n, e1, pow(m, e1, n), e2, pow(m, e2, n))
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["plaintext"], FLAG)
        self.assertIn("gcd(e1,e2)=2", res["detail"])

    def test_gcd_two_large_message_says_why_it_cannot(self):
        # FLAG is 27 bytes, so a ~300-bit modulus keeps m < n while m^2 > n
        n = _modulus(150, 150)
        m = int.from_bytes(FLAG, "big")
        self.assertLess(m, n)
        self.assertGreater(m * m, n)
        e1, e2 = 4, 6
        res = R.common_modulus_attack(n, e1, pow(m, e1, n), e2, pow(m, e2, n))
        self.assertFalse(res["ok"])
        self.assertIn("only m^g mod n is obtainable", res["note"])
        self.assertIn("the root is ambiguous", res["note"])

    def test_coprime_exponents_are_unchanged(self):
        n = _modulus(512, 512)
        m = int.from_bytes(FLAG, "big")
        e1, e2 = 65537, 17
        self.assertEqual(A.egcd(e1, e2)[0], 1)
        res = R.common_modulus_attack(n, e1, pow(m, e1, n), e2, pow(m, e2, n))
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["plaintext"], FLAG)
        self.assertEqual(res["detail"], "common modulus attack")


class TestLinearizeEffortLadder(unittest.TestCase):
    """Cheapest effort first; the note records which level answered"""

    def _system(self):
        rng = random.Random(41)
        mod = 2 ** 255 - 19
        x = rng.getrandbits(64) | (1 << 63)
        y = rng.getrandbits(64) | (1 << 63)
        eqs = [
            {"terms": {("x",): 1, ("y",): 1}, "mod": mod, "rhs": (x + y) % mod},
            {"terms": {("x",): 1, ("y",): -1}, "mod": mod, "rhs": (x - y) % mod},
        ]
        return eqs, {("x",): 2 ** 64, ("y",): 2 ** 64}, x, y

    def test_reports_the_effort_that_answered(self):
        eqs, bounds, x, y = self._system()
        res = LIN.linearize(eqs, bounds, effort="normal")
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["solution"], {"x": x, "y": y})
        self.assertIn(res["effort"], ("light", "normal"))
        # `effort` is a ceiling: when the cheap rung answers, the note says so
        if res["effort"] != "normal":
            self.assertIn("solved at effort='%s'" % res["effort"], res["note"])

    def test_the_light_rung_answers_this_shape(self):
        """The cheap rung must be reachable on its own - that is the 104 s fix"""
        eqs, bounds, x, y = self._system()
        self.assertTrue(LIN.linearize(eqs, bounds, effort="light")["ok"])

    def test_a_full_failure_names_every_attempt(self):
        rng = random.Random(2026)
        x = rng.getrandbits(71) | (1 << 70)
        y = rng.getrandbits(71) | (1 << 70)
        p = A.next_prime(2 ** 256)
        a = rng.getrandbits(200) | 1
        b = rng.getrandbits(200) | 1
        c = (a * x * y * y + b * x * x * y + 1) % p
        equation = {"terms": {("x", "y", "y"): a, ("x", "x", "y"): b},
                    "mod": p, "rhs": (c - 1) % p}
        res = LIN.linearize([equation], {("x", "y", "y"): 2 ** 213,
                                         ("x", "x", "y"): 2 ** 213}, effort="normal")
        self.assertFalse(res["ok"])
        self.assertIn("efforts tried (cheapest first)", res["note"])
        self.assertIn("effort='light'", res["note"])
        self.assertIn("effort='normal'", res["note"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
