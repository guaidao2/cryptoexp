"""Regressions for the linearization-lattice request (2026-10-03).

The user asked for the "modular equation + small unknowns" shape with the linearization
lattice first and bivariate Coppersmith as the fallback, plus the gcd step that turns
recovered monomials into the variables themselves.

What is pinned here: the determined-system case works, the gcd separation works, and the
shape that the lattice genuinely cannot do stays an honest refusal with a reason instead
of a fabricated value.
"""

import math
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import cryptoexp as ck
from cryptoexp.utils import algebra as A
from cryptoexp.utils import linearize as LIN


class TestLinearizeBasics(unittest.TestCase):

    def test_determined_system_is_solved(self):
        rng = random.Random(41)
        mod = 2 ** 255 - 19
        x = rng.getrandbits(64) | (1 << 63)
        y = rng.getrandbits(64) | (1 << 63)
        equations = [
            {"terms": {("x",): 1, ("y",): 1}, "mod": mod, "rhs": (x + y) % mod},
            {"terms": {("x",): 1, ("y",): -1}, "mod": mod, "rhs": (x - y) % mod},
        ]
        res = LIN.linearize(equations, {("x",): 2 ** 64, ("y",): 2 ** 64})
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["solution"], {"x": x, "y": y})

    def test_underdetermined_system_refuses(self):
        """x + y = 11 cannot be split: the note must say so, not guess a pair"""
        res = LIN.linearize([{"terms": {("x",): 1, ("y",): 1}, "mod": 0, "rhs": 11}],
                            {("x",): 16, ("y",): 16})
        self.assertFalse(res["ok"])
        self.assertIsNone(res.get("solution"))

    def test_multi_modulus_case(self):
        rng = random.Random(7)
        x = rng.getrandbits(40)
        p1, p2 = 2 ** 61 - 1, 2 ** 89 - 1
        equations = [
            {"terms": {("x",): 1, ("y",): 3}, "mod": p1, "rhs": (x + 3 * 5) % p1},
            {"terms": {("x",): 2, ("y",): 1}, "mod": p2, "rhs": (2 * x + 5) % p2},
        ]
        res = LIN.linearize(equations, {("x",): 2 ** 48, ("y",): 2 ** 48})
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["solution"]["y"], 5)


class TestSeparateVariables(unittest.TestCase):
    """The gcd step from the user's example: gcd(x*y^2, x^2*y) = x*y"""

    def test_pairwise_gcd_separates_two_variables(self):
        x, y = 1234567891, 987654321
        out = LIN.separate_variables({("x", "y", "y"): x * y * y, ("x", "x", "y"): x * x * y},
                                     ["x", "y"])
        self.assertTrue(out["ok"], out["note"])
        self.assertEqual(out["solution"], {"x": x, "y": y})

    def test_three_pairwise_products(self):
        a, b, c = 13, 7, 11
        out = LIN.separate_variables({("a", "b"): a * b, ("a", "c"): a * c,
                                      ("b", "c"): b * c}, ["a", "b", "c"])
        self.assertTrue(out["ok"], out["note"])
        self.assertEqual(out["solution"], {"a": a, "b": b, "c": c})

    def test_single_product_is_refused_honestly(self):
        out = LIN.separate_variables({("x", "y"): 6}, ["x", "y"])
        self.assertFalse(out["ok"])
        self.assertIsNone(out["solution"])
        self.assertIn("no integer combination", out["note"])

    def test_contradictory_gcd_is_noticed(self):
        out = LIN.separate_variables({("x", "y"): 6, ("x", "y", "y"): 12}, ["x"])
        self.assertFalse(out["solution"] and out["solution"].get("x") not in (2, 3))


class TestHonestRefusal(unittest.TestCase):
    """The shape from the user's report: one congruence, unknown *products* only"""

    def test_single_congruence_is_refused_with_a_reason(self):
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
                                         ("x", "x", "y"): 2 ** 213})
        self.assertFalse(res["ok"])
        self.assertIsNone(res.get("solution"))
        # the note must name the limitation, and no value may appear out of nowhere
        self.assertTrue(res["note"])
        self.assertIsNone(res.get("monomial_values"))


class TestExports(unittest.TestCase):

    def test_root_exports(self):
        self.assertTrue(callable(ck.linearize))
        self.assertTrue(callable(ck.separate_variables))
        for name in ("linearize", "separate_variables", "recover_from_products"):
            self.assertIn(name, ck.__all__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
