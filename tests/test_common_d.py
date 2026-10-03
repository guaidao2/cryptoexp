"""Tests for the shared-private-exponent attacks (common_d, 2026-10-03).

Two stages: the convergent one (already in `rsa_ops`) and the SDAP lattice added here.
The measured boundary matters more than the happy path, so the honest limits are pinned
too: the lattice adds nothing for two moduli, and a non-shared d must stay a refusal.
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
from cryptoexp.utils import common_d, rsa_ops as R


def shared_d_case(d_bits, count, seed=5, n_bits=512):
    """`count` moduli that all use the same odd d with gcd(d, phi_i) == 1

    512-bit moduli on purpose: the measured working cells are stated for that size
    (m=3 up to roughly 2^128 bits of d, m=4 up to roughly 2^150), and a 256-bit modulus
    with the same d behaves differently - the boundary moves with the modulus size too.
    """
    rng = random.Random(seed)
    d = A.next_prime(2 ** d_bits)
    items = []
    for _ in range(count):
        for _attempt in range(5000):
            p = A.next_prime(rng.getrandbits(n_bits // 2) | (1 << (n_bits // 2 - 1)))
            q = A.next_prime(rng.getrandbits(n_bits // 2) | (1 << (n_bits // 2 - 1)))
            phi = (p - 1) * (q - 1)
            if p != q and A.gcd(d, phi) == 1:
                items.append((A.modinv(d, phi), p * q, p, q))
                break
    assert len(items) == count
    return d, items


class TestDispatch(unittest.TestCase):

    def test_dispatcher_solves_a_shared_d(self):
        d, items = shared_d_case(80, 3)
        res = common_d.common_d_attack([(e, n) for e, n, _p, _q in items])
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["d"], d)
        for idx, (p, q) in enumerate(res["factors"]):
            e_i, n_i = items[idx][0], items[idx][1]
            self.assertEqual(p * q, n_i)
            self.assertEqual(e_i * d % ((p - 1) * (q - 1)), 1)

    def test_identical_d_per_modulus_is_not_assumed(self):
        """A modulus keyed with a different d must not be forced into the answer"""
        d, items = shared_d_case(80, 3)
        p, q = items[2][2], items[2][3]
        other = A.next_prime(2 ** 80 + 7919)
        while A.gcd(other, (p - 1) * (q - 1)) != 1:
            other = A.next_prime(other + 2)
        pairs = [(items[0][0], items[0][1]), (items[1][0], items[1][1]),
                 (A.modinv(other, (p - 1) * (q - 1)), p * q)]
        res = common_d.common_d_attack(pairs)
        self.assertFalse(res["ok"])
        self.assertIsNone(res["d"])

    def test_two_moduli_are_handled_by_the_convergent_stage(self):
        """Measured: the lattice adds nothing for m=2 - the cheap stage must carry it"""
        d, items = shared_d_case(80, 2)
        res = common_d.common_d_attack([(e, n) for e, n, _p, _q in items])
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["d"], d)

    def test_lattice_stage_reports_its_limit_on_two_moduli(self):
        d, items = shared_d_case(80, 2)
        res = common_d.common_d_lattice([(e, n) for e, n, _p, _q in items])
        if not res["ok"]:
            self.assertIsNone(res["d"])
            self.assertIn("moduli", res["note"].lower())

    def test_acceptance_never_returns_unverified_factors(self):
        d, items = shared_d_case(80, 3)
        res = common_d.common_d_attack([(e, n) for e, n, _p, _q in items])
        if res["ok"]:
            self.assertIsNotNone(res["factors"])
            for idx, (p, q) in enumerate(res["factors"]):
                self.assertEqual(p * q, items[idx][1])
                self.assertEqual(items[idx][0] * res["d"] % ((p - 1) * (q - 1)), 1)


class TestExports(unittest.TestCase):

    def test_root_exports(self):
        self.assertTrue(callable(ck.common_d_attack))
        self.assertTrue(callable(ck.common_d_lattice))
        self.assertIn("common_d_attack", ck.__all__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
