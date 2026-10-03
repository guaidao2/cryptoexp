"""Tests for the ADFGX / ADFGVX ciphers (added on user request, 2026-10-03).

The hand-checkable vector is the important one: it is what proves the square, the label
order and the transposition are the textbook ones rather than something self-consistent.
"""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import cryptoexp as ck
from cryptoexp.utils import adfgvx

PT = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDTHEDOGISNOTAMUSED"


class TestCorrectness(unittest.TestCase):

    def test_hand_checkable_adfgx_vector(self):
        """square keyword ZEBRA, key KEY: ATTACK -> XGXFAXAAGXDD (worked out by hand)"""
        square, labels = adfgvx.adfgx_square("ZEBRA")
        self.assertEqual(labels, ("A", "D", "F", "G", "X"))
        self.assertEqual(square[0], "ZEBRA")
        self.assertEqual(adfgvx.adfgx_encrypt("ATTACK", key="KEY", square=square),
                         "XGXFAXAAGXDD")
        self.assertEqual(adfgvx.adfgx_decrypt("XGXFAXAAGXDD", key="KEY", square=square),
                         "ATTACK")

    def test_unkeyed_squares_follow_the_documented_layout(self):
        square, labels = adfgvx.adfgx_square()
        self.assertEqual(labels, ("A", "D", "F", "G", "X"))
        self.assertEqual(adfgvx.adfgx_encrypt("A", square=square), "AA")
        self.assertEqual(adfgvx.adfgx_encrypt("B", square=square), "AD")
        square6, labels6 = adfgvx.adfgvx_square()
        self.assertEqual(labels6, ("A", "D", "F", "G", "V", "X"))
        self.assertEqual(len(square6), 6)
        self.assertTrue(all(len(row) == 6 for row in square6))

    def test_round_trips(self):
        self.assertEqual(adfgvx.adfgx_decrypt(adfgvx.adfgx_encrypt(PT, key="SECRET"),
                                              key="SECRET"),
                         PT.replace("J", "I"))
        self.assertEqual(adfgvx.adfgvx_decrypt(adfgvx.adfgvx_encrypt(PT, key="SECRET"),
                                                key="SECRET"), PT)

    def test_ragged_grid_round_trip(self):
        """The grid is unpadded, so a short plaintext must still come back exactly"""
        for text in ("A", "ATTAC", "ATTACKX"):
            cipher = adfgvx.adfgx_encrypt(text, key="KEY")
            self.assertEqual(adfgvx.adfgx_decrypt(cipher, key="KEY"), text,
                             f"ragged round trip failed for {text!r}")

    def test_digit_substitution(self):
        square, _ = adfgvx.adfgvx_square()
        cipher = adfgvx.adfgvx_encrypt("HELLO42", key="KEY", square=square,
                                       digit_substitution="ZXCVBNMAQP")
        self.assertEqual(adfgvx.adfgvx_decrypt(cipher, key="KEY", square=square,
                                               digit_substitution="ZXCVBNMAQP"),
                         "HELLO42")
        with self.assertRaises(ValueError):
            adfgvx.adfgvx_encrypt("HELLO", key="KEY", digit_substitution="SECRET")
        with self.assertRaises(ValueError):
            adfgvx.adfgx_encrypt("HELLO1", key="KEY")      # no cell for a digit


class TestDetection(unittest.TestCase):

    def test_ciphertexts_are_recognized(self):
        self.assertEqual(adfgvx.adfgvx_detect(adfgvx.adfgx_encrypt(PT, key="K"))["variant"],
                         "adfgx")
        self.assertEqual(adfgvx.adfgvx_detect(adfgvx.adfgvx_encrypt(PT, key="K"))["variant"],
                         "adfgvx")

    def test_plain_text_and_junk_are_not(self):
        for text in (PT, "cryptoexp is a crypto toolkit", "Zm9vYmFyMTIz",
                     "ADFGVXADFGVXADFGV", "no labels here"):
            self.assertFalse(adfgvx.adfgvx_detect(text)["is_adfgvx"], text[:24])

    def test_odd_length_adfgvx_stream_is_rejected(self):
        detection = adfgvx.adfgvx_detect("ADFGVXADFGVXADFGV")
        self.assertFalse(detection["is_adfgvx"])

    def test_detect_is_reachable_from_the_package_root(self):
        self.assertTrue(ck.adfgvx_detect("ADFGXADFGX")["is_adfgvx"])
        # and `analyze` surfaces the detection as a note rather than silently ignoring it
        result = ck.analyze_all(adfgvx.adfgx_encrypt(PT, key="SECRET"))
        self.assertIsNotNone(result["classical"]["adfgvx"])
        self.assertTrue(any("ADFGX ciphertext detected" in n
                            for n in result["classical"]["notes"]))


class TestCrack(unittest.TestCase):

    def test_known_square_is_solved(self):
        square, _ = adfgvx.adfgvx_square("ZEBRA")
        cipher = adfgvx.adfgvx_encrypt(PT, key="FALCON", square=square)
        res = adfgvx.adfgvx_crack(cipher, square=square, effort="quick")
        self.assertTrue(res["ok"], res["note"])
        self.assertEqual(res["key"], "CADBFE")         # canonical order, not FALCON
        self.assertEqual(res["plaintext"], PT)
        # verification is by re-encryption, which is the only check available here
        self.assertEqual(adfgvx.adfgvx_encrypt(res["plaintext"], key=res["key"],
                                               square=res["square"]), cipher)

    def test_unknown_square_refuses_instead_of_fabricating(self):
        square, _ = adfgvx.adfgvx_square("XYLOPHONE")
        cipher = adfgvx.adfgvx_encrypt(PT, key="RAVEN", square=square)
        res = adfgvx.adfgvx_crack(cipher, effort="quick", time_budget=8)
        self.assertFalse(res["ok"])
        self.assertIsNone(res["plaintext"])
        self.assertIn("square", res["note"])

    def test_non_adfgvx_input_fails_honestly(self):
        res = adfgvx.adfgvx_crack("just some english text", effort="quick")
        self.assertFalse(res["ok"])
        self.assertIsNone(res["plaintext"])

    def test_search_objective_carries_no_flag_bonus(self):
        """House rule: a flag bonus lets hill climbing invent flags"""
        source = open(os.path.join(ROOT, "src", "cryptoexp", "utils", "adfgvx.py"),
                      encoding="utf-8").read()
        calls = [line for line in source.splitlines() if "score_text(" in line
                 and "import" not in line and "`" not in line]
        self.assertTrue(calls)
        for line in calls:
            self.assertIn("flag_bonus=False", line, line.strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
