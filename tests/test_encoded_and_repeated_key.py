"""Regressions for the reported defects of 2026-10-04, part 1 of 2.

Two real reports are pinned here:
  * `analyze` ran Caesar/affine scoring on strings it had already identified as encoded
    blobs, and the meaningless candidate it produced pushed "decode first" out of the
    recommended path.
  * a score alone produced `confidence="high"`: a repeated-key mod-256 addition challenge
    came back as "keysize=12, score=102.53, confidence='high'" with a garbage plaintext,
    while `analyze` on the same data said "no strong verification yet".
  * plus the new repeated-key `op` parameter (add/sub mod 256), which had no solver at
    all before.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from cryptoexp.core.analysis import analyze_all
from cryptoexp.utils import encoding as E
from cryptoexp.utils import pad as P

CH_DIR = os.path.join(ROOT, "challenges")
_CLASSICAL_ATTACKS = {"caesar", "affine", "vigenere", "fence"}


def _classical_attacks(blob):
    res = analyze_all(blob, effort="fast")
    attacks = {c.get("attack") for c in res["classical"]["candidates"]}
    routes = [s["type"] for s in res["strategy"]]
    return attacks, routes


class TestEncodedBlobsAreNotClassicalCiphertext(unittest.TestCase):
    """A base64/hex blob must be deferred to the encoding layer, not shift-scored"""

    def test_base64_blob_is_deferred(self):
        attacks, routes = _classical_attacks("bXNobntGMGJfTjBhXzGBfQ==")
        self.assertFalse(attacks & _CLASSICAL_ATTACKS, attacks)
        self.assertNotIn("classical cipher recovery", routes)

    def test_hex_blob_is_deferred(self):
        attacks, routes = _classical_attacks("abcdef0123456789abcdef")
        self.assertFalse(attacks & _CLASSICAL_ATTACKS, attacks)
        self.assertNotIn("classical cipher recovery", routes)

    def test_a_genuine_caesar_ciphertext_is_still_scored(self):
        res = analyze_all(os.path.join(CH_DIR, "classical_caesar.txt"), effort="fast")
        data = b" ".join(c["data"] for c in res["classical"]["candidates"])
        self.assertIn(b"flag{caesar_is_classic}", data, res["classical"]["candidates"])


class TestConfidenceNeedsAKnownFlagPrefix(unittest.TestCase):
    """A text score is a heuristic; only a known prefix match may say "high"."""

    def test_a_score_alone_never_reaches_high(self):
        self.assertEqual(E.confidence_of(120.0, False), "medium")
        self.assertEqual(E.confidence_of(200.0, False), "medium")
        self.assertEqual(E.confidence_of(10.0, False), "low")
        self.assertEqual(E.confidence_of(10.0, True), "high")

    def test_every_score_based_producer_obeys_it(self):
        flag = b"flag{repeating_key_xor_with_hamming_distance}"
        ct = P.xor_repeat(flag, b"KEY42")
        grouped = {
            "single_byte_xor": E.single_byte_xor(b"\x1f\x0b\x1f\x1f\x0b\x1f"),
            "caesar": E.caesar_candidates("wklv lv d vhfuhw phvvdjh"),
            "affine": E.affine_candidates("wklv lv d vhfuhw phvvdjh"),
            "fence": E.fence_candidates("wklv lv d vhfuhw phvvdjh"),
            "repeating_key": E.repeating_key(ct),
            "repeating_key_xor": E.repeating_key_xor(ct),
        }
        for name, cands in grouped.items():
            self.assertTrue(cands, name)
            for cand in cands:
                if not cand["flags"]:
                    self.assertNotEqual(cand["confidence"], "high", (name, cand))
                    self.assertTrue(cand.get("note"), (name, cand))
        self.assertEqual(grouped["repeating_key"][0]["confidence"], "high")

    def test_the_reason_uses_the_verification_wording(self):
        note = E.confidence_note(b"mshn{F0b_N0a_1}")
        self.assertEqual(note, "flag-like shape but prefix not in the known list")
        self.assertEqual(E.confidence_note(b"flag{real_one_here}"), "")


class TestRepeatedKeyOperations(unittest.TestCase):
    """`repeating_key(op=...)` covers xor, add and sub mod 256 with one pipeline"""

    PLAIN = (b"the quick brown fox jumps over the lazy dog and then reads the "
             b"secret message flag{add_mod_256_repeating_key} which was hidden")
    KEY = b"ADDKEY"

    def _cipher(self, op):
        if op == "add":
            return bytes((b + self.KEY[i % 6]) % 256 for i, b in enumerate(self.PLAIN))
        return bytes((b - self.KEY[i % 6]) % 256 for i, b in enumerate(self.PLAIN))

    def test_add_mod_256_is_solved(self):
        best = E.repeating_key(self._cipher("add"), op="add")[0]
        self.assertEqual(best["plaintext"], self.PLAIN)
        self.assertEqual(best["keysize"] % 6, 0)
        self.assertEqual(best["op"], "add")

    def test_sub_mod_256_is_solved(self):
        best = E.repeating_key(self._cipher("sub"), op="sub")[0]
        self.assertEqual(best["plaintext"], self.PLAIN)
        self.assertEqual(best["keysize"] % 6, 0)

    def test_xor_still_solved_and_wrapper_matches(self):
        flag = b"flag{repeating_key_xor_with_hamming_distance}"
        ct = P.xor_repeat(flag, b"KEY42")
        direct = E.repeating_key(ct, op="xor")
        wrapped = E.repeating_key_xor(ct)
        self.assertEqual(direct[0]["key"], b"KEY42")
        self.assertEqual(direct[0]["plaintext"], flag)
        self.assertEqual([c["key"] for c in wrapped], [c["key"] for c in direct])

    def test_single_byte_op_agrees_with_single_byte_xor(self):
        data = bytes(b ^ 0x42 for b in b"flag{single}")
        self.assertEqual(E.single_byte_op(data, "xor"), E.single_byte_xor(data))
        self.assertEqual(E.single_byte_xor(data)[0]["key"], 0x42)

    def test_unknown_op_is_rejected(self):
        with self.assertRaises(ValueError):
            E.repeating_key(b"x" * 32, op="mul")


if __name__ == "__main__":
    unittest.main(verbosity=2)
