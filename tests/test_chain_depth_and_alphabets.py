"""Reviewer follow-ups: configurable chain depth, hit_limit, custom alphabets.

Every case here is about an *opt-in*: the default path must stay exactly as it was,
so each feature is asserted twice, once off (unchanged behaviour) and once on.

Run: python -m unittest tests.test_chain_depth_and_alphabets -v
"""

import base64
import os
import random
import string
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))      # src layout, no install needed

from cryptoexp.core.analysis import analyze_all, DEFAULT_CHAIN_LAYERS   # noqa: E402
from cryptoexp.core.context import build_context                        # noqa: E402
from cryptoexp.core.report import json_summary                          # noqa: E402
from cryptoexp.core.verify import verify_candidates                     # noqa: E402
from cryptoexp.hypothesis import evaluate, params_from_ctx              # noqa: E402
from cryptoexp.lab import build_workbench                               # noqa: E402
from cryptoexp.utils import encoding as E                               # noqa: E402

STD = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
PT4 = b"the this reader hidden quick over for the and"
# Scratch lives under the repo's .tmp/ (never the system temp dir), and every
# helper below removes what it created.
SCRATCH = os.path.join(ROOT, ".tmp")


def write_scratch(text):
    """Drop a uniquely named sample file under .tmp/ and return its path"""
    os.makedirs(SCRATCH, exist_ok=True)
    fd, path = tempfile.mkstemp(suffix=".txt", dir=SCRATCH)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(text)
    return path


def four_layer_blob(pt=PT4):
    """plaintext -> base64 x4, i.e. a chain that needs four iterations"""
    data = pt
    for _ in range(4):
        data = base64.b64encode(data)
    return data.decode()


def shuffled_std(seed):
    rng = random.Random(seed)
    table = list(STD)
    rng.shuffle(table)
    return "".join(table)


def swap_encode(body, alphabet):
    """Standard-base64 body -> the same body written in `alphabet`"""
    return body.translate(str.maketrans(STD, alphabet))


class TestChainDepth(unittest.TestCase):
    """Item 1: the built-in chain depth is configurable, default stays 3"""

    def test_default_constant_is_three_and_reaches_every_call_site(self):
        self.assertEqual(3, DEFAULT_CHAIN_LAYERS)
        self.assertEqual(DEFAULT_CHAIN_LAYERS, E.DEFAULT_CHAIN_LAYERS)
        # Signature defaults, so "no new argument" really does mean 3 everywhere.
        import inspect
        for fn in (E.decode_chain, E.swapped_alphabet_analysis):
            self.assertEqual(DEFAULT_CHAIN_LAYERS,
                             inspect.signature(fn).parameters["max_layers"].default,
                             fn.__name__)
        from cryptoexp.core.analysis.encoding_scan import analyze_encoding
        self.assertEqual(DEFAULT_CHAIN_LAYERS,
                         inspect.signature(analyze_encoding)
                         .parameters["max_layers"].default)
        self.assertIsNone(inspect.signature(analyze_all).parameters["max_layers"].default)

    def test_four_layer_chain_truncated_by_default_solved_when_raised(self):
        blob = four_layer_blob()
        default = E.decode_chain(blob)
        raised = E.decode_chain(blob, max_layers=6)
        self.assertFalse(any(c["data"] == PT4 for c in default))
        self.assertTrue(any(c["data"] == PT4 for c in raised))
        # The default is still exactly three layers of work; asking for more
        # changes the answer, asking for nothing does not.
        self.assertEqual(["base64", "base64", "base64"], default[0]["steps"])
        self.assertEqual(["base64"] * 4, raised[0]["steps"])

    def test_analyze_all_default_untouched_but_max_layers_reaches_the_chain(self):
        blob = four_layer_blob()
        plain = analyze_all(blob, effort="fast")
        raised = analyze_all(blob, effort="fast", max_layers=6)
        self.assertEqual(3, plain["max_layers"])
        self.assertEqual(["base64", "base64", "base64"],
                         plain["encoding"]["blobs"][0]["chain"][0]["steps"])
        self.assertEqual(["base64"] * 4,
                         raised["encoding"]["blobs"][0]["chain"][0]["steps"])
        self.assertEqual(6, raised["max_layers"])

    def test_max_layers_must_be_positive(self):
        with self.assertRaises(ValueError):
            analyze_all("AAAA", effort="fast", max_layers=0)
        with self.assertRaises(ValueError):
            E.decode_chain("AAAA", max_layers=0)


class TestHitLimit(unittest.TestCase):
    """Item 2: a chain stopped by the cap says so in the data"""

    def test_truncated_chain_sets_hit_limit(self):
        top = E.decode_chain(four_layer_blob())[0]
        self.assertTrue(top["hit_limit"])
        self.assertEqual(3, len(top["steps"]))

    def test_completed_chain_does_not_set_hit_limit(self):
        # A finished chain, even when it consumes the whole budget, is not truncated.
        for blob, cap in (("666c61677b6865787d", 3),          # hex -> flag{hex}
                          (four_layer_blob(), 6)):
            top = E.decode_chain(blob, max_layers=cap)[0]
            self.assertFalse(top["hit_limit"], f"{blob!r} at {cap}")

    def test_chain_that_ends_by_itself_is_not_flagged(self):
        # Only one layer exists; nothing was cut off, so nothing is reported.
        top = E.decode_chain("666c61677b6865787d")[0]
        self.assertEqual(["hex"], top["steps"])
        self.assertFalse(top["hit_limit"])

    def test_unreadable_output_at_the_cap_counts_as_truncated(self):
        # The second half of the rule: `max_layers` layers consumed, the output
        # still shaped like an encoding and not readable enough to call it done.
        # base64 -> hex string, stopped after one layer.
        blob = base64.b64encode((b"flag{hex}" * 5).hex().encode()).decode()
        top = E.decode_chain(blob, max_layers=1)[0]
        self.assertEqual(["base64"], top["steps"])
        self.assertIn("hex", E.guess_kinds(top["text"]))
        self.assertLess(top["score"], 70)
        self.assertTrue(top["hit_limit"])
        # With room for the hex layer the same chain ends properly and clears.
        top3 = E.decode_chain(blob, max_layers=3)[0]
        self.assertEqual(["base64", "hex"], top3["steps"])
        self.assertFalse(top3["hit_limit"])

    def test_input_string_itself_is_never_flagged(self):
        # `steps == []` is the untouched input, not a truncated chain.
        for crypto in E.decode_chain("666c61677b6865787d", max_layers=1):
            if not crypto["steps"]:
                self.assertFalse(crypto["hit_limit"])

    def test_hit_limit_is_in_the_analyzer_output_and_the_json_contract(self):
        blob = four_layer_blob()
        results = analyze_all(blob, effort="fast")
        self.assertIs(results["encoding"]["blobs"][0]["chain"][0]["hit_limit"], True)
        summary = json_summary(results, verify_candidates(results))
        self.assertEqual(3, summary["decode_chain"]["max_layers"])
        self.assertTrue(summary["decode_chain"]["hit_limit"])
        self.assertEqual(["base64", "base64", "base64"],
                         summary["decode_chain"]["limited"][0]["steps"])
        # And it clears once the caller takes the hint.
        raised = json_summary(analyze_all(blob, effort="fast", max_layers=6))
        self.assertFalse(raised["decode_chain"]["hit_limit"])


class TestConfiguredDepthReachesOtherLayers(unittest.TestCase):
    """Item 1 again: the same knob must reach hypothesis.py and lab.py"""

    def _ctx_file(self, blob):
        path = write_scratch(blob + "\n")
        self.addCleanup(os.remove, path)
        return build_context(path), path

    def test_hypothesis_decode_uses_params_max_layers(self):
        ctx, _ = self._ctx_file(four_layer_blob())
        for layers, expect_steps, expect_cap in ((3, 3, True), (6, 4, False)):
            params = params_from_ctx(ctx, max_layers=layers)
            self.assertEqual(layers, params["max_layers"])
            res = evaluate(params, budget="full")
            row = next(r for r in res["results"] if r["name"] == "decode_chain")
            self.assertEqual(["base64"] * expect_steps,
                             row["detail"].split(" ")[0].split("\u2192"))
            self.assertEqual(expect_cap, "cap" in row["detail"])
            if not expect_cap:
                self.assertEqual(PT4, row["plaintext"])

    def test_workbench_bakes_in_the_requested_depth(self):
        path = write_scratch(four_layer_blob() + "\n")
        self.addCleanup(os.remove, path)
        results = analyze_all(path, effort="fast", max_layers=6)
        text = build_workbench(results, max_layers=6)
        self.assertIn("MAX_LAYERS = 6", text)
        self.assertIn("decode_chain(b, max_layers=MAX_LAYERS)", text)
        self.assertNotIn("max_layers=3", text)
        default_text = build_workbench(results)
        self.assertIn("MAX_LAYERS = 3", default_text)


class TestCustomAlphabet(unittest.TestCase):
    """Item 4: opt-in custom base64 alphabets, default off"""

    @classmethod
    def setUpClass(cls):
        cls.alphabet = shuffled_std(42)
        plain = b"flag{custom_base64_alphabet_is_supported}"
        while len(plain) % 3:              # no '=' padding, so the body maps 1:1
            plain += b"!"
        cls.plain = plain
        cls.ciphertext = swap_encode(base64.b64encode(plain).decode(), cls.alphabet)

    def test_off_by_default_is_unsolved(self):
        self.assertFalse(any(c["flags"] for c in E.decode_chain(self.ciphertext)))
        self.assertEqual([], E.check_alphabets(None))

    def test_supplied_alphabet_solves_it(self):
        top = E.decode_chain(self.ciphertext, alphabets=[self.alphabet])[0]
        self.assertEqual(self.plain, top["data"])
        self.assertEqual("high", top["confidence"])
        self.assertEqual(["base64-swap#1"], top["steps"])

    def test_wrong_alphabet_cannot_reach_high_confidence(self):
        # "high" is reserved for a known flag prefix, so a wrong table can only
        # ever produce a low/medium heuristic candidate.
        for wrong in (self.alphabet[::-1], shuffled_std(1234)):
            got = E.decode_chain(self.ciphertext, alphabets=[wrong])
            self.assertFalse([c for c in got if c["confidence"] == "high"])
            self.assertFalse([c for c in got if c["flags"]])

    def test_analyze_all_threads_alphabets(self):
        results = analyze_all(self.ciphertext, effort="fast", alphabets=[self.alphabet])
        self.assertEqual([self.alphabet], results["alphabets"])
        found = [c for c in verify_candidates(results)["entries"]
                 if c["state"] == "confirmed"]
        self.assertTrue(found, verify_candidates(results)["verdict"])
        self.assertIn("flag{custom_base64_alphabet_is_supported}", found[0]["preview"])

    def test_malformed_alphabets_are_rejected_by_name(self):
        for bad in self.alphabet[:-1], self.alphabet + "x", "abc":
            with self.assertRaises(ValueError) as caught:
                E.decode_chain(self.ciphertext, alphabets=[bad])
            self.assertIn("alphabet #0", str(caught.exception))
        with self.assertRaises(ValueError):        # whitespace and '=' are not values
            E.decode_chain(self.ciphertext, alphabets=[self.alphabet[:-2] + " ="])


class TestSwappedAlphabetLines(unittest.TestCase):
    """Item 5: the cross-line "second line is the alphabet" judgement"""

    @classmethod
    def setUpClass(cls):
        cls.alphabet = shuffled_std(7)
        plain = (b"the quick brown fox jumps over the lazy dog "
                 b"flag{swapped_alphabet_within_two_lines}")
        while len(plain) % 3:
            plain += b"!"
        cls.plain = plain
        cls.sample = cls.alphabet + "\n" + \
            swap_encode(base64.b64encode(plain).decode(), cls.alphabet) + "\n"

    def _analyze(self, text, **kwargs):
        path = write_scratch(text)
        self.addCleanup(os.remove, path)
        return analyze_all(path, effort="fast", **kwargs)

    def test_heuristic_finds_the_table_line(self):
        cands = E.guess_alphabet_candidates(self.sample)
        self.assertEqual(1, len(cands))
        self.assertEqual(1, cands[0]["line"])
        self.assertEqual(self.alphabet, cands[0]["alphabet"])
        self.assertEqual(64, cands[0]["unique"])

    def test_candidate_carries_line_preview_and_score_evidence(self):
        block = self._analyze(self.sample,
                              guess_alphabets=True)["encoding"]["swapped_alphabets"]
        self.assertEqual(1, len(block["alphabets"]))
        entry = block["alphabets"][0]
        self.assertEqual(1, entry["line"])                 # which line was taken
        self.assertEqual(self.alphabet, entry["alphabet"])
        level = entry["levels"][0]
        self.assertEqual(self.plain.decode(), level["preview"])   # the preview
        self.assertGreater(level["score"], 100)                   # and the score
        self.assertEqual(1, len(block["candidates"]))             # deduplicated
        self.assertIn("taken as the base64 alphabet",
                      block["candidates"][0]["detail"])
        confirmed = [c for c in verify_candidates(self._analyze(
            self.sample, guess_alphabets=True))["entries"] if c["state"] == "confirmed"]
        self.assertTrue(confirmed)

    def test_json_contract_exposes_the_evidence(self):
        results = self._analyze(self.sample, guess_alphabets=True)
        block = json_summary(results, verify_candidates(results))["swapped_alphabet"]
        self.assertEqual(1, len(block["alphabets"]))
        self.assertEqual(1, block["alphabets"][0]["line"])
        self.assertEqual(self.plain.decode(), block["alphabets"][0]["levels"][0]["preview"])
        self.assertEqual("high", block["candidates"][0]["confidence"])
        self.assertIn("flag{swapped_alphabet_within_two_lines}",
                      block["candidates"][0]["preview"])

    def test_off_by_default(self):
        block = self._analyze(self.sample)["encoding"]["swapped_alphabets"]
        self.assertEqual([], block["alphabets"])
        self.assertEqual([], block["candidates"])

    def test_negative_control_ordinary_multiline_text(self):
        text = ("# notes on the challenge\n"
                "The first line is a hint, not a table; a base64 alphabet holds\n"
                "exactly 64 characters and an ordinary sentence never does.\n")
        self.assertEqual([], E.guess_alphabet_candidates(text))
        block = self._analyze(text, guess_alphabets=True)["encoding"]["swapped_alphabets"]
        self.assertEqual([], block["alphabets"])
        self.assertEqual([], block["candidates"])

    def test_wrong_table_on_a_real_payload_is_a_table_candidate_only(self):
        # A line of the right shape that decodes to noise: recorded as tried,
        # never promoted to a candidate.
        noise = self.alphabet + "\n" + ("A" * 80) + "\n"
        block = self._analyze(noise, guess_alphabets=True)["encoding"]["swapped_alphabets"]
        self.assertEqual(1, len(block["alphabets"]))
        self.assertEqual([], block["candidates"])
        for level in block["alphabets"][0]["levels"]:
            self.assertLess(level["score"], 70)


if __name__ == "__main__":
    unittest.main()

