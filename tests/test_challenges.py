"""End-to-end challenge tests — every sample must actually yield its flag.

Run: python -m unittest tests.test_challenges -v
Prerequisite: python challenges/make_challenges.py (samples are committed; usually
no need to regenerate).

These assertions are the only hard evidence that the toolkit works:
analyzer -> candidates -> three-state verification -> flag.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))      # src layout, no install needed

from cryptoexp.core.analysis import analyze_all
from cryptoexp.core.verify import verify_candidates

CH_DIR = os.path.join(ROOT, "challenges")

# Expected flag per sample (mirrors challenges/make_challenges.py)
EXPECTED = {
    "rsa_small_e.txt": "flag{small_e_no_padding}",
    "rsa_wiener.txt": "flag{wiener_attack_small_d}",
    "rsa_shared_prime.txt": "flag{shared_prime_gcd}",
    "rsa_fermat.txt": "flag{fermat_close_primes}",
    "rsa_factor.txt": "flag{pollard_rho_factors}",
    "rsa_dp_leak.txt": "flag{dp_leak_factors_n}",
    "rsa_high_bits.txt": "flag{coppersmith_known_high_bits}",
    "xor_single.txt": "flag{single_byte_xor_is_easy}",
    "xor_repeating.txt": "flag{repeating_key_xor_with_hamming_distance}",
    "classical_caesar.txt": "flag{caesar_is_classic}",
    "classical_vigenere.txt": "flag{vigenere_key_recovered}",
    "classical_morse.txt": "THEFLAGISMORSECODED",
    "encoding_chain.txt": "flag{multi_layer_encoding_chain}",
    "crc_preimage.txt": "flag{lin4}",
    "lfsr_predict.txt": "flag{lfsr_taps}",
    "classical_custom_prefix.txt": "DH{caesar_with_custom_prefix}",
}


def _analyze(name: str, effort: str = "normal", **kwargs):
    return analyze_all(os.path.join(CH_DIR, name), effort=effort, **kwargs)


class TestChallengesSolve(unittest.TestCase):
    """13 samples whose flag must come out"""

    def _check_flag(self, name, expected, effort="normal", **kwargs):
        results = _analyze(name, effort, **kwargs)
        verification = verify_candidates(results)
        # Inspect the FULL candidate data, not just the 80-character previews:
        # a flag can sit past the preview cut (e.g. a long Vigenere plaintext).
        # Dynamic: every analyzer that reports candidates participates.
        from cryptoexp.core.verify import iter_candidates
        blob = " ".join(e["preview"] for e in verification["entries"])
        for c in iter_candidates(results):
            data = c.get("data", b"")
            blob += " " + (data.decode('utf-8', errors='replace')
                           if isinstance(data, (bytes, bytearray)) else str(data))
        self.assertIn(expected, blob,
                      f"{name}: did not recover {expected}\n"
                      f"candidates={blob[:300]}\n"
                      f"verdict={verification['verdict']}\n"
                      f"notes={(results.get('rsa') or {}).get('notes')}")
        states = {e["state"] for e in verification["entries"]
                  if expected in e["preview"] or expected in blob}
        self.assertTrue(states & {"confirmed", "candidate"},
                        f"{name}: unexpected state for the matching candidate: {states}")

    def test_rsa_small_e(self):
        self._check_flag("rsa_small_e.txt", EXPECTED["rsa_small_e.txt"])

    def test_rsa_wiener(self):
        self._check_flag("rsa_wiener.txt", EXPECTED["rsa_wiener.txt"])

    def test_rsa_shared_prime(self):
        self._check_flag("rsa_shared_prime.txt", EXPECTED["rsa_shared_prime.txt"])

    def test_rsa_fermat(self):
        self._check_flag("rsa_fermat.txt", EXPECTED["rsa_fermat.txt"])

    def test_rsa_factor(self):
        self._check_flag("rsa_factor.txt", EXPECTED["rsa_factor.txt"])

    def test_rsa_dp_leak(self):
        self._check_flag("rsa_dp_leak.txt", EXPECTED["rsa_dp_leak.txt"])

    def test_rsa_high_bits(self):
        """Coppersmith needs m=t=3; the toolbox must pick that by default"""
        self._check_flag("rsa_high_bits.txt", EXPECTED["rsa_high_bits.txt"])

    def test_xor_single(self):
        self._check_flag("xor_single.txt", EXPECTED["xor_single.txt"])

    def test_xor_repeating(self):
        self._check_flag("xor_repeating.txt", EXPECTED["xor_repeating.txt"])

    def test_classical_caesar(self):
        self._check_flag("classical_caesar.txt", EXPECTED["classical_caesar.txt"])

    def test_classical_vigenere(self):
        self._check_flag("classical_vigenere.txt", EXPECTED["classical_vigenere.txt"])

    def test_classical_morse(self):
        self._check_flag("classical_morse.txt", EXPECTED["classical_morse.txt"])

    def test_encoding_chain(self):
        self._check_flag("encoding_chain.txt", EXPECTED["encoding_chain.txt"])

    def test_crc_preimage(self):
        """CRC is affine over GF(2): a 4-byte hole is a linear system, not a search"""
        self._check_flag("crc_preimage.txt", EXPECTED["crc_preimage.txt"])
        results = _analyze("crc_preimage.txt")
        crc = results["crc"]
        self.assertEqual(crc["params"]["width"], 32)
        self.assertEqual(crc["params"]["poly"], 0x04C11DB7)
        self.assertTrue(crc["params"]["refin"] and crc["params"]["refout"])
        attack = next(v for v in crc["vulns"] if v["attack"] == "crc_preimage")
        self.assertEqual(attack["confidence"], "high")

    def test_classical_custom_prefix(self):
        """A non-standard flag format must work once the engagement says so"""
        name = "classical_custom_prefix.txt"
        want = EXPECTED[name]
        self._check_flag(name, want, flag_prefixes=["DH"])
        # and the same sample must NOT be confirmed with the built-in list, which is
        # what proves the option does something rather than decorating the output.
        # (No reset needed: analyze_all scopes its flag config to the call.)
        default = verify_candidates(_analyze(name))
        self.assertNotEqual(default["verdict"].split()[0], "confirmed")
        self.assertFalse(any(e["state"] == "confirmed" for e in default["entries"]))

    def test_lfsr_keystream(self):
        """Berlekamp-Massey on the observed bits, then the continuation is forced"""
        self._check_flag("lfsr_predict.txt", EXPECTED["lfsr_predict.txt"])
        results = _analyze("lfsr_predict.txt")
        lfsr = results["lfsr"]
        self.assertEqual(lfsr["params"]["taps"], [0, 7, 13, 16])
        self.assertEqual(lfsr["params"]["observed_bits"], 64)
        attack = next(v for v in lfsr["vulns"] if v["attack"] == "lfsr_predict")
        self.assertEqual(attack["confidence"], "high")


class TestChallengesStructural(unittest.TestCase):
    """Samples that produce a structural verdict instead of a flag"""

    def test_symmetric_ecb_detected(self):
        results = _analyze("symmetric_ecb.txt")
        sym = results["symmetric"]
        self.assertEqual(sym["mode"], "ECB", f"ECB not detected: {sym}")
        self.assertEqual(sym["block_size"], 16)
        self.assertTrue(sym["repeated_blocks"])
        attack = next(v for v in sym["vulns"] if v["attack"] == "ecb_detect")
        self.assertEqual(attack["confidence"], "high")

    def test_lcg_recovered(self):
        results = _analyze("lcg.txt")
        lcg = results["numbertheory"]["lcg"]
        self.assertIsNotNone(lcg, "LCG parameters not recovered")
        self.assertEqual((lcg["a"], lcg["c"], lcg["m"]),
                         (1103515245, 12345, 2 ** 31))

    def test_knapsack_solved(self):
        results = _analyze("knapsack.txt")
        ks = results["lattice"]["knapsack"]
        self.assertTrue(ks["solved"], f"knapsack not solved: {ks}")
        # independent recomputation: take only the weights line, never the target
        import re
        text = open(os.path.join(CH_DIR, "knapsack.txt"), encoding="utf-8").read()
        wline = next(l for l in text.splitlines() if l.startswith("weights:"))
        weights = [int(x) for x in re.findall(r'\d+', wline)]
        target = int(re.search(r'^s\s*=\s*(\d+)', text, re.M).group(1))
        self.assertEqual(len(weights), 8)
        self.assertEqual(sum(weights[i] for i in ks["picks"]), target)


class TestCliFlagPrefix(unittest.TestCase):
    """The CLI must expose the same knob the library does"""

    def test_flag_prefix_option(self):
        import subprocess
        sample = os.path.join(CH_DIR, "classical_custom_prefix.txt")
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "cryptoexp_cli.py"),
                               "analyze", sample, "--flag-prefix", "DH"],
                              capture_output=True, text=True, timeout=180,
                              encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        self.assertIn("DH{caesar_with_custom_prefix}", proc.stdout)

    def test_flag_regex_option(self):
        import subprocess
        proc = subprocess.run([sys.executable, os.path.join(ROOT, "cryptoexp_cli.py"),
                               "analyze", os.path.join(CH_DIR, "classical_caesar.txt"),
                               "--flag-regex", r"flag\{[a-z_]+\}"],
                              capture_output=True, text=True, timeout=180,
                              encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        self.assertIn("flag{caesar_is_classic}", proc.stdout)


class TestReportContract(unittest.TestCase):

    def test_json_contract(self):
        import json
        from cryptoexp.core.report import json_summary
        results = _analyze("rsa_fermat.txt")
        verification = verify_candidates(results)
        payload = json.loads(json.dumps(json_summary(results, verification),
                                        default=str))
        for key in ("schema_version", "target", "context", "rsa", "candidates",
                    "findings", "strategy", "hypotheses", "verification"):
            self.assertIn(key, payload)
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertNotIn("_ctx", payload)          # blackboard must not leak
        states = {e["state"] for e in payload["verification"]["entries"]}
        self.assertTrue(states <= {"confirmed", "candidate", "not_reproduced"})

    def test_findings_use_english_severity(self):
        results = _analyze("rsa_fermat.txt")
        self.assertIn(results["summary"]["max_severity"],
                      {"critical", "high", "medium", "low", "info"})
        for item in results["summary"]["items"]:
            self.assertIn(item["severity"],
                          {"critical", "high", "medium", "low", "info"})

    def test_plugin_analyzer_autoregisters(self):
        """A registered plugin must show up in the report without touching report.py"""
        from cryptoexp.core.analysis import register_analyzer, analyze_all as aa

        @register_analyzer("demo_plugin")
        def demo_plugin(ctx, results):
            return {"found": True, "detail": "plugin registered"}

        results = aa(os.path.join(CH_DIR, "xor_single.txt"))
        self.assertIn("demo_plugin", results)
        self.assertTrue(results["demo_plugin"]["found"])
        from cryptoexp.core.report import json_summary
        payload = json_summary(results)
        self.assertIn("demo_plugin", payload["extra"])


class TestSolverGeneration(unittest.TestCase):

    def test_generated_scripts_compile_and_are_english(self):
        import ast
        from cryptoexp.core.solve import generate, _register_builtins
        _register_builtins()
        for name in ("rsa_small_e.txt", "rsa_wiener.txt", "xor_single.txt",
                     "classical_caesar.txt", "lcg.txt"):
            results = _analyze(name, effort="fast")
            path = generate(results, out_dir=os.path.join(ROOT, ".tmp", "solves"))
            src = open(path, encoding="utf-8").read()
            ast.parse(src)
            self.assertIn("#!/usr/bin/env python3", src)
            self.assertFalse(any('\u4e00' <= ch <= '\u9fff' for ch in src),
                             f"{name}: generated script contains Chinese text")

    def test_generated_scripts_actually_solve(self):
        """The promise is a *runnable* script, so run it and check the flag.

        Regression for two real defects: the generated script used a weaker search
        than the library, and it embedded the display-truncated ciphertext.
        """
        import subprocess
        from cryptoexp.core.solve import generate, _register_builtins
        _register_builtins()
        out_dir = os.path.join(ROOT, ".tmp", "solves")
        cases = {
            "xor_single.txt": "flag{single_byte_xor_is_easy}",
            "xor_repeating.txt": "flag{repeating_key_xor_with_hamming_distance}",
            "rsa_small_e.txt": "flag{small_e_no_padding}",
            "rsa_wiener.txt": "flag{wiener_attack_small_d}",
            "rsa_shared_prime.txt": "flag{shared_prime_gcd}",
            "rsa_fermat.txt": "flag{fermat_close_primes}",
            "lcg.txt": None,          # structural sample: only require clean exit
            "classical_caesar.txt": "flag{caesar_is_classic}",
            "crc_preimage.txt": "flag{lin4}",
            "lfsr_predict.txt": "flag{lfsr_taps}",
            # Added after the 2026-10-03 pipeline audit. Each of these four was broken in
            # a different way and none of them was in this list, so the suite stayed
            # green while the generated scripts printed a truncated flag, a hardcoded
            # demo string, the wrong cipher family, or nothing at all.
            "classical_morse.txt": "THEFLAGISMORSECODED",
            "classical_vigenere.txt": "flag{vigenere_key_recovered}",
            "encoding_chain.txt": "flag{multi_layer_encoding_chain}",
            "knapsack.txt": "selected indices",
        }
        for name, want in cases.items():
            results = _analyze(name)
            path = generate(results, out_dir=out_dir)
            proc = subprocess.run([sys.executable, path], capture_output=True,
                                  text=True, encoding="utf-8", errors="replace",
                                  timeout=300)
            self.assertEqual(proc.returncode, 0,
                             f"{name}: {os.path.basename(path)} exited "
                             f"{proc.returncode}\n{proc.stderr[-400:]}")
            if want:
                self.assertIn(want, proc.stdout,
                              f"{name}: {os.path.basename(path)} did not print {want}\n"
                              f"stdout={proc.stdout[:300]}")

    def test_solver_routing_picks_expected_template(self):
        from cryptoexp.core.solve import generate, _register_builtins
        _register_builtins()
        cases = {
            "rsa_small_e.txt": "rsa_small_e",
            "rsa_wiener.txt": "rsa_wiener",
            "rsa_shared_prime.txt": "rsa_shared_prime",
            "rsa_fermat.txt": "rsa_fermat",
            "rsa_dp_leak.txt": "rsa_dp_leak",
            "xor_repeating.txt": "xor_repeating",
            "classical_morse.txt": "classical",
            "encoding_chain.txt": "decode_chain",
            "lcg.txt": "lcg",
            "crc_preimage.txt": "crc_preimage",
            "lfsr_predict.txt": "lfsr",
        }
        for name, want in cases.items():
            # the repeating-XOR path needs the real budget (effort=fast skips it)
            effort = "normal" if name == "xor_repeating.txt" else "fast"
            results = _analyze(name, effort=effort)
            path = generate(results, out_dir=os.path.join(ROOT, ".tmp", "solves"))
            self.assertIn(f"solve_{want}_", os.path.basename(path),
                          f"{name} routed to {os.path.basename(path)}, expected {want}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
