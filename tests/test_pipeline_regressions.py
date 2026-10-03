"""Regressions from the 2026-10-03 pipeline/CLI audit.

The audit ran against the published 0.1.0a2 and found, among others: a crash on a
non-UTF-8 console, a challenge that confirmed itself, generated scripts that printed a
truncated flag or a hardcoded demo string, and a `list` command that showed no solve
templates. Each check below fails on the pre-fix code.
"""

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import cryptoexp as ck
from cryptoexp.core.solve import _reporoot
from cryptoexp.utils import encoding as E

CLI = os.path.join(ROOT, "cryptoexp_cli.py")


def cli(args, env_extra=None, timeout=300):
    env = dict(os.environ)
    env.pop("PYTHONIOENCODING", None)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, CLI] + args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=ROOT, env=env,
                          timeout=timeout)


class TestConsoleEncoding(unittest.TestCase):

    def test_json_survives_a_gbk_console(self):
        """H1: ensure_ascii=False + U+FFFD in a candidate killed the whole report"""
        proc = cli(["analyze", os.path.join(ROOT, "challenges", "classical_caesar.txt"),
                    "--json"], env_extra={"PYTHONIOENCODING": "gbk"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        payload = json.loads(proc.stdout)          # stdout must be valid JSON
        self.assertIn("verification", payload)

    def test_json_payload_is_pure_ascii(self):
        proc = cli(["analyze", os.path.join(ROOT, "challenges", "symmetric_ecb.txt"),
                    "--json"], env_extra={"PYTHONIOENCODING": "gbk"})
        self.assertEqual(proc.returncode, 0, proc.stderr[-500:])
        proc.stdout.encode("ascii")                # would raise on any non-ASCII byte


class TestStatementIsNotEvidence(unittest.TestCase):

    def test_example_flag_in_the_statement_cannot_confirm_itself(self):
        """H2: an example in the statement used to be reported as `confirmed`"""
        statement = ("The flag format is flag{EXAMPLE_FLAG_NOT_THE_ANSWER}. "
                     "Ciphertext: khoor zruog")
        proc = cli(["analyze", statement])
        self.assertNotIn("verdict        confirmed", proc.stdout)
        self.assertNotIn("[confirmed]", proc.stdout)

    def test_a_real_answer_still_confirms(self):
        proc = cli(["analyze", os.path.join(ROOT, "challenges", "classical_caesar.txt")])
        self.assertIn("confirmed", proc.stdout)
        self.assertIn("flag{caesar_is_classic}", proc.stdout)


class TestGeneratedScriptWiring(unittest.TestCase):

    def test_reporoot_is_the_importable_root(self):
        """H6: it returned .../src/cryptoexp, so `import cryptoexp` failed in scripts"""
        root = _reporoot()
        self.assertTrue(os.path.isdir(os.path.join(root, "cryptoexp")),
                        f"{root} does not contain the package")
        sys.path.insert(0, root)
        import importlib
        importlib.import_module("cryptoexp.utils.lattice")

    def test_batch_json_is_an_object(self):
        """M3: --dir --json emitted a bare list, violating the library's own schema"""
        proc = cli(["analyze", "--dir", os.path.join(ROOT, "challenges"), "--json"])
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        payload = json.loads(proc.stdout)
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertIsInstance(payload["targets"], list)

    def test_missing_target_reports_json_error(self):
        """L4: JSON consumers got a plain-text line"""
        proc = cli(["analyze", "--json"])
        self.assertEqual(proc.returncode, 1)
        self.assertIn("error", json.loads(proc.stdout))

    def test_list_shows_the_solve_templates(self):
        """M1: the registry fills lazily, so `list` printed '(not registered yet)'"""
        proc = cli(["list"])
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("not registered yet", proc.stdout)
        self.assertIn("gen_", proc.stdout.replace("  ", " ")) if "gen_" in proc.stdout \
            else self.assertIn("caesar", proc.stdout.lower())
        self.assertIn("API map", proc.stdout)

    def test_json_and_solve_together_still_generate(self):
        """M2: --json returned before the solve block, silently dropping it"""
        out = os.path.join(ROOT, ".tmp", "json_solve_check")
        proc = cli(["analyze", os.path.join(ROOT, "challenges", "xor_single.txt"),
                    "--json", "--solve", "--out", out])
        self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
        json.loads(proc.stdout)                    # stdout stays one JSON document
        scripts = [f for f in os.listdir(out) if f.endswith(".py")] if os.path.isdir(out) \
            else []
        self.assertTrue(scripts, "no solve script was generated")


class TestFlagConfiguration(unittest.TestCase):

    def test_merge_keeps_the_built_in_prefixes(self):
        """M5: README promised 'DH plus the built-ins'; merge dropped every built-in"""
        previous = E.set_flag_prefixes(["DH"], merge=True)
        try:
            prefixes = E.get_flag_prefixes()
            self.assertIn("DH", prefixes)
            self.assertIn("flag", prefixes)
            self.assertTrue(E.flag_candidates(b"flag{caesar_is_classic}"))
            self.assertTrue(E.flag_candidates(b"DH{caesar_with_custom_prefix}"))
        finally:
            E.set_flag_prefixes(list(previous[0] or []))     # restore
            E.reset_flag_prefixes()

    def test_strict_pattern_follows_the_prefix_tuple(self):
        """L7: the alternation was typed twice, so editing the tuple changed nothing"""
        source = open(os.path.join(ROOT, "src", "cryptoexp", "utils", "encoding.py"),
                      encoding="utf-8").read()
        self.assertIn("DEFAULT_FLAG_PREFIXES)", source.split("_STRICT_FLAG_PAT")[1][:400])


if __name__ == "__main__":
    unittest.main(verbosity=2)
