"""Forensics / assessment layer tests — the "beyond CTF" surface.

These are the functions a penetration tester or a researcher reaches for on real
material: a pile of public keys, a captured JWT, a DER signature, a "random" token
sequence. Each test asserts an externally checkable property (a factor divides both
moduli, a decoded JWT field, a signature round-trip, a predicted continuation).
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

import cryptoexp as ck
from cryptoexp.utils import forensics as F


class TestBatchGCD(unittest.TestCase):

    def test_shared_prime_is_found(self):
        p, q1, q2 = 0, 0, 0
        while True:
            p = ck.next_prime(ck.next_prime(2 ** 200) ^ 0xABCDEF)
            if ck.is_prime(p):
                break
        q1 = ck.next_prime(p + 12345)
        q2 = ck.next_prime(p + 54321)
        n1, n2, n3 = p * q1, p * q2, q1 * q2
        res = F.batch_gcd([n1, n2, n3])
        self.assertTrue(res["pairs"], "no shared factor reported")
        pairs = {(f["i"], f["j"]): f["factor"] for f in res["pairs"]}
        self.assertEqual(pairs.get((0, 1)), p)
        self.assertEqual(n1 % p, 0)
        self.assertEqual(n2 % p, 0)
        self.assertIn(p, res["groups"])
        self.assertEqual(sorted(res["groups"][p]), [0, 1])

    def test_no_false_positives_on_coprime_moduli(self):
        import random as _r
        rng = _r.Random(1234)
        moduli = []
        primes = [ck.next_prime(rng.getrandbits(160) | (1 << 160)) for _ in range(60)]
        for i in range(0, 60, 2):
            moduli.append(primes[i] * primes[i + 1])
        res = F.batch_gcd(moduli)
        self.assertEqual(res["pairs"], [])
        self.assertGreaterEqual(res["checked"], len(moduli))
        self.assertEqual(F.common_factor_pairs(moduli), [])


class TestParseJWT(unittest.TestCase):

    # The canonical jwt.io HS256 example
    TOKEN = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
             "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
             "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

    def test_decodes_header_and_payload(self):
        out = F.parse_jwt(self.TOKEN)
        self.assertEqual(out["alg"], "HS256")
        self.assertEqual(out["typ"], "JWT")
        self.assertEqual(out["header"]["alg"], "HS256")
        self.assertEqual(out["payload"]["sub"], "1234567890")
        self.assertEqual(out["payload"]["name"], "John Doe")
        self.assertEqual(out["segments"], 3)
        self.assertTrue(out["weak_alg"], "HS256 must be reported as a weak algorithm")
        self.assertTrue(out["signature"])

    def test_unpadded_and_none_alg(self):
        import base64
        import json

        def seg(obj):
            raw = json.dumps(obj, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        token = f"{seg({'alg': 'none'})}.{seg({'role': 'admin'})}."
        out = F.parse_jwt(token)
        self.assertEqual(out["alg"], "none")
        self.assertEqual(out["payload"]["role"], "admin")
        self.assertIsNone(out["signature"])
        self.assertTrue(out["weak_alg"])

    def test_garbage_is_reported_not_raised(self):
        out = F.parse_jwt("not.a.jwt.at.all")
        self.assertTrue(out["errors"])
        self.assertIsNone(out["payload"])


class TestParseDERSignature(unittest.TestCase):

    @staticmethod
    def _der_int(value):
        raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw

    def _wrap(self, r, s):
        body = self._der_int(r) + self._der_int(s)
        return b"\x30" + bytes([len(body)]) + body

    def test_round_trip(self):
        for r, s in ((1, 2), (0x12, 0x34), (0x7F, 0x80), (2 ** 200 + 7, 3)):
            der = self._wrap(r, s)
            parsed = F.parse_der_signature(der)
            self.assertIsNotNone(parsed, f"failed to parse {der.hex()}")
            self.assertEqual((parsed["r"], parsed["s"]), (r, s))

    def test_rejects_bad_input(self):
        der = self._wrap(0x11, 0x22)
        self.assertIsNone(F.parse_der_signature(der[:-1]))
        self.assertIsNone(F.parse_der_signature(b"\x30\x00"))
        self.assertIsNone(F.parse_der_signature(b"junk junk junk"))


class TestAuditRSAKey(unittest.TestCase):

    def test_generated_key_has_no_critical_finding(self):
        key = ck.keygen(512, e=65537)
        out = F.audit_rsa_key(key["n"], key["e"])
        # keygen(512) can hand back a 511-bit product; the audit must report the
        # modulus it was actually given, not a nominal size
        self.assertEqual(out["n_bits"], key["n"].bit_length())
        self.assertFalse(any(f["severity"] == "critical" for f in out["findings"]))
        # a 512-bit modulus must at least be flagged as too small for production
        self.assertTrue(any("bits" in f["id"] for f in out["findings"]))

    def test_close_primes_flagged(self):
        p = ck.next_prime(2 ** 256)
        q = ck.next_prime(p + 4)
        out = F.audit_rsa_key(p * q, 65537)
        ids = {f["id"] for f in out["findings"]}
        self.assertIn("fermat_close_primes", ids)

    def test_small_exponent_and_shared_factor(self):
        p = ck.next_prime(2 ** 200)
        q1 = ck.next_prime(p + 1000)
        q2 = ck.next_prime(p + 2000)
        out = F.audit_rsa_key(p * q1, 3, extra_moduli=[p * q2])
        ids = {f["id"] for f in out["findings"]}
        self.assertIn("small_exponent", ids)
        self.assertIn("shared_factor", ids)

    def test_honest_about_skipped_checks(self):
        out = F.audit_rsa_key(15, 3)
        self.assertTrue(out["checked"], "the audit must say what it ran")
        self.assertTrue(all(isinstance(c, (str, dict)) for c in out["checked"]))


class TestDetectWeakPRNG(unittest.TestCase):

    def test_lcg_is_identified_and_predicted(self):
        m, a, c, s = 2 ** 31, 1103515245, 12345, 987654321
        outs = []
        for _ in range(12):
            s = (a * s + c) % m
            outs.append(s)
        out = F.detect_weak_prng(outs)
        self.assertEqual(out["family"], "lcg")
        truth = []
        for _ in range(4):
            s = (a * s + c) % m
            truth.append(s)
        self.assertEqual(out["predict"], truth)

    def test_mt19937_is_identified(self):
        """Python's random module is MT19937, so this is the real forensic case"""
        import random as _r
        rnd = _r.Random(1234)
        outs = [rnd.getrandbits(32) for _ in range(700)]
        truth = [rnd.getrandbits(32) for _ in range(4)]
        out = F.detect_weak_prng(outs)
        self.assertEqual(out["family"], "mt19937")
        self.assertEqual(out["predict"], truth)

    def test_unknown_input_claims_nothing(self):
        import hashlib
        outs = [int.from_bytes(hashlib.sha256(str(i).encode()).digest()[:4], 'big')
                for i in range(40)]
        out = F.detect_weak_prng(outs)
        if out["family"] is not None:
            # only acceptable when the claim replays the observed values
            self.assertIsNotNone(out["predict"])
        else:
            self.assertTrue(out["tried"], "must report what it tried")


class TestLibraryUsableBeyondCTF(unittest.TestCase):
    """The pieces a non-CTF user needs must be importable and composable"""

    def test_end_to_end_key_audit_workflow(self):
        """Build two "leaked" keys that share a prime, find it, then decrypt"""
        p = ck.next_prime(2 ** 256)
        q1 = ck.next_prime(p + 11)
        q2 = ck.next_prime(q1 + 1000)          # must differ from q1, or the moduli repeat
        self.assertNotEqual(q1, q2)
        k1 = {"n": p * q1, "e": 65537}
        k1["d"] = ck.modinv(65537, (p - 1) * (q1 - 1))
        k2 = {"n": p * q2, "e": 65537}
        audit = F.audit_rsa_key(k1["n"], k1["e"], extra_moduli=[k2["n"]])
        self.assertIn("shared_factor", {f["id"] for f in audit["findings"]})
        factor = F.batch_gcd([k1["n"], k2["n"]])["pairs"][0]["factor"]
        self.assertEqual(factor, p)
        # decrypt with the recovered factor, no owner cooperation
        m = ck.bytes_to_long(b"secret message")
        ct = pow(m, k2["e"], k2["n"])
        recovered = ck.decrypt_with_factors(k2["n"], k2["e"], ct, factor,
                                            k2["n"] // factor)
        self.assertTrue(recovered["ok"], recovered.get("note"))
        self.assertEqual(recovered["plaintext"], b"secret message")

    def test_flag_finder_on_arbitrary_data(self):
        data = (b"-----BEGIN nothing-----\n"
                b"session=deadbeef\n"
                b"FLAG: corp_a1b2c3{rotate-me}\n"
                b"other{not-a-real-marker}\n")
        found = ck.find_flags(data, prefixes=["corp_a1b2c3"])
        kinds = {(f["match"], f["kind"]) for f in found}
        self.assertIn(("corp_a1b2c3{rotate-me}", "strict"), kinds)
        self.assertIn(("other{not-a-real-marker}", "loose"), kinds)


if __name__ == "__main__":
    unittest.main(verbosity=2)
