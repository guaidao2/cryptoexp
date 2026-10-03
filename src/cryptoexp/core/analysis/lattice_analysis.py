"""Lattice analyzer — low-density subset sum / Coppersmith factoring with known high bits

Lattice attacks are kept honest by requiring every solution to pass validation (a subset
sum must satisfy the equation, a factorization must divide), and LLL is used purely as a
candidate generator — deliberately: LLL carries no trustworthiness itself, validation does.
"""

import re

from ...utils import lattice as L
from ...utils import algebra as A
from ...utils import rsa_ops as R

_BIGNUM_LINE_RE = re.compile(r'(?:\d{4,}[\s,]+){5,}\d{4,}')
# "known N bits (of p)" as challenge prompts in Chinese state it — kept as escapes so the
# source holds no Chinese characters; the pattern itself is unchanged.
# "known high 160 bits of p" / "top 160 bits known" / "160 bits leaked".
# Chinese statements are still parsed via escaped codepoints so the source stays
# CJK-free while remaining compatible with Chinese write-ups.
_KNOWN_BITS_RE = re.compile(
    r'(?:(?:known|top|high|leaked|given)\D{0,14}?(\d{1,4})\s*bits?'
    r'|\u5df2\u77e5.{0,8}?(\d{2,4})\s*(?:\u4e2a)?\s*\u4f4d)', re.I)


def _pick(named, labels):
    for lab in labels:
        if lab in named and named[lab]:
            return named[lab][0]
    return None


def _knapsack_inputs(ctx: dict):
    """Find (weights, target): a line with 6+ big integers plus a target/s label"""
    named = ctx.get("named", {})
    target = _pick(named, ("s", "target", "sum", "total", "c"))
    lines = []
    for line in ctx.get("raw_text", "").splitlines():
        nums = [int(x) for x in re.findall(r'\d{3,}', line)]
        if len(nums) >= 6:
            lines.append(nums)
    if not lines:
        return None, None
    nums = max(lines, key=len)
    if target is not None and target in nums:
        nums = [v for v in nums if v != target]
    if len(nums) < 6 or len(nums) > 12:
        return None, None
    # Keep the original order from the challenge — the solved indices must map back onto
    # the challenge's bit string, and sorting would break that (hit in tests: indices
    # looked right while every weight was shifted)
    return nums[:12], target


def analyze_lattice(ctx: dict) -> dict:
    out = {"knapsack": None, "coppersmith": None, "vulns": [], "candidates": [],
           "notes": []}
    named = ctx.get("named", {})
    n = _pick(named, ("n", "modulus"))

    # ── 1. Low-density subset sum (knapsack) ──
    weights, target = _knapsack_inputs(ctx)
    if weights and target:
        density = len(weights) / max(1, max(weights).bit_length())
        picks = L.subset_sum_lll(weights, target)
        out["knapsack"] = {"n_items": len(weights), "density": round(density, 3),
                           "target": str(target)[:40], "solved": picks is not None,
                           "picks": picks}
        if picks is not None:
            out["vulns"].append({
                "type": "low-density subset sum (LLL-solvable)", "severity": "critical",
                "confidence": "high",
                "detail": f"{len(weights)} items, density {density:.3f} < 0.94, "
                          f"solved selection indices {picks}",
                "attack": "knapsack_lll"})
            out["candidates"].append({
                "attack": "knapsack_lll",
                "data": ("picks=" + ",".join(map(str, picks))).encode(),
                "confidence": "high",
                "detail": "subset-sum selection indices (map back to the challenge's "
                          "bit string/plaintext)"})
        else:
            out["vulns"].append({
                "type": "subset sum hint", "severity": "medium", "confidence": "low",
                "detail": f"{len(weights)} items, density {density:.3f} — LLL did not "
                          f"solve it (density too high or dimension over the limit)",
                "attack": "knapsack_lll"})

    # ── 2. Coppersmith: known high bits of p ──
    p_high = _pick(named, ("p_high", "phigh", "hint", "p_hint", "high", "known_p"))
    known_bits = None
    m = _KNOWN_BITS_RE.search(ctx.get("raw_text", ""))
    if m:
        known_bits = int(m.group(1) or m.group(2))
    if n and p_high:
        if known_bits is None:
            known_bits = p_high.bit_length()
        total = n.bit_length()
        e = _pick(named, ("e", "exponent", "pub"))
        c = _pick(named, ("c", "cipher", "ct", "ciphertext"))
        res = R.known_high_bits_attack(n, p_high, known_bits, e=e, c=c, total_bits=total)
        if res.get("ok"):
            factors = res.get("factors")
            note = "Coppersmith small root hit" + (" → decrypted" if res.get("plaintext") else "")
            out["coppersmith"] = {
                "known_bits": known_bits, "total_bits": total,
                "p": (hex(factors[0]) if factors else None),
                "note": note}
            out["vulns"].append({
                "type": "Coppersmith known high bits", "severity": "critical",
                "confidence": "high",
                "detail": res.get("detail") or f"{known_bits} known bits of p (n is "
                                                f"{total} bits), LLL small root hit",
                "attack": "coppersmith_high_bits"})
            if res.get("plaintext"):
                out["candidates"].append({
                    "attack": "coppersmith_high_bits", "data": res["plaintext"],
                    "confidence": "high",
                    "detail": "Coppersmith factorization → decryption"})
            else:
                out["candidates"].append({
                    "attack": "coppersmith_high_bits",
                    "data": f"p={factors[0]}\nq={factors[1]}".encode(),
                    "confidence": "high",
                    "detail": "factorization result (intermediate, pair with e/c to decrypt)"})
        else:
            out["coppersmith"] = {"known_bits": known_bits, "total_bits": total,
                                  "p": None, "note": res.get("note", "")}
            out["vulns"].append({
                "type": "known high bits of p (Coppersmith hint)", "severity": "high",
                "confidence": "medium",
                "detail": f"{known_bits}/{total} bits known, small root missed — needs "
                          f"more known bits or larger lattice parameters",
                "attack": "coppersmith_high_bits"})
    elif n and known_bits:
        out["notes"].append(f"prompt mentions {known_bits} known bits, but no high-bit "
                            f"value was extracted (needs a p_high/hint label)")

    # ── 3. Only n given and its bit length is modest: point toward lattice/high-bit leakage ──
    if n and not out["vulns"] and n.bit_length() <= 1024:
        if A.is_prime(n):
            out["notes"].append("n itself is prime — not standard RSA, "
                                "check whether the wrong parameter was used")
    return out
