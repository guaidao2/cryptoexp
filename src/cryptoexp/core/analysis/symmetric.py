"""Block cipher analyzer — ECB detection / CBC hints / padding oracle hints

Honest division of labor: mode and block size can be decided statically here (repeated
blocks in ECB are hard evidence), but byte flipping and padding oracles require
interacting with an oracle — those only get hints and skeletons, with no pretended
verdict (the same tradeoff as intelpwn marking "[WARN]" when a template lacks a gadget).
"""

import re

_AES_MARKERS = ("AES.new", "Cipher import AES", "from Crypto", "Crypto.Cipher",
                "AES.MODE_ECB", "AES.MODE_CBC")
_UNPAD_MARKERS = ("unpad", "pkcs7", "PKCS7", "strip(b'\\x")
_CBC_MARKERS = ("MODE_CBC", "iv", "IV", "xor", "^")
_ORACLE_MARKERS = ("except", "Traceback", "try:", "return False", "return True")


def _block_size_guess(data: bytes, max_bs: int = 32):
    """Infer the block size from the distance between repeated blocks
    (the standard ECB detection trick)"""
    for bs in (16, 8, 32):
        if len(data) < bs * 2:
            continue
        blocks = [data[i:i + bs] for i in range(0, len(data) - bs + 1, bs)]
        if len(set(blocks)) < len(blocks):
            return bs
    return None


def _ecb_evidence(data: bytes, bs: int = 16):
    blocks = [data[i:i + bs] for i in range(0, len(data) - bs + 1, bs)]
    counts = {}
    for b in blocks:
        counts[b] = counts.get(b, 0) + 1
    dups = {b: n for b, n in counts.items() if n > 1}
    return blocks, dups


def analyze_symmetric(ctx: dict) -> dict:
    out = {"mode": "unknown", "block_size": None, "repeated_blocks": [],
           "oracle_hints": {}, "vulns": [], "notes": []}

    datas = [d for d in ctx.get("data", []) if len(d.get("data", b"")) >= 32]
    py_code = "\n".join(p["code"] for p in ctx.get("py", []))
    text = ctx.get("raw_text", "")

    best = None
    for item in datas:
        data = item["data"]
        bs = _block_size_guess(data)
        if bs is None:
            continue
        blocks, dups = _ecb_evidence(data, bs)
        if dups and (best is None or len(dups) > len(best[2])):
            best = (item, bs, dups, blocks)

    if best:
        item, bs, dups, blocks = best
        out["mode"] = "ECB"
        out["block_size"] = bs
        out["repeated_blocks"] = [
            {"block": b.hex(), "count": n}
            for b, n in sorted(dups.items(), key=lambda kv: -kv[1])[:5]]
        out["vulns"].append({
            "type": "ECB mode (repeated blocks)", "severity": "high", "confidence": "high",
            "detail": f"{item['source']}: block size {bs}, {len(dups)} repeated block "
                      f"groups — equal plaintext gives equal ciphertext",
            "attack": "ecb_detect"})
    elif datas:
        out["mode"] = "CBC/other"
        out["notes"].append("no repeated ciphertext blocks → not ECB (or the data is too short)")
    else:
        out["notes"].append("no byte string long enough to split into blocks "
                            "(need at least 32 bytes of ciphertext)")

    # Oracle hints (heuristic, confidence explicitly marked "low")
    hints = {}
    if py_code:
        hints["has_aes_code"] = any(m in py_code for m in _AES_MARKERS)
        hints["has_unpad"] = any(m in py_code for m in _UNPAD_MARKERS)
        hints["has_cbc"] = any(m in py_code for m in _CBC_MARKERS)
        hints["exception_based_oracle"] = (
            any(m in py_code for m in _ORACLE_MARKERS)
            and ("except" in py_code or "try:" in py_code))
        if hints["exception_based_oracle"]:
            out["vulns"].append({
                "type": "suspected padding oracle (exception/error-message split)",
                "severity": "high",
                "confidence": "low",
                "detail": "the decrypt call in the attachment is wrapped in try/except "
                          "and returns different results — heuristic, needs manual confirmation",
                "attack": "padding_oracle"})
        if hints["has_cbc"] and hints["has_unpad"]:
            out["vulns"].append({
                "type": "CBC + PKCS7 structure (byte-flip candidate)", "severity": "medium",
                "confidence": "medium",
                "detail": "in CBC, a known plaintext position can be changed by flipping "
                          "the preceding ciphertext block",
                "attack": "cbc_bitflip"})
    elif "iv" in text.lower() or "cbc" in text.lower():
        hints["mentions_iv_or_cbc"] = True
        out["notes"].append("prompt mentions IV/CBC but gives no oracle code — "
                            "only a skeleton is possible")
    out["oracle_hints"] = hints
    return out
