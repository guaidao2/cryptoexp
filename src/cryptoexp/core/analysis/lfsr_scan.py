"""LFSR-family analysis: recover the taps from output bits, then predict.

Two shapes show up in CTF crypto:

1. "here are N output bits, predict the rest" — Berlekamp-Massey recovers the minimal
   recurrence from 2L bits and the continuation is then deterministic.
2. "taps and seed are given, the ciphertext is the plaintext XOR the keystream" — the
   register is run forward and the ciphertext decrypts.

The analyzer handles both, and it is careful about the one honest trap here: an
all-zero bit run has no recurrence to find, and a run shorter than twice the register
length does not determine the taps. In those cases it reports the gap instead of a
guess.
"""

import re

from ...utils import gf2 as G

_BITS_RE = re.compile(r'(?<![01])([01]{40,})(?![01])')
_TAPS_RE = re.compile(r'taps\s*=?\s*\[([0-9,\s]+)\]', re.I)
_STATE_RE = re.compile(r'(?:state|seed)\s*=?\s*(?:0x([0-9a-fA-F]+)|(\d+))', re.I)
_NEXT_RE = re.compile(r'(?:next|predict)\D{0,20}?(\d+)\s*(?:bit|byte)', re.I)


def _bits_to_bytes(bits):
    """MSB-first, the same convention gf2.bits_to_bytes documents"""
    return G.bits_to_bytes(bits)


def analyze_lfsr(ctx: dict, effort: str = "normal") -> dict:
    """Detect LFSR tasks: tap recovery + continuation, or keystream decryption"""
    out = {"notes": [], "candidates": [], "params": {}, "vulns": []}
    text = ctx.get("raw_text") or ""
    # Ciphertext bytes: the decoded blobs ("data"), same source the symmetric analyzer uses
    blobs = [bytes(d["data"]) for d in (ctx.get("data") or [])
             if isinstance(d.get("data"), (bytes, bytearray)) and d.get("data")]

    # ── shape 2: explicit taps/state + ciphertext ──
    taps_m, state_m = _TAPS_RE.search(text), _STATE_RE.search(text)
    if taps_m and state_m:
        taps = [int(t) for t in re.findall(r'\d+', taps_m.group(1))]
        state = int(state_m.group(1), 16) if state_m.group(1) else int(state_m.group(2))
        out["params"] = {"taps": taps, "state": state}
        if blobs:
            out["params"]["ciphertexts_hex"] = [b.hex() for b in blobs]
        out["vulns"].append({"attack": "lfsr_keystream", "confidence": "high",
                             "detail": "taps and seed were both given, so the keystream "
                                       "is fully determined"})
        lfsr = G.LFSR(taps, state)
        for blob in blobs:
            ks = lfsr.keystream(8 * len(blob))
            pt = bytes(a ^ b for a, b in zip(blob, ks))
            out["candidates"].append({
                "attack": "lfsr_keystream",
                "data": pt,
                "confidence": "high",
                "detail": f"XORed the given LFSR (taps {taps}) keystream into "
                          f"{len(blob)} byte(s) of ciphertext",
            })
        if not blobs:
            out["notes"].append("taps and seed are given but no ciphertext blob was found")
        return out

    # ── shape 1: a long run of output bits ──
    runs = sorted((m.group(1) for m in _BITS_RE.finditer(text)), key=len, reverse=True)
    if not runs:
        out["notes"].append("no long bit run (>= 40 bits) found")
        return out
    bits = [int(c) for c in runs[0]]
    out["params"] = {"observed_bits": len(bits), "observed_run": runs[0]}
    if blobs:
        # Every decoded blob is kept: the context also decodes the bit run itself as
        # "hex", so pinning one blob would as easily pin the wrong one.
        out["params"]["ciphertexts_hex"] = [b.hex() for b in blobs]
    if not any(bits):
        out["notes"].append("the bit run is all zeros: nothing to recover "
                            "(an LFSR that only emits zeros gives no information)")
        return out
    taps = G.berlekamp_massey(bits)
    if not taps:
        out["notes"].append(f"Berlekamp-Massey found no recurrence in {len(bits)} bits")
        return out
    length = max(taps) if taps else 0
    out["params"]["taps"] = taps
    out["notes"].append(f"Berlekamp-Massey: register length {length}, taps {taps}")
    if len(bits) < 2 * length:
        out["notes"].append(f"only {len(bits)} bits for a register of length {length}: "
                            f"the taps are not uniquely determined, so no prediction "
                            f"is claimed")
        return out

    next_m = _NEXT_RE.search(text)
    want_bits = 8 * int(next_m.group(1)) if (next_m and "byte" in next_m.group(0).lower()) \
        else (int(next_m.group(1)) if next_m else 64)
    if blobs:
        # The keystream continuation is as long as the ciphertext needs to be
        want_bits = max(want_bits, 8 * max(len(b) for b in blobs))
    prediction = G.lfsr_next(bits, want_bits)
    if prediction is None:
        out["notes"].append("prediction failed: the recovered register does not replay "
                            "the observed bits")
        return out
    out["params"]["predicted_bits"] = want_bits
    out["params"]["prediction"] = "".join(str(b) for b in prediction)
    out["vulns"].append({"attack": "lfsr_predict", "confidence": "high",
                         "detail": f"taps {taps} recovered from {len(bits)} bits; the "
                                   f"continuation is deterministic"})
    stream = _bits_to_bytes(prediction)
    for blob in blobs:
        pt = bytes(a ^ b for a, b in zip(blob, stream))
        out["candidates"].append({
            "attack": "lfsr_keystream",
            "data": pt,
            "confidence": "high",
            "detail": f"recovered taps {taps} from {len(bits)} observed bits, predicted "
                      f"{want_bits} keystream bit(s) and XORed them into the ciphertext",
        })
    if not blobs:
        out["candidates"].append({
            "attack": "lfsr_predict",
            "data": stream,
            "confidence": "medium",
            "detail": f"predicted {want_bits} bit(s) after the observed run with taps "
                      f"{taps}, read MSB-first as bytes (no ciphertext to XOR)",
        })
    return out


__all__ = ["analyze_lfsr"]
