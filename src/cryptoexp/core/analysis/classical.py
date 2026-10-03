"""Classical cipher analyzer — Caesar / affine / Vigenere / morse / rail fence

Only acts on fragments that look like classical ciphertext: high letter ratio, or a
morse charset. Everything else is skipped explicitly instead of running a meaningless
26x26 brute force — the same "capabilities have gates" stance as intelpwn.
"""

import re

from ...utils import encoding as E

_WORD_RE = re.compile(r'[A-Za-z]{3,}')
_MORSE_RE = re.compile(r'^[.\-/|\s]+$')


def _text_candidates(ctx: dict):
    """Candidate text fragments: whole alphabetic lines from the prompt + extracted blobs

    Comment lines (`# ...`) are skipped: they are our own prose, and running
    Caesar/affine over them only produces noise candidates (observed in reports).
    """
    chunks = []
    for line in ctx.get("raw_text", "").splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        if len(line) >= 12 and E.printable_ratio(line.encode()) > 0.95:
            chunks.append(line)
    for b in ctx.get("blobs", []):
        if b["length"] >= 12:
            chunks.append(b["text"])
    # Deduplicate and drop long pure-digit/pure-hex strings (that is the encoding layer's job)
    out, seen = [], set()
    for c in chunks:
        if c in seen:
            continue
        seen.add(c)
        letters = sum(1 for ch in c if ch.isalpha())
        if letters >= 8 and letters / max(1, len(c)) >= 0.4:
            out.append(c)
        elif _MORSE_RE.match(c.strip()) and ('.' in c or '-' in c):
            out.append(c)
    return out[:8]


def analyze_classical(ctx: dict) -> dict:
    out = {"probes": [], "candidates": [], "notes": [], "adfgvx": None}
    # A stream built only of the ADFGX/ADFGVX labels is instantly recognisable, and the
    # scoring below is useless on it (a fractionated coordinate stream looks like noise).
    # Detection only: cracking needs a search (seconds to minutes), so it stays a library
    # call (`cx.adfgvx_crack`) rather than something `analyze` runs on every target.
    try:
        from ...utils import adfgvx as _ADF
        detection = _ADF.adfgvx_detect(ctx.get("raw_text") or "")
    except Exception:                                  # a lead must never break a report
        detection = None
    if detection and detection.get("is_adfgvx"):
        out["adfgvx"] = detection
        out["notes"].append(
            f"{detection['variant'].upper()} ciphertext detected "
            f"({detection['why']}); recover the key with cx.adfgvx_crack(ciphertext)")
    chunks = _text_candidates(ctx)
    if not chunks:
        out["notes"].append("no sufficiently long alphabetic fragment, "
                            "skipping classical analysis")
        return out

    for chunk in chunks:
        # `text` is display-truncated; `full_text` is what code generators must use
        probe = {"text": chunk[:60], "full_text": chunk, "morse": None,
                 "caesar": [], "affine": [], "vigenere": [], "fence": []}

        # Morse: clear charset → decode, never guess
        if _MORSE_RE.match(chunk.strip()):
            dec = E.morse_decode(chunk)
            if dec:
                sc = E.score_text(dec)
                probe["morse"] = {"plaintext": dec, "score": round(sc, 2)}
                if sc >= 60 or E.flag_candidates(dec.encode()):
                    out["candidates"].append({
                        "attack": "morse", "data": dec.encode(),
                        "confidence": E.confidence_of(sc, bool(E.flag_candidates(dec.encode()))),
                        "detail": f"morse decode, score {sc:.1f}"})
                # Keep the probe even though the remaining classical probes make no
                # sense for Morse: the solve generator reads probes[0] to inline the
                # ciphertext, and skipping the append here left it empty, so the Morse
                # template fell back to a hardcoded demo string and printed '??'.
                out["probes"].append(probe)
                continue

        # Caesar
        cas = E.caesar_candidates(chunk, top=2)
        probe["caesar"] = [{"shift": c["shift"], "score": c["score"],
                            "flags": c["flags"]} for c in cas]
        if cas and (cas[0]["flags"] or cas[0]["score"] >= 75):
            out["candidates"].append({
                "attack": "caesar", "data": cas[0]["plaintext"].encode(),
                "confidence": cas[0]["confidence"],
                "detail": f"shift={cas[0]['shift']}, score {cas[0]['score']}"})

        # Affine (26x12 combinations, cheap)
        aff = E.affine_candidates(chunk, top=1)
        probe["affine"] = [{"a": a["a"], "b": a["b"], "score": a["score"],
                            "flags": a["flags"]} for a in aff]
        if aff and (aff[0]["flags"] or aff[0]["score"] >= 80):
            out["candidates"].append({
                "attack": "affine", "data": aff[0]["plaintext"].encode(),
                "confidence": aff[0]["confidence"],
                "detail": f"a={aff[0]['a']} b={aff[0]['b']}, score {aff[0]['score']}"})

        # Vigenere (needs enough length to be accurate)
        if len([c for c in chunk if c.isalpha()]) >= 30:
            vig = E.vigenere_recover(chunk)
            probe["vigenere"] = [{"key": v["key"], "score": v["score"],
                                  "ioc": v["ioc"], "flags": v["flags"]} for v in vig[:2]]
            if vig and (vig[0]["flags"] or vig[0]["score"] >= 80):
                out["candidates"].append({
                    "attack": "vigenere", "data": vig[0]["plaintext"].encode(),
                    "confidence": vig[0]["confidence"],
                    "detail": f"key={vig[0]['key']}, IoC={vig[0]['ioc']}, "
                              f"score {vig[0]['score']}"})

        # Rail fence
        fen = E.fence_candidates(chunk, max_rails=8, top=1)
        probe["fence"] = [{"rails": f["rails"], "score": f["score"],
                           "flags": f["flags"]} for f in fen]
        if fen and (fen[0]["flags"] or fen[0]["score"] >= 80):
            out["candidates"].append({
                "attack": "fence", "data": fen[0]["plaintext"].encode(),
                "confidence": fen[0]["confidence"],
                "detail": f"rails={fen[0]['rails']}, score {fen[0]['score']}"})

        out["probes"].append(probe)
    return out
