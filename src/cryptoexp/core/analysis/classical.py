"""Classical cipher analyzer — Caesar / affine / Vigenere / morse / rail fence

Only acts on fragments that look like classical ciphertext: high letter ratio, or a
morse charset. Everything else is skipped explicitly instead of running a meaningless
26x26 brute force — the same "capabilities have gates" stance as intelpwn.
"""

import re

from ...utils import encoding as E

_WORD_RE = re.compile(r'[A-Za-z]{3,}')
_MORSE_RE = re.compile(r'^[.\-/|\s]+$')
# Encoded-blob kinds that make shift/affine scoring meaningless (morse keeps its own
# branch: its charset is clear, so decoding it is right and guessing is not).
_ENC_KINDS = frozenset(("hex", "base64", "base32", "base58", "binary"))
_HEX_SHAPE_RE = re.compile(r'^[0-9a-fA-F]+$')
_B64_SHAPE_RE = re.compile(r'^[A-Za-z0-9+/=_-]+$')


def _blob_kind_in(ctx: dict, text: str):
    """(kind, exact) for a context blob this text is or contains, else (None, False)

    `exact` is True only when the text IS the blob. A mere CONTAINMENT is reported but
    not acted on by itself: the blob extractor splits brace-delimited classical
    ciphertexts, so `cixd{zxbpxo_fp_zixppfz}` yields the pseudo-blob
    `zxbpxo_fp_zixppfz`, and deferring on containment alone silently deleted the
    genuine Caesar sample (`challenges/classical_caesar.txt`) - exactly the regression
    that must not happen. Containment therefore only defers when the chunk is itself
    encoded-shaped, which such a ciphertext is not.
    """
    for blob in ctx.get("blobs", []):
        blob_text = (blob.get("text") or "").strip()
        kinds = [k for k in (blob.get("kinds") or []) if k in _ENC_KINDS]
        if not blob_text or not kinds:
            continue
        if text == blob_text:
            return kinds[0], True
        if blob_text in text:
            return kinds[0], False
    return None, False


def _encoded_deferral(ctx: dict, chunk: str):
    """Why this chunk is encoded data rather than a classical ciphertext, else None

    Shift/affine scoring on an encoded blob is meaningless and actively harmful: the
    alphabet of base64/hex is not the alphabet of a substitution cipher, so the score
    it produces is noise, and the candidate it turns into adds a "classical cipher
    recovery" route that pushes the route which actually matters (decode first) down
    the recommendation list. Reported by a user: a base64 blob scored as
    "caesar shift=5 score 80.72" and a hex blob as "caesar shift=23", both with
    "classical cipher recovery" in the recommended path (2026-10-04).

    Two gates, same stance as the morse gate below:
      * the context already extracted this exact text as a blob and classified it as an
        encoding - the encoding analyzer owns it, not us;
      * the text is pure-hex or base64-shaped, which is a property of the string
        itself, so it is deferred even when the blob extractor missed it.
    The return value is the reason, phrased for the note.
    """
    text = chunk.strip()
    kind, exact = _blob_kind_in(ctx, text)
    if exact:
        return "this looks like a %s string" % kind
    body = re.sub(r'\s', '', text)
    if len(body) >= 8 and _HEX_SHAPE_RE.match(body):
        return "this looks like a hex string"
    # Base64 shape alone is not enough: an alphabetic word is also a valid base64
    # alphabet, and a bare Caesar ciphertext is exactly that. So a 12+ character body
    # additionally needs one non-letter base64 character; 16+ base64 runs are already
    # covered by the blob gate above.
    if len(body) >= 12 and _B64_SHAPE_RE.match(body) \
            and any(not c.isalpha() for c in body) and E.from_base64(body) is not None:
        return "this looks like a %s string" % (kind or "base64")
    return None


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


def _candidate(attack: str, data: bytes, best: dict, detail: str) -> dict:
    """Build a candidate dict, carrying the reason its confidence tier was capped

    `best` is one entry from the encoding-layer brute forces, whose `note` explains a
    non-"high" tier (no known flag prefix matched). Appending it to `detail` keeps the
    why next to the candidate instead of only in the library result.
    """
    note = best.get("note") or ""
    return {"attack": attack, "data": data, "confidence": best["confidence"],
            "detail": detail + (" (%s)" % note if note else "")}


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

    deferred = []
    for chunk in chunks:
        # Gate: an encoded blob is the encoding analyzer's job. Producing a caesar or
        # affine candidate from it is a meaningless score that then outranks the decode
        # route (see _encoded_deferral). Deferred chunks are reported after the scored
        # ones so that `probes[0]` - which the solve generator inlines as the
        # ciphertext - still belongs to a chunk that was actually scored.
        reason = _encoded_deferral(ctx, chunk)
        if reason is not None:
            note = "deferred: %s - analyse the decoded bytes instead" % reason
            out["notes"].append(note)
            deferred.append({"text": chunk[:60], "full_text": chunk, "morse": None,
                             "caesar": [], "affine": [], "vigenere": [], "fence": [],
                             "deferred": True, "note": note})
            continue
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
                    mflags = E.flag_candidates(dec.encode())
                    note = E.confidence_note(dec.encode(), mflags)
                    out["candidates"].append({
                        "attack": "morse", "data": dec.encode(),
                        "confidence": E.confidence_of(sc, bool(mflags)),
                        "detail": f"morse decode, score {sc:.1f}"
                                  + (f" ({note})" if note else "")})
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
            out["candidates"].append(_candidate(
                "caesar", cas[0]["plaintext"].encode(), cas[0],
                f"shift={cas[0]['shift']}, score {cas[0]['score']}"))

        # Affine (26x12 combinations, cheap)
        aff = E.affine_candidates(chunk, top=1)
        probe["affine"] = [{"a": a["a"], "b": a["b"], "score": a["score"],
                            "flags": a["flags"]} for a in aff]
        if aff and (aff[0]["flags"] or aff[0]["score"] >= 80):
            out["candidates"].append(_candidate(
                "affine", aff[0]["plaintext"].encode(), aff[0],
                f"a={aff[0]['a']} b={aff[0]['b']}, score {aff[0]['score']}"))

        # Vigenere (needs enough length to be accurate)
        if len([c for c in chunk if c.isalpha()]) >= 30:
            vig = E.vigenere_recover(chunk)
            probe["vigenere"] = [{"key": v["key"], "score": v["score"],
                                  "ioc": v["ioc"], "flags": v["flags"]} for v in vig[:2]]
            if vig and (vig[0]["flags"] or vig[0]["score"] >= 80):
                out["candidates"].append(_candidate(
                    "vigenere", vig[0]["plaintext"].encode(), vig[0],
                    f"key={vig[0]['key']}, IoC={vig[0]['ioc']}, score {vig[0]['score']}"))

        # Rail fence
        fen = E.fence_candidates(chunk, max_rails=8, top=1)
        probe["fence"] = [{"rails": f["rails"], "score": f["score"],
                           "flags": f["flags"]} for f in fen]
        if fen and (fen[0]["flags"] or fen[0]["score"] >= 80):
            out["candidates"].append(_candidate(
                "fence", fen[0]["plaintext"].encode(), fen[0],
                f"rails={fen[0]['rails']}, score {fen[0]['score']}"))

        out["probes"].append(probe)
    out["probes"].extend(deferred)
    return out
