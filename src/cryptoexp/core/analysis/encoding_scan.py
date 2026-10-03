"""Encoding analyzer — decode chains + xor cracking

Each blob is processed alone; it yields candidates, never verdicts.
"""

from ...utils import encoding as E


def analyze_encoding(ctx: dict, max_blobs: int = 20, effort: str = "normal") -> dict:
    """Encoding / xor analysis

    Performance tradeoff (measured): full 256-key repeating-xor with multi-start hill
    climbing is valuable but slow, and running it on every blob drags one analysis into
    minutes. So there are two tiers here:
      - single-byte xor: cheap, tried on every blob
      - repeating xor: only on the first few blobs that are long enough and unsolved,
        with a low budget
    For a more thorough pass run `cryptoexp_cli.py hypotheses` (the hypothesis engine runs
    everything) or call the library directly.
    """
    out = {"blobs": [], "candidates": [], "notes": []}
    blobs = ctx.get("blobs", [])[:max_blobs]
    if not blobs:
        out["notes"].append("no suspected encoded/ciphertext string found")
        return out
    solved = False
    # Repeating xor is valuable but slow: by default give only the first decent blob one
    # **full** attempt (measured: a reduced configuration became the root cause of
    # "cannot solve it", while running more blobs only burns time)
    rep_budget = {"fast": 0, "normal": 1, "max": 4}.get(effort, 1)

    for idx_blob, blob in enumerate(blobs):
        # `text` is display-truncated; `full_text` is what code generators must use
        # (a truncated ciphertext silently yields a wrong solve script)
        entry = {"text": blob["text"][:80], "full_text": blob["text"],
                 "source": blob["source"], "kinds": blob["kinds"],
                 "length": blob["length"], "chain": [], "xor": [],
                 "repeating_xor": []}
        text = blob["text"]
        # Gate: a plain decimal string is an RSA parameter, not XOR ciphertext
        if text.strip().isdigit():
            entry["note"] = "decimal string (RSA-style parameter), no encoding analysis"
            out["blobs"].append(entry)
            continue
        # Gate: a pure morse string gets no xor cracking (clear charset, xor only adds noise)
        if blob["kinds"] and set(blob["kinds"]) == {"morse"}:
            entry["note"] = "pure morse string, handed to the classical analyzer, no xor"
            out["blobs"].append(entry)
            continue

        # Gate: a source file is the analyst's own tooling, not ciphertext. Probing
        # `import gmpy2` with caesar/xor scored 77 and landed in the report as a
        # "classical cipher candidate" (reported 2026-10-03).
        source_names = {p.get("name") for p in ctx.get("py", [])}
        if str(blob.get("source")) in source_names or \
                str(blob.get("source", "")).endswith((".py", ".sage", ".sh")):
            entry["note"] = ("source-code file, not ciphertext: no decode/xor probes "
                             "(the code itself is the analyst's tooling)")
            out["blobs"].append(entry)
            continue

        # 1) Multi-layer decode chain
        chain = E.decode_chain(text, max_layers=3)
        entry["chain"] = [{k: c[k] for k in ("steps", "score", "confidence", "flags")}
                          for c in chain[:3]]
        for rank, c in enumerate(chain[:2]):
            # Top candidate only: that is E.confidence_of's highest tier
            # (flag hit or very high score)
            if c["flags"] or rank == 0:
                out["candidates"].append({
                    "attack": "decode_chain:" + "→".join(c["steps"]),
                    "data": c["data"], "confidence": c["confidence"],
                    "detail": f"score {c['score']} ({blob['source']})",
                })
                solved = solved or bool(c["flags"])

        # 2) Single-byte xor (cheap, tried on every blob)
        views = []
        if "hex" in blob["kinds"]:
            d = E.from_hex(text)
            if d:
                views.append(("hex", d))
        try:
            views.append(("raw", text.encode('latin-1')))
        except UnicodeEncodeError:
            pass
        for label, raw in views:
            if len(raw) < 4:
                continue
            tops = E.single_byte_xor(raw, top=3)
            entry["xor"].append({"view": label, "top": [
                {"key": t["key"], "score": t["score"], "flags": t["flags"]} for t in tops]})
            best = tops[0]
            if best["flags"] or best["score"] >= 70:
                out["candidates"].append({
                    "attack": "single_byte_xor", "data": best["plaintext"],
                    "confidence": best["confidence"],
                    "detail": f"key=0x{best['key']:02x}, score {best['score']} ({label})",
                })
                solved = solved or bool(best["flags"])

            # 3) Repeating-key xor (expensive → capped count + length)
            #    Length gate: real XOR ciphertext is usually tens of bytes; a few-hundred
            #    bit hex RSA parameter burning a full hill climb wastes tens of seconds
            #    (measured: a 16-challenge batch went from 76s to 278s)
            if rep_budget > 0 and 16 <= len(raw) <= 128:
                rep_budget -= 1
                reps = E.repeating_key_xor(raw, max_ks=min(32, max(4, len(raw) // 2)))
                if reps:
                    entry["repeating_xor"] = [{
                        "keysize": r["keysize"], "key": r["key"].decode('latin-1'),
                        "score": r["score"], "flags": r["flags"],
                        "confidence": r["confidence"]} for r in reps[:3]]
                    top = reps[0]
                    if top["flags"] or top["score"] >= 90:
                        out["candidates"].append({
                            "attack": "repeating_key_xor", "data": top["plaintext"],
                            "confidence": top["confidence"],
                            "detail": f"keylen={top['keysize']} key={top['key']!r} "
                                      f"score {top['score']}",
                        })
                        solved = solved or bool(top["flags"])
        out["blobs"].append(entry)
        if solved and effort != "max":
            out["notes"].append("flag already recovered from an earlier blob, "
                                "remaining blobs only get a light check")
            for rest in blobs[idx_blob + 1:]:
                out["blobs"].append({
                    "text": rest["text"][:80], "full_text": rest["text"],
                    "source": rest["source"],
                    "kinds": rest["kinds"], "length": rest["length"],
                    "chain": [], "xor": [], "repeating_xor": []})
            break
    return out
