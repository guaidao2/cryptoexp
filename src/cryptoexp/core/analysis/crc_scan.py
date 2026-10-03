"""CRC-family analysis: catalog lookup, parameter recovery, and preimage solving.

Why this analyzer exists: a whole class of CTF tasks hands you a CRC value and asks
for the bytes behind it ("the checker compares the CRC of your input"). That is not a
guessing game — CRC is affine over GF(2), so a fixed-length unknown field is a linear
system. This module recognises the task from the statement, picks the CRC parameters
(from an explicit mention or from the standard catalog) and solves the preimage.

Everything it reports carries its own verification: the recovered bytes are fed back
through the CRC engine, so a "confirmed" candidate here cannot be a coincidence.
"""

import re

from ...utils import gf2 as G

# "CRC-32", "CRC32", "CRC-16/CCITT-FALSE", "crc_32"
_NAME_RE = re.compile(r'\bcrc[-_ ]?(8|16|32|64)(?:[/\-_ ]([A-Za-z0-9]{2,}))?', re.I)
_HEX_RE = re.compile(r'0x([0-9a-fA-F]{1,16})')
_TARGET_RE = re.compile(r'(?:target|expected|want|goal|checksum)[^0-9a-fA-F]{0,12}'
                        r'0x([0-9a-fA-F]{1,16})', re.I)
_PREFIX_RE = re.compile(r'prefix\s*=\s*"([^"]*)"', re.I)
_SUFFIX_RE = re.compile(r'suffix\s*=\s*"([^"]*)"', re.I)
_UNKNOWN_RE = re.compile(r'(?:unknown|hidden)\D{0,20}?(\d+)\s*(?:byte|char)', re.I)
_FLAG_BODY_RE = re.compile(r'flag\{([^{}]*)\}')


def _catalog_match(text: str):
    """Find the most specific CRC catalog entry named in the statement"""
    best = None
    for m in _NAME_RE.finditer(text):
        width = int(m.group(1))
        variant = (m.group(2) or "").strip().upper()
        for name, spec in G.crc_known().items():
            if spec["width"] != width:
                continue
            if variant and variant not in name.upper().replace("CRC-", ""):
                continue
            # a named variant beats a bare width; the first specific hit wins
            if variant:
                return name, spec
            if best is None:
                best = (name, spec)
    return best if best else (None, None)


def _explicit_params(text: str, spec: dict) -> dict:
    """Explicit poly/init/xorout/refin/refout mentions override the catalog"""
    params = dict(spec) if spec else {}
    if not params:
        width = None
        m = _NAME_RE.search(text)
        if m:
            width = int(m.group(1))
        params = {"width": width, "poly": None, "init": 0, "xorout": 0,
                  "refin": False, "refout": False}
    poly = re.search(r'poly\s*=?\s*0x([0-9a-fA-F]+)', text, re.I)
    if poly:
        params["poly"] = int(poly.group(1), 16)
    for field, pattern in (("init", r'init\s*=?\s*0x([0-9a-fA-F]+)'),
                           ("xorout", r'xorout\s*=?\s*0x([0-9a-fA-F]+)')):
        hit = re.search(pattern, text, re.I)
        if hit:
            params[field] = int(hit.group(1), 16)
    for field in ("refin", "refout"):
        hit = re.search(rf'{field}\s*=?\s*(true|false|1|0)', text, re.I)
        if hit:
            params[field] = hit.group(1).lower() in ("true", "1")
    return params


def analyze_crc(ctx: dict, effort: str = "normal") -> dict:
    """Detect CRC tasks and run the mechanical paths (pure function of the statement)"""
    out = {"notes": [], "candidates": [], "params": {}, "vulns": []}
    text = ctx.get("raw_text") or ""
    if "crc" not in text.lower():
        out["notes"].append("no CRC mention in the statement")
        return out

    name, spec = _catalog_match(text)
    if name:
        out["notes"].append(f"CRC catalog entry matched: {name}")
    params = _explicit_params(text, spec)
    out["params"] = {k: v for k, v in params.items() if k != "aliases"}

    width = params.get("width")
    poly = params.get("poly")
    if not width or poly is None:
        out["notes"].append("CRC mentioned but the width/polynomial is not identifiable "
                           "from the statement; supply poly=0x... (and width) to go on")
        return out

    # ── preimage: a known prefix/suffix with a fixed-length unknown field ──
    prefix_m = _PREFIX_RE.search(text)
    suffix_m = _SUFFIX_RE.search(text)
    unknown_m = _UNKNOWN_RE.search(text)
    target_m = _TARGET_RE.search(text)
    flag_m = _FLAG_BODY_RE.search(text)
    prefix = prefix_m.group(1).encode() if prefix_m else b""
    suffix = suffix_m.group(1).encode() if suffix_m else b""
    unknown_len = int(unknown_m.group(1)) if unknown_m else None
    if unknown_len is None and flag_m:
        # "the flag has the form flag{????}" -> the body length is the unknown length
        unknown_len = len(flag_m.group(1)) or None
        if not prefix:
            prefix = b"flag{"
            suffix = b"}"
    target = None
    if target_m:
        target = int(target_m.group(1), 16)
    else:
        hexes = [int(h, 16) for h in _HEX_RE.findall(text)]
        cands = [h for h in hexes if h < (1 << width) and h != poly]
        if len(cands) == 1:
            target = cands[0]

    if target is not None and unknown_len:
        out["params"].update({"prefix": prefix, "suffix": suffix,
                              "unknown_len": unknown_len, "target": target})
        res = G.crc_solve_unknown(prefix, suffix, target, width, poly, unknown_len,
                                  params.get("init", 0), params.get("refin", False),
                                  params.get("refout", False), params.get("xorout", 0))
        if res["ok"]:
            note = ("unique solution" if res["unique"]
                    else f"{res['free_bits']} free bit(s): one of several valid "
                         f"preimages, the CRC is matched but the bytes may differ from "
                         f"the original")
            out["candidates"].append({
                "attack": "crc_preimage",
                "data": res["data"],
                "confidence": "high" if res["unique"] else "medium",
                "detail": f"CRC-{width} preimage by GF(2) linear algebra; {note}",
            })
            out["vulns"].append({"attack": "crc_preimage", "confidence": "high",
                                 "detail": note})
        else:
            out["notes"].append(res.get("note", "CRC preimage failed"))

    # ── forgery: append bytes to an existing message to hit a target ──
    if target is not None and prefix and not unknown_len:
        appended = G.crc_forge_append(prefix, target, width, poly, params.get("init", 0),
                                      params.get("refin", False), params.get("refout", False),
                                      params.get("xorout", 0))
        if appended:
            out["vulns"].append({
                "attack": "crc_forge",
                "confidence": "high",
                "detail": f"append {appended.hex()} to reach CRC 0x{target:x}",
            })
            out["notes"].append("CRC forgery: the checker's own CRC can be satisfied by "
                                "appending 4 bytes (linearity), no secret needed")
    return out


__all__ = ["analyze_crc"]
