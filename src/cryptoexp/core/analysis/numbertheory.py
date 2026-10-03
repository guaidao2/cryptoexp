"""Number theory analyzers — LCG recovery / discrete log / MT19937 hints / modular equations

Every sub-check first asks whether the parameters are complete; if not it says exactly
what is missing rather than guessing without grounds.
"""

import re

from ...utils import algebra as A

_SEQ_RE = re.compile(r'[-+]?\d{3,}')


def _pick(named, labels):
    for lab in labels:
        if lab in named and named[lab]:
            return named[lab][0]
    return None


def _number_sequences(text: str, min_len: int = 4):
    """Pull consecutive number sequences in order of appearance (input for LCG recovery)"""
    seqs = []
    for line in text.splitlines():
        nums = [int(m.group(0)) for m in _SEQ_RE.finditer(line)]
        if len(nums) >= min_len:
            seqs.append(nums)
    # Numbers running through the whole text (the prompt spreads its output over lines)
    allnums = [int(m.group(0)) for m in _SEQ_RE.finditer(text)]
    if len(allnums) >= min_len:
        seqs.append(allnums)
    return seqs


def analyze_numbertheory(ctx: dict) -> dict:
    out = {"lcg": None, "dlog": None, "mt19937": False, "vulns": [], "candidates": [],
           "notes": []}
    named = ctx.get("named", {})
    text = ctx.get("raw_text", "")

    # ── 1. LCG: consecutive outputs recover a/c/m, then predict the next term ──
    for seq in _number_sequences(text):
        if len(seq) < 5:
            continue
        rec = A.lcg_recover(seq[:min(len(seq), 12)])
        if rec:
            nxt = (rec["a"] * seq[-1] + rec["c"]) % rec["m"]
            out["lcg"] = {"a": rec["a"], "c": rec["c"], "m": rec["m"],
                          "observed": seq[:6], "next": nxt,
                          "terms_used": len(seq[:12])}
            out["vulns"].append({
                "type": "LCG parameters recoverable", "severity": "high", "confidence": "high",
                "detail": f"a/c/m solved from {len(seq[:12])} consecutive outputs "
                          f"(modulus {rec['m']}), subsequent outputs are predictable",
                "attack": "lcg_recover"})
            out["candidates"].append({
                "attack": "lcg_recover",
                "data": f"next={nxt} (a={rec['a']}, c={rec['c']}, m={rec['m']})".encode(),
                "confidence": "high",
                "detail": "LCG parameter recovery "
                          "(candidate holds the predicted value, not a flag)"})
            break

    # ── 2. Discrete log (small group): g, h, p all present ──
    g = _pick(named, ("g", "generator", "base"))
    h = _pick(named, ("h", "y", "target", "beta"))
    p = _pick(named, ("p", "prime", "mod", "modulus"))
    if g and h and p and p.bit_length() <= 64:
        x = A.bsgs(g, h, p)
        if x is not None:
            out["dlog"] = {"g": g, "h": h, "p": p, "x": x}
            out["vulns"].append({"type": "discrete log (small modulus)", "severity": "high",
                                 "confidence": "high",
                                 "detail": f"BSGS solved x={x}", "attack": "dlog"})
            out["candidates"].append({"attack": "dlog", "data": str(x).encode(),
                                      "confidence": "high",
                                      "detail": "discrete log solution (not a flag)"})
        else:
            out["notes"].append(f"p is {p.bit_length()} bits, BSGS exceeds the memory budget "
                                f"→ needs Pollard rho/Pohlig-Hellman")
    elif g and h and p:
        out["notes"].append(f"discrete log modulus is {p.bit_length()} bits, too large — "
                            f"pure-Python BSGS is not viable")

    # ── 3. MT19937 hints: attachment uses random and plenty of output is given ──
    py_code = "\n".join(item["code"] for item in ctx.get("py", []))
    if py_code and re.search(r'random\.(getrandbits|randint|randrange|random)', py_code):
        outnums = _number_sequences(text)
        count = max((len(s) for s in outnums), default=0)
        out["mt19937"] = True
        conf = "high" if count >= 624 else "medium"
        out["vulns"].append({
            "type": "MT19937 (Python random) hint", "severity": "high", "confidence": conf,
            "detail": f"attachment uses the random module, {count} consecutive outputs "
                      f"visible in the prompt"
                      + (" (>=624 allows a full state clone)" if count >= 624
                         else " (fewer than 624 — needs more output, and watch the "
                              "getrandbits width)"),
            "attack": "mt19937_clone"})

    # ── 4. Modular equation: a*x ≡ b (mod m) ──
    a_ = _pick(named, ("a", "coef", "multiplier"))
    b_ = _pick(named, ("b", "rhs", "value"))
    m_ = _pick(named, ("m", "mod", "modulus"))
    if a_ and b_ and m_:
        inv = A.modinv(a_ % m_, m_)
        if inv is not None:
            x = b_ * inv % m_
            out["vulns"].append({"type": "linear congruence", "severity": "medium",
                                 "confidence": "high",
                                 "detail": f"x ≡ {x} (mod {m_})", "attack": "linear_congruence"})
            out["candidates"].append({"attack": "linear_congruence", "data": str(x).encode(),
                                      "confidence": "high",
                                      "detail": "congruence solution (not a flag)"})

    if not out["vulns"]:
        out["notes"].append("no number-theory attack surface hit "
                            "(LCG / small-group discrete log / MT19937 / congruence)")
    return out
