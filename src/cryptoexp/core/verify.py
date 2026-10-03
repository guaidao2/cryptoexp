"""Candidate verification — three-state decision (confirmed / candidate / not_reproduced).

The counterpart of intelpwn's cross_validate, plus one strong check that is specific
to crypto: an RSA-family candidate plaintext can be **re-encrypted** and compared
against the ciphertext. That upgrades a result from "looks like a flag" to
"mathematically correct".

Principles (inherited from intelpwn):
  - verify whenever verification exists, never decide by "looks readable"
  - what cannot be verified is not denied: mark it "candidate" and say why
  - intermediate values (p/q/d/predictions) are never called "not_reproduced"
"""

from .analysis.rsa import bytes_to_int

# Attacks that produce a plaintext (verifiable)
_PLAINTEXT_ATTACKS = {
    "direct", "p_leak", "phi_leak", "d_given", "dp_leak", "factor", "fermat",
    "wiener", "shared_prime", "small_e_root", "low_exponent_broadcast",
    "single_byte_xor", "repeating_key_xor", "caesar", "affine", "vigenere",
    "morse", "fence", "decode_chain",
}
# Attacks that produce an intermediate value (parameters / predictions / indices)
_INTERMEDIATE_PREFIX = ("knapsack", "lcg", "dlog", "linear_congruence",
                        "coppersmith", "mt19937")


def _is_intermediate(attack: str) -> bool:
    return any(attack.startswith(p) for p in _INTERMEDIATE_PREFIX)


def _printable_ok(data: bytes) -> bool:
    if not data:
        return False
    good = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(data) >= 0.9


# Result keys that carry no candidates (nested/aggregate views of the same run)
_NON_CANDIDATE_KEYS = {
    "target", "context", "env", "effort", "_ctx", "strategy", "summary",
    "hypotheses", "verification", "error",
}


def iter_candidates(results: dict):
    """Yield {"source": key, **candidate} for every analyzer that produced candidates

    Deliberately dynamic: a newly registered analyzer participates in verification,
    the report and the JSON contract without editing a list of key names here, which
    is the same extensibility rule the analyzer/solver registries follow.
    """
    for key, value in (results or {}).items():
        if key in _NON_CANDIDATE_KEYS or key.startswith("_") or not isinstance(value, dict):
            continue
        for cand in value.get("candidates") or []:
            if isinstance(cand, dict):
                yield {**cand, "source": key}


def verify_candidates(results: dict, candidates=None) -> dict:
    """Three-state decision over every candidate.

    Returns:
        {"entries": [...], "verdict": str, "best": {...}|None, "caveats": [...]}
    """
    from ..utils import encoding as E
    if candidates is None:
        candidates = list(iter_candidates(results))

    params = (results.get("rsa") or {}).get("params") or {}
    n, e, c = params.get("n"), params.get("e"), params.get("c")

    # The statement is not evidence about itself. A challenge that explains the flag
    # format ("The flag format is flag{EXAMPLE_FLAG_NOT_THE_ANSWER}") used to be
    # reported as `confirmed`, because the classical analyzer probes the statement text
    # and any strict flag shape was accepted. A match that is already present verbatim
    # in the statement proves nothing, so it is downgraded to a candidate.
    raw_text = (results.get("_ctx") or {}).get("raw_text") or ""
    if not raw_text:
        raw_text = results.get("raw") or ""
    if isinstance(raw_text, bytes):
        raw_text = raw_text.decode("utf-8", errors="replace")

    entries = []
    for cand in candidates:
        data = cand.get("data", b"")
        if isinstance(data, str):
            data = data.encode()
        attack = cand.get("attack", "?")
        entry = {"attack": attack, "source": cand.get("source", "?"),
                 "confidence": cand.get("confidence", "medium"),
                 "detail": cand.get("detail", ""),
                 "preview": data[:80].decode('utf-8', errors='replace'),
                 "length": len(data)}
        flags = E.flag_candidates(data, prefixes=results.get("flag_prefixes"),
                                  pattern=results.get("flag_pattern"))
        loose = E.loose_flag_candidates(data, prefixes=results.get("flag_prefixes"),
                                       pattern=results.get("flag_pattern"))

        if _is_intermediate(attack):
            entry.update({
                "state": "candidate",
                "note": "intermediate value (parameters/prediction/indices); "
                        "plaintext check does not apply",
            })
            entries.append(entry)
            continue

        # 1) strict flag shape -- strongest evidence, unless the statement itself
        # already contains that exact string (then it is an example, not an answer)
        if flags:
            from_statement = bool(raw_text) and flags[0] in raw_text
            if from_statement:
                entry.update({"state": "candidate",
                              "note": f"flag-shaped match {flags[0][:60]} appears verbatim "
                                      f"in the challenge statement - an example, not an "
                                      f"answer, so it cannot confirm itself",
                              "flags": flags})
            else:
                entry.update({"state": "confirmed",
                              "note": f"matches known flag format: {flags[0][:60]}",
                              "flags": flags})
            entries.append(entry)
            continue

        # 2) RSA re-encryption cross-check
        if attack in _PLAINTEXT_ATTACKS and n and e and c is not None and data:
            try:
                m = bytes_to_int(data)
                if pow(m, e, n) == c:
                    entry.update({"state": "confirmed",
                                  "note": "re-encrypts to the original ciphertext "
                                          "(pow(m,e,n)==c) -- mathematically verified"})
                    entries.append(entry)
                    continue
            except Exception:
                pass

        # 3) readability (order: strict flag -> re-encryption -> loose flag -> readability)
        score = E.score_text(data)
        if loose:
            entry.update({"state": "candidate",
                          "note": f"flag-like shape but prefix not in the known list: "
                                  f"{loose[0][:48]} (garbage can match by accident)",
                          "score": round(score, 2)})
        elif _printable_ok(data) and score >= 55:
            entry.update({"state": "candidate",
                          "note": f"printable, text score {score:.1f}, "
                                  f"but no strong verification yet",
                          "score": round(score, 2)})
        else:
            entry.update({"state": "not_reproduced",
                          "note": f"not readable (text score {score:.1f}, printable "
                                  f"{E.printable_ratio(data):.2f}) -- this attack likely fails",
                          "score": round(score, 2)})
        entries.append(entry)

    states = [e["state"] for e in entries]
    if "confirmed" in states:
        verdict = "confirmed (at least one candidate passed a strong check)"
    elif "candidate" in states:
        verdict = "candidates only (no strong check passed, needs a human look)"
    elif "not_reproduced" in states:
        verdict = "not reproduced (every candidate is unreadable)"
    else:
        verdict = "no candidate (needs extra leakage or a hand-written idea)"

    caveats = [f"{e['attack']}: {e['note']}" for e in entries
               if e["state"] == "not_reproduced"]
    best = None
    for want in ("confirmed", "candidate"):
        hit = next((e for e in entries if e["state"] == want), None)
        if hit:
            best = hit
            break
    return {"entries": entries, "verdict": verdict, "best": best, "caveats": caveats}
