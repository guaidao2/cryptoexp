"""Combined findings and strategy — merge analyzer vulns into one table + recommended routes

Mirrors intelpwn's findings/strategy: severity ordering is decided here alone, analyzers
only report facts and never rank them.
"""

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONF_SCORE = {"high": 3, "medium": 2, "low": 1}


def _collect_vulns(results: dict):
    items = []
    for key in ("rsa", "symmetric", "numbertheory", "lattice"):
        block = results.get(key) or {}
        for v in block.get("vulns", []):
            items.append({
                "source": key,
                "type": v.get("type", "?"),
                "severity": v.get("severity", "medium"),
                "confidence": v.get("confidence", "medium"),
                "detail": v.get("detail", ""),
                "attack": v.get("attack", ""),
                "exploitable": bool(v.get("attack")),
            })
    return items


def generate_findings(results: dict) -> dict:
    """Merge the vuln table + max severity + candidate solution counts"""
    items = _collect_vulns(results)

    # Encoding/classical layer content surfaces as "candidates"; normalize it into the
    # vuln table separately (they are hints, not vulnerabilities)
    for key, label in (("encoding", "encoding candidate"),
                       ("classical", "classical cipher candidate")):
        block = results.get(key) or {}
        cands = block.get("candidates", [])
        if cands:
            best = cands[0]
            items.append({
                "source": key, "type": label,
                "severity": "medium", "confidence": best.get("confidence", "medium"),
                "detail": f"{best['attack']} → {best['detail']}",
                "attack": best["attack"], "exploitable": True,
            })

    max_sev = "low"
    for it in items:
        if _SEV_ORDER.get(it["severity"], 9) < _SEV_ORDER.get(max_sev, 9):
            max_sev = it["severity"]
    if not items:
        max_sev = "info"

    cand_count = sum(len((results.get(k) or {}).get("candidates", []))
                     for k in ("rsa", "encoding", "classical", "symmetric",
                               "numbertheory", "lattice"))
    return {"count": len(items), "max_severity": max_sev, "items": items,
            "candidate_count": cand_count}


def generate_strategy(results: dict) -> list:
    """Recommended routes, ordered by which is most likely to break through first"""
    rsa = results.get("rsa") or {}
    params = rsa.get("params") or {}
    strategies = []
    attacks = {v.get("attack") for v in rsa.get("vulns", [])}

    if params.get("has_p") or params.get("has_q") or params.get("has_d") \
            or params.get("has_phi") or params.get("has_dp"):
        strategies.append({"type": "known private key material", "priority": 1,
                           "why": "challenge gives p/q/d/phi/dp directly, one-step decryption"})
    if {"shared_prime"} & attacks:
        strategies.append({"type": "shared prime factor", "priority": 2,
                           "why": "several moduli share a prime → gcd factors them directly"})
    if {"small_e_root", "low_exponent_broadcast"} & attacks:
        strategies.append({"type": "small-exponent root/broadcast", "priority": 2,
                           "why": "e is tiny and unpadded → integer root or CRT plus root"})
    if {"wiener"} & attacks:
        strategies.append({"type": "Wiener", "priority": 3, "why": "d is too small"})
    if {"fermat", "factor"} & attacks:
        strategies.append({"type": "direct factoring", "priority": 3,
                           "why": "p/q are close, or n is factorable"})
    if (results.get("lattice") or {}).get("coppersmith", {}) and \
            (results["lattice"]["coppersmith"] or {}).get("p"):
        strategies.append({"type": "Coppersmith high-bit factoring", "priority": 2,
                           "why": "high bits of p known → LLL small root"})
    if (results.get("encoding") or {}).get("candidates"):
        strategies.append({"type": "encoding/xor decode", "priority": 4,
                           "why": "multi-layer encoding or xor candidates exist, "
                                  "get plaintext first"})
    if (results.get("classical") or {}).get("candidates"):
        strategies.append({"type": "classical cipher recovery", "priority": 4,
                           "why": "alphabetic text has a high-scoring plaintext candidate"})
    if (results.get("symmetric") or {}).get("mode") == "ECB":
        strategies.append({"type": "ECB structure exploitation", "priority": 4,
                           "why": "repeated blocks prove ECB, byte-level oracle "
                                  "exploitation is possible"})
    if (results.get("numbertheory") or {}).get("lcg"):
        strategies.append({"type": "LCG state prediction", "priority": 4,
                           "why": "parameters recoverable → predict subsequent outputs"})
    if not strategies:
        strategies.append({"type": "no automatic route", "priority": 99,
                           "why": "no common attack surface hit, needs extra leakage "
                                  "or manual analysis"})
    strategies.sort(key=lambda s: s["priority"])
    return strategies
