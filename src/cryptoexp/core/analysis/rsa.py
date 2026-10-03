"""RSA analyzer — parameter sanity check + reachable attack surface + candidate plaintexts

Layering principle (inherited from intelpwn):
  - every attack first checks its precondition, then attempts the solve; a successful
    solve is high confidence, a failure is downgraded to a hint
  - every candidate plaintext carries the attack that produced it, and the verify layer
    decides "confirmed/candidate/not_reproduced"
  - expensive operations (Pollard rho factoring) get a budget; over budget we state
    plainly that factoring did not finish within it
"""

import re

from ...utils import algebra as A


def _suffix_ok(key: str, lab: str) -> bool:
    """Whether a label suffix is acceptable

    n1/n2/c1/e1 (digit suffix) and phi_n/d_p (underscore suffix) are fine;
    but dp must not count as d — once prefix matching is loosened to "any suffix",
    dp is taken for the private exponent and yields garbage plaintext (measured).
    """
    if len(lab) >= 4:
        return True  # long labels like modulus / cipher / prime allow prefix matching
    rest = key[len(lab):]
    return bool(re.fullmatch(r'[0-9][A-Za-z0-9_]*|[A-Za-z0-9_]*_[A-Za-z0-9_]+', rest))

# Common labels → semantics (case-insensitive)
_N_LABELS = ("n", "modulus", "nn")
_E_LABELS = ("e", "e1", "exp", "exponent", "pub")
_C_LABELS = ("c", "cipher", "ct", "ciphertext", "enc", "c1")
_P_LABELS = ("p", "prime1", "prime_p")
_Q_LABELS = ("q", "prime2", "prime_q")
_DP_LABELS = ("dp", "d_p", "dmodp", "dp_leak")
_PHI_LABELS = ("phi", "phin", "phi_n", "eu")
_D_LABELS = ("d", "priv", "private")


def int_to_bytes(x: int) -> bytes:
    """Integer → big-endian byte string (b'\\x00' for 0, never raises)"""
    if x < 0:
        raise ValueError("int_to_bytes: negative value")
    if x == 0:
        return b'\x00'
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def bytes_to_int(b) -> int:
    return int.from_bytes(b, 'big')


def _pick(named, labels):
    """Take the first match from the labeled parameters (case-insensitive)"""
    for lab in labels:
        if lab in named and named[lab]:
            return named[lab][0]
    for key, vals in named.items():
        for lab in labels:
            if key.startswith(lab) and key != lab and _suffix_ok(key, lab) and vals:
                return vals[0]
    return None


def _pick_all(named, labels):
    out = []
    for key, vals in named.items():
        if any(key == lab or (key.startswith(lab) and _suffix_ok(key, lab))
               for lab in labels):
            out.extend(vals)
    return out


def collect_params(ctx: dict) -> dict:
    """Extract the RSA parameters from the context (labels first, bare integers as fallback)"""
    named = ctx.get("named", {})
    params = {
        "n": _pick(named, _N_LABELS),
        "e": _pick(named, _E_LABELS),
        "c": _pick(named, _C_LABELS),
        "p": _pick(named, _P_LABELS),
        "q": _pick(named, _Q_LABELS),
        "dp": _pick(named, _DP_LABELS),
        "phi": _pick(named, _PHI_LABELS),
        "d": _pick(named, _D_LABELS),
        "n_list": _pick_all(named, ("n", "modulus")),
        "c_list": _pick_all(named, ("c",)),
    }
    # Bare-bignum fallback: take the largest few and guess which two look like n
    # (>=256 bits, and coprime so they are distinct moduli).
    big = [i["value"] for i in ctx.get("ints", []) if i["value"].bit_length() >= 256]
    if params["n"] is None and big:
        params["n"] = max(big)
    if not params["n_list"] and big:
        # Several 256-bit+ values are most likely several moduli (broadcast/shared factor)
        params["n_list"] = sorted(set(big), reverse=True)
    if params["e"] is None:
        # Common public exponents
        for cand in (65537, 3, 17):
            if any(i["value"] == cand for i in ctx.get("ints", [])):
                params["e"] = cand
                break
        if params["e"] is None and params["n"] is not None:
            params["e"] = 65537  # default to the most common value, flagged "assumed" in the report
            params["e_assumed"] = True
    if params["c"] is None:
        smaller = [i["value"] for i in ctx.get("ints", [])
                   if params["n"] and i["value"] < params["n"]]
        if smaller and params["n"]:
            if len(smaller) > 1:
                # Closest in bit length to a balanced factor of n
                params["c"] = min(
                    smaller, key=lambda v: abs(v.bit_length() - params["n"].bit_length() // 2))
            else:
                params["c"] = smaller[0]
    return params


def _cand(attack, data, confidence, detail):
    return {"attack": attack, "data": data, "confidence": confidence, "detail": detail}


def _emit(out, res, attack, vtype, severity, confidence, detail_fallback):
    """Single exit point: library result → vuln + candidate

    The analyzer does not implement attacks itself — everything calls utils.rsa_ops,
    one implementation used in both places (the CLI analysis and
    `from cryptoexp import wiener_attack` run the very same code).
    """
    if res.get("ok"):
        out["vulns"].append({"type": vtype, "severity": severity,
                             "confidence": confidence,
                             "detail": res.get("detail") or detail_fallback,
                             "attack": attack})
        if res.get("plaintext"):
            out["candidates"].append(_cand(attack, res["plaintext"], confidence,
                                           res.get("detail") or detail_fallback))
    elif res.get("note"):
        out["notes"].append(f"{vtype}: {res['note']}")


def analyze_rsa(ctx: dict) -> dict:
    """RSA sanity check + attack attempts → {params, vulns, candidates, notes}"""
    from ...utils import rsa_ops as R

    out = {"params": {}, "vulns": [], "candidates": [], "notes": []}
    if not ctx.get("named") and not ctx.get("ints"):
        out["notes"].append("no integer parameters extracted")
        return out

    params = collect_params(ctx)
    n, e, c = params["n"], params["e"], params["c"]
    if n is None:
        out["notes"].append("no modulus n found (need a >=256-bit integer or an n=... label)")
        return out
    out["params"] = {
        "n": n, "e": e, "c": c,
        "n_bits": n.bit_length(),
        "e_bits": (e.bit_length() if e else None),
        "has_p": params["p"] is not None,
        "has_q": params["q"] is not None,
        "has_d": params["d"] is not None,
        "has_dp": params["dp"] is not None,
        "has_phi": params["phi"] is not None,
        "n_count": len(params["n_list"]),
        "e_assumed": params.get("e_assumed", False),
    }
    if params.get("e_assumed"):
        out["notes"].append("challenge gives no e, assuming default e=65537 "
                            "(the other verdicts still hold if that is wrong)")

    p, q = params["p"], params["q"]
    ns = list(dict.fromkeys([v for v in params["n_list"] if v] + ([n] if n else [])))
    cs = [v for v in params["c_list"] if v]

    # ── 1. Private key material already given ──
    if p and q and p * q == n:
        res = R.decrypt_with_factors(n, e, c, p, q) if c is not None else {
            "ok": True, "factors": (p, q), "detail": "p and q given directly"}
        _emit(out, res, "direct", "known factorization", "critical", "high",
              "challenge gives p and q directly")
    elif p and n % p == 0:
        qq = n // p
        res = R.decrypt_with_factors(n, e, c, p, qq) if c is not None else {
            "ok": True, "factors": (p, qq), "detail": "p known and divides n"}
        _emit(out, res, "p_leak", "known p", "critical", "high", "p known → q = n/p")
    if not out["candidates"] and params["phi"]:
        if c is not None:
            res = R.phi_leak_attack(n, e, params["phi"], c)
        else:
            fac = R.factor_from_phi(n, params["phi"])
            res = ({"ok": True, "factors": fac, "detail": "phi known → recover p, q"}
                   if fac else {"ok": False, "note": "recovering p, q from phi failed"})
        _emit(out, res, "phi_leak", "known phi", "critical", "high",
              "phi known → recover p, q")
    if params["d"] and c is not None:
        res = {"ok": True, "plaintext": R.itob(pow(c, params["d"], n)),
               "detail": "d given → decrypt directly"}
        _emit(out, res, "d_given", "known private exponent", "critical", "high",
              "challenge gives d")

    # ── 2. dp leak ──
    if params["dp"] and e:
        res = R.dp_leak_attack(n, e, params["dp"], c)
        _emit(out, res, "dp_leak", "dp leak", "critical", "high",
              "gcd(2^(e*dp)-2, n) → factor")

    # ── 3. Multiple moduli: shared factor / low-exponent broadcast ──
    if len(ns) >= 2 and cs:
        pairs = list(zip(ns, cs))
        res = R.shared_prime_attack([(nv, cv) for nv, cv in pairs])
        _emit(out, res, "shared_prime", "shared prime factor", "critical", "high",
              "two moduli share a prime factor")
        if not out["candidates"] and e and 2 <= e <= 17:
            res = R.broadcast_attack(e, [(nv, cv) for nv, cv in pairs])
            _emit(out, res, "low_exponent_broadcast", "low-exponent broadcast (Håstad)",
                  "critical", "high", f"same e={e} across ciphers, CRT then integer root")
    elif len(ns) >= 2:
        # Only several n's and no c: a shared factor is still a usable conclusion
        for i in range(len(ns)):
            for j in range(i + 1, len(ns)):
                g = A.gcd(ns[i], ns[j])
                if 1 < g < min(ns[i], ns[j]):
                    out["vulns"].append({
                        "type": "shared prime factor", "severity": "critical",
                        "confidence": "high",
                        "detail": f"n{i + 1} and n{j + 1} share a prime factor "
                                  f"(no ciphertext yet, add c to decrypt)",
                        "attack": "shared_prime"})
                    break

    # ── 4. Small public exponent ──
    if not out["candidates"] and e and e <= 17 and c is not None:
        res = R.small_e_attack(n, e, c)
        if res["ok"]:
            _emit(out, res, "small_e_root", "small public exponent (no padding)",
                  "critical", "high", f"e={e}, c is a perfect {e}-th power")
        else:
            out["vulns"].append({
                "type": "small public exponent (needs broadcast)", "severity": "high",
                "confidence": "medium",
                "detail": f"e={e}, but c is not a perfect {e}-th power — needs {e} "
                          f"(n,c) pairs for a broadcast attack",
                "attack": "low_exponent_broadcast"})

    # ── 5. Wiener / Fermat / bounded factoring ──
    if not out["candidates"] and e and n:
        res = R.wiener_attack(e, n, c)
        _emit(out, res, "wiener", "Wiener attack (small d)", "critical", "high",
              "recover d from convergents of e/n")
    if not out["candidates"] and n:
        res = R.fermat_attack(n, e or 65537, c, max_iter=200000)
        _emit(out, res, "fermat", "Fermat factorization (close p, q)", "critical",
              "high", "|p-q| is small, Fermat factors quickly")
    if not out["candidates"] and n and n.bit_length() <= 512:
        res = R.pollard_attack(n, e or 65537, c, max_steps=500000)
        if res["ok"]:
            _emit(out, res, "factor", "n factorable (small/weak primes)", "critical",
                  "high", "Pollard rho factored it within budget")
        else:
            out["notes"].append(f"n is {n.bit_length()} bits, not factored within the "
                                f"500k-step budget (may need lattice or high-bit leakage)")
    elif n and n.bit_length() > 512 and not out["candidates"]:
        out["notes"].append(f"n is {n.bit_length()} bits, skipping blind factoring "
                            f"(needs known high bits / leakage / a shared factor)")

    # ── 6. Honest verdict when nothing is attackable ──
    if not out["vulns"]:
        out["notes"].append("no common attack surface applies (small e / Wiener / Fermat / "
                            "shared factor / small n) — needs extra leakage (high bits, dp, "
                            "several ciphertexts) or the challenge is not RSA")
    return out
