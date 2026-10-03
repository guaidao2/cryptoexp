"""Hypothesis engine — crypto challenges cannot be cracked by template matching alone,
so this layer organises the knowledge differently.

The trouble with templates: a matching predicate emits a script, a non-match gives
nothing useful, and the long tail of crypto challenges is endless — the real work is
"read the construction → decide which class of attack applies → find the missing piece".

So this layer writes knowledge as **hypothesis entries**, each of them declaring:
    needs     which known quantities are required → when unmet it names what is missing
    condition applicability test
    idea      the principle in one line
    gives     what running it yields
    run       actually try it (reuses the library layer, no second implementation)
    state     confirmed / candidate / not_reproduced / not_applicable

It outputs two kinds of things:
  1) the **results** of applicable hypotheses (with three-state verification)
  2) the **gap list** of inapplicable ones — executable next steps like "get X and Y works"
That is exactly what the long tail needs: for an unseen construction you still know
which direction to look for the missing piece.
"""

from .utils import algebra as A
from .utils import encoding as E
from .utils import lattice as L
from .utils import prng as PR
from .utils import rsa_ops as R
from .utils.dlp import discrete_log, dlog_feasibility

_HYPOTHESES = []


def register_hypothesis(name, domain, idea, needs, condition, run,
                        gives="plaintext/parameters", cost="cheap", confidence="medium",
                        missing=None):
    """Register one hypothesis (a decorator would work too; explicit calls keep
    dynamic registration easy)"""
    _HYPOTHESES.append({
        "name": name, "domain": domain, "idea": idea, "needs": tuple(needs),
        "condition": condition, "run": run, "gives": gives, "cost": cost,
        "confidence": confidence, "missing": missing,
    })
    return name


def list_hypotheses():
    return [(h["name"], h["domain"], h["cost"]) for h in _HYPOTHESES]


# ────────────────────────── parameter normalisation ──────────────────────────

def params_from_ctx(ctx: dict) -> dict:
    """Normalise the blackboard ctx into the parameter dict the engine consumes"""
    from .core.analysis.rsa import collect_params
    raw = collect_params(ctx)
    p = {
        "n": raw.get("n"), "e": raw.get("e"), "c": raw.get("c"),
        "p": raw.get("p"), "q": raw.get("q"), "dp": raw.get("dp"),
        "phi": raw.get("phi"), "d": raw.get("d"),
        "n_list": raw.get("n_list") or [], "c_list": raw.get("c_list") or [],
        "named": ctx.get("named", {}),
        "text": ctx.get("raw_text", ""),
        "code": "\n".join(item["code"] for item in ctx.get("py", [])),
        "datas": [d["data"] for d in ctx.get("data", []) if len(d.get("data", b"")) >= 16],
        "blobs": [b["text"] for b in ctx.get("blobs", [])],
        "flags_found": [],
    }
    named = ctx.get("named", {})
    g = next((named[k][0] for k in named if k in ("g", "generator", "base")), None)
    h = next((named[k][0] for k in named if k in ("h", "y", "target", "beta")), None)
    mod = next((named[k][0] for k in named if k in ("p", "mod", "prime")), None)
    p["g"], p["h"], p["mod"] = g, h, mod
    # consecutive numeric sequences (LCG / MT outputs)
    p["sequences"] = _sequences(p["text"])
    return p


def _sequences(text: str, min_len: int = 4):
    import re
    out = []
    for line in text.splitlines():
        nums = [int(m.group(0)) for m in re.finditer(r'[-+]?\d{3,}', line)]
        if len(nums) >= min_len:
            out.append(nums)
    allnums = [int(m.group(0)) for m in re.finditer(r'[-+]?\d{3,}', text)]
    if len(allnums) >= min_len:
        out.append(allnums)
    return out


# ────────────────────────── RSA hypotheses ──────────────────────────

def _has(d, *keys):
    return all(d.get(k) for k in keys)


def _rsa(name, idea, needs, cond, runner, gives="plaintext", confidence="high",
         cost="cheap"):
    register_hypothesis(name, "rsa", idea, needs, cond, runner,
                        gives=gives, confidence=confidence, cost=cost)


_rsa("rsa_direct", "p and q are given → derive d and decrypt directly", ("p", "q", "e", "c"),
     lambda d: _has(d, "p", "q", "n") and d["p"] * d["q"] == d["n"],
     lambda d: R.decrypt_with_factors(d["n"], d["e"] or 65537, d["c"], d["p"], d["q"])
     if d.get("c") else {"ok": True, "detail": "factored (no c, so cannot decrypt)"})

_rsa("rsa_phi_leak", "phi leaked → recover p and q (p+q = n-phi+1)", ("phi", "n"),
     lambda d: _has(d, "phi", "n"),
     lambda d: R.phi_leak_attack(d["n"], d["e"] or 65537, d["phi"], d.get("c")))

_rsa("rsa_d_leak", "private exponent d given → decrypt directly", ("d", "c"),
     lambda d: _has(d, "d", "c"),
     lambda d: {"ok": True, "plaintext": R.itob(pow(d["c"], d["d"], d["n"])),
                "detail": "d known → decrypt directly"})

_rsa("rsa_dp_leak", "dp leak: gcd(2^(e·dp)-2, n) yields p", ("dp", "e", "n"),
     lambda d: _has(d, "dp", "e", "n"),
     lambda d: R.dp_leak_attack(d["n"], d["e"], d["dp"], d.get("c")))

_rsa("rsa_factor_from_d", "(n, e, d) known → factor n back out", ("n", "e", "d"),
     lambda d: _has(d, "n", "e", "d") and not d.get("p"),
     lambda d: (lambda f: {"ok": bool(f), "plaintext": None, "factors": f,
                           "detail": "factored from d"} if f else
                {"ok": False, "note": "factoring from d failed"})(
         R.factor_from_d(d["n"], d["e"], d["d"])))

_rsa("rsa_shared_prime", "two moduli share a prime factor → gcd factors them instantly",
     ("n×2", "c×2"),
     lambda d: len({v for v in d["n_list"] if v}) >= 2,
     lambda d: R.shared_prime_attack(list(zip(d["n_list"], d["c_list"])))
     if d["c_list"] else {"ok": False, "note": "several n given but no ciphertext"})

_rsa("rsa_common_modulus", "same n, two coprime exponents → m = c1^a·c2^b",
     ("n", "e1", "c1", "e2", "c2"),
     lambda d: _has(d, "n") and len(d["named"].get("e", [])) >= 2
     and len(d["named"].get("c", [])) >= 2,
     lambda d: R.common_modulus_attack(
         d["n"], d["named"]["e"][0], d["named"]["c"][0],
         d["named"]["e"][1], d["named"]["c"][1]),
     cost="cheap")

_rsa("rsa_small_e", "e tiny and no padding → take the e-th root of c", ("e≤17", "c"),
     lambda d: d.get("e") and d["e"] <= 17 and d.get("c"),
     lambda d: R.small_e_attack(d["n"], d["e"], d["c"]) if d.get("n")
     else {"ok": False, "note": "missing n"})

_rsa("rsa_broadcast", "e ciphertexts under the same e → CRT then take the root (Håstad)",
     ("e≤17", "e pairs of (n, c)"),
     lambda d: d.get("e") and 2 <= d["e"] <= 17
     and len(d["n_list"]) >= d["e"] and len(d["c_list"]) >= d["e"],
     lambda d: R.broadcast_attack(d["e"], list(zip(d["c_list"], d["n_list"]))))

_rsa("rsa_wiener", "d too small → a convergent of the continued fraction of e/n",
     ("n", "e"),
     lambda d: _has(d, "n", "e"),
     lambda d: R.wiener_attack(d["e"], d["n"], d.get("c")))

_rsa("rsa_fermat", "p and q close together → Fermat factorisation", ("n",),
     lambda d: _has(d, "n"),
     lambda d: R.fermat_attack(d["n"], d["e"] or 65537, d.get("c"), max_iter=200000),
     cost="moderate")

_rsa("rsa_pollard", "n small enough → bounded Pollard rho factorisation", ("n",),
     lambda d: d.get("n") and d["n"].bit_length() <= 512,
     lambda d: R.pollard_attack(d["n"], d["e"] or 65537, d.get("c"), max_steps=500000),
     cost="expensive")

_rsa("rsa_known_high_bits", "high bits of p known → Coppersmith small roots",
     ("n", "high bits of p", "known bit count"),
     lambda d: _has(d, "n") and any(k in d["named"] for k in
                                    ("p_high", "phigh", "hint", "p_hint", "known_p")),
     lambda d: R.known_high_bits_attack(
         d["n"], next(d["named"][k][0] for k in
                      ("p_high", "phigh", "hint", "p_hint", "known_p")
                      if k in d["named"]),
         None or (next(d["named"][k][0] for k in ("p_high", "phigh", "hint", "p_hint", "known_p")
                       if k in d["named"]).bit_length()),
         e=d.get("e"), c=d.get("c")),
     cost="expensive")


def _rsa_missing_high_bits(d):
    if not any(k in d["named"] for k in ("p_high", "phigh", "hint", "p_hint", "known_p")):
        return ["high bits of p (common phrasing: p_high = 0x…, plus how many bits are known)"]
    return []


# ────────────────────────── lattice / number theory / PRNG ──────────────────────────

def _knapsack_ready(d):
    """Guard for both knapsack hypotheses.

    `_weights_target` returns a (weights, target) tuple whose members can be None;
    a truthiness test on the tuple is always True, which previously crashed the
    runner with `TypeError: object of type 'NoneType' has no len()`.
    """
    wt = _weights_target(d)
    return bool(wt and wt[0] and wt[1]), wt


register_hypothesis(
    "knapsack_lll", "lattice",
    "low-density subset sum (density < 0.94) solved directly with LLL",
    ("weights", "target"),
    lambda d: _knapsack_ready(d)[0],
    lambda d: (lambda wt: (lambda picks: {"ok": picks is not None,
                                          "plaintext": None,
                                          "detail": f"selected indices {picks}",
                                          "meta": {"picks": picks}}
                           if picks is not None else
                           {"ok": False, "note": "LLL found no solution (density too high?)"})(
        L.subset_sum_lll(wt[0], wt[1])))(_weights_target(d)),
    gives="selected indices (map back to plaintext per the challenge)", cost="moderate")

register_hypothesis(
    "knapsack_mitm", "lattice",
    "medium-density subset sum via meet-in-the-middle (n ≤ 44 comfortable)",
    ("weights", "target"),
    lambda d: _knapsack_ready(d)[0] and len(_weights_target(d)[0]) <= 44,
    lambda d: (lambda wt: (lambda picks: {"ok": picks is not None,
                                          "detail": f"MITM selected indices {picks}",
                                          "meta": {"picks": picks}}
                           if picks is not None else
                           {"ok": False, "note": "MITM found no solution"})(
        L.mitm_subset_sum(wt[0], wt[1])))(_weights_target(d)),
    gives="selected indices", cost="expensive")

register_hypothesis(
    "lcg_recover", "prng",
    "consecutive outputs recover the LCG parameters and predict the next term",
    ("≥4 consecutive outputs",),
    lambda d: any(len(s) >= 4 for s in d["sequences"]),
    lambda d: _run_lcg(d),
    gives="parameters a/c/m + next term", cost="cheap")

register_hypothesis(
    "mt19937_clone", "prng",
    "624 32-bit outputs are enough to clone the MT19937 state", ("≥624 outputs",),
    lambda d: any(len(s) >= 624 for s in d["sequences"]),
    lambda d: _run_mt(d),
    gives="all later outputs (enough to recover key/flag)", cost="cheap")

register_hypothesis(
    "mt19937_seed_crack", "prng",
    "small seed space → brute-force the seed", ("1 output + small-seed assumption",),
    lambda d: "random" in d["code"] and any(len(s) >= 1 for s in d["sequences"]),
    lambda d: _run_seed(d),
    gives="seed → reproduce the whole random stream", cost="expensive")

register_hypothesis(
    "discrete_log", "dlp",
    "Pohlig-Hellman when the group order is smooth, BSGS for small groups",
    ("g", "h", "p"),
    lambda d: _has(d, "g", "h") and d.get("mod"),
    lambda d: _run_dlog(d),
    gives="private key x", cost="moderate")


def _weights_target(d):
    from .core.analysis.lattice_analysis import _knapsack_inputs
    class _C:
        def __init__(self, named, text):
            self._n, self._t = named, text
        def get(self, k, default=None):
            return {"named": self._n, "raw_text": self._t}.get(k, default)
    return _knapsack_inputs(_C(d["named"], d["text"]))


def _run_lcg(d):
    for seq in d["sequences"]:
        if len(seq) < 4:
            continue
        rec = A.lcg_recover(seq[:min(len(seq), 12)])
        if rec:
            nxt = (rec["a"] * seq[-1] + rec["c"]) % rec["m"]
            return {"ok": True, "plaintext": None,
                    "meta": {**rec, "next": nxt},
                    "detail": f"a={rec['a']} c={rec['c']} m={rec['m']} → next term {nxt}"}
    return {"ok": False, "note": "sequence does not satisfy the LCG relation "
                                 "(unknown modulus or too little data)"}


def _run_mt(d):
    for seq in d["sequences"]:
        if len(seq) < 624:
            continue
        try:
            nxt = PR.predict_next([v & 0xFFFFFFFF for v in seq[:624]], 3)
            return {"ok": True, "meta": {"next": nxt},
                    "detail": f"state cloned, next 3 outputs = {nxt}"}
        except Exception as e:
            return {"ok": False, "note": f"clone failed: {e}"}
    return {"ok": False, "note": "fewer than 624 outputs"}


def _run_seed(d):
    target = d["sequences"][0][0] & 0xFFFFFFFF
    seed = PR.crack_seed(target, max_seed=2000000)
    if seed is None:
        return {"ok": False, "note": "no hit within a 2,000,000 seed space"}
    return {"ok": True, "meta": {"seed": seed}, "detail": f"seed = {seed}"}


def _run_dlog(d):
    feas = dlog_feasibility(d["mod"])
    if not feas["feasible"]:
        return {"ok": False, "note": feas["why"]}
    res = discrete_log(d["g"], d["h"], d["mod"])
    if res.get("x") is None:
        return {"ok": False, "note": res.get("note", "not solved")}
    return {"ok": True, "meta": {"x": res["x"]},
            "detail": f"{res['used']} → x={res['x']}"}


# ────────────────────────── symmetric / encoding / classical ──────────────────────────

def _run_ecb(d):
    """Count repeated 16-byte blocks in every decoded ciphertext blob.

    Repeated blocks are hard evidence: identical plaintext blocks encrypt
    identically, so the mode is ECB. Nothing is reported when there is no repeat.
    """
    best = None
    for data in d["datas"][:8]:
        for bs in (16, 8):
            if len(data) < bs * 2:
                continue
            blocks = [data[i:i + bs] for i in range(0, len(data) - bs + 1, bs)]
            counts = {}
            for b in blocks:
                counts[b] = counts.get(b, 0) + 1
            dups = {b: n for b, n in counts.items() if n > 1}
            if dups and (best is None or len(dups) > len(best[2])):
                best = (bs, blocks, dups)
    if best is None:
        return {"ok": False,
                "note": "no repeated ciphertext block → not ECB (or the sample is too short)"}
    bs, blocks, dups = best
    return {"ok": True,
            "meta": {"block_size": bs, "repeated_groups": len(dups),
                     "top_repeat": max(dups.values())},
            "detail": f"mode=ECB, block size {bs}, {len(dups)} repeated block group(s), "
                      f"max repeat {max(dups.values())}"}


register_hypothesis(
    "ecb_repeated_blocks", "symmetric",
    "repeated ciphertext blocks → ECB: equal plaintext blocks encrypt equally",
    ("≥32 bytes of ciphertext",),
    lambda d: bool(d["datas"]),
    lambda d: _run_ecb(d),
    gives="mode verdict + repeated-block positions", cost="cheap")

register_hypothesis(
    "cbc_bitflip", "symmetric",
    "in CBC, flipping the previous ciphertext block flips the plaintext (no key needed)",
    ("iv", "ciphertext", "known plaintext position"),
    lambda d: bool(d["datas"]) and ("cbc" in d["text"].lower() or "iv" in d["text"].lower()
                                    or "MODE_CBC" in d["code"]),
    lambda d: {"ok": False,
               "note": "needs a known plaintext position and a target value — generate a "
                       "workbench with cryptoexp.lab, then call pad.bitflip_cbc() "
                       "for the last step"},
    gives="forged ciphertext", cost="cheap", confidence="medium")

register_hypothesis(
    "ecb_byte_at_a_time", "symmetric",
    "an ECB encryption oracle recovers the suffix byte by byte",
    ("encryption oracle (function/remote)",),
    lambda d: "AES" in d["code"] or "encrypt" in d["code"],
    lambda d: {"ok": False,
               "note": "no oracle available statically — one call to "
                       "oracle.ecb_byte_at_a_time(enc) does it; the workbench already "
                       "sketches the call"},
    gives="the full secret", cost="moderate", confidence="medium")

register_hypothesis(
    "padding_oracle", "symmetric",
    "a CBC padding oracle decrypts everything", ("valid oracle (bytes→bool)", "iv+ct"),
    lambda d: "unpad" in d["code"] or "pkcs7" in d["code"].lower(),
    lambda d: {"ok": False,
               "note": "needs an online oracle — call "
                       "oracle.padding_oracle_attack(valid, iv+ct)"},
    gives="plaintext", cost="moderate", confidence="medium")

register_hypothesis(
    "decode_chain", "encoding",
    "peel multi-layer encodings one by one (hex/base64/base32/binary)",
    ("ciphertext string",),
    lambda d: bool(d["blobs"]),
    lambda d: _run_decode(d),
    gives="plaintext", cost="cheap")

register_hypothesis(
    "repeating_key_xor", "encoding",
    "repeating-key XOR: Hamming distance for the key size + score-based hill climbing",
    ("≥16 bytes of ciphertext",),
    lambda d: any(len(b) >= 32 for b in d["blobs"]),
    lambda d: _run_xor(d),
    gives="plaintext + key", cost="moderate")

register_hypothesis(
    "classical_cipher", "classical",
    "statistical recovery of Caesar/affine/Vigenère/Morse/rail fence",
    ("a long enough alphabetic text",),
    lambda d: sum(c.isalpha() for c in d["text"]) >= 20,
    lambda d: _run_classical(d),
    gives="plaintext", cost="cheap")

register_hypothesis(
    "linear_map_recover", "linear",
    "linear constructions (Hill/LFSR/linear transform) solved as a matrix over GF(p)",
    ("≥k known plaintext-ciphertext pairs",),
    lambda d: "matrix" in d["text"].lower() or "hill" in d["text"].lower(),
    lambda d: {"ok": False,
               "note": "arrange the known plaintext/ciphertext vectors into "
                       "inputs/outputs, then call "
                       "gf.recover_linear_map(inputs, outputs, p)"},
    gives="the linear map matrix", cost="cheap", confidence="medium")


def _run_decode(d):
    for blob in d["blobs"][:10]:
        chain = E.decode_chain(blob, max_layers=3)
        if chain and (chain[0]["flags"] or chain[0]["score"] >= 70):
            return {"ok": True, "plaintext": chain[0]["data"],
                    "detail": f"{'→'.join(chain[0]['steps'])} (score {chain[0]['score']})"}
    return {"ok": False, "note": "no high-scoring decode chain"}


def _run_xor(d):
    for blob in d["blobs"][:10]:
        # Gate: a plain decimal string is an RSA parameter, not XOR ciphertext.
        # Without this gate the hill climber happily "decodes" it into garbage.
        if blob.strip().isdigit():
            continue
        raw = E.from_hex(blob)
        if raw is None:
            raw = blob.encode('latin-1', errors='replace')
        if len(raw) < 16:
            continue
        cands = E.repeating_key_xor(raw)
        if cands and (cands[0]["flags"] or cands[0]["score"] >= 90):
            return {"ok": True, "plaintext": cands[0]["plaintext"],
                    "meta": {"key": cands[0]["key"], "keysize": cands[0]["keysize"]},
                    "detail": f"keysize={cands[0]['keysize']} key={cands[0]['key']!r}"}
        single = E.single_byte_xor(raw, top=1)[0]
        if single["flags"] or single["score"] >= 90:
            return {"ok": True, "plaintext": single["plaintext"],
                    "meta": {"key": single["key"]},
                    "detail": f"single-byte key=0x{single['key']:02x}"}
    return {"ok": False, "note": "no XOR candidate scores high enough"}


def _run_classical(d):
    from .core.analysis.classical import analyze_classical

    class _Ctx(dict):
        pass
    ctx = _Ctx(raw_text=d["text"], blobs=[{"text": b, "length": len(b), "kinds": []}
                                          for b in d["blobs"]])
    res = analyze_classical(ctx)
    cands = res.get("candidates") or []
    if cands:
        best = cands[0]
        return {"ok": True, "plaintext": best["data"],
                "detail": f"{best['attack']}: {best['detail']}"}
    return {"ok": False, "note": "no high-scoring classical cipher candidate"}


# ────────────────────────── engine ──────────────────────────

def _verify(outcome, d):
    """Assign the state: strict flag / RSA re-encryption / readability"""
    pt = outcome.get("plaintext")
    if not pt:
        return "confirmed" if outcome.get("ok") and outcome.get("meta") else "candidate", []
    if E.flag_candidates(pt):
        return "confirmed", E.flag_candidates(pt)
    if d.get("n") and d.get("e") and d.get("c") is not None:
        try:
            if pow(int.from_bytes(pt, 'big'), d["e"], d["n"]) == d["c"]:
                return "confirmed", ["re-encrypts to the original ciphertext"]
        except Exception:
            pass
    if E.printable_ratio(pt) >= 0.9 and E.score_text(pt) >= 55:
        return "candidate", []
    return "not_reproduced", []


def evaluate(params: dict, budget: str = "normal"):
    """Run the hypothesis engine once

    Returns:
        {"applicable": [...], "gaps": [...], "results": [...]}
        applicable: applicable hypotheses (with principle / output / cost)
        gaps:       the **gaps** of inapplicable hypotheses — "get X and Y is usable"
        results:    results of the attempts actually made (with state and why it was graded so)
    """
    applicable, gaps, results = [], [], []
    for h in _HYPOTHESES:
        try:
            ok = bool(h["condition"](params))
        except Exception as e:
            gaps.append({"name": h["name"], "domain": h["domain"],
                         "missing": [f"condition check raised: {e}"]})
            continue
        item = {"name": h["name"], "domain": h["domain"], "idea": h["idea"],
                "needs": list(h["needs"]), "gives": h["gives"],
                "cost": h["cost"], "confidence": h["confidence"],
                "applicable": ok}
        if not ok:
            miss = []
            if h.get("missing"):
                try:
                    miss = h["missing"](params)
                except Exception:
                    miss = list(h["needs"])
            else:
                miss = list(h["needs"])
            item["missing"] = miss
            gaps.append(item)
            continue
        applicable.append(item)
        if budget == "list":
            continue
        try:
            outcome = h["run"](params) or {"ok": False, "note": "no result"}
        except Exception as e:
            outcome = {"ok": False, "note": f"run raised: {type(e).__name__}: {e}"}
        state, evidence = _verify(outcome, params)
        if not outcome.get("ok"):
            state = "not_reproduced"
        results.append({**item, "state": state, "note": outcome.get("note", ""),
                        "detail": outcome.get("detail", ""),
                        "plaintext": outcome.get("plaintext"),
                        "meta": outcome.get("meta", {}),
                        "evidence": evidence})
    # result ordering: confirmed → candidate → not_reproduced; ties broken by cost
    order = {"confirmed": 0, "candidate": 1, "not_reproduced": 2}
    cost_order = {"cheap": 0, "moderate": 1, "expensive": 2}
    results.sort(key=lambda r: (order.get(r["state"], 9), cost_order.get(r["cost"], 9)))
    return {"applicable": applicable, "gaps": gaps, "results": results}
