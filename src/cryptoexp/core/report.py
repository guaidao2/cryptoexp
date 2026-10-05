"""Reporting layer — English terminal report + versioned JSON contract.

JSON contract:
  schema_version / target / context / rsa / symmetric / numbertheory / lattice /
  candidates / findings / strategy / hypotheses / verification
Any new key produced by a plugin (`register_analyzer`) lands in the "extra" block
automatically, so adding an analyzer never requires touching this file.
"""

import json
import os

from ..utils.output import (Colors, print_field, print_info, print_section_header,
                            print_success, print_warning)

SCHEMA_VERSION = "1.0"

# Keys rendered explicitly below; they must not show up again in the wildcard block
_RENDERED_KEYS = {
    "target", "context", "env", "effort", "encoding", "classical", "rsa",
    "symmetric", "numbertheory", "lattice", "strategy", "summary",
    "verification", "hypotheses", "_ctx",
    # New scalar settings are surfaced through `decode_chain` / `swapped_alphabet`
    # in the JSON contract, so the text report does not need a plugin-looking block
    # that prints "guess_alphabets: True" as if it were an analyzer.
    "max_layers", "alphabets", "guess_alphabets",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_COLOR = {"critical": Colors.RED, "high": Colors.RED, "medium": Colors.YELLOW,
                   "low": Colors.GREEN, "info": Colors.CYAN}


def enc_layers(results: dict) -> int:
    """The chain depth this run actually used (for the hit_limit warning text)"""
    from ..utils.encoding import DEFAULT_CHAIN_LAYERS
    try:
        return int(results.get("max_layers") or DEFAULT_CHAIN_LAYERS)
    except (TypeError, ValueError):
        return DEFAULT_CHAIN_LAYERS


def _fmt_value(v, indent: int = 2):
    """Wildcard rendering for plugin output: dict/list/scalar -> indented text."""
    pad = " " * indent
    if isinstance(v, dict):
        lines = []
        for k, val in v.items():
            if isinstance(val, (dict, list)) and val:
                lines.append(f"{pad}{k}:")
                lines.append(_fmt_value(val, indent + 2))
            else:
                lines.append(f"{pad}{k}: {val}")
        return "\n".join(lines)
    if isinstance(v, list):
        if not v:
            return f"{pad}(empty)"
        lines = []
        for item in v[:8]:
            if isinstance(item, dict):
                brief = ", ".join(f"{k}={val}" for k, val in list(item.items())[:4])
                lines.append(f"{pad}- {brief}")
            else:
                lines.append(f"{pad}- {item}")
        if len(v) > 8:
            lines.append(f"{pad}... {len(v)} total")
        return "\n".join(lines)
    return f"{pad}{v}"


def print_results(results: dict, verification: dict = None):
    """Terminal report (English)."""
    print_section_header("Target")
    print_field("target", results.get("target"))
    ctx = results.get("context") or {}
    print_field("kind", ctx.get("kind"))
    files = ctx.get("files") or []
    if files:
        print_field("files", f"{len(files)}: " + ", ".join(
            f"{f['name']}({f['kind']})" for f in files[:6]))
    named = ctx.get("named") or {}
    if named:
        brief = ", ".join(
            f"{k}={str(v[0])[:14]}{'...' if len(str(v[0])) > 14 else ''}"
            for k, v in list(named.items())[:8])
        print_field("params", brief)
    for w in ctx.get("warnings", []):
        print_warning(w)

    # -- RSA --
    rsa = results.get("rsa") or {}
    if rsa.get("params"):
        print_section_header("RSA parameters")
        p = rsa["params"]
        print_field("n", f"{str(p.get('n'))[:40]}... ({p.get('n_bits')} bits)")
        print_field("e", p.get("e"))
        print_field("c", f"{str(p.get('c'))[:40]}..." if p.get("c") else "not given")
        given = [k.replace("has_", "") for k in ("has_p", "has_q", "has_d", "has_dp",
                                                 "has_phi") if p.get(k)]
        print_field("given", ", ".join(given) if given else "none (public key only)")
        if p.get("e_assumed"):
            print_warning("no e in the statement, assuming e=65537")

    # -- encoding / classical --
    enc = results.get("encoding") or {}
    if enc.get("blobs"):
        print_section_header("Encoding / XOR")
        for b in enc["blobs"][:6]:
            print_field("blob", f"{b['text'][:46]}..." if len(b["text"]) > 46 else b["text"])
            print_field("looks like", ", ".join(b["kinds"]) or "unknown")
            if b["chain"]:
                c = b["chain"][0]
                print_field("decode chain",
                            f"{'->'.join(c['steps'])} (score {c['score']}, {c['confidence']})")
                # A truncated chain is not a failed one: say so, so the caller can
                # re-run with a higher max_layers instead of trusting the ranking.
                if c.get("hit_limit"):
                    print_warning(f"decode chain stopped at the {enc_layers(results)}-layer "
                                  f"cap and is still decodable - re-run with a higher "
                                  f"max_layers")
            if b["xor"]:
                x = b["xor"][0]["top"][0]
                print_field("single-byte xor", f"key=0x{x['key']:02x} score {x['score']}")
            if b["repeating_xor"]:
                r = b["repeating_xor"][0]
                print_field("repeating xor",
                            f"keylen={r['keysize']} key={r['key']!r} score {r['score']}")
        print_field("candidates", len(enc.get("candidates", [])))

    swapped = enc.get("swapped_alphabets") or {}
    for entry in swapped.get("alphabets", [])[:4]:
        print_section_header("Cross-line swapped base64 alphabet")
        print_field("candidate", f"{entry['source']} ({entry['unique']} unique characters)")
        print_field("alphabet", entry["alphabet"][:64])
        for lvl in entry.get("levels", [])[:2]:
            print_field("decoded", f"{lvl['view']} score {lvl['score']} "
                                   f"-> {lvl['preview'][:60]!r}")
            if lvl.get("chain"):
                c = lvl["chain"][0]
                print_field("chain", f"{'->'.join(c['steps'])} (score {c['score']}, "
                                     f"{c['confidence']})")
        if not entry.get("levels"):
            print_warning("table candidate only: no other line is a valid base64 body in it")

    cla = results.get("classical") or {}
    if cla.get("probes"):
        print_section_header("Classical ciphers")
        for probe in cla["probes"][:4]:
            print_field("text", probe["text"][:46] + ("..." if len(probe["text"]) > 46 else ""))
            if probe.get("note"):
                # Deferred chunks (encoded blobs) carry the reason here; the scored
                # chunks never set it.
                print_warning(probe["note"])
            if probe.get("morse"):
                print_field("morse", f"{probe['morse']['plaintext'][:50]} "
                                     f"(score {probe['morse']['score']})")
            if probe.get("caesar"):
                c = probe["caesar"][0]
                print_field("caesar", f"shift={c['shift']} score {c['score']}")
            if probe.get("vigenere"):
                v = probe["vigenere"][0]
                print_field("vigenere", f"key={v['key']} IoC={v['ioc']} score {v['score']}")

    # -- block ciphers --
    sym = results.get("symmetric") or {}
    if sym.get("mode") != "unknown" or sym.get("oracle_hints"):
        print_section_header("Block cipher")
        print_field("mode", sym.get("mode"))
        if sym.get("block_size"):
            print_field("block size", sym["block_size"])
        if sym.get("repeated_blocks"):
            print_field("repeated blocks", f"{len(sym['repeated_blocks'])} groups "
                                           f"(max repeat {sym['repeated_blocks'][0]['count']})")
        for k, v in (sym.get("oracle_hints") or {}).items():
            print_field(k, v)
        for n in sym.get("notes", []):
            print_warning(n)

    # -- number theory / lattice --
    nt = results.get("numbertheory") or {}
    if nt.get("lcg") or nt.get("dlog") or nt.get("mt19937"):
        print_section_header("Number theory / PRNG")
        if nt.get("lcg"):
            lcg = nt["lcg"]
            print_field("LCG", f"a={lcg['a']} c={lcg['c']} m={lcg['m']} -> next {lcg['next']}")
        if nt.get("dlog"):
            print_field("discrete log", f"x={nt['dlog']['x']} (p={nt['dlog']['p']})")
        if nt.get("mt19937"):
            print_field("MT19937", "random module in use; state cloneable with enough output")

    lat = results.get("lattice") or {}
    if lat.get("knapsack") or lat.get("coppersmith"):
        print_section_header("Lattice")
        if lat.get("knapsack"):
            k = lat["knapsack"]
            print_field("subset sum", f"{k['n_items']} items density {k['density']} "
                                      f"{'solved ' + str(k['picks']) if k['solved'] else 'unsolved'}")
        if lat.get("coppersmith"):
            c = lat["coppersmith"]
            print_field("Coppersmith", f"{c['known_bits']}/{c['total_bits']} bits known "
                                       f"{'-> factored' if c['p'] else '-> ' + c['note']}")

    # -- findings --
    summary = results.get("summary") or {}
    if summary.get("items"):
        print_section_header(f"Findings ({summary['count']}, max {summary['max_severity']})")
        for it in sorted(summary["items"],
                         key=lambda x: _SEVERITY_ORDER.get(x["severity"], 9)):
            col = _SEVERITY_COLOR.get(it["severity"], Colors.CYAN)
            tag = f"[{it['severity']}]"
            suffix = f" (confidence {it['confidence']})" if it.get("confidence") else ""
            print(f"  {col}{tag}{Colors.END} {it['type']}{suffix}")
            if it.get("detail"):
                print(f"        {it['detail']}")

    # -- strategy --
    strat = results.get("strategy") or []
    if strat:
        print_section_header("Recommended path")
        for s in strat:
            print(f"  {s['priority']}. {s['type']} - {s['why']}")

    # -- hypothesis engine --
    hy = results.get("hypotheses") or {}
    if hy.get("applicable") or hy.get("gaps"):
        print_section_header("Hypothesis engine")
        if hy.get("applicable"):
            print(f"  applicable attack surface ({len(hy['applicable'])}):")
            for h in hy["applicable"]:
                print(f"    . {h['name']} ({h['domain']}, {h['cost']}) - {h['idea']}")
        if hy.get("gaps"):
            print(f"  gaps ({len(hy['gaps'])}; getting these unlocks more paths):")
            for g in hy["gaps"][:8]:
                miss = "; ".join(g.get("missing", [])[:2])
                print(f"    . {g['name']} <- missing: {miss}")

    # -- verification --
    if verification:
        print_section_header("Candidate verification")
        print_field("verdict", verification["verdict"])
        for ev in verification["entries"][:8]:
            state = ev["state"]
            col = {"confirmed": Colors.GREEN, "candidate": Colors.YELLOW,
                   "not_reproduced": Colors.RED}.get(state, Colors.CYAN)
            print(f"  {col}[{state}]{Colors.END} {ev['attack']} - {ev['note']}")
            if state in ("confirmed", "candidate"):
                print(f"        {ev['preview'][:70]}")
        if verification.get("best"):
            print_success(f"best candidate ({verification['best']['attack']}): "
                          f"{verification['best']['preview'][:80]}")
        for c in verification.get("caveats", [])[:3]:
            print_warning(c)

    # -- environment --
    env = results.get("env") or {}
    avail = [k for k, v in env.items() if v.get("available")]
    if avail:
        print_info(f"optional accelerators enabled: {', '.join(avail)} "
                   f"(core stays dependency-free)")

    # -- plugin wildcard block --
    extras = {k: v for k, v in results.items()
              if k not in _RENDERED_KEYS and not k.startswith("_") and v}
    if extras:
        print_section_header(f"Extension output ({len(extras)} plugins)")
        for k, v in extras.items():
            print(f"  {Colors.BOLD}{k}{Colors.END}")
            print(_fmt_value(v))


def json_summary(results: dict, verification: dict = None) -> dict:
    """Stable machine-readable contract (internal `_ctx` never leaks)."""
    from .verify import iter_candidates
    rsa = results.get("rsa") or {}
    cands = []
    for c in iter_candidates(results):
        data = c.get("data", b"")
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode('utf-8', errors='replace')
        cands.append({"source": c.get("source"), "attack": c.get("attack"),
                      "confidence": c.get("confidence"),
                      "detail": c.get("detail"), "preview": str(data)[:200]})
    # The decode-chain cap and whether any chain hit it: a JSON consumer needs both
    # to decide "re-run with a higher max_layers" without guessing from the score.
    enc = results.get("encoding") or {}
    limited = [{"steps": c.get("steps"), "score": c.get("score"),
                "source": b.get("source")}
               for b in enc.get("blobs", []) for c in b.get("chain", [])
               if c.get("hit_limit")]
    # Cross-line swapped-alphabet evidence, lifted out of the encoding block: a
    # caller needs "which line was taken as the table" and "what it decoded to".
    swapped = enc.get("swapped_alphabets") or {}
    swapped_out = {
        "alphabets": [{"line": e.get("line"), "source": e.get("source"),
                       "unique": e.get("unique"), "alphabet": e.get("alphabet"),
                       "levels": [{"view": l.get("view"), "score": l.get("score"),
                                   "flags": l.get("flags"),
                                   "preview": (l.get("preview") or "")[:120]}
                                  for l in e.get("levels", [])]}
                      for e in swapped.get("alphabets", [])],
        "candidates": [{"attack": c.get("attack"), "confidence": c.get("confidence"),
                        "detail": c.get("detail"),
                        "preview": str(c.get("data", b""))[:200]}
                       for c in swapped.get("candidates", [])],
        "notes": swapped.get("notes", []),
    }
    extra = {k: v for k, v in results.items()
             if k not in _RENDERED_KEYS and not k.startswith("_")
             and isinstance(v, (dict, list, str, int, float, bool))}
    out = {
        "schema_version": SCHEMA_VERSION,
        "target": results.get("target"),
        "context": results.get("context"),
        "rsa": {
            "params": {k: (str(v) if isinstance(v, int) and v and v.bit_length() > 64 else v)
                       for k, v in (rsa.get("params") or {}).items()},
            "vulns": rsa.get("vulns", []),
        },
        "symmetric": results.get("symmetric"),
        "numbertheory": results.get("numbertheory"),
        "lattice": results.get("lattice"),
        "candidates": cands,
        "decode_chain": {
            "max_layers": enc_layers(results),
            # The custom alphabets this run was given (empty = opt-in feature off).
            "alphabets": list(results.get("alphabets") or []),
            "guess_alphabets": bool(results.get("guess_alphabets")),
            "hit_limit": bool(limited),
            "limited": limited,
        },
        "swapped_alphabet": swapped_out,
        "findings": (results.get("summary") or {}).get("items", []),
        "max_severity": (results.get("summary") or {}).get("max_severity"),
        "strategy": results.get("strategy"),
        "hypotheses": {
            "applicable": [{"name": h["name"], "domain": h["domain"],
                            "idea": h["idea"], "gives": h["gives"],
                            "cost": h["cost"]}
                           for h in (results.get("hypotheses") or {}).get("applicable", [])],
            "gaps": [{"name": g["name"], "missing": g.get("missing", []),
                      "idea": g.get("idea", "")}
                     for g in (results.get("hypotheses") or {}).get("gaps", [])],
        },
        "extra": extra,
    }
    if verification:
        out["verification"] = {
            "verdict": verification["verdict"],
            "entries": [{k: v for k, v in e.items() if k != "flags"}
                        for e in verification["entries"]],
        }
    return out


def print_json_summary(results: dict, verification: dict = None) -> str:
    # ensure_ascii=True keeps the payload pure ASCII. Candidates can hold arbitrary
    # bytes; decoded with errors="replace" they become U+FFFD, and printing that on a
    # non-UTF-8 console (a Windows GBK shell, which the reporter used) raised
    # UnicodeEncodeError and produced *no* JSON at all. Escaped now, not lost.
    return json.dumps(json_summary(results, verification), ensure_ascii=True,
                      indent=2, default=str)


def target_basename(target: str) -> str:
    return os.path.basename(str(target).rstrip("\\/")) or "target"
