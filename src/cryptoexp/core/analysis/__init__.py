"""Analysis orchestration — built-in pipeline + plugin registry + blackboard materialization

    analyze_all(target)
        ├─ build_context()       challenge/attachments → blackboard ctx (built once)
        ├─ analyze_encoding()    decode chains + xor
        ├─ analyze_classical()   Caesar/affine/Vigenere/morse/rail fence
        ├─ analyze_rsa()         parameter sanity check + attack attempts
        ├─ analyze_symmetric()   ECB/CBC/oracle hints
        ├─ analyze_numbertheory() LCG/discrete log/MT/congruence
        ├─ analyze_lattice()     knapsack/Coppersmith
        ├─ run_extra_analyzers() plugins (just register, no need to touch this file)
        └─ generate_findings()/generate_strategy()

Difference from intelpwn: one extra layer of input parsing (context), one layer less
of disassembly.
"""

from ..context import build_context, context_public
from ...utils.encoding import DEFAULT_CHAIN_LAYERS
from .encoding_scan import analyze_encoding
from .classical import analyze_classical
from .rsa import analyze_rsa
from .symmetric import analyze_symmetric
from .numbertheory import analyze_numbertheory
from .lattice_analysis import analyze_lattice
from .crc_scan import analyze_crc
from .lfsr_scan import analyze_lfsr
from .findings import generate_findings, generate_strategy

# ── Plugin registry ────────────────────────────────────────
_EXTRA_ANALYZERS = {}


def register_analyzer(name: str):
    """Register an extension analyzer (decorator)

    Usage:
        @register_analyzer("my_check")
        def my_check(ctx, results):
            return {...}      # written to results["my_check"] automatically
    """
    def deco(fn):
        _EXTRA_ANALYZERS[name] = fn
        return fn
    return deco


def list_analyzers():
    return sorted(_EXTRA_ANALYZERS)


def run_extra_analyzers(ctx: dict, results: dict) -> dict:
    """Run extension analyzers; one broken plugin must not sink the whole report
    (same policy as intelpwn)"""
    for name, fn in _EXTRA_ANALYZERS.items():
        try:
            results[name] = fn(ctx, results)
        except Exception as e:
            results[name] = {"error": f"{type(e).__name__}: {e}"}
    return results


def probe_optional_deps() -> dict:
    """Auto-detect optional accelerators (zero core dependencies; enabled if installed)"""
    env = {}
    for mod, label in (("gmpy2", "bignum acceleration"), ("sympy", "symbolic/number theory"),
                       ("Crypto", "pycryptodome"), ("z3", "constraint solving")):
        try:
            __import__(mod)
            env[mod] = {"available": True, "use": label}
        except Exception:
            env[mod] = {"available": False, "use": label}
    return env


def analyze_all(target: str, skip_encoding: bool = False,
                effort: str = "normal", flag_prefixes=None,
                flag_pattern=None, max_layers: int = None,
                alphabets=None, guess_alphabets: bool = False) -> dict:
    """Full analysis entry point → results dict (English keys)

    effort: fast (cheap checks only) / normal (default) / max (no early stop, try everything)
    flag_prefixes / flag_pattern: the marker format this engagement uses, e.g.
        ["DH", "corp_"] or a regex. They are recorded in the result so verification
        uses them, and they are also installed as the process-wide default for the
        duration (that is what makes the analyzers' own flag detection agree with
        verification). Library callers who want no global state should use
        encoding.flag_candidates(data, prefixes=[...]) directly.
    max_layers: how many layers the built-in decode chain may peel (None = the
        library default, `utils.encoding.DEFAULT_CHAIN_LAYERS` = 3). Raise it when a
        chain entry comes back with `hit_limit: True`; that flag means the chain
        consumed the whole cap and the result was still decodable.
    alphabets: opt-in list of 64-character base64 alphabets to also try while
        decoding (custom/shuffled tables). Default None = off, which is
        byte-identical to the previous behaviour.
    guess_alphabets: opt-in cross-line heuristic - a line of 64 +/- 1 characters
        with >= 60 distinct characters is treated as a substitution table for the
        other lines. Default False = off. The result lands under
        `results["encoding"]["swapped_alphabets"]`, and anything it reports is a
        normal candidate graded by score.
    """
    from ...utils import encoding as _E
    layers = _E.DEFAULT_CHAIN_LAYERS if max_layers is None else int(max_layers)
    if layers < 1:
        raise ValueError("max_layers must be >= 1")
    tables = _E.check_alphabets(alphabets)
    token = None
    if flag_prefixes is not None or flag_pattern is not None:
        # Scoped to this run: analyzers and verification see it, other callers do not.
        token = _E.push_flag_config(flag_prefixes, flag_pattern)
    try:
        return _analyze_scoped(target, skip_encoding, effort, flag_prefixes,
                               flag_pattern, layers, tables, guess_alphabets)
    finally:
        if token is not None:
            _E.pop_flag_config(token)


def _analyze_scoped(target: str, skip_encoding: bool, effort: str,
                    flag_prefixes, flag_pattern, max_layers: int = None,
                    alphabets=None, guess_alphabets: bool = False) -> dict:
    """analyze_all body; the flag config is already scoped by the caller"""
    from ...utils import encoding as _E
    layers = _E.DEFAULT_CHAIN_LAYERS if max_layers is None else int(max_layers)
    ctx = build_context(target)
    results = {
        "target": target,
        "context": context_public(ctx),
        "env": probe_optional_deps(),
        "effort": effort,
        "flag_prefixes": flag_prefixes,
        "flag_pattern": flag_pattern,
        "max_layers": layers,
        "alphabets": alphabets,
        "guess_alphabets": bool(guess_alphabets),
        "_ctx": ctx,
    }

    results["encoding"] = {"blobs": [], "candidates": [], "notes": ["skipped"]} \
        if skip_encoding else analyze_encoding(ctx, effort=effort,
                                               max_layers=layers,
                                               alphabets=alphabets,
                                               guess_alphabets=guess_alphabets)
    if ctx.get("source_like"):
        # Score-based probes on code are pure noise (`import gmpy2` scored as a caesar
        # candidate). The encodings inside a script are still analysed by the encoding
        # analyzer; only the "this looks like English after a shift" family is skipped.
        results["classical"] = {
            "probes": [], "candidates": [], "vulns": [],
            "note": "target looks like source code: classical cipher scoring skipped "
                    "(code text scores as English by accident)",
        }
    else:
        results["classical"] = analyze_classical(ctx)
    results["rsa"] = analyze_rsa(ctx)
    results["symmetric"] = analyze_symmetric(ctx)
    results["numbertheory"] = analyze_numbertheory(ctx)
    results["lattice"] = analyze_lattice(ctx)
    results["crc"] = analyze_crc(ctx, effort=effort)
    results["lfsr"] = analyze_lfsr(ctx, effort=effort)

    if list_analyzers():
        run_extra_analyzers(ctx, results)

    # Hypothesis engine (list mode, cheap): only answers "which attack class applies /
    # which is ruled out and for want of what". The real attempts live in the analyzers
    # above; for a full run see cryptoexp.py hypotheses / lab.
    try:
        from ..hypothesis import params_from_ctx, evaluate
        # The chain depth and any supplied alphabets travel with the params, so the
        # decode_chain hypothesis peels exactly as deep as the analyzer did.
        results["hypotheses"] = evaluate(
            params_from_ctx(ctx, max_layers=layers, alphabets=alphabets), budget="list")
    except Exception as e:
        results["hypotheses"] = {"applicable": [], "gaps": [],
                                 "results": [], "error": str(e)}

    results["strategy"] = generate_strategy(results)
    results["summary"] = generate_findings(results)
    return results


__all__ = [
    "analyze_all", "build_context", "context_public",
    "register_analyzer", "list_analyzers", "run_extra_analyzers",
    "probe_optional_deps", "DEFAULT_CHAIN_LAYERS",
]
