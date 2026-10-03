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
                flag_pattern=None) -> dict:
    """Full analysis entry point → results dict (English keys)

    effort: fast (cheap checks only) / normal (default) / max (no early stop, try everything)
    flag_prefixes / flag_pattern: the marker format this engagement uses, e.g.
        ["DH", "corp_"] or a regex. They are recorded in the result so verification
        uses them, and they are also installed as the process-wide default for the
        duration (that is what makes the analyzers' own flag detection agree with
        verification). Library callers who want no global state should use
        encoding.flag_candidates(data, prefixes=[...]) directly.
    """
    from ...utils import encoding as _E
    token = None
    if flag_prefixes is not None or flag_pattern is not None:
        # Scoped to this run: analyzers and verification see it, other callers do not.
        token = _E.push_flag_config(flag_prefixes, flag_pattern)
    try:
        return _analyze_scoped(target, skip_encoding, effort, flag_prefixes,
                               flag_pattern)
    finally:
        if token is not None:
            _E.pop_flag_config(token)


def _analyze_scoped(target: str, skip_encoding: bool, effort: str,
                    flag_prefixes, flag_pattern) -> dict:
    """analyze_all body; the flag config is already scoped by the caller"""
    ctx = build_context(target)
    results = {
        "target": target,
        "context": context_public(ctx),
        "env": probe_optional_deps(),
        "effort": effort,
        "flag_prefixes": flag_prefixes,
        "flag_pattern": flag_pattern,
        "_ctx": ctx,
    }

    results["encoding"] = {"blobs": [], "candidates": [], "notes": ["skipped"]} \
        if skip_encoding else analyze_encoding(ctx, effort=effort)
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
        results["hypotheses"] = evaluate(params_from_ctx(ctx), budget="list")
    except Exception as e:
        results["hypotheses"] = {"applicable": [], "gaps": [],
                                 "results": [], "error": str(e)}

    results["strategy"] = generate_strategy(results)
    results["summary"] = generate_findings(results)
    return results


__all__ = [
    "analyze_all", "build_context", "context_public",
    "register_analyzer", "list_analyzers", "run_extra_analyzers",
    "probe_optional_deps",
]
