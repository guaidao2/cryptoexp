"""cryptoexp command line interface.

Installed console script (`cryptoexp`) and the repository-level `cryptoexp_cli.py`
shim both call `main()` here. English-first output.
"""

import argparse
import contextlib
import io
import json
import os
import sys

from .utils.output import (print_banner, print_error, print_info,
                           print_section_header, print_success, print_warning)
from .core.analysis import analyze_all, list_analyzers
from .core.report import print_results, print_json_summary
from .core.verify import verify_candidates
from .core.solve import generate as gen_solve, list_solvers


def _json_error(message: str) -> int:
    """Error path for JSON consumers: stdout stays a JSON document, not a text line"""
    print(json.dumps({"schema_version": "1.0", "error": message}, ensure_ascii=True,
                     indent=2))
    return 1


def _run_one(target: str, args) -> dict:
    results = analyze_all(target, skip_encoding=args.no_encoding,
                          effort=getattr(args, "effort", "normal"),
                          flag_prefixes=getattr(args, "flag_prefix", None),
                          flag_pattern=getattr(args, "flag_regex", None))
    verification = verify_candidates(results)
    results["verification"] = verification

    # Solve/run happens before the JSON branch on purpose: `--json --solve` used to
    # return here and silently drop the solve step (the reporter lost time to that).
    # Its progress lines go to stderr so stdout stays a single valid JSON document.
    if args.solve or args.run:
        path = gen_solve(results, out_dir=args.out, only=args.only)
        print(f"[+] solve script: {path}", file=sys.stderr)
        results["solve_script"] = path
        if args.run:
            import subprocess
            print(f"[*] running {path} ...", file=sys.stderr)
            proc = subprocess.run([sys.executable, path], capture_output=True,
                                  text=True, timeout=300)
            print(proc.stdout.rstrip() or "(no output)", file=sys.stderr)
            if proc.returncode != 0:
                # A failing generated script must not look like success: the reporter
                # hit a skeleton returning 1 while the CLI still exited 0.
                results["solve_failed"] = proc.returncode
                print_warning(f"script exit code {proc.returncode} "
                              f"(may be a [skeleton], see the notes above)")
                if proc.stderr.strip():
                    print(proc.stderr.strip()[-500:], file=sys.stderr)
            else:
                results["solve_ran"] = True

    if args.json:
        print(print_json_summary(results, verification))
        return results

    print_section_header(f"Analyzing target: {target}")
    print_results(results, verification)
    return results


def cmd_analyze(args):
    target = args.target
    # A directory passed positionally used to be fed to the blackboard as one target,
    # which merged 20 unrelated files into a single context and produced both a fake
    # "shared prime" critical and a fake confirmed verdict. `--dir` did the sane thing
    # all along, so a positional directory now means the same as --dir.
    if target and os.path.isdir(target) and not args.dir:
        print_warning(f"{target} is a directory: switching to batch mode "
                      f"(same as --dir)")
        args.dir = target

    if args.dir:
        if not os.path.isdir(args.dir):
            print_error(f"directory does not exist: {args.dir}")
            return 1 if not args.json else _json_error(f"directory does not exist: {args.dir}")
        entries = [os.path.join(args.dir, n) for n in sorted(os.listdir(args.dir))
                   if os.path.isfile(os.path.join(args.dir, n))]
        if not entries:
            print_error("no files in the directory")
            return 1 if not args.json else _json_error("no files in the directory")
        all_res, failures = [], 0
        for i, p in enumerate(entries, 1):
            if args.json:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    r = _run_one(p, args)
                all_res.append(json.loads(print_json_summary(r, r.get("verification"))))
            else:
                print(f"\n=== [{i}/{len(entries)}] {os.path.basename(p)} ===")
                r = _run_one(p, args)
            failures += 1 if r.get("solve_failed") else 0
        if args.json:
            # Batch output is wrapped in an object: the single-target payload is an
            # object per schema/cryptoexp.schema.json, and a bare list here violated it.
            print(json.dumps({"schema_version": "1.0", "mode": "batch",
                              "targets": all_res},
                             ensure_ascii=True, indent=2, default=str))
        return 1 if failures else 0

    if not target:
        message = ('analyze needs <target> or --dir; the target may be a file, '
                   'a directory or challenge text')
        if args.json:
            return _json_error(message)      # stdout must stay one JSON document
        print_error(message)
        return 1
    # A path-looking argument that does not exist is almost always a typo; saying so
    # beats silently analysing the path string as if it were the challenge text.
    if (os.sep in target or target.endswith((".txt", ".py", ".json", ".pem"))) \
            and not os.path.exists(target):
        print_warning(f"{target} does not exist - treating it as inline challenge text")
    r = _run_one(target, args)
    return 1 if r.get("solve_failed") else 0


def cmd_hypotheses(args):
    """Run the hypothesis engine end to end (every entry is really attempted)"""
    from .hypothesis import params_from_ctx, evaluate
    from .core.context import build_context

    ctx = build_context(args.target)
    params = params_from_ctx(ctx)
    result = evaluate(params, budget="full")

    if args.json:
        print(json.dumps({
            "target": args.target,
            "applicable": result["applicable"],
            "gaps": result["gaps"],
            "results": [{k: v for k, v in r.items() if k != "plaintext"}
                        for r in result["results"]],
        }, ensure_ascii=False, indent=2, default=str))
        return 0

    print_section_header(f"Hypothesis engine: {args.target}")
    if not result["results"]:
        print_warning("no hypothesis applies — see the gap list below for the missing piece")
    for r in result["results"]:
        tag = {"confirmed": "[confirmed]", "candidate": "[candidate]",
               "not_reproduced": "[not_reproduced]"}.get(r["state"], "[?]")
        print(f"  {tag} {r['name']} ({r['domain']}, {r['cost']}) - {r['idea']}")
        if r.get("detail"):
            print(f"        {r['detail']}")
        if r.get("note"):
            print(f"        {r['note']}")
        if r.get("plaintext"):
            print(f"        plaintext: {r['plaintext'][:80]!r}")
    print_section_header(f"Gap list ({len(result['gaps'])} entries)")
    for g in result["gaps"]:
        print(f"  - {g['name']} - {g['idea']}")
        print(f"      missing: {'; '.join(g.get('missing', [])[:3])}")
    return 0


def cmd_lab(args):
    """Generate the workbench scaffold (start here for challenges no template covers)"""
    from .lab import write_workbench
    from .hypothesis import params_from_ctx, evaluate

    results = analyze_all(args.target, skip_encoding=args.no_encoding)
    params = params_from_ctx(results.get("_ctx") or {})
    hypotheses = evaluate(params, budget="full" if args.deep else "list")
    path = write_workbench(results, out_dir=args.out, params=params,
                           hypotheses=hypotheses)
    print_success(f"workbench script: {path}")
    print_info("open it: parameters are already extracted, applicable hypotheses and gaps "
               "are written in comments, and the starting moves are ready to call")
    if args.run:
        import subprocess
        proc = subprocess.run([sys.executable, path], capture_output=True,
                              text=True, timeout=180)
        print(proc.stdout.rstrip() or "(no output)")
        if proc.returncode != 0 and proc.stderr.strip():
            print_warning(proc.stderr.strip()[-400:])
    return 0


def cmd_list(args):
    from .core.analysis import probe_optional_deps
    from .core.solve import _register_builtins
    from . import api as api_map
    # The solver registry fills lazily on the first generate() call, so `list` used to
    # print "(not registered yet)" for every template - which read as "no templates
    # exist". Register them here instead.
    _register_builtins()
    print_section_header("Analyzers (built-in + plugins)")
    for name in ("encoding", "classical", "rsa", "symmetric", "numbertheory", "lattice",
                 "crc", "lfsr"):
        print(f"  {name}")
    for name in list_analyzers():
        print(f"  {name}  (plugin)")
    print_section_header("solve templates (lower priority runs first)")
    for name, prio in list_solvers():
        print(f"  {prio:>4}  {name}")
    print_section_header("optional extras (core is dependency-free; missing ones are harmless)")
    for mod, info in probe_optional_deps().items():
        mark = "installed" if info["available"] else "missing"
        print(f"  {mod:<8} {mark}  {info['use']}")
    print_section_header("API map (same as cryptoexp.api())")
    print(api_map())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="cryptoexp - cryptography CTF helper")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("analyze", help="analyze a challenge (file/directory/challenge text)")
    p.add_argument("target", nargs="?", help="challenge file, directory, or raw challenge text")
    p.add_argument("--dir", help="batch-analyze every file in a directory")
    p.add_argument("--json", action="store_true", help="JSON output (schema v1.0)")
    p.add_argument("--solve", action="store_true", help="generate a solve script")
    p.add_argument("--run", action="store_true", help="generate and run the solve script")
    p.add_argument("--out", default="solves",
                   help="output directory for solve scripts (default solves/)")
    p.add_argument("--only", help="only allow the solve template with this exact name")
    p.add_argument("--no-encoding", action="store_true",
                   help="skip encoding/XOR analysis (faster)")
    p.add_argument("--effort", choices=["fast", "normal", "max"], default="normal",
                   help="effort level: fast = cheap checks only / max = attempt everything")
    p.add_argument("--flag-prefix", action="append", metavar="PREFIX",
                   help="expected flag prefix, repeatable (e.g. --flag-prefix DH). "
                        "Defaults to CRYPTOEXP_FLAG_PREFIXES, else the built-in "
                        "CTF event list")
    p.add_argument("--flag-regex", metavar="REGEX",
                   help="a regex that replaces the prefix list entirely, for marker "
                        "formats that are not PREFIX{...}")

    sub.add_parser("list", help="list analyzers and solve templates")

    p = sub.add_parser("hypotheses",
                       help="run the hypothesis engine end to end (attack surface + gaps)")
    p.add_argument("target", help="challenge file/directory/challenge text")
    p.add_argument("--json", action="store_true", help="JSON output")

    p = sub.add_parser("lab",
                       help="generate a workbench scaffold (start here for long-tail challenges)")
    p.add_argument("target", help="challenge file/directory/challenge text")
    p.add_argument("--out", default="lab", help="output directory (default lab/)")
    p.add_argument("--deep", action="store_true",
                   help="try every hypothesis while generating (slow)")
    p.add_argument("--run", action="store_true", help="run it once right after generating")
    p.add_argument("--no-encoding", action="store_true", help="skip encoding/XOR analysis")
    return parser


def main(argv=None):
    # A Windows console defaults to a legacy codepage (GBK here). The report prints
    # candidate bytes, which can contain characters that codepage cannot encode - the
    # run then died with UnicodeEncodeError and emitted no report at all. Reconfigure
    # instead of hoping the locale is UTF-8; errors="replace" keeps a bad byte from
    # killing the whole output.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass                     # a redirected/odd stream: nothing to do
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1
    if not getattr(args, "json", False):
        print_banner()
    match args.command:
        case "analyze":
            return cmd_analyze(args)
        case "hypotheses":
            return cmd_hypotheses(args)
        case "lab":
            return cmd_lab(args)
        case "list":
            return cmd_list(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
