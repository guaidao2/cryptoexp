"""Workbench — a scaffold for the challenges templates cannot reach

This is the direct answer to "crypto challenges cannot rely on templates":
templates cover the common 20% at best, and the other 80% is
"read the construction → find the weakness → write the last step yourself".
The workbench is not a replacement for that last step; it does four things at once:

  1. extract every parameter reproducibly (PARAMS literals, no re-parsing the challenge)
  2. write the hypothesis engine's verdicts into comments: what applies, what does not and why
  3. make the usual starters (RSA/encoding/oracle/lattice) importable and ready to call
  4. leave one explicit slot — your own idea goes here

The output is a runnable script, not a report: open it, edit it, run it.
"""

import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _lit(v):
    """Render big integers / byte strings as readable Python literals
    (long integers are split into 64-digit hex chunks)"""
    if isinstance(v, int):
        if v.bit_length() > 256:
            h = hex(v)[2:]
            parts = [h[i:i + 64] for i in range(0, len(h), 64)]
            inner = " +\n        ".join(f'"{p}"' for p in parts)
            return f"int(\n        {inner}, 16)"
        return str(v)
    if isinstance(v, bytes):
        return repr(v)
    return repr(v)


def build_workbench(results: dict, params: dict = None, hypotheses: dict = None,
                    max_layers: int = None) -> str:
    """Render the workbench script as text

    max_layers: decode-chain depth baked into the generated `try_decode_chain()`
        (None = `encoding.DEFAULT_CHAIN_LAYERS`, i.e. 3). The generated script reads
        it back from `cx.encoding.DEFAULT_CHAIN_LAYERS`, so editing that one constant
        in the workbench changes the depth without touching the loop.
    """
    from .hypothesis import params_from_ctx, evaluate
    from .utils.encoding import DEFAULT_CHAIN_LAYERS
    depth = int(max_layers if max_layers is not None else DEFAULT_CHAIN_LAYERS)
    ctx = results.get("_ctx") or {}
    params = params or params_from_ctx(ctx)
    hy = hypotheses or evaluate(params, budget="full")

    lines = [
        "#!/usr/bin/env python3",
        "# -*- coding: utf-8 -*-",
        "# cryptoexp workbench — generated scaffold (not an answer)",
        "# It lays out the known parameters / applicable hypotheses / what is missing /",
        "# available tools in one place; the last step (your idea) is yours to write.",
        f"# target: {results.get('target')}",
        "import sys",
        f'sys.path.insert(0, r"{_ROOT}")',
        "",
        "import cryptoexp as cx   # number theory / encoding / AES / LLL / oracle / MT here",
        "",
        "# ─────────────────── extracted parameters ───────────────────",
        "PARAMS = {",
    ]
    for key in ("n", "e", "c", "p", "q", "dp", "phi", "d", "g", "h", "mod"):
        if params.get(key):
            lines.append(f"    {key!r}: {_lit(params[key])},")
    if params.get("n_list"):
        lines.append(f"    'n_list': {params['n_list'][:6]},")
    if params.get("c_list"):
        lines.append(f"    'c_list': {params['c_list'][:6]},")
    lines.append("}")

    lines += ["", "# ─────────────────── hypothesis engine verdicts ───────────────────"]
    for r in hy.get("results", []):
        lines.append(f"# [{r['state']}] {r['name']} ({r['domain']}) — {r['idea']}")
        if r.get("detail"):
            lines.append(f"#         measured: {r['detail'][:110]}")
        if r.get("note"):
            lines.append(f"#         note: {r['note'][:110]}")
    for g in hy.get("gaps", []):
        miss = "; ".join(g.get("missing", [])[:2])
        lines.append(f"# [gap] {g['name']} — applies when: {miss}")

    blobs = params.get("blobs") or []
    if blobs:
        lines += ["", "# ─────────────────── suspected ciphertext blobs ───────────────────",
                  "BLOBS = ["]
        for b in blobs[:8]:
            lines.append(f"    {b[:120]!r},")
        lines.append("]")
    if params.get("sequences"):
        lines += ["", "OUTPUTS = " + repr(params["sequences"][0][:24])]

    lines += [
        "",
        "# ─────────────────── starter snippets (pick one and keep going) ───────────────────",
        # The depth the analysis actually used. `cx.encoding.DEFAULT_CHAIN_LAYERS` is
        # the same constant the analyzers read, so raising it here raises it for the
        # chain below (a chain that stops at the cap reports hit_limit=True).
        f"MAX_LAYERS = {depth}   # == cx.encoding.DEFAULT_CHAIN_LAYERS",
        "def try_rsa_auto():",
        "    r = auto_attack(PARAMS.get('n'), PARAMS.get('e', 65537), PARAMS.get('c'))",
        "    print('auto_attack:', r['ok'], r.get('detail') or r.get('note'))",
        "    if r.get('plaintext'):",
        "        print('plaintext:', r['plaintext'])",
        "    return r",
        "",
        "def try_decode_chain():",
        "    for b in BLOBS:",
        "        for c in decode_chain(b, max_layers=MAX_LAYERS)[:3]:",
        "            print('→'.join(c['steps']), c['score'], c['flags'],",
        "                  'hit_limit' if c['hit_limit'] else '', c['text'][:60])",
        "",
        "def try_xor():",
        "    for b in BLOBS:",
        "        raw = unhex(b) or None",
        "        if raw is None:",
        "            continue",
        "        for c in repeating_key_xor(raw)[:2]:",
        "            print(c['keysize'], c['key'], c['score'], c['plaintext'][:60])",
        "",
        "def remote_oracle(host, port, encode=lambda d: d.hex().encode() + b'\\n',",
        "                  decode=lambda r: bytes.fromhex(r.decode().strip())):",
        "    \"\"\"Remote encryption oracle template (fill in the socket details).\"\"\"",
        "    import socket",
        "",
        "    def call(payload: bytes) -> bytes:",
        "        with socket.create_connection((host, port)) as s:",
        "            s.sendall(encode(payload))",
        "            return decode(s.recv(1 << 20))",
        "    return call",
        "",
        "# secret = ecb_byte_at_a_time(remote_oracle('127.0.0.1', 1337))",
        "",
        "if __name__ == '__main__':",
        "    print('parameters:', {k: (str(v)[:32] + '…' if len(str(v)) > 32 else v)",
        "                          for k, v in PARAMS.items()})",
        "    # ↓↓↓ your idea here (the tools above are ready to use) ↓↓↓",
        "    try_rsa_auto()",
        "    try_decode_chain()",
        "    try_xor()",
    ]
    return "\n".join(lines) + "\n"


def write_workbench(results: dict, out_dir: str = "lab", params: dict = None,
                    hypotheses: dict = None, max_layers: int = None) -> str:
    """Drop the workbench script on disk and return its path

    `max_layers` is forwarded to `build_workbench` (decode-chain depth).
    """
    target = str(results.get("target") or "target")
    base = os.path.basename(target.rstrip("\\/")) or "target"
    base = "".join(ch for ch in base if ch.isalnum() or ch in "._-") or "target"
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"workbench_{base}.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_workbench(results, params, hypotheses, max_layers=max_layers))
    return path
