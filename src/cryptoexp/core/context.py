"""Challenge context / blackboard — materialized once, analyzers read it without re-scanning

In intelpwn the equivalent of `results["_shared"]` is `ctx` here. Keys carried:
  raw_text   raw text (challenge prompt / script)
  files      attachment list
  ints       every integer found (with source and label hints)
  named      {label: [value, ...]} — same name keeps all values (RSA low-exponent
             broadcast is exactly several n's)
  blobs      suspected ciphertext strings (hex/base64/morse/...)
  data       already-decoded byte strings (for the symmetric/xor analyzers)
  py         Python sources found in attachments (oracle challenges)

Parsing only *extracts*; it never judges. Judgment belongs to the analyzers, the
same layering intelpwn uses.
"""

import os
import re

from ..utils import encoding as E

_MAX_FILE_BYTES = 4 * 1024 * 1024

_LABELED_RE = re.compile(
    r'(?:^|[\s,;(\[{])([A-Za-z_][A-Za-z0-9_]{0,15})\s*[:=]\s*'
    r'(0x[0-9a-fA-F]{2,}|\d+)'
)
_BARE_INT_RE = re.compile(r'(?<![\w.])(\d{4,})(?![\w.])')
_HEX_BLOB_RE = re.compile(r'(?<![\w])((?:[0-9a-fA-F]{2}){8,})(?![\w])')
_B64_BLOB_RE = re.compile(r'(?<![\w+/=])([A-Za-z0-9+/=_-]{16,})(?![\w+/=])')
_MORSE_BLOB_RE = re.compile(r'(?<![\w])([.\-]{1,6}(?:[ /|]+[.\-]{1,6})+)(?![\w])')
_BIN_BLOB_RE = re.compile(r'(?<![\w])([01]{16,})(?![\w])')

_TEXT_EXT = {'.txt', '.md', '.py', '.sage', '.json', '.pem', '.crt', '.log',
             '.out', '.enc', '.hex', '.b64', '.csv'}


def _read_file(path: str):
    try:
        size = os.path.getsize(path)
        if size > _MAX_FILE_BYTES:
            return None, f"file too large ({size} bytes), skipping content parsing"
        with open(path, 'rb') as f:
            data = f.read()
        return data, None
    except OSError as e:
        return None, f"read failed: {e}"


def _classify(path: str, data: bytes) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in _TEXT_EXT:
        return "text"
    if data[:4] == b'\x7fELF':
        return "elf"
    if b'-----BEGIN' in data[:200]:
        return "pem"
    try:
        data.decode('utf-8')
        return "text"
    except UnicodeDecodeError:
        return "binary"


def build_context(target: str) -> dict:
    """Materialize target (file/directory/inline text) into a context dict

    target rules:
      - an existing directory -> every file under it
      - an existing file      -> that file
      - anything else         -> treated as an inline challenge prompt
        (handy for `cryptoexp analyze "n=... e=... c=..."`)
    """
    ctx = {
        "target": target, "kind": "", "raw_text": "", "files": [],
        "ints": [], "named": {}, "blobs": [], "data": [], "py": [],
        "warnings": [],
    }
    file_paths = []
    if os.path.isdir(target):
        ctx["kind"] = "dir"
        for root, dirs, names in os.walk(target):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d != '__pycache__']
            for n in sorted(names):
                file_paths.append(os.path.join(root, n))
    elif os.path.isfile(target):
        ctx["kind"] = "file"
        file_paths = [target]
    else:
        ctx["kind"] = "inline"
        ctx["raw_text"] = target

    texts = []
    for p in file_paths:
        data, err = _read_file(p)
        if err:
            ctx["warnings"].append(f"{os.path.basename(p)}: {err}")
            continue
        kind = _classify(p, data)
        item = {"path": p, "name": os.path.basename(p), "size": len(data),
                "kind": kind, "data": data}
        if kind in ("text", "pem"):
            try:
                item["text"] = data.decode('utf-8', errors='replace')
                texts.append((item["name"], item["text"]))
                if p.endswith('.py') or p.endswith('.sage'):
                    ctx["py"].append({"name": item["name"], "code": item["text"]})
            except Exception:
                pass
        ctx["files"].append(item)
        if kind == "binary":
            ctx["data"].append({"source": item["name"], "data": data, "kind": "raw"})

    if ctx["kind"] == "inline":
        texts.append(("<inline>", ctx["raw_text"]))
    ctx["raw_text"] = "\n".join(t for _, t in texts)

    # ── Extraction: labeled parameters / bare integers / ciphertext strings ──
    named = {}
    for name, text in texts:
        for m in _LABELED_RE.finditer(text):
            label, raw = m.group(1), m.group(2)
            val = int(raw, 16) if raw.lower().startswith('0x') else int(raw)
            named.setdefault(label.lower(), []).append(val)
            ctx["ints"].append({"name": label.lower(), "value": val,
                                "source": name, "named": True})
        for m in _BARE_INT_RE.finditer(text):
            val = int(m.group(1))
            if val < 10000:
                continue
            ctx["ints"].append({"name": None, "value": val, "source": name,
                                "named": False})
    ctx["named"] = named

    # Deduplicate (one entry per value, but keep the labeled one)
    seen = {}
    for item in ctx["ints"]:
        key = (item["value"], item["name"])
        if key in seen:
            continue
        seen[key] = item
    ctx["ints"] = sorted(seen.values(), key=lambda x: x["value"], reverse=True)

    for name, text in texts:
        blobs = _extract_blobs(text, name)
        ctx["blobs"].extend(blobs)

    # Decoded bytes (hex/base64 decoded up front for the symmetric/xor analyzers)
    for b in ctx["blobs"]:
        dec = None
        if "hex" in b["kinds"]:
            dec = E.from_hex(b["text"])
        if dec is None and "base64" in b["kinds"]:
            dec = E.from_base64(b["text"])
        if dec and len(dec) >= 8:
            ctx["data"].append({"source": b["source"], "data": dec,
                                "kind": b["kinds"][0], "blob": b["text"][:64]})
    return ctx


def _extract_blobs(text: str, source: str):
    """Extract suspected ciphertext strings (one line may hold both hex and base64)"""
    out, seen = [], set()
    for kind, pat in (("hex", _HEX_BLOB_RE), ("base64", _B64_BLOB_RE),
                      ("binary", _BIN_BLOB_RE), ("morse", _MORSE_BLOB_RE)):
        for m in pat.finditer(text):
            blob = m.group(1).strip()
            if len(blob) < 8 or blob in seen:
                continue
            # Hex strings are a subset of the base64 charset: crude pre-filter by
            # "does it contain letters outside a-f", the score decides precisely.
            seen.add(blob)
            out.append({
                "text": blob, "kinds": E.guess_kinds(blob), "declared": kind,
                "source": source, "length": len(blob),
            })
    return out


def context_public(ctx: dict) -> dict:
    """Public view for reports/JSON (large fields truncated, no internal references)
    Returns: a JSON-safe view {"target", "kind", "files", "named",
             "blob_count", "data_count", "warnings"} with large fields
             truncated; the internal blackboard (`_ctx`) never leaks.
    """
    return {
        "target": ctx["target"],
        "kind": ctx["kind"],
        "files": [{"name": f["name"], "size": f["size"], "kind": f["kind"]}
                  for f in ctx["files"]],
        "named": {k: [hex(v) if v > 2 ** 64 else v for v in vs]
                  for k, vs in ctx["named"].items()},
        "blob_count": len(ctx["blobs"]),
        "data_count": len(ctx["data"]),
        "warnings": ctx["warnings"],
    }
