"""Key-container parsing and encoding - PEM / DER / OpenSSH, standard library only

    from cryptoexp.utils import keys as K
    K.parse_pem(open("key.pem", "rb").read())      # -> RSA numbers
    K.parse_der_rsa_public(der)                    # -> (n, e)
    K.parse_ssh_public_key("ssh-rsa AAAA... me")  # -> {"type", "e", "n", "comment"}
    K.rsa_public_der(n, e)                         # DER encoder (round-trip tests)
    K.key_fingerprint_sha256(line_or_key)          # "SHA256:...."

Everything is hand-rolled ASN.1 DER and SSH wire format: no pycryptodome, no
cryptography, no external files. Supported containers:

    PKCS#1  RSAPublicKey        (RSA PUBLIC KEY, and the inner form of SPKI)
    SPKI    SubjectPublicKeyInfo (PUBLIC KEY with OID 1.2.840.113549.1.1.1)
    PKCS#1  RSAPrivateKey       (RSA PRIVATE KEY)
    PKCS#8  PrivateKeyInfo      (PRIVATE KEY, unencrypted RSA only)
    OpenSSH openssh-key-v1      (OPENSSH PRIVATE KEY, cipher "none" only)
    OpenSSH authorized_keys     (ssh-rsa, with or without options/comment)

Out of scope by construction (NotImplementedError with the exact reason, never a
silent wrong answer): encrypted PEM (PBES2), encrypted OpenSSH keys
(bcrypt-pbkdf + AES/ChaCha20-Poly1305), non-RSA key types.
"""

import base64
import hashlib
import re


RSA_OID = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])

_OPENSSH_MAGIC = b"openssh-key-v1\x00"

_PEM_BLOCK_RE = re.compile(rb"-----BEGIN ([A-Za-z0-9 ._-]+?)-----(.*?)-----END \1-----", re.S)


# -------------------------- ASN.1 DER primitives --------------------------

def _der_read(data: bytes, off: int = 0):
    """Read one TLV: returns (tag, value_bytes, offset_after_value)"""
    data = bytes(data)
    if off + 2 > len(data):
        raise ValueError("truncated DER (no room for a tag and a length)")
    tag = data[off]
    off += 1
    first = data[off]
    off += 1
    if first & 0x80:
        nlen = first & 0x7F
        if nlen == 0:
            raise ValueError("indefinite length is not valid DER")
        if nlen > 4:
            raise ValueError(f"DER length field of {nlen} bytes is implausibly large")
        if off + nlen > len(data):
            raise ValueError("truncated DER length field")
        length = int.from_bytes(data[off:off + nlen], "big")
        off += nlen
    else:
        length = first
    if off + length > len(data):
        raise ValueError(f"truncated DER value (tag 0x{tag:02x} claims {length} bytes)")
    return tag, data[off:off + length], off + length


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + bytes(value)


def _der_encode_int(value: int) -> bytes:
    """DER INTEGER (minimal two's-complement, leading 0x00 when the top bit is set)"""
    if value < 0:
        raise ValueError("negative integers are not supported by this minimal encoder")
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_decode_int(raw: bytes) -> int:
    """DER INTEGER value -> non-negative int (a negative encoding is rejected)"""
    if not raw:
        raise ValueError("empty INTEGER")
    if raw[0] & 0x80:
        raise ValueError("negative INTEGER (this library only handles RSA key numbers)")
    return int.from_bytes(raw, "big")


def _der_seq(*parts) -> bytes:
    return _der_tlv(0x30, b"".join(bytes(p) for p in parts))


def _oid_to_dotted(raw: bytes) -> str:
    if not raw:
        return "<empty>"
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _algo_oid(algid_body: bytes) -> bytes:
    """AlgorithmIdentifier SEQUENCE body -> OID value bytes"""
    tag, val, _ = _der_read(algid_body, 0)
    if tag != 0x06:
        raise ValueError(f"AlgorithmIdentifier does not start with an OID (tag 0x{tag:02x})")
    return val


def _require_rsa_oid(algid_body: bytes):
    oid = _algo_oid(algid_body)
    if oid != RSA_OID:
        raise ValueError(f"algorithm OID {_oid_to_dotted(oid)} is not rsaEncryption "
                         f"(1.2.840.113549.1.1.1) - not an RSA key")


# -------------------------- DER -> RSA numbers --------------------------

def parse_der_rsa_public(der: bytes):
    """DER public key -> (n, e)

    Accepts both shapes: PKCS#1 RSAPublicKey (SEQUENCE {n, e}) and
    SubjectPublicKeyInfo (the SPKI wrapper used by "PUBLIC KEY" PEM blocks and
    by most DER files in the wild).
    """
    der = bytes(der)
    tag, body, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError(f"expected a SEQUENCE at the top level, got tag 0x{tag:02x}")
    tag1, val1, off1 = _der_read(body, 0)
    if tag1 == 0x02:  # PKCS#1 RSAPublicKey { n INTEGER, e INTEGER }
        n = _der_decode_int(val1)
        tag2, val2, _ = _der_read(body, off1)
        if tag2 != 0x02:
            raise ValueError(f"expected INTEGER e, got tag 0x{tag2:02x}")
        e = _der_decode_int(val2)
        return n, e
    if tag1 == 0x30:  # SubjectPublicKeyInfo
        _require_rsa_oid(val1)
        tag2, val2, _ = _der_read(body, off1)
        if tag2 != 0x03:
            raise ValueError(f"SPKI without a BIT STRING subjectPublicKey (tag 0x{tag2:02x})")
        if not val2 or val2[0] != 0:
            raise ValueError("BIT STRING with unused bits set - not a DER key blob")
        return parse_der_rsa_public(val2[1:])
    raise ValueError(f"unexpected first element tag 0x{tag1:02x} (neither INTEGER nor SEQUENCE)")


def parse_der_rsa_private(der: bytes) -> dict:
    """DER private key -> {type, version, n, e, d, p, q, dp, dq, qinv, other_primes}

    Accepts PKCS#1 RSAPrivateKey and the PKCS#8 PrivateKeyInfo wrapper (which is
    recursed into when the algorithm OID is rsaEncryption). dp/dq/qinv are the
    values stored in the container, not recomputed ones.
    """
    der = bytes(der)
    tag, body, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError(f"expected a SEQUENCE at the top level, got tag 0x{tag:02x}")
    tag1, val1, off1 = _der_read(body, 0)
    if tag1 != 0x02:
        raise ValueError(f"expected the version INTEGER first, got tag 0x{tag1:02x}")
    version = _der_decode_int(val1)

    if off1 < len(body):
        tag2, val2, off2 = _der_read(body, off1)
        if tag2 == 0x30:  # PKCS#8 PrivateKeyInfo: version, AlgorithmIdentifier, OCTET STRING
            _require_rsa_oid(val2)
            tag3, val3, _ = _der_read(body, off2)
            if tag3 != 0x04:
                raise ValueError(f"PKCS#8 without an OCTET STRING privateKey (tag 0x{tag3:02x})")
            inner = parse_der_rsa_private(val3)
            inner["pkcs8"] = True
            return inner

    names = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")
    out = {"type": "rsa_private", "version": version, "pkcs8": False}
    cur = off1
    for name in names:
        tag_i, val_i, cur = _der_read(body, cur)
        if tag_i != 0x02:
            raise ValueError(f"expected INTEGER {name}, got tag 0x{tag_i:02x} "
                             f"(truncated PKCS#1 RSAPrivateKey?)")
        out[name] = _der_decode_int(val_i)
    other = []
    while cur < len(body):  # otherPrimeInfos (multi-prime keys)
        tag_i, val_i, cur = _der_read(body, cur)
        if tag_i != 0x30:
            break
        primes = []
        inner_off = 0
        while inner_off < len(val_i):
            tag_j, val_j, inner_off = _der_read(val_i, inner_off)
            if tag_j != 0x02:
                break
            primes.append(_der_decode_int(val_j))
        other.append(primes)
    out["other_primes"] = other
    return out


# -------------------------- DER encoder (round-trip support) --------------------------

def rsa_public_der(n, e) -> bytes:
    """minimal DER encoder: PKCS#1 RSAPublicKey = SEQUENCE { INTEGER n, INTEGER e }

    This is the form openssl produces with `-RSAPublicKey_out -outform DER` and
    exactly what parse_der_rsa_public reads back, so tests need no key files.
    (For the SPKI wrapper, wrap it yourself or use openssl; the parser reads both.)
    """
    return _der_seq(_der_encode_int(int(n)), _der_encode_int(int(e)))


# -------------------------- PEM --------------------------

def _pem_blocks(data: bytes):
    for m in _PEM_BLOCK_RE.finditer(data):
        label = m.group(1).decode("ascii", "replace").strip()
        yield label, m.group(2)


def _pem_body_to_der(body: bytes):
    """PEM body (headers + base64) -> (der_bytes, headers_dict)"""
    headers = {}
    payload = []
    in_headers = True
    for raw in body.split(b"\n"):
        line = raw.strip()
        if not line:
            # The newline right after the BEGIN line is part of the wrapper, not the
            # end of the header section: treating it as such made every header line
            # fall through into the base64 payload (caught by the known-answer run on
            # a hand-built Proc-Type PEM).
            if in_headers and not headers:
                continue
            in_headers = False
            continue
        if in_headers and b":" in line:
            key, _, val = line.partition(b":")
            headers[key.strip().decode("ascii", "replace").lower()] = \
                val.strip().decode("ascii", "replace")
            continue
        in_headers = False
        payload.append(line)
    text = b"".join(payload)
    if not text:
        raise ValueError("PEM block has an empty body")
    try:
        der = base64.b64decode(text, validate=False)
    except Exception as exc:
        raise ValueError(f"PEM body is not valid base64: {exc}")
    return der, headers


def _rsa_dict(kind: str, numbers: dict) -> dict:
    """Exactly the documented 9 keys - no extras, so equality checks stay stable"""
    return {
        "type": kind,
        "n": numbers.get("n"),
        "e": numbers.get("e"),
        "d": numbers.get("d"),
        "p": numbers.get("p"),
        "q": numbers.get("q"),
        "dp": numbers.get("dp"),
        "dq": numbers.get("dq"),
        "qinv": numbers.get("qinv"),
    }


def parse_pem(data):
    """Detect and decode PEM blocks -> RSA numbers

    Returns, for an RSA block:
        {"type": "rsa_public"|"rsa_private", "n": int, "e": int, "d": int|None,
         "p": int|None, "q": int|None, "dp": int|None, "dq": int|None,
         "qinv": int|None}
    with None for every field the container does not carry (a public key has no
    d/p/q). The first RSA block in the input wins.

    Raises:
        ValueError: no PEM block, damaged base64/DER, or no RSA block at all
        NotImplementedError: an encrypted container (legacy "Proc-Type:
            ...ENCRYPTED" PEM or "ENCRYPTED PRIVATE KEY"), which needs a
            passphrase-based KDF/cipher this module deliberately does not carry

    A non-RSA block (CERTIFICATE, EC PRIVATE KEY, ...) is reported as
    {"type": "unsupported", "label": ..., "der": ..., "note": ...} rather than
    being mistaken for a key.
    """
    if isinstance(data, str):
        raw = data.encode("utf-8", "replace")
    else:
        raw = bytes(data)
    blocks = list(_pem_blocks(raw))
    if not blocks:
        raise ValueError("no PEM block found (expected '-----BEGIN ...-----')")

    unsupported = None
    failures = []
    for label, body in blocks:
        norm = label.upper()
        # NB: norm is already upper-cased, so the test has to lower-case it again --
        # testing "encrypted" against the upper-cased label silently never matched and
        # an encrypted block fell through to the "unsupported" branch (caught by the
        # known-answer run against an openssl PBES2 container).
        if "encrypted" in norm.lower():
            raise NotImplementedError(
                f"encrypted PEM container '{label}': PBES2/PBES1 needs the passphrase, "
                f"the KDF parameters (salt/iteration count), the cipher and padding - "
                f"none of which this parser derives. Decrypt it first, e.g. "
                f"`openssl rsa -in enc.pem -out plain.pem` or `openssl pkcs8 -in enc.pem "
                f"-out plain.pem`, then parse the plaintext container.")
        if norm == "OPENSSH PRIVATE KEY":
            # Not really PEM, but it is the same wrapper: hand it to the OpenSSH parser
            return parse_openssh_private(raw)
        try:
            der, headers = _pem_body_to_der(body)
        except ValueError as exc:
            failures.append(f"{label}: {exc}")
            continue
        if "proc-type" in headers and "encrypted" in headers["proc-type"].lower():
            raise NotImplementedError(
                f"legacy encrypted PEM '{label}' (Proc-Type: {headers['proc-type']}, "
                f"DEK-Info: {headers.get('dek-info', '?')}): needs the passphrase plus "
                f"the OpenSSL EVP_BytesToKey derivation and the named cipher. Decrypt "
                f"it with `openssl rsa -in enc.pem -out plain.pem` first.")
        if norm in ("RSA PUBLIC KEY", "PUBLIC KEY"):
            try:
                n, e = parse_der_rsa_public(der)
                return _rsa_dict("rsa_public", {"n": n, "e": e})
            except ValueError as exc:
                failures.append(f"{label}: {exc}")
        elif norm in ("RSA PRIVATE KEY", "PRIVATE KEY"):
            try:
                key = parse_der_rsa_private(der)
                return _rsa_dict("rsa_private", key)
            except ValueError as exc:
                failures.append(f"{label}: {exc}")
        else:
            if unsupported is None:
                unsupported = {
                    "type": "unsupported",
                    "label": label,
                    "der": der,
                    "note": f"PEM label '{label}' is not an RSA key container",
                }
    if unsupported is not None:
        return unsupported
    raise ValueError("no RSA PEM block could be decoded: " + "; ".join(failures))


def pem_wrap(label: str, der: bytes) -> str:
    """64-column PEM encoder: '-----BEGIN <label>-----' + base64 + END line

    The trailing newline is included, as in every file openssl writes.
    """
    b64 = base64.b64encode(bytes(der)).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    body = "".join(line + "\n" for line in lines)
    return f"-----BEGIN {label}-----\n{body}-----END {label}-----\n"


# -------------------------- OpenSSH wire format --------------------------

def _ssh_read_string(blob: bytes, off: int):
    if off + 4 > len(blob):
        raise ValueError("truncated SSH blob (missing a uint32 length)")
    ln = int.from_bytes(blob[off:off + 4], "big")
    off += 4
    if off + ln > len(blob):
        raise ValueError(f"truncated SSH blob (a field claims {ln} bytes, "
                         f"{len(blob) - off} left)")
    return blob[off:off + ln], off + ln


def _ssh_write_string(raw: bytes) -> bytes:
    return len(raw).to_bytes(4, "big") + bytes(raw)


def _ssh_write_mpint(value: int) -> bytes:
    """SSH mpint: big-endian, minimal, with a leading 0x00 when the top bit is set"""
    raw = int(value).to_bytes((int(value).bit_length() + 7) // 8 or 1, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _ssh_write_string(raw)


def _ssh_read_mpint(blob: bytes, off: int, name: str):
    raw, off = _ssh_read_string(blob, off)
    if raw and raw[0] & 0x80:
        raise ValueError(f"mpint {name} has the top bit set (negative encoding)")
    return int.from_bytes(raw, "big"), off


def _find_key_type(parts):
    for i, tok in enumerate(parts):
        if tok.startswith(("ssh-", "ecdsa-", "sk-")) or tok == "xmss":
            return i
    return None


def _b64_tolerant(text) -> bytes:
    """base64 decode that tolerates missing padding and stray whitespace"""
    if isinstance(text, str):
        text = text.encode("ascii", "ignore")
    cleaned = re.sub(rb"\s+", b"", text)
    pad = (-len(cleaned)) % 4
    try:
        return base64.b64decode(cleaned + b"=" * pad, validate=False)
    except Exception as exc:
        raise ValueError(f"not valid base64: {exc}")


def parse_ssh_public_key(line: str) -> dict:
    """authorized_keys line -> {"type": "ssh-rsa", "e": int, "n": int, "comment": str}

    Leading options and the comment field are both tolerated; the type inside the
    blob is authoritative (a line whose outer type disagrees with its blob is
    rejected). Non-RSA types raise NotImplementedError, a malformed blob raises
    ValueError - an unparsable line never yields a dict full of Nones.
    """
    if isinstance(line, (bytes, bytearray)):
        s = bytes(line).decode("utf-8", "replace").strip()
    else:
        s = str(line).strip()
    if not s:
        raise ValueError("empty SSH public key line")
    parts = s.split()
    idx = _find_key_type(parts)
    if idx is None:
        raise ValueError("no SSH key type found (expected ssh-rsa / ecdsa-... / ssh-ed25519)")
    if idx + 1 >= len(parts):
        raise ValueError("SSH public key line has no base64 key blob")
    declared = parts[idx]
    blob = _b64_tolerant(parts[idx + 1])
    comment = " ".join(parts[idx + 2:])
    inner, off = _ssh_read_string(blob, 0)
    inner_type = inner.decode("ascii", "replace")
    if inner_type != declared:
        raise ValueError(f"the outer type '{declared}' does not match the key blob "
                         f"type '{inner_type}'")
    if inner_type != "ssh-rsa":
        raise NotImplementedError(f"SSH key type '{inner_type}' is not RSA "
                                  f"(only ssh-rsa is decoded)")
    e, off = _ssh_read_mpint(blob, off, "e")
    n, off = _ssh_read_mpint(blob, off, "n")
    return {"type": "ssh-rsa", "e": e, "n": n, "comment": comment}


def parse_openssh_private(data, passphrase: bytes = None) -> dict:
    """openssh-key-v1 container -> RSA numbers

    Implements the unencrypted case (cipher "none", kdf "none"): the private
    section carries checkint1 == checkint2 followed by, per key, the type, the
    numbers and the comment, padded with 1, 2, 3, ... to the cipher block size.

    Returns the documented RSA keys plus: comment, cipher, kdf, n_keys,
    check_ints_ok, padding_ok and consistent (whether p*q == n, a free sanity
    check on the key material).

    Raises:
        NotImplementedError: the key is encrypted (cipher != "none"). OpenSSH
            uses bcrypt-pbkdf for the key/nonce and then AES-CTR or
            chacha20-poly1305; bcrypt is Blowfish-based and has no standard
            library implementation, so this module refuses rather than
            pretending. `ssh-keygen -p -N '' -f key` produces the plain form.
        ValueError: not an openssh-key-v1 container, or a damaged one
    """
    if isinstance(data, str):
        raw = data.encode("utf-8", "replace")
    else:
        raw = bytes(data)
    blocks = [b for b in _pem_blocks(raw) if b[0].upper() == "OPENSSH PRIVATE KEY"]
    if not blocks:
        if raw.startswith(_OPENSSH_MAGIC):
            blob = raw  # bare container without the PEM wrapper
        else:
            raise ValueError("not an OpenSSH private key "
                             "(no '-----BEGIN OPENSSH PRIVATE KEY-----' block)")
    else:
        der, _ = _pem_body_to_der(blocks[0][1])
        blob = der
    if not blob.startswith(_OPENSSH_MAGIC):
        raise ValueError("missing the 'openssh-key-v1' magic")

    off = len(_OPENSSH_MAGIC)
    ciphername, off = _ssh_read_string(blob, off)
    kdfname, off = _ssh_read_string(blob, off)
    kdfoptions, off = _ssh_read_string(blob, off)
    if off + 4 > len(blob):
        raise ValueError("truncated openssh-key-v1 header (no key count)")
    n_keys = int.from_bytes(blob[off:off + 4], "big")
    off += 4
    public_blobs = []
    for _ in range(n_keys):
        pub, off = _ssh_read_string(blob, off)
        public_blobs.append(pub)
    private_blob, off = _ssh_read_string(blob, off)

    cipher = ciphername.decode("ascii", "replace")
    kdf = kdfname.decode("ascii", "replace")
    if cipher != "none" or kdf != "none":
        raise NotImplementedError(
            f"encrypted OpenSSH private key (cipher '{cipher}', kdf '{kdf}'): the "
            f"passphrase-based derivation is bcrypt-pbkdf (Blowfish based) and the "
            f"cipher is {cipher}; neither bcrypt nor the AEAD ciphers used here are "
            f"in the Python standard library, so this module does not decrypt it. "
            f"Convert it first: `ssh-keygen -p -N '' -f <key>` (or export to PEM with "
            f"`ssh-keygen -m PEM -p -N '' -f <key>`) and parse the plaintext form."
            + (" A passphrase was supplied, but bcrypt-pbkdf is still out of scope."
               if passphrase else ""))

    if len(private_blob) < 8:
        raise ValueError("truncated private section (no check integers)")
    check1 = int.from_bytes(private_blob[0:4], "big")
    check2 = int.from_bytes(private_blob[4:8], "big")
    if check1 != check2:
        raise ValueError(f"the two check integers differ (0x{check1:08x} vs "
                         f"0x{check2:08x}): damaged container or a wrong-decrypt")
    # Private section: per key { string type, numbers, string comment }, then
    # 1, 2, 3, ... padding. Only ssh-rsa is decoded; for another key type the
    # field layout is unknown here, so parsing stops instead of misreading bytes.
    cur = 8
    first_rsa = None
    types = []
    try:
        keytype_raw, cur = _ssh_read_string(private_blob, cur)
    except ValueError:
        keytype_raw, cur = b"", len(private_blob)
    keytype = keytype_raw.decode("ascii", "replace")
    if keytype:
        types.append(keytype)
    if keytype == "ssh-rsa":
        n, cur2 = _ssh_read_mpint(private_blob, cur, "n")
        e, cur2 = _ssh_read_mpint(private_blob, cur2, "e")
        d, cur2 = _ssh_read_mpint(private_blob, cur2, "d")
        qinv, cur2 = _ssh_read_mpint(private_blob, cur2, "iqmp")
        p, cur2 = _ssh_read_mpint(private_blob, cur2, "p")
        q, cur2 = _ssh_read_mpint(private_blob, cur2, "q")
        comment_raw, cur2 = _ssh_read_string(private_blob, cur2)
        first_rsa = {
            "type": "rsa_private",
            "n": n, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1) if p > 1 else None,
            "dq": d % (q - 1) if q > 1 else None,
            "qinv": qinv,
            "comment": comment_raw.decode("utf-8", "replace"),
            "cipher": cipher,
            "kdf": kdf,
            "n_keys": n_keys,
            "check_ints_ok": True,
            "consistent": (p * q == n),
        }
        cur = cur2
    if first_rsa is None:
        raise NotImplementedError(f"no ssh-rsa key found in this container "
                                  f"(key types inside: {types or ['<none readable>']})")
    pad = private_blob[cur:]
    first_rsa["padding_ok"] = all(b == (i % 256) + 1 for i, b in enumerate(pad)) if pad else True
    return first_rsa


def key_fingerprint_sha256(ssh_line_or_key) -> str:
    """OpenSSH-style fingerprint "SHA256:<base64-without-padding>"

    Accepts an authorized_keys line (str/bytes) or the dict returned by
    parse_ssh_public_key. The digest is taken over the canonical wire blob
    (string "ssh-rsa" + mpint e + mpint n), which is what ssh-keygen prints.
    """
    if isinstance(ssh_line_or_key, dict):
        ktype = ssh_line_or_key.get("type", "ssh-rsa")
        e = ssh_line_or_key.get("e")
        n = ssh_line_or_key.get("n")
        if e is None or n is None:
            raise ValueError("key dict must carry 'e' and 'n' "
                             "(the output of parse_ssh_public_key)")
        ktype = "ssh-rsa" if ktype in ("ssh-rsa", "rsa") else ktype
    else:
        key = parse_ssh_public_key(ssh_line_or_key)
        ktype, e, n = key["type"], key["e"], key["n"]
    if ktype != "ssh-rsa":
        raise NotImplementedError(f"fingerprints for '{ktype}' are not implemented")
    blob = (_ssh_write_string(ktype.encode("ascii")) +
            _ssh_write_mpint(int(e)) + _ssh_write_mpint(int(n)))
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


__all__ = [
    "parse_pem",
    "parse_der_rsa_public",
    "parse_der_rsa_private",
    "parse_ssh_public_key",
    "parse_openssh_private",
    "rsa_public_der",
    "key_fingerprint_sha256",
    "pem_wrap",
]
