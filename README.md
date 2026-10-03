# cryptoexp

**Crypto toolkit for CTF, security assessment and research** — a pwntools-style
toolbox of dependency-free primitives, plus an analysis pipeline on top.

**Authors: coolmoon & guaidao2** — MIT. Import name and PyPI distribution name are
both `cryptoexp` (the plain `cryptokit` name was already taken by an unrelated 2022
project, so this one is `cryptoexp`).

[中文说明](https://github.com/guaidao2/cryptoexp/blob/main/README.zh-CN.md) ·
[repository](https://github.com/guaidao2/cryptoexp)

- Library: `import cryptoexp as cx` — number theory, modular arithmetic, polynomial
  and GF(2) algebra, encodings, classic ciphers, block/stream ciphers, hash length
  extension, PRNG recovery, RSA/signature attacks, lattice tools, oracle attacks, and
  a forensics/assessment layer (batch GCD key audits, DER signature and JWT parsing,
  weak-PRNG fingerprinting).
- CLI: `python3 cryptoexp_cli.py analyze|hypotheses|lab|list` (analysis pipeline, JSON
  contract, solve-script generation).
- **Zero dependencies**: the core uses only the standard library (AES, LLL,
  Coppersmith, SHA-1/2 length extension, ChaCha20, MT19937 … are all implemented
  here). Optional accelerators (`gmpy2`, `sympy`, `pycryptodome`, `z3`) are
  auto-detected and never required.
- **English-first** source and tool output (reports, generated scripts, docstrings);
  this document is English, with a [Chinese README](https://github.com/guaidao2/cryptoexp/blob/main/README.zh-CN.md)
  alongside for readers who prefer it.
- `from cryptoexp import *` exists but is meant for throwaway solve scripts: it only
  brings names that are unmistakably ours. Generic primitives (`gcd`, `sha256`,
  `AES`, …) stay reachable as `cx.gcd` so a star import cannot shadow your own names.
- CTF solving is the core target, **not the only one** — see
  [Beyond CTF](#beyond-ctf-security-assessment-and-research).
- No web UI: this is a library plus a CLI.

---

## Custom flag formats (library-first)

"What a flag looks like" belongs to the engagement, not to the library, so it is
configurable in three layers. All of them work straight from `pip install cryptoexp`:

```python
from cryptoexp import flag_candidates, find_flags, set_flag_prefixes

# 1) per call (no hidden state - the right way inside a library or a service)
flag_candidates(payload, prefixes=["DH", "corp_"])     # DH{...}, corp_...{...}
flag_candidates(payload, pattern=r"ACME-\d{4}-[a-z0-9]{8}")   # arbitrary format

# 2) process default (scripts, notebooks)
set_flag_prefixes(["DH"], merge=True)
flag_candidates(payload)                              # now uses DH, plus the built-ins

# 3) environment (CLI, CI)
#   CRYPTOEXP_FLAG_PREFIXES=DH,corp_ cryptoexp analyze challenge.txt
```

The CLI mirrors it: `--flag-prefix DH` (repeatable) and `--flag-regex '<regex>'`.

`find_flags(data, prefixes=[...])` is the general entry point: it returns every
marker-shaped string with `{"match", "kind": "strict"|"loose", "offset"}`, which is
what you want on a dump, a config file or a log rather than on a challenge
statement. Prefixes are matched literally (a prefix containing `.` cannot match
`abc{...}`), matching is case-insensitive, and placeholder shapes such as `DH{...}`
inside a statement are deliberately *not* treated as flags — otherwise a challenge
would confirm itself.

`analyze_all(path, flag_prefixes=["DH"])` scopes the format to that one run
(a `ContextVar`, so parallel calls cannot leak into each other) and records it in
the result, so verification and the JSON report agree with the caller.

---

## Beyond CTF: security assessment and research

The same primitives answer real engagement questions. Library first, everything
importable from the package root:

| Question | Call |
|---|---|
| Do any of our public keys share a prime factor? | `batch_gcd(moduli)` → pairs + factor groups, product-tree based |
| Is this RSA key weak? | `audit_rsa_key(n, e, extra_moduli=[...])` → findings with severity (`fermat_close_primes`, `wiener_vulnerable`, `shared_factor`, `small_exponent`, …) |
| Is this token really random? | `detect_weak_prng(outputs)` → identifies LCG / glibc `rand` / xorshift / Java `Random` / MT19937, only when the recovery replays the observations |
| What is in this capture? | `parse_jwt(token)`, `parse_der_signature(der)`, `parse_pem`/`parse_ssh_public_key`, `key_fingerprint_sha256` |
| Where are the marked strings in this dump? | `find_flags(data, prefixes=[...])` |
| Two signatures, same nonce? | `ecdsa_nonce_reuse(...)` / `dsa_nonce_reuse(...)` → private key |
| Is this checksum forgeable? | `crc_forge_append(...)`, `crc_solve_unknown(...)` |
| Can I extend this MAC? | `length_extension(...)`, `HashState` |

Honest scope, because overclaiming here is worse than a missing feature: cryptoexp
does no network I/O, no scanning and no HTTP/TLS session parsing. Oracle attacks
take a callable you supply (write a ten-line adapter for the target), and the
analysis pipeline expects "a statement plus ciphertext blobs" as input. For research
it gives you the primitives (LLL, Coppersmith, GF(2)/GF(p) algebra, DLP, PRNG state
recovery, CRC/JWT/DER handling) as composable functions with published-vector tests.

---

## Install

```bash
pip install cryptoexp          # once a stable release exists (see the alpha note)
pipx install cryptoexp         # if you only want the CLI
```

Every release so far is a **pre-release** (`0.1.0aN`), so pip needs `--pre`:

```bash
pip install --pre cryptoexp
```

From a clone, nothing needs installing — the package is importable through the
repository entry point and the source tree:

```bash
git clone https://github.com/guaidao2/cryptoexp.git
cd cryptoexp
python cryptoexp_cli.py analyze challenges/rsa_wiener.txt     # CLI, no install
python -c "import sys; sys.path.insert(0, 'src'); import cryptoexp"   # or add src/ to PYTHONPATH
```

Zero runtime dependencies: the core is standard-library only, so it also works on
locked-down machines without a package index.

---

## Quick start

```bash
# nothing to install
python3 cryptoexp_cli.py analyze challenges/rsa_wiener.txt
python3 cryptoexp_cli.py analyze challenges/xor_repeating.txt --solve --run
python3 cryptoexp_cli.py hypotheses challenges/rsa_high_bits.txt   # attack surface + gaps
python3 cryptoexp_cli.py lab "paste the whole statement here"      # workbench scaffold
python3 cryptoexp_cli.py list                                      # analyzers + solvers + API map
```

```python
import cryptoexp as cx

cx.long_to_bytes(0x4142)              # b'AB'
cx.b64d('ZmxhZ3thfQ==')               # b'flag{a}'
cx.algebra.gcd(24, 36)                # 12
cx.lll([[1, 1, 1], [1, 0, 1], [0, 1, 1]])         # pure-Python lattice reduction
cx.known_high_bits_factor(n, p_high, 160)         # Coppersmith
cx.wiener_attack(e, n, c)                         # {'ok':..., 'plaintext':..., 'factors':...}
cx.ecb_byte_at_a_time(cx.make_ecb_oracle(key, secret))   # oracle attacks
cx.padding_oracle_attack(valid, iv + ct)
cx.clone_from_outputs(six_hundred_and_twenty_four_words) # MT19937 state clone
cx.discrete_log(g, h, p)['x']                     # BSGS -> Pohlig-Hellman
cx.dsa_nonce_reuse(p, q, g, y, r, s1, s2, h1, h2) # nonce-reuse key recovery
cx.crc_compute(b"123456789", 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF)  # 0xCBF43926
cx.length_extension(h1, len(data), b"&admin=1", secret_len=len(secret))
cx.audit_rsa_key(n, e, extra_moduli=[other_n])    # weak-key findings with severity
cx.berlekamp_massey(bits)                          # recover LFSR taps from output bits
cx.java_random_predict(outputs, 4)                 # java.util.Random state recovery
```

---

## Coverage (the mechanical operations)

| Domain | Module | What you get |
|---|---|---|
| Number theory | `utils/algebra.py` | gcd/egcd/lcm, modinv, CRT, integer roots, Miller-Rabin, Pollard rho, continued fractions, Wiener, Fermat, BSGS, Tonelli-Shanks, LCG recovery |
| Modular extras | `utils/modular.py` | Legendre/Jacobi/Kronecker, `sqrt_mod` (prime and composite), totient/Carmichael/Möbius, `order_mod`, primitive roots, non-coprime `crt_general`, gcd/lcm of lists, Pollard p-1, Williams p+1, smoothness, `binomial_mod` |
| Polynomials | `utils/polytools.py` | poly divmod/gcd/derivative/roots-mod-p/from-roots/compose/powmod, irreducibility (Rabin), resultant, GF(2) polynomial arithmetic (bit-encoded) |
| GF(p) linear algebra | `utils/gf.py` | RREF, solve, nullspace, inverse, matrix product, LCG parameter solving, linear-map recovery (Hill / LFSR-style) |
| GF(2) + LFSR + CRC | `utils/gf2.py` | GF(2) RREF/rank/solve/nullspace/inverse, `LFSR`, Berlekamp-Massey tap recovery, CRC compute/catalog/parameter recovery/**forgery**/**preimage with an unknown field**, bit-ordering helpers |
| Lattice | `utils/lattice.py` | pure-Python LLL, univariate Coppersmith, known-high-bits factoring, low-density subset sum (LLL) and meet-in-the-middle |
| Encodings | `utils/encoding.py` | hex/base64/base32/base58/base85/binary, decode-chain search, single-byte and repeating-key XOR, Caesar/affine/Vigenère/Morse/fence with scoring |
| Classic ciphers | `utils/classic_extra.py` | Atbash, ROT47/ROT-N, Bacon, Playfair, Hill, columnar transposition, rail fence, autokey, substitution, base62/base91, URL/HTML decoding, cipher fingerprinting |
| Block ciphers | `utils/aes.py`, `utils/pad.py`, `utils/symtools.py` | pure-Python AES-128/192/256 in ECB/CBC, PKCS#7, XOR, CBC byte flipping, ECB detection from ciphertext alone, block-size inference |
| Stream ciphers | `utils/stream.py` | RC4, ChaCha20 (RFC 8439), AES-CTR, keystream reuse / crib dragging |
| Hashes | `utils/hashes.py` | pure-Python SHA-1/SHA-256 and **length extension** (`length_extension`, resumable `HashState`) |
| PRNG | `utils/prng.py`, `utils/prng_extra.py` | MT19937 clone/predict/seed-crack, Java `Random` recovery+prediction, glibc `rand` state recovery, xorshift recovery, truncated-LCG (lattice) |
| RSA attacks | `utils/rsa_ops.py`, `utils/rsa_attacks.py` | small-e, broadcast, common modulus, shared prime, Wiener, Fermat, Pollard, dp leak, phi leak, known high bits, Franklin-Reiter, Håstad with padding, stereotyped message, parity/LSB oracle |
| Keys | `utils/keys.py` | PEM/DER RSA public+private parsing, OpenSSH public/private keys, DER encoder, SHA256 fingerprints |
| Signatures | `utils/signatures.py` | ECDSA/DSA nonce-reuse recovery, toy-curve sign/verify, e=3 signature forgery, PKCS#1 v1.5 padding |
| Oracle attacks | `oracle.py` | block-size/mode detection, unknown-prefix alignment, ECB byte-at-a-time, CBC padding oracle, local oracles for practice |
| Analysis | `core/`, `hypothesis.py`, `lab.py` | blackboard context, two registries, 27 attack hypotheses with gap reporting, workbench scaffold generator, three-state verification; analyzer coverage now includes **CRC** (catalog lookup, preimage, forgery) and **LFSR** (tap recovery + keystream), each with a solve template |

---

## Why it is not a template bank

intelpwn's "fixed vulnerability class → fixed exploit chain" works for pwn because
the classes are finite. Crypto is the opposite: you read the construction, find the
structural weakness, and often write the last step. So cryptoexp is layered:

| Layer | Role | Where |
|---|---|---|
| Primitives | reusable building blocks (everything in the table above) | `src/cryptoexp/utils/*` |
| Analysis | extract parameters, detect the attack surface, attempt attacks | `src/cryptoexp/core/analysis/*` |
| Hypothesis engine | 27 explicit hypotheses with `needs`/gaps: which apply, why not, **what piece is missing** | `src/cryptoexp/hypothesis.py` |
| Workbench | runnable scaffold: params inlined, hypotheses and gaps as comments, starter snippets, a seam for your idea | `src/cryptoexp/lab.py` |
| Solve templates | fast path for well-known families; emits a standalone script | `src/cryptoexp/core/solve.py` |
| Verification | confirmed / candidate / not_reproduced, with RSA re-encryption and strict flag matching | `src/cryptoexp/core/verify.py` |

Templates are a convenience, not the answer. Mechanical operations live in the
library so you can compose them; for the long tail the CLI hands you the ranked
hypotheses, the missing-information list and a workbench.

---

## Design notes (inherited discipline)

- **Blackboard**: `analyze_all` materialises the context once (text, files, named
  parameters, ints, blobs, decoded bytes); analyzers consume it instead of
  re-parsing. Failures degrade to warnings and never abort the run.
- **Two registries**: `register_analyzer(name)` and
  `register_solver(name, predicate, gen, priority)`; unknown keys render
  automatically, so a new analyzer needs no changes in the presentation layer.
- **Evidence grading**: every conclusion carries severity + confidence; "rule guess"
  is labelled as such.
- **Unknown is a first-class state**: hypotheses declare what they need and the
  engine reports the gap instead of staying silent.
- **Bounded work**: expensive steps take explicit budgets; a budget hit is reported.
- **Verification beats heuristics**: every bug found while building this is now a
  regression test. Examples: search objectives must not contain the flag bonus (hill
  climbing otherwise fabricates a flag), Coppersmith must reject the trivial
  `p = n` "factor", LLL parameters `m=t=3` are required for 160-of-256 known bits,
  generated scripts must actually run and print the flag.

---

## Tests

```bash
python -m unittest discover -s tests -v
python challenges/make_challenges.py     # regenerate the sample corpus (optional)
```

`tests/test_library.py` checks official vectors (FIPS-197 AES, RFC 8439 ChaCha20,
CRC-32/CRC-16 check values, SHA-1/SHA-256 test vectors), algebra and lattice
identities, oracle attacks against locally built oracles, signature nonce reuse and
the MT19937 clone. `tests/test_toolkit.py` covers the mechanical layer added in v0.3:
modular symbols and non-coprime CRT, polynomial/GF(2) arithmetic, CRC forgery,
LFSR tap recovery, length extension, RC4/ChaCha20/AES-CTR vectors, Java/glibc PRNG
recovery, RSA attack wrappers, key parsing and the signature primitives.
`tests/test_challenges.py` is end-to-end: 19 samples must yield their flags, generated
solve scripts must compile **and run to the flag**, and the JSON contract must hold.
`tests/test_forensics.py` covers the assessment layer (batch GCD, key audit, JWT/DER
parsing, weak-PRNG identification) on constructed real-world material.

Current total: **153 tests, all green** (`python -m unittest discover -s tests`).

---

## Honest limitations

- `glibc_rand_recover` needs roughly **96+ consecutive outputs**. Below that the
  hidden low bits are genuinely underdetermined: the function enumerates *all*
  states consistent with the observations and returns a state only when they agree
  on the next outputs, otherwise `None`. It never guesses.
- `lcg_recover_truncated` is **not** implemented as a lattice. When the visible high
  bits do not uniquely determine the parameters it returns `None` (documented in its
  docstring) instead of inventing a sequence. The lattice formulation was attempted
  and did not reach a reliable state.
- Coppersmith with degree > 1 only works at small lattice sizes in pure Python:
  `stereotyped_message` and `hastad_padded` therefore try the exact integer-root path
  first (when no reduction modulo n happens, which is the common CTF shape) and fall
  back to the lattice, which is where the time budget can run out on large moduli.
- ECC beyond toy curves, multivariate Coppersmith, Boneh-Durfee, Bleichenbacher's
  full attack: documented skeletons or absent — the tool reports the hypothesis and
  the gap rather than pretending.
- Discrete log only via BSGS / Pohlig-Hellman; group orders with large prime factors
  are reported as infeasible.
- Pure-Python Fraction LLL is comfortable up to dimension ~8; Coppersmith defaults
  for degree 1 are tuned to `m=t=3` (~6 s on a 512-bit N with 160 known bits).
- Oracle attacks need a callable; the workbench ships a remote-oracle template.
- The analyzer routes **CRC** and **LFSR** challenges end to end (catalog lookup,
  preimage, forgery; tap recovery + keystream) with generated solve scripts. The
  remaining new families (ChaCha20/RC4, hash length extension, Java/glibc PRNG, keys,
  signatures) are **library + unit-test** coverage with published vectors, not yet
  routed by the CLI: compose the library calls (or use the hypothesis/workbench
  layers) for those.
- CRC preimage solving pins the unknown field only when `8 * unknown_len <= width`
  (4 bytes under CRC-32, 2 under CRC-16). With more unknowns it returns one solution
  with the CRC matched and says `unique: False` — several byte strings fit, so it
  cannot claim to have found the original one.
- Playfair / Hill / columnar / bacon are lossy by design (X padding, I/J and U/V
  folding), so "round-trip" there means `decrypt(encrypt(x)) == prepared(x)`.
- No web interface and no CI yet.

License: MIT — coolmoon & guaidao2.
