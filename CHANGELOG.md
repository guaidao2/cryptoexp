# Changelog

Notable changes per release. This project follows [PEP 440] versioning; the `0.1.0`
alpha series was never closed with a final `0.1.0` — the work folded into `0.2.0`.

[PEP 440]: https://peps.python.org/pep-0440/

## 0.2.0b1 — 2026-10-03 (beta)

First beta. Everything below was developed, reviewed and tested in a single day of
intensive work, which is also why this is a beta and not the final `0.2.0`: the newest
lattice capabilities have measured limits and deserve a round of real use first.

Install with `pip install --pre -U cryptoexp` (a beta is not picked up by a plain
`pip install`).

### Added

- **Linearization lattice** — `linearize`, `solve_linearized`, `recover_from_products`,
  `separate_variables`, `monomials_of`, `parse_monomial`, `check_solution`
  (`utils/linearize.py`). Builds the small lattice for "modular equation(s) + small
  unknowns", reduces it, and reports monomial values only when the reduced vector
  proves them; determination is settled per modulus and glued with CRT, then completed
  with exact arithmetic. `separate_variables` handles the gcd step
  (`gcd(x*y^2, x^2*y) = x*y`).
- **Bivariate Coppersmith** — `poly2_*` (construction, multiplication, powers, shifts,
  evaluation, Sylvester-based resultant) and `coppersmith_bivariate`,
  `known_high_bits_two_primes` (`utils/bivariate.py`). Every reported root is verified by
  substitution; a failed solve names the bound it reached.
- **Shared private exponent across moduli** — `common_d_attack`, `common_d_lattice`
  (`utils/common_d.py`): the convergent stage first, then a scaling-free SDAP lattice.
  `auto_attack` tries the lattice only for three or more moduli, where it measurably
  helps.
- **ADFGX / ADFGVX** — squares, encrypt/decrypt (with an explicit `digit_substitution`),
  `adfgvx_detect` (a stream built only of the label letters is a strong signature) and
  `adfgvx_crack` (exhaustive read orders within the effort budget, annealing above;
  every reported plaintext is re-encrypted and must reproduce the ciphertext).
  `analyze` now surfaces the detection with its evidence.
- **`scan_structured_gcd(moduli, offsets=(0, -1, 1))`** — the `N±1` gcd combination scan,
  keeping a plain shared factor apart from a structural lead.
- Versioning and release plumbing: `CHANGELOG.md`; the test suite counts are stated
  accurately in the READMEs.

### Fixed

Two independent read-only audits (one over `utils/`, one over the pipeline, CLI, JSON
contract and packaging) found the following, each reproduced before being fixed:

- **Silent wrong answers.** `ecdsa_recover_k` divided by `r` instead of `s` (`s` was
  never read), so it returned a plausible wrong nonce for every input;
  `broadcast_attack` unpacked `(c_i, n_i)` while documenting `(n_i, c_i)`, so
  documentation-driven code failed with a misleading "moduli are not coprime" (all three
  internal callers and the test had to be corrected with it); `poly_resultant` dropped
  `(-1)^(m*n)` on the degree swap, breaking antisymmetry; `crt_decrypt` returned `0` on
  failure, indistinguishable from plaintext `0`; `batch_gcd` reported identical moduli as
  a shared prime (`factor == n`, so `n // factor == 1`); `kronecker_symbol` applied
  `sign(a)` for any modulus and so contradicted `jacobi_symbol` for negative numerators;
  `detect_weak_prng` called the exact 624-word MT19937 clone "not weak";
  `known_high_bits_factor(n, 0, k)` raised `ZeroDivisionError`.
- **Wrong claims in documentation of behaviour.** `ecdsa_nonce_reuse` claimed a
  verification it cannot perform (the equations hold by construction — the claim is gone
  and the limitation is stated); `rsa_e3_signature_forge` named result keys that never
  existed; `known_high_bits_factor` said "nothing is returned" where the keys are `None`;
  `dlp.is_smooth` returned a tuple while its name said bool (now `bool`, with
  `smooth_with_factors` for the pair); `glibc_rand_recover` claimed 31 outputs where
  roughly 100 are needed; `modinv` claimed never to raise.
- **CLI and pipeline.** `analyze --json` crashed on a non-UTF-8 console (Windows GBK) and
  emitted no JSON at all — output is UTF-8 now and the payload is pure ASCII; a challenge
  that explains the flag format confirmed *itself* (a strict match appearing verbatim in
  the statement is now a candidate, not a confirmation); the decode-chain solve script
  inlined the display-truncated ciphertext and printed a flag with its tail missing; the
  Morse template fell back to a hardcoded demo string; the Vigenère template routed by
  list index rather than score and never found the flag; the knapsack skeleton had no
  `[skeleton]` marker, a wrong `sys.path` and ignored the indices the analyzer had
  already solved; `--json` silently dropped `--solve`/`--run`; batch JSON was a bare list
  violating the project's own schema; a positional directory was analyzed as one merged
  target (producing a fake critical finding and a fake confirmation) instead of batch
  mode; a failing generated script left the CLI exiting `0`; `list` showed no solve
  templates because the registry fills lazily.
- **`lll` no longer returns `None` silently** when a basis exceeds `max_dim`: it names the
  actual dimensions on stderr, and `strict=True` raises `LatticeDimensionError`.
- **`set_flag_prefixes(..., merge=True)`** now merges with the prefixes actually in force,
  so `["DH"]` keeps the built-ins — as the README always claimed.
- **`analyze` on source code** (a `.py` target or inline code) skips classical-cipher
  scoring, which used to report "caesar shift=6, score 77" for a line like
  `import gmpy2`.
- **Packaging**: SPDX `license` metadata with `license-files` (the setuptools deprecation
  warnings are gone, `setuptools>=77`), a stale local `dist/` from `0.1.0a1` removed, and
  the strict flag pattern is now built from `DEFAULT_FLAG_PREFIXES` instead of a second
  hand-typed copy.

### Tests

231 tests, all green (`python -m unittest discover -s tests`). The suite grew two
regression files that pin every defect the audits found
(`test_audit_regressions.py`, `test_pipeline_regressions.py`) plus per-feature files for
the new modules (`test_linearize.py`, `test_bivariate.py`, `test_common_d.py`,
`test_adfgvx.py`). `.github/workflows/publish.yml` runs them on Python 3.10 and 3.12 and
releases to PyPI via trusted publishing.
