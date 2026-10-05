"""cryptoexp — dependency-free crypto toolkit for CTF, security work and research

Three usage tiers, in order of how much hidden state they involve:

1) The recommended way (no namespace surprises):
       import cryptoexp as cx
       cx.algebra.gcd(a, b)
       cx.long_to_bytes(0x4142)
       cx.rsa_ops.wiener_attack(e, n)
       cx.crc_forge_append(prefix, target, 32, 0x04C11DB7)

2) Namespaced imports when a script wants shorter lines:
       from cryptoexp import algebra, encoding, forensics
       algebra.gcd(a, b)

3) `from cryptoexp import *` is meant for **throwaway solve scripts**, and it only
   brings names that are unmistakably ours (attack and helper names such as
   `wiener_attack`, `audit_rsa_key`, `crc_forge_append`). One-word primitives that
   user code, `math`, `hashlib` or pycryptodome also define (`gcd`, `sha256`, `AES`,
   `xor`, ...) are deliberately **not** star-exported - they would silently shadow the
   caller's own names. They remain available as `cx.gcd` or `from cryptoexp import gcd`.

As a tool:
       python3 cryptoexp_cli.py analyze challenge.txt --solve

Zero dependencies: the core uses only the standard library (AES/LLL/Coppersmith/MT19937
are all implemented here); optional extras (gmpy2/sympy/pycryptodome/z3) are auto-detected,
and missing ones never affect correctness.

Naming convention: attack functions return a unified structure
    {"ok", "plaintext", "detail", "factors", "d", "note"}

Authors: coolmoon & guaidao2 (MIT)
"""

from .utils import algebra, encoding, lattice, pad, prng, rsa_ops, aes, gf, dlp
from .utils.algebra import (
    egcd, gcd, lcm, modinv, crt, isqrt, iroot, exact_root, perfect_square,
    is_prime, next_prime, prime_sieve, pollard_rho, factor, factor_limited,
    divisors, continued_fraction, convergents, wiener_recover_d, fermat_factor,
    close_factor_probe, bsgs, tonelli_shanks, lcg_recover,
)
from .utils.encoding import (
    score_text, printable_ratio, confidence_of, flag_candidates,
    loose_flag_candidates, find_flags, build_flag_pattern, set_flag_prefixes,
    get_flag_prefixes, reset_flag_prefixes, DEFAULT_FLAG_PREFIXES,
    decode_chain, guess_kinds, single_byte_xor, repeating_key_xor,
    repeating_key, single_byte_op, confidence_note,
    caesar, rot13, affine_decrypt, morse_decode, morse_encode,
    vigenere_recover, fence_decrypt, index_of_coincidence,
    to_hex, to_base64, to_base32, to_base58,
    from_hex, from_base64, from_base32, from_base58, from_base85,
    enhex, unhex, b64e, b64d, b32e, b32d, b58e, b58d,
)
from .utils.pad import (
    pkcs7_pad, pkcs7_unpad, pkcs7_valid, zero_pad, zero_unpad, xor, xor_repeat,
    blocks, bitflip_cbc, BLOCK,
)
from .utils.lattice import (
    lll, poly_trim, poly_mul, poly_pow, poly_eval, coppersmith_univariate,
    known_high_bits_factor, subset_sum_lll,
)
from .utils.rsa_ops import (
    itob, btoi, long_to_bytes, bytes_to_long, keygen, encrypt as rsa_encrypt,
    decrypt as rsa_decrypt, crt_decrypt, reencrypt_check, factor_from_phi,
    factor_from_d, decrypt_with_factors, small_e_attack, broadcast_attack,
    common_modulus_attack, shared_prime_attack, wiener_attack, fermat_attack,
    pollard_attack, dp_leak_attack, phi_leak_attack, known_high_bits_attack,
    common_private_exponent_attack, auto_attack,
)
from .utils.prng import (
    MT19937, untemper, clone_from_outputs, predict_next, clone_python_random,
    crack_seed,
)
from . import oracle
from .oracle import (
    detect_block_size, detect_mode, find_prefix_len, ecb_byte_at_a_time,
    padding_oracle_attack, make_ecb_oracle, make_cbc_oracle, make_padding_oracle,
)
from .utils.gf import (
    mat_rref, solve_linear, nullspace, mat_mul, mat_inv, solve_lcg_params,
    recover_linear_map,
)
from .utils.dlp import discrete_log, pohlig_hellman, dlog_feasibility
from .utils.lattice import mitm_subset_sum
from .utils import modular, polytools, gf2, hashes, stream, rsa_attacks, keys, prng_extra
from .utils import signatures, symtools, classic_extra
from .utils.modular import (
    legendre_symbol, jacobi_symbol, kronecker_symbol, is_quadratic_residue,
    sqrt_mod, totient, carmichael, mobius, is_squarefree, sum_of_divisors,
    divisor_count, order_mod, primitive_root, is_primitive_root, crt_general,
    crt_list, gcd_list, lcm_list, pollard_pm1, williams_pp1, is_smooth,    smooth_part, integer_log, binomial_mod,
)
from .utils.polytools import (
    poly_divmod, poly_mod, poly_gcd, poly_derivative, poly_roots_mod_p,
    poly_from_roots, poly_compose, poly_powmod, poly_eval_mod,
    poly_is_irreducible, poly_resultant, gf2_poly_mul, gf2_poly_mod,
    gf2_poly_gcd, gf2_poly_roots,
)
from .utils.gf2 import (
    gf2_rref, gf2_rank, gf2_solve, gf2_nullspace, gf2_inv, LFSR,
    lfsr_from_bits, lfsr_recover, lfsr_next, berlekamp_massey, CRC,
    crc_compute, crc_known, crc_reverse_params, crc_forge_append,
    crc_solve_unknown, bits_to_int, int_to_bits, bytes_to_bits, bits_to_bytes,
)
from .utils.hashes import (
    sha1, sha256, sha1_hex, sha256_hex, md5, md5_hex, sha1_state, sha256_state,
    md5_state, HashState, length_extension, hmac_sha256,
)
from .utils.stream import (
    rc4, rc4_keystream, ChaCha20, chacha20, chacha20_block, aes_ctr,
    aes_ctr_keystream, crib_drag, keystream_xor, fixed_nonce_reuse_recover,
)
from .utils.rsa_attacks import (
    franklin_reiter, hastad_padded, stereotyped_message, parity_oracle_attack,
    lsb_oracle_attack, rsa_recover_d_from_factors, bleichenbacher_note,
)
from .utils.keys import (
    parse_pem, parse_der_rsa_public, parse_der_rsa_private, parse_ssh_public_key,
    parse_openssh_private, rsa_public_der, key_fingerprint_sha256, pem_wrap,
)
from .utils.prng_extra import (
    java_random_next, java_random_ints, java_random_recover, java_random_predict,
    glibc_rand_values, glibc_rand_recover, glibc_rand_predict,
    xorshift32_next, xorshift32_stream, xorshift_recover, xorshift_predict,
    lcg_recover_truncated,
)
from .utils.classic_extra import (
    atbash, rot47, rot_n, bacon_encode, bacon_decode, playfair_encrypt,
    playfair_decrypt, hill_encrypt, hill_decrypt, columnar_encrypt,
    columnar_decrypt, rail_fence_encrypt, rail_fence_decrypt, autokey_encrypt,
    autokey_decrypt, substitution_decrypt, to_base62, from_base62, to_base91,
    from_base91, url_encode, url_decode, html_entity_decode, detect_classic,
)
from .utils.signatures import (
    hash_to_int, ecdsa_nonce_reuse, dsa_nonce_reuse, ecdsa_recover_k,
    ecdsa_verify, ecdsa_sign, dsa_sign, rsa_e3_signature_forge, pkcs1_v15_pad,
    pkcs1_v15_unpad,
)
from .utils.symtools import (
    ecb_repeated_blocks, is_ecb, infer_block_size, block_index,
    cbc_flip_plaintext, cbc_decrypt_blocks, strip_pkcs7, pad_pkcs7,
)
from .utils.forensics import (
    batch_gcd, common_factor_pairs, parse_der_signature, parse_jwt,
    audit_rsa_key, detect_weak_prng, scan_structured_gcd,
)
from .utils.linearize import (
    linearize, solve_linearized, recover_from_products, separate_variables,
    monomials_of, parse_monomial, check_solution,
)
from .utils.adfgvx import (
    adfgx_square, adfgvx_square, adfgx_encrypt, adfgx_decrypt,
    adfgvx_encrypt, adfgvx_decrypt, adfgvx_detect, adfgvx_crack,
)
from .utils.common_d import common_d_lattice, common_d_attack
from .utils.bivariate import (
    poly2_from_terms, poly2_mul, poly2_add, poly2_sub, poly2_pow, poly2_eval,
    poly2_degree, poly2_scale, poly2_shift_x, poly2_shift_y, poly2_resultant,
    coppersmith_bivariate, known_high_bits_two_primes,
)
from . import hypothesis
from .hypothesis import (
    evaluate as evaluate_hypotheses, list_hypotheses, register_hypothesis,
    params_from_ctx,
)
from . import lab
from .lab import build_workbench, write_workbench
from .core.context import build_context
from .core.analysis import (
    analyze_all, register_analyzer, list_analyzers, probe_optional_deps,
)
from .core.verify import verify_candidates
from .core.solve import (
    register_solver, list_solvers, generate as solve_script,
)

__version__ = "0.2.0"
__author__ = "coolmoon & guaidao2"
__license__ = "MIT"

_CANDIDATE_EXPORTS = [
    # submodules (for finer-grained entry points use cryptoexp.rsa_ops.xxx)
    "algebra", "encoding", "lattice", "pad", "prng", "rsa_ops", "aes", "oracle",
    "gf", "dlp", "hypothesis", "lab", "modular", "polytools", "gf2", "hashes",
    "stream", "rsa_attacks", "keys", "prng_extra", "signatures", "symtools",
    # hypothesis engine / workbench
    "evaluate_hypotheses", "list_hypotheses", "register_hypothesis",
    "params_from_ctx", "build_workbench", "write_workbench",
    # number theory
    "egcd", "gcd", "lcm", "modinv", "crt", "isqrt", "iroot", "exact_root",
    "perfect_square", "is_prime", "next_prime", "prime_sieve", "pollard_rho",
    "factor", "factor_limited", "divisors", "continued_fraction", "convergents",
    "wiener_recover_d", "fermat_factor", "close_factor_probe", "bsgs",
    "tonelli_shanks", "lcg_recover",
    # encoding / classical
    "score_text", "printable_ratio", "confidence_of", "flag_candidates",
    "loose_flag_candidates", "find_flags", "build_flag_pattern",
    "set_flag_prefixes", "get_flag_prefixes", "reset_flag_prefixes",
    "DEFAULT_FLAG_PREFIXES",
    "decode_chain", "guess_kinds", "single_byte_xor", "repeating_key_xor",
    "repeating_key", "single_byte_op", "confidence_note",
    "caesar", "rot13", "affine_decrypt", "morse_decode", "morse_encode",
    "vigenere_recover", "fence_decrypt", "index_of_coincidence",
    "to_hex", "to_base64", "from_base64", "to_base32", "from_base32", "to_base58", "from_base58",
    "enhex", "unhex", "b64e", "b64d", "b32e", "b32d", "b58e", "b58d",
    # bytes / padding
    "pkcs7_pad", "pkcs7_unpad", "pkcs7_valid", "zero_pad", "zero_unpad",
    "xor", "xor_repeat", "blocks", "bitflip_cbc", "BLOCK",
    # lattice
    "lll", "poly_trim", "poly_mul", "poly_pow", "poly_eval",
    "coppersmith_univariate", "known_high_bits_factor", "subset_sum_lll",
    "mitm_subset_sum",
    # GF(p) linear algebra / discrete log
    "mat_rref", "solve_linear", "nullspace", "mat_mul", "mat_inv",
    "solve_lcg_params", "recover_linear_map", "discrete_log", "pohlig_hellman",
    "dlog_feasibility",
    # RSA
    "itob", "btoi", "long_to_bytes", "bytes_to_long", "keygen", "rsa_encrypt",
    "rsa_decrypt", "crt_decrypt", "reencrypt_check", "factor_from_phi",
    "factor_from_d", "decrypt_with_factors", "small_e_attack",
    "broadcast_attack", "common_modulus_attack", "shared_prime_attack",
    "wiener_attack", "fermat_attack", "pollard_attack", "dp_leak_attack",
    "common_private_exponent_attack",
    "phi_leak_attack", "known_high_bits_attack", "auto_attack",
    # PRNG
    "MT19937", "untemper", "clone_from_outputs", "predict_next",
    "clone_python_random", "crack_seed",
    # oracle
    "detect_block_size", "detect_mode", "find_prefix_len",
    "ecb_byte_at_a_time", "padding_oracle_attack", "make_ecb_oracle",
    "make_cbc_oracle", "make_padding_oracle",
    # analysis / generation / verification
    "build_context", "analyze_all", "verify_candidates", "solve_script",
    "register_analyzer", "register_solver", "list_analyzers", "list_solvers",
    "probe_optional_deps",
    # modular extras
    "legendre_symbol", "jacobi_symbol", "kronecker_symbol", "is_quadratic_residue",
    "sqrt_mod", "totient", "carmichael", "mobius", "is_squarefree",
    "sum_of_divisors", "divisor_count", "order_mod", "primitive_root",
    "is_primitive_root", "crt_general", "crt_list", "gcd_list", "lcm_list",
    "pollard_pm1", "williams_pp1", "is_smooth", "smooth_part", "integer_log",
    "binomial_mod",
    # polynomials
    "poly_divmod", "poly_mod", "poly_gcd", "poly_derivative", "poly_roots_mod_p",
    "poly_from_roots", "poly_compose", "poly_powmod", "poly_eval_mod",
    "poly_is_irreducible", "poly_resultant", "gf2_poly_mul", "gf2_poly_mod",
    "gf2_poly_gcd", "gf2_poly_roots",
    # GF(2) / LFSR / CRC / bits
    "gf2_rref", "gf2_rank", "gf2_solve", "gf2_nullspace", "gf2_inv", "LFSR",
    "lfsr_from_bits", "lfsr_recover", "lfsr_next", "berlekamp_massey", "CRC",
    "crc_compute", "crc_known", "crc_reverse_params", "crc_forge_append",
    "crc_solve_unknown", "bits_to_int", "int_to_bits", "bytes_to_bits", "bits_to_bytes",
    # hashes
    "sha1", "sha256", "sha1_hex", "sha256_hex", "md5", "md5_hex", "sha1_state",
    "sha256_state", "md5_state", "HashState", "length_extension", "hmac_sha256",
    # stream ciphers
    "rc4", "rc4_keystream", "ChaCha20", "chacha20", "chacha20_block", "aes_ctr",
    "aes_ctr_keystream", "crib_drag", "keystream_xor", "fixed_nonce_reuse_recover",
    # symmetric helpers
    "ecb_repeated_blocks", "is_ecb", "infer_block_size", "block_index",
    "cbc_flip_plaintext", "cbc_decrypt_blocks", "strip_pkcs7", "pad_pkcs7",
    # real-world forensics (beyond CTF)
    "batch_gcd", "common_factor_pairs", "parse_der_signature", "parse_jwt",
    "audit_rsa_key", "detect_weak_prng", "scan_structured_gcd",
    # small-root helpers: linearization lattice first, then the polynomial route
    "linearize", "solve_linearized", "recover_from_products", "separate_variables",
    "monomials_of", "parse_monomial",
    # fractionating transposition ciphers (ADFGX / ADFGVX)
    "adfgx_encrypt", "adfgx_decrypt", "adfgvx_encrypt", "adfgvx_decrypt",
    "adfgvx_detect", "adfgvx_crack", "adfgx_square", "adfgvx_square",
    # shared private exponent across moduli (convergent stage, then the SDAP lattice)
    "common_d_attack", "common_d_lattice",
    # bivariate polynomials + bivariate Coppersmith (the product-shaped small-root case)
    "poly2_from_terms", "poly2_mul", "poly2_add", "poly2_sub", "poly2_pow", "poly2_eval",
    "poly2_degree", "poly2_scale", "poly2_shift_x", "poly2_shift_y", "poly2_resultant",
    "coppersmith_bivariate", "known_high_bits_two_primes",
    # RSA attacks (extra) / keys
    "franklin_reiter", "hastad_padded", "stereotyped_message",
    "parity_oracle_attack", "lsb_oracle_attack", "rsa_recover_d_from_factors",
    "bleichenbacher_note", "parse_pem", "parse_der_rsa_public",
    "parse_der_rsa_private", "parse_ssh_public_key", "parse_openssh_private",
    "rsa_public_der", "key_fingerprint_sha256", "pem_wrap",
    # signatures
    "hash_to_int", "ecdsa_nonce_reuse", "dsa_nonce_reuse", "ecdsa_recover_k",
    "ecdsa_verify", "ecdsa_sign", "dsa_sign", "rsa_e3_signature_forge",
    "pkcs1_v15_pad", "pkcs1_v15_unpad",
    # PRNG (extra)
    "java_random_next", "java_random_ints", "java_random_recover",
    "java_random_predict", "glibc_rand_values", "glibc_rand_recover",
    "glibc_rand_predict", "xorshift32_next", "xorshift32_stream",
    "xorshift_recover", "xorshift_predict", "lcg_recover_truncated",
    # classic ciphers (extra)
    "atbash", "rot47", "rot_n", "bacon_encode", "bacon_decode",
    "playfair_encrypt", "playfair_decrypt", "hill_encrypt", "hill_decrypt",
    "columnar_encrypt", "columnar_decrypt", "rail_fence_encrypt",
    "rail_fence_decrypt", "autokey_encrypt", "autokey_decrypt",
    "substitution_decrypt", "to_base62", "from_base62", "to_base91",
    "from_base91", "url_encode", "url_decode", "html_entity_decode",
    "detect_classic",
]

# ── What a star import brings, and what it deliberately does not ──────────────
# `from cryptoexp import *` must not shadow the caller's own names. These are the
# one-word primitives that user code, `math`, `hashlib` and pycryptodome also define;
# a star import that grabbed `gcd` or `AES` would silently break the calling module.
# They stay *fully available* - as attributes (`cx.gcd`) and by explicit import
# (`from cryptoexp import gcd`) - they are just not pushed into the caller's
# namespace behind their back.
_COLLISION_PRONE = {
    "gcd", "egcd", "lcm", "modinv", "crt", "isqrt", "iroot", "exact_root",
    "perfect_square", "is_prime", "next_prime", "prime_sieve", "pollard_rho",
    "factor", "factor_limited", "divisors", "totient", "carmichael", "mobius",
    "is_squarefree", "sum_of_divisors", "divisor_count", "order_mod",
    "primitive_root", "is_primitive_root", "is_smooth", "smooth_part",
    "integer_log", "binomial_mod", "legendre_symbol", "jacobi_symbol",
    "kronecker_symbol", "sqrt_mod", "is_quadratic_residue",
    "xor", "blocks", "BLOCK", "itob", "btoi", "long_to_bytes", "bytes_to_long",
    "sha1", "sha256", "md5", "sha1_hex", "sha256_hex", "md5_hex", "hmac_sha256",
    "keygen", "to_hex", "to_base64", "to_base32", "to_base58",
    "score_text", "printable_ratio", "confidence_of",
    "int_to_bits", "bits_to_int", "bytes_to_bits", "bits_to_bytes",
    "detect_block_size", "is_ecb", "nullspace", "mat_inv", "mat_mul",
    "poly_trim", "poly_mul", "poly_pow", "poly_eval", "gcd_list", "lcm_list",
    "factor_from_phi", "factor_from_d", "crt_decrypt", "rsa_encrypt", "rsa_decrypt",
}

# Submodules are reached through the package (`cx.algebra.gcd`) or imported by name
# (`from cryptoexp import algebra`); they are not star-exported either, because
# `encoding`, `keys`, `stream` and `aes` are exactly the kind of names a caller
# already has.
_SUBMODULES = {
    "algebra", "encoding", "lattice", "pad", "prng", "rsa_ops", "aes", "gf", "dlp",
    "modular", "polytools", "gf2", "hashes", "stream", "rsa_attacks", "keys",
    "prng_extra", "signatures", "symtools", "classical_extra", "forensics",
    "oracle", "hypothesis", "lab",
}

__all__ = [name for name in _CANDIDATE_EXPORTS
           if name not in _COLLISION_PRONE and name not in _SUBMODULES]


def api(verbose: bool = False) -> str:
    """Print/return the API map (the `from pwn import help` equivalent)"""
    groups = {        "number theory": ["gcd", "egcd", "modinv", "crt", "iroot", "isqrt", "is_prime",
                          "next_prime", "factor", "factor_limited", "divisors",
                          "pollard_rho", "continued_fraction", "convergents",
                          "fermat_factor", "bsgs", "tonelli_shanks", "lcg_recover"],
        "encoding/classical": ["enhex", "unhex", "b64e", "b64d", "b32e", "b32d", "b58d",
                               "score_text", "flag_candidates", "loose_flag_candidates",
                               "find_flags", "set_flag_prefixes", "get_flag_prefixes",
                               "build_flag_pattern",
                               "decode_chain",
                               "single_byte_xor", "repeating_key_xor", "caesar",
                               "affine_decrypt", "vigenere_recover", "morse_decode",
                               "morse_encode", "fence_decrypt"],
        "bytes/padding": ["pkcs7_pad", "pkcs7_unpad", "pkcs7_valid", "xor",
                          "xor_repeat", "blocks", "bitflip_cbc"],
        "AES": ["aes.new", "aes.encrypt_ecb", "aes.decrypt_cbc", "aes.MODE_ECB"],
        "lattice": ["lll", "coppersmith_univariate", "known_high_bits_factor",
                    "subset_sum_lll"],
        "RSA": ["keygen", "rsa_encrypt", "rsa_decrypt", "long_to_bytes",
                "small_e_attack", "broadcast_attack", "common_modulus_attack",
                "shared_prime_attack", "wiener_attack", "fermat_attack",
                "pollard_attack", "dp_leak_attack", "phi_leak_attack",
                "known_high_bits_attack", "auto_attack", "reencrypt_check"],
        "PRNG": ["MT19937", "untemper", "clone_from_outputs", "predict_next",
                 "clone_python_random", "crack_seed"],
        "oracle attacks": ["detect_block_size", "detect_mode", "find_prefix_len",
                           "ecb_byte_at_a_time", "padding_oracle_attack",
                           "make_ecb_oracle", "make_cbc_oracle", "make_padding_oracle"],
        "analysis/solve": ["analyze_all", "verify_candidates", "solve_script",
                           "register_analyzer", "register_solver"],
        "hypothesis engine / workbench": ["evaluate_hypotheses", "list_hypotheses",
                                          "register_hypothesis", "write_workbench"],
        "linear algebra / discrete log": ["solve_linear", "mat_inv", "recover_linear_map",
                                          "solve_lcg_params", "discrete_log", "pohlig_hellman",
                                          "dlog_feasibility", "mitm_subset_sum"],
        "modular extras": ["legendre_symbol", "jacobi_symbol", "kronecker_symbol",
                           "sqrt_mod", "totient", "carmichael", "mobius",
                           "order_mod", "primitive_root", "crt_general", "pollard_pm1",
                           "williams_pp1", "is_smooth", "binomial_mod"],
        "polynomials": ["poly_divmod", "poly_gcd", "poly_roots_mod_p", "poly_from_roots",
                        "poly_powmod", "poly_is_irreducible", "poly_resultant",
                        "gf2_poly_gcd", "gf2_poly_roots"],
        "GF(2) / LFSR / CRC": ["gf2_rref", "gf2_solve", "gf2_nullspace", "gf2_inv",
                               "LFSR", "lfsr_recover", "lfsr_next", "berlekamp_massey",
                               "CRC", "crc_compute", "crc_known", "crc_reverse_params",
                               "crc_forge_append", "crc_solve_unknown",
                               "bits_to_bytes", "bytes_to_bits"],
        "hashes": ["sha1", "sha256", "md5", "sha1_hex", "sha256_hex",
                   "length_extension", "HashState", "hmac_sha256"],
        "stream ciphers": ["rc4", "ChaCha20", "chacha20", "aes_ctr", "aes_ctr_keystream",
                           "crib_drag", "keystream_xor", "fixed_nonce_reuse_recover"],
        "symmetric tools": ["is_ecb", "ecb_repeated_blocks", "infer_block_size",
                            "cbc_flip_plaintext", "cbc_decrypt_blocks", "pad_pkcs7"],
        "RSA attacks (extra)": ["franklin_reiter", "hastad_padded", "stereotyped_message",
                                "parity_oracle_attack", "lsb_oracle_attack",
                                "bleichenbacher_note"],
        "keys": ["parse_pem", "parse_der_rsa_public", "parse_der_rsa_private",
                 "parse_ssh_public_key", "parse_openssh_private", "rsa_public_der",
                 "key_fingerprint_sha256", "pem_wrap"],
        "signatures": ["ecdsa_nonce_reuse", "dsa_nonce_reuse", "ecdsa_verify",
                       "ecdsa_sign", "dsa_sign", "rsa_e3_signature_forge",
                       "pkcs1_v15_pad", "pkcs1_v15_unpad"],
        "PRNG (extra)": ["java_random_recover", "java_random_predict",
                         "glibc_rand_recover", "glibc_rand_predict",
                         "xorshift_recover", "xorshift_predict",
                         "lcg_recover_truncated"],
        "forensics / assessment": ["batch_gcd", "common_factor_pairs",
                                   "parse_der_signature", "parse_jwt",
                                   "audit_rsa_key", "detect_weak_prng",
                                   "find_flags", "set_flag_prefixes"],
    }
    lines = [f"cryptoexp {__version__} — dependency-free crypto toolkit", ""]
    for group, names in groups.items():
        lines.append(f"[{group}]")
        lines.append("  " + ", ".join(names))
    lines.append("")
    lines.append("usage: import cryptoexp as cx; cx.algebra.gcd(24, 36); "
                 "cx.crc_forge_append(...)")
    lines.append("       from cryptoexp import * brings only unmistakably-ours names "
                 "(star import is for throwaway scripts)")
    text = "\n".join(lines)
    print(text)
    return text
