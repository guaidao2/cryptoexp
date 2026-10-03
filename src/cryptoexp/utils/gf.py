"""GF(p) linear algebra — general infrastructure for "linear construction" tasks

Lots of weaknesses in crypto tasks are linear: Hill cipher, LFSR feedback, LCG
with unknown parameters, multivariate linear congruences, AES MixColumns
differentials... With a GF(p) matrix / linear-system toolkit these tasks need no
"template" — you model them and solve them directly.

Pure standard library (no numpy); the modulus may be prime, or an arbitrary
modulus may be attempted (invertible elements required).
"""

from .algebra import modinv, gcd


def mat_rref(mat, p):
    """Row-reduced echelon form (RREF) modulo p

    Args:
        mat: 2-D list (not modified in place; a new matrix is returned)
        p: modulus
    Returns:
        (rref_matrix, pivot_cols, rank)
    """
    M = [[x % p for x in row] for row in mat]
    rows = len(M)
    cols = len(M[0]) if rows else 0
    pivots = []
    r = 0
    for c in range(cols):
        # find a pivot
        piv = None
        for i in range(r, rows):
            if M[i][c] % p:
                piv = i
                break
        if piv is None:
            continue
        M[r], M[piv] = M[piv], M[r]
        inv = modinv(M[r][c], p)
        if inv is None:
            continue
        M[r] = [(x * inv) % p for x in M[r]]
        for i in range(rows):
            if i != r and M[i][c] % p:
                factor = M[i][c]
                M[i] = [(M[i][j] - factor * M[r][j]) % p for j in range(cols)]
        pivots.append(c)
        r += 1
        if r == rows:
            break
    return M, pivots, r


def solve_linear(mat, rhs, p):
    """Solve the linear system mat·x = rhs mod p → (solution list | None, info)

    With no solution it returns (None, "no solution"); with several solutions it
    returns one particular solution plus the free-variable count (a hint that the
    answer is not unique)
    """
    rows = len(mat)
    cols = len(mat[0]) if rows else 0
    if len(rhs) != rows:
        raise ValueError("rhs length does not match the number of matrix rows")
    aug = [list(mat[i]) + [rhs[i] % p] for i in range(rows)]
    R, pivots, rank = mat_rref(aug, p)
    # look for an inconsistent row: 0 ... 0 | non-zero
    for row in R:
        if all(x % p == 0 for x in row[:-1]) and row[-1] % p:
            return None, "no solution"
    sol = [0] * cols
    for i, c in enumerate(pivots):
        if c >= cols:
            continue
        sol[c] = R[i][cols] % p
    free = cols - len([c for c in pivots if c < cols])
    return sol, ("unique solution" if free == 0 else f"multiple solutions, {free} free variables")


def nullspace(mat, p):
    """Null-space basis mod p (solves mat·x = 0)"""
    rows = len(mat)
    cols = len(mat[0]) if rows else 0
    R, pivots, _ = mat_rref(mat, p)
    free_cols = [c for c in range(cols) if c not in pivots]
    basis = []
    for fc in free_cols:
        vec = [0] * cols
        vec[fc] = 1
        for i, pc in enumerate(pivots):
            if pc < cols:
                vec[pc] = (-R[i][fc]) % p
        basis.append(vec)
    return basis


def mat_mul(a, b, p):
    n, k, m = len(a), len(b), len(b[0])
    out = [[0] * m for _ in range(n)]
    for i in range(n):
        for t in range(k):
            if a[i][t] % p:
                av = a[i][t] % p
                for j in range(m):
                    out[i][j] = (out[i][j] + av * b[t][j]) % p
    return out


def mat_inv(a, p):
    """Inverse mod p (square matrix) → matrix or None"""
    n = len(a)
    if any(len(row) != n for row in a):
        raise ValueError("not a square matrix")
    aug = [list(a[i]) + [1 if i == j else 0 for j in range(n)] for i in range(n)]
    R, pivots, rank = mat_rref(aug, p)
    if rank < n:
        return None
    return [[R[i][n + j] % p for j in range(n)] for i in range(n)]


def solve_lcg_params(outputs, p):
    """Solve LCG parameters straight from consecutive outputs
    (x_{i+1} = a·x_i + c mod p) — the linear-algebra view

    Difference from algebra.lcg_recover: here the modulus p is known and the
    linear system is solved directly, with no difference-gcd estimation — a good
    fit when the task hands you p.
    Returns: {"a", "c", "m", "info"} on success, or None when the outputs
             do not determine the parameters (it never guesses).
    """
    xs = [x % p for x in outputs]
    if len(xs) < 3:
        return None
    # a·x_i + c = x_{i+1}  →  subtract pairs to eliminate c
    mat, rhs = [], []
    for i in range(len(xs) - 2):
        mat.append([(xs[i + 1] - xs[i]) % p])
        rhs.append((xs[i + 2] - xs[i + 1]) % p)
    sol, info = solve_linear(mat, rhs, p)
    if sol is None:
        return None
    a = sol[0]
    c = (xs[1] - a * xs[0]) % p
    if all((a * xs[i] + c) % p == xs[i + 1] % p for i in range(len(xs) - 1)):
        return {"a": a, "c": c, "m": p, "info": info}
    return None


def recover_linear_map(inputs, outputs, p):
    """From several (input vector → output vector) pairs, recover the linear map
    matrix M (Hill cipher / linear-transform tasks)

    Args:
        inputs:  [[...], ...]  plaintext vectors (each of length k)
        outputs: [[...], ...]  ciphertext vectors (each of length n)
    Returns:
        (M, info) — M is an n×k matrix; when the data is insufficient or the
        rank is too low it returns (None, reason)
    """
    if not inputs or len(inputs) != len(outputs):
        return None, "input and output counts do not match"
    k = len(inputs[0])
    n = len(outputs[0])
    if len(inputs) < k:
        return None, f"need at least {k} known plaintexts (got {len(inputs)})"
    # solve row by row (one component of the output): out_j = sum_i M[j][i] * in_i
    X = [list(v) for v in inputs[:k]]
    Xt, pivots, rank = mat_rref(X, p)
    if rank < k:
        return None, f"known plaintext vectors have rank {rank} < {k}, not uniquely solvable"
    rows = []
    for j in range(n):
        rhs = [outputs[i][j] % p for i in range(k)]
        sol, info = solve_linear(X[:k], rhs, p)
        if sol is None:
            return None, f"no solution for output component {j}"
        rows.append(sol)
    return rows, f"{n}×{k} linear map"
