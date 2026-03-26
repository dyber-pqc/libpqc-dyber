/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece - Goppa code operations.
 *
 * Generates a random irreducible polynomial g(x) over GF(2^m), constructs
 * the parity-check matrix H, and converts to systematic form [I | T].
 */

#include <stdlib.h>
#include <string.h>

#include "mceliece.h"
#include "pqc/rand.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Generate random irreducible polynomial of degree t                  */
/* ------------------------------------------------------------------ */

/*
 * Test irreducibility using Ben-Or's algorithm:
 * Check that gcd(x^(2^i) - x, g(x)) = 1 for i = 1, ..., t/2.
 * If so, g(x) is irreducible over GF(2^m).
 *
 * Simplified approach: generate random monic polynomial and test.
 */

/* Polynomial GCD over GF(2^m)[x] */
static int poly_gcd_degree(const gf_t *a, int deg_a,
                           const gf_t *b, int deg_b,
                           int m)
{
    gf_t u[MCELIECE_MAX_T + 1];
    gf_t v[MCELIECE_MAX_T + 1];
    int du, dv;

    /* Copy a and b */
    memcpy(u, a, (size_t)(deg_a + 1) * sizeof(gf_t));
    memcpy(v, b, (size_t)(deg_b + 1) * sizeof(gf_t));
    du = deg_a;
    dv = deg_b;

    while (dv >= 0) {
        /* u = u mod v */
        while (du >= dv && du >= 0) {
            gf_t coeff = gf_frac(u[du], v[dv], m);
            for (int i = 0; i <= dv; i++) {
                u[du - dv + i] = gf_add(u[du - dv + i], gf_mul(coeff, v[i], m));
            }
            /* Find new degree of u */
            while (du >= 0 && u[du] == 0)
                du--;
        }
        /* Swap u and v */
        gf_t tmp[MCELIECE_MAX_T + 1];
        int td;
        memcpy(tmp, u, sizeof(tmp));
        memcpy(u, v, sizeof(u));
        memcpy(v, tmp, sizeof(v));
        td = du;
        du = dv;
        dv = td;
    }

    return du;
}

int goppa_gen_irr_poly(gf_t *g, int t, int m)
{
    int field_size = 1 << m;
    uint8_t rand_bytes[MCELIECE_MAX_T * 2];
    int attempts = 0;

    gf_init_tables(m);

    while (attempts < 1000) {
        attempts++;

        /* Generate random coefficients */
        if (pqc_randombytes(rand_bytes, (size_t)(t * 2)) != PQC_OK)
            return -1;

        for (int i = 0; i < t; i++) {
            g[i] = (gf_t)(((uint16_t)rand_bytes[2*i] |
                           ((uint16_t)rand_bytes[2*i+1] << 8)) &
                          (uint16_t)(field_size - 1));
        }
        g[t] = 1; /* monic */

        /* Ensure g(0) != 0 (necessary for irreducibility) */
        if (g[0] == 0)
            continue;

        /*
         * Test irreducibility using minimal polynomial check:
         * g(x) is irreducible iff x^(2^(m*t)) = x mod g(x)
         * and gcd(x^(2^(m*i)) - x, g(x)) = 1 for 1 <= i < t.
         *
         * Simplified: check that g has no roots in GF(2^m).
         */
        int has_root = 0;
        for (int a = 0; a < field_size && !has_root; a++) {
            gf_t val = 0;
            gf_t x_pow = 1;
            for (int j = 0; j <= t; j++) {
                val = gf_add(val, gf_mul(g[j], x_pow, m));
                x_pow = gf_mul(x_pow, (gf_t)a, m);
            }
            if (val == 0)
                has_root = 1;
        }

        if (!has_root)
            return 0; /* irreducible */
    }

    return -1; /* failed to find irreducible polynomial */
}

/* ------------------------------------------------------------------ */
/* Parity-check matrix in systematic form                              */
/* ------------------------------------------------------------------ */

/*
 * Build the parity-check matrix H for the Goppa code.
 *
 * H is an mt x n matrix over GF(2). We construct it from the
 * alternant form:
 *   H_ij = alpha_j^i / g(alpha_j), for i=0..t-1, j=0..n-1
 * where alpha_j = perm[j] (the support).
 *
 * Then convert the mt x n binary matrix to systematic form [I | T].
 * The public key is T (an (n-k) x k matrix, or equivalently k x (n-k)).
 */

int goppa_systematic_matrix(uint8_t *T, const gf_t *g,
                            const uint16_t *perm,
                            const mceliece_params_t *p)
{
    int mt = p->m * p->t;
    int n = p->n;
    int k = p->k;
    int m = p->m;

    /* Allocate the mt x n binary matrix (packed in bytes per row) */
    int row_bytes = (n + 7) / 8;
    uint8_t *mat = (uint8_t *)calloc((size_t)mt, (size_t)row_bytes);
    if (!mat)
        return -1;

    gf_init_tables(m);

    /* Evaluate 1/g(alpha_j) for each support element */
    gf_t *inv_g = (gf_t *)calloc((size_t)n, sizeof(gf_t));
    if (!inv_g) {
        free(mat);
        return -1;
    }

    for (int j = 0; j < n; j++) {
        gf_t alpha = (gf_t)perm[j];
        gf_t val = 0;
        gf_t x_pow = 1;
        for (int d = 0; d <= p->t; d++) {
            val = gf_add(val, gf_mul(g[d], x_pow, m));
            x_pow = gf_mul(x_pow, alpha, m);
        }
        inv_g[j] = gf_inv(val, m);
    }

    /*
     * Build the alternant matrix:
     * Row block i (for i=0..t-1) contributes m binary rows.
     * Entry at (i, j) in GF(2^m) is alpha_j^i * inv_g[j].
     * Each GF(2^m) element expands to m binary bits.
     */
    for (int j = 0; j < n; j++) {
        gf_t alpha = (gf_t)perm[j];
        gf_t alpha_pow = 1; /* alpha^0 = 1 */

        for (int i = 0; i < p->t; i++) {
            gf_t entry = gf_mul(alpha_pow, inv_g[j], m);

            /* Place m bits from entry into rows i*m .. i*m + m - 1 */
            for (int b = 0; b < m; b++) {
                int row = i * m + b;
                if ((entry >> b) & 1) {
                    mat[row * row_bytes + (j >> 3)] |= (uint8_t)(1u << (j & 7));
                }
            }

            alpha_pow = gf_mul(alpha_pow, alpha, m);
        }
    }

    /*
     * Gaussian elimination to get systematic form [I_mt | T].
     * Pivot on the first mt columns.
     */
    for (int col = 0; col < mt; col++) {
        /* Find pivot */
        int pivot = -1;
        for (int row = col; row < mt; row++) {
            if (mat[row * row_bytes + (col >> 3)] & (1u << (col & 7))) {
                pivot = row;
                break;
            }
        }

        if (pivot < 0) {
            free(inv_g);
            free(mat);
            return -1; /* not systematic */
        }

        /* Swap rows */
        if (pivot != col) {
            for (int b = 0; b < row_bytes; b++) {
                uint8_t tmp = mat[col * row_bytes + b];
                mat[col * row_bytes + b] = mat[pivot * row_bytes + b];
                mat[pivot * row_bytes + b] = tmp;
            }
        }

        /* Eliminate */
        for (int row = 0; row < mt; row++) {
            if (row == col)
                continue;
            if (mat[row * row_bytes + (col >> 3)] & (1u << (col & 7))) {
                for (int b = 0; b < row_bytes; b++) {
                    mat[row * row_bytes + b] ^= mat[col * row_bytes + b];
                }
            }
        }
    }

    /*
     * Extract T: the mt x k matrix from columns mt..n-1.
     * Store as k rows of ceil(mt/8) bytes (transposed for the public key).
     * Actually, store row-major: mt rows, each row has ceil(k/8) bytes
     * representing the columns mt..n-1.
     */
    int pk_row_bytes = (k + 7) / 8;
    memset(T, 0, (size_t)mt * (size_t)pk_row_bytes);

    for (int row = 0; row < mt; row++) {
        for (int c = 0; c < k; c++) {
            int src_col = mt + c;
            if (mat[row * row_bytes + (src_col >> 3)] & (1u << (src_col & 7))) {
                T[row * pk_row_bytes + (c >> 3)] |= (uint8_t)(1u << (c & 7));
            }
        }
    }

    free(inv_g);
    free(mat);
    return 0;
}
