/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece - Decryption via Patterson's algorithm.
 *
 * Given a syndrome s and the secret key (Goppa polynomial g, support perm),
 * recover the error vector e of weight t.
 *
 * Steps:
 *   1. Extract GF(2^m) syndromes from the binary syndrome vector.
 *   2. Build the syndrome polynomial S(x) and compute R(x) = S^{-1}(x) + x.
 *   3. Compute T(x) = sqrt(R(x)) mod g(x).
 *   4. Run partial Euclidean algorithm to get error-locator sigma(x).
 *   5. Find roots of sigma(x) to locate error positions.
 */

#include <stdlib.h>
#include <string.h>

#include "mceliece.h"

/* ------------------------------------------------------------------ */
/* Polynomial arithmetic mod g(x) in GF(2^m)[x]                       */
/* ------------------------------------------------------------------ */

/* Reduce poly of degree up to 2*deg modulo g of degree t */
static void poly_mod(gf_t *r, const gf_t *a, int deg_a,
                     const gf_t *g, int t, int m)
{
    gf_t tmp[2 * MCELIECE_MAX_T + 1];
    memcpy(tmp, a, (size_t)(deg_a + 1) * sizeof(gf_t));

    for (int i = deg_a; i >= t; i--) {
        if (tmp[i] == 0) continue;
        gf_t c = gf_frac(tmp[i], g[t], m);
        for (int j = 0; j <= t; j++) {
            tmp[i - t + j] = gf_add(tmp[i - t + j], gf_mul(c, g[j], m));
        }
    }

    memcpy(r, tmp, (size_t)t * sizeof(gf_t));
}

/* Multiply two polynomials mod g(x) */
static void poly_mul_mod(gf_t *r, const gf_t *a, const gf_t *b,
                         const gf_t *g, int t, int m)
{
    gf_t tmp[2 * MCELIECE_MAX_T + 1];
    memset(tmp, 0, sizeof(tmp));

    for (int i = 0; i < t; i++) {
        for (int j = 0; j < t; j++) {
            tmp[i + j] = gf_add(tmp[i + j], gf_mul(a[i], b[j], m));
        }
    }

    poly_mod(r, tmp, 2 * t - 2, g, t, m);
}

/* Compute inverse of polynomial a(x) mod g(x) using extended Euclidean */
static int poly_inv_mod(gf_t *r, const gf_t *a, const gf_t *g, int t, int m)
{
    gf_t u[MCELIECE_MAX_T + 1], v[MCELIECE_MAX_T + 1];
    gf_t s0[MCELIECE_MAX_T + 1], s1[MCELIECE_MAX_T + 1];
    gf_t tmp[MCELIECE_MAX_T + 1];
    int du, dv, ds0, ds1;

    /* u = g, v = a */
    memcpy(u, g, (size_t)(t + 1) * sizeof(gf_t));
    du = t;
    memset(v, 0, sizeof(v));
    memcpy(v, a, (size_t)t * sizeof(gf_t));
    dv = t - 1;
    while (dv >= 0 && v[dv] == 0) dv--;

    if (dv < 0) return -1; /* a is zero */

    /* s0 = 0, s1 = 1 */
    memset(s0, 0, sizeof(s0));
    memset(s1, 0, sizeof(s1));
    ds0 = -1;
    s1[0] = 1;
    ds1 = 0;

    while (dv >= 0) {
        while (du >= dv && du >= 0) {
            gf_t coeff = gf_frac(u[du], v[dv], m);
            int shift = du - dv;

            for (int i = 0; i <= dv; i++)
                u[shift + i] = gf_add(u[shift + i], gf_mul(coeff, v[i], m));
            while (du >= 0 && u[du] == 0) du--;

            /* s0 -= coeff * x^shift * s1 */
            for (int i = 0; i <= ds1; i++) {
                if (shift + i <= t)
                    s0[shift + i] = gf_add(s0[shift + i], gf_mul(coeff, s1[i], m));
            }
            ds0 = -1;
            for (int i = t; i >= 0; i--) {
                if (s0[i] != 0) { ds0 = i; break; }
            }
        }

        /* Swap u,v and s0,s1 */
        memcpy(tmp, u, sizeof(tmp));
        memcpy(u, v, sizeof(u));
        memcpy(v, tmp, sizeof(v));
        int td = du; du = dv; dv = td;

        memcpy(tmp, s0, sizeof(tmp));
        memcpy(s0, s1, sizeof(s0));
        memcpy(s1, tmp, sizeof(s1));
        td = ds0; ds0 = ds1; ds1 = td;
    }

    /* r = s0 / u[0] (normalize) */
    gf_t inv_lc = gf_inv(u[0], m);
    for (int i = 0; i < t; i++)
        r[i] = gf_mul(s0[i], inv_lc, m);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Square root of polynomial mod g(x) in GF(2^m)[x]                   */
/* ------------------------------------------------------------------ */

/*
 * Compute sqrt(a(x)) mod g(x).
 *
 * a(x) = a_even(x^2) + x * a_odd(x^2)
 * sqrt(a(x)) = a_even_coeffs(x) + sqrt(x) * a_odd_coeffs(x) mod g(x)
 *
 * where sqrt of field elements uses gf_sqrt, and sqrt(x) mod g(x)
 * is precomputed as x^(2^(mt-1)) mod g(x).
 */
static void poly_sqrt_mod(gf_t *r, const gf_t *a,
                          const gf_t *g, int t, int m)
{
    gf_t even_part[MCELIECE_MAX_T];
    gf_t odd_part[MCELIECE_MAX_T];
    gf_t sqrt_x[MCELIECE_MAX_T];
    gf_t tmp[MCELIECE_MAX_T];

    memset(even_part, 0, sizeof(even_part));
    memset(odd_part, 0, sizeof(odd_part));
    memset(sqrt_x, 0, sizeof(sqrt_x));

    /* Separate even and odd coefficients, take sqrt of field elements */
    for (int i = 0; i < t; i++) {
        if (2 * i < t)
            even_part[i] = gf_sqrt(a[2 * i], m);
        if (2 * i + 1 < t)
            odd_part[i] = gf_sqrt(a[2 * i + 1], m);
    }

    /*
     * Compute sqrt(x) mod g(x):
     * y = x^(2^(m*t - 1)) mod g(x).
     */
    gf_t base[MCELIECE_MAX_T];
    memset(base, 0, sizeof(base));
    if (t > 1) base[1] = 1; /* base = x */
    else base[0] = 1;

    /* Compute x^(2^(mt-1)) mod g(x) by mt-1 squarings */
    memcpy(sqrt_x, base, (size_t)t * sizeof(gf_t));
    for (int i = 0; i < m * t - 1; i++) {
        gf_t sq[MCELIECE_MAX_T];
        poly_mul_mod(sq, sqrt_x, sqrt_x, g, t, m);
        memcpy(sqrt_x, sq, (size_t)t * sizeof(gf_t));
    }

    /* r = even_part + sqrt_x * odd_part mod g(x) */
    poly_mul_mod(tmp, sqrt_x, odd_part, g, t, m);
    for (int i = 0; i < t; i++)
        r[i] = gf_add(even_part[i], tmp[i]);
}

/* ------------------------------------------------------------------ */
/* Patterson's decoding algorithm                                      */
/* ------------------------------------------------------------------ */

int mceliece_decrypt(uint8_t *e, const uint8_t *ct,
                     const gf_t *sk_g, const uint16_t *sk_perm,
                     const mceliece_params_t *p)
{
    int m = p->m;
    int t = p->t;
    int n = p->n;
    int mt = m * t;
    int e_bytes = (n + 7) / 8;

    gf_init_tables(m);

    /*
     * Step 1: Extract the GF(2^m) syndromes from the binary syndrome.
     *
     * The syndrome ct contains mt bits. These encode t elements of GF(2^m):
     *   S_i is stored in bits [i*m .. i*m + m - 1] of ct, for i = 0..t-1.
     *
     * S(x) = S_0 + S_1*x + ... + S_{t-1}*x^{t-1}
     * where S_i = sum_{j: e_j=1} alpha_j^i.
     */
    gf_t S[MCELIECE_MAX_T];
    memset(S, 0, sizeof(S));

    for (int i = 0; i < t; i++) {
        gf_t val = 0;
        for (int b = 0; b < m; b++) {
            int bit_pos = i * m + b;
            if (bit_pos < mt && (ct[bit_pos >> 3] & (1u << (bit_pos & 7)))) {
                val |= (gf_t)(1u << b);
            }
        }
        S[i] = val;
    }

    /* Check if syndrome is zero */
    int all_zero = 1;
    for (int i = 0; i < t; i++) {
        if (S[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) {
        memset(e, 0, (size_t)e_bytes);
        return 0;
    }

    /*
     * Step 2: Compute R(x) = S^{-1}(x) + x mod g(x).
     */
    gf_t R[MCELIECE_MAX_T];
    memset(R, 0, sizeof(R));

    if (poly_inv_mod(R, S, sk_g, t, m) != 0) {
        /* Syndrome polynomial not invertible - decoding failure */
        memset(e, 0, (size_t)e_bytes);
        return -1;
    }

    /* R(x) + x */
    if (t > 1) {
        R[1] = gf_add(R[1], 1);
    }

    /*
     * Step 3: T(x) = sqrt(R(x)) mod g(x)
     */
    gf_t T_poly[MCELIECE_MAX_T];
    poly_sqrt_mod(T_poly, R, sk_g, t, m);

    /*
     * Step 4: Error-locator polynomial via partial Euclidean algorithm.
     *
     * Run extended GCD on g(x) and T(x) until remainder degree < ceil(t/2).
     * Then sigma(x) = r(x)^2 + x * s(x)^2 where r is the remainder
     * and s is the cofactor.
     */

    gf_t u_poly[MCELIECE_MAX_T + 1], v_poly[MCELIECE_MAX_T + 1];
    gf_t s0_poly[MCELIECE_MAX_T + 1], s1_poly[MCELIECE_MAX_T + 1];
    int du, dv, ds0, ds1;

    memcpy(u_poly, sk_g, (size_t)(t + 1) * sizeof(gf_t));
    du = t;
    memset(v_poly, 0, sizeof(v_poly));
    memcpy(v_poly, T_poly, (size_t)t * sizeof(gf_t));
    dv = t - 1;
    while (dv >= 0 && v_poly[dv] == 0) dv--;

    memset(s0_poly, 0, sizeof(s0_poly));
    ds0 = -1;
    memset(s1_poly, 0, sizeof(s1_poly));
    s1_poly[0] = 1;
    ds1 = 0;

    int threshold = (t + 1) / 2;

    while (dv >= threshold) {
        while (du >= dv && du >= 0) {
            gf_t coeff = gf_frac(u_poly[du], v_poly[dv], m);
            int shift = du - dv;

            for (int i = 0; i <= dv; i++)
                u_poly[shift + i] = gf_add(u_poly[shift + i],
                                           gf_mul(coeff, v_poly[i], m));
            while (du >= 0 && u_poly[du] == 0) du--;

            for (int i = 0; i <= ds1; i++) {
                if (shift + i <= t)
                    s0_poly[shift + i] = gf_add(s0_poly[shift + i],
                                                gf_mul(coeff, s1_poly[i], m));
            }
            ds0 = -1;
            for (int i = t; i >= 0; i--) {
                if (s0_poly[i] != 0) { ds0 = i; break; }
            }
        }

        /* Swap */
        gf_t tmp_poly[MCELIECE_MAX_T + 1];
        int td;
        memcpy(tmp_poly, u_poly, sizeof(tmp_poly));
        memcpy(u_poly, v_poly, sizeof(u_poly));
        memcpy(v_poly, tmp_poly, sizeof(v_poly));
        td = du; du = dv; dv = td;

        memcpy(tmp_poly, s0_poly, sizeof(tmp_poly));
        memcpy(s0_poly, s1_poly, sizeof(s0_poly));
        memcpy(s1_poly, tmp_poly, sizeof(s1_poly));
        td = ds0; ds0 = ds1; ds1 = td;
    }

    /* sigma(x) = v_poly(x)^2 + x * s1_poly(x)^2 */
    gf_t sigma[MCELIECE_MAX_T + 1];
    memset(sigma, 0, sizeof(sigma));

    /* v^2 */
    for (int i = 0; i <= dv && i < t; i++) {
        for (int j = 0; j <= dv && j < t; j++) {
            if (i + j <= t)
                sigma[i + j] = gf_add(sigma[i + j],
                                      gf_mul(v_poly[i], v_poly[j], m));
        }
    }

    /* + x * s1^2 */
    for (int i = 0; i <= ds1 && i < t; i++) {
        for (int j = 0; j <= ds1 && j < t; j++) {
            if (i + j + 1 <= t)
                sigma[i + j + 1] = gf_add(sigma[i + j + 1],
                                          gf_mul(s1_poly[i], s1_poly[j], m));
        }
    }

    /* Find degree of sigma */
    int deg_sigma = 0;
    for (int i = t; i >= 0; i--) {
        if (sigma[i] != 0) { deg_sigma = i; break; }
    }

    /*
     * Step 5: Find roots of sigma(x) by evaluating at all support elements.
     * Roots correspond to error positions.
     */
    gf_t *eval = (gf_t *)calloc((size_t)n, sizeof(gf_t));
    if (!eval) return -1;

    root_eval(eval, sigma, deg_sigma, sk_perm, n, m);

    memset(e, 0, (size_t)e_bytes);
    int weight = 0;

    for (int i = 0; i < n; i++) {
        if (eval[i] == 0) {
            e[i >> 3] |= (uint8_t)(1u << (i & 7));
            weight++;
        }
    }

    free(eval);

    /* Verify weight */
    if (weight != t)
        return -1;

    return 0;
}
