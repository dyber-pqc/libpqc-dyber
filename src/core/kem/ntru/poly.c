/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU - Polynomial arithmetic in Z_q[x]/(x^n - 1).
 *
 * All arithmetic is performed in the quotient ring Z_q[x]/(x^n - 1)
 * with q a power of 2 and n prime.
 */

#include <string.h>
#include "ntru.h"

/* ------------------------------------------------------------------ */
/* Basic operations                                                    */
/* ------------------------------------------------------------------ */

void ntru_poly_zero(ntru_poly_t *r)
{
    memset(r->coeffs, 0, sizeof(r->coeffs));
}

void ntru_poly_copy(ntru_poly_t *r, const ntru_poly_t *a)
{
    memcpy(r->coeffs, a->coeffs, sizeof(r->coeffs));
}

void ntru_poly_add(ntru_poly_t *r, const ntru_poly_t *a,
                   const ntru_poly_t *b, const ntru_params_t *p)
{
    int mask = p->q - 1;
    for (int i = 0; i < p->n; i++) {
        r->coeffs[i] = (int16_t)((a->coeffs[i] + b->coeffs[i]) & mask);
    }
}

void ntru_poly_sub(ntru_poly_t *r, const ntru_poly_t *a,
                   const ntru_poly_t *b, const ntru_params_t *p)
{
    int mask = p->q - 1;
    for (int i = 0; i < p->n; i++) {
        r->coeffs[i] = (int16_t)((a->coeffs[i] - b->coeffs[i]) & mask);
    }
}

/* ------------------------------------------------------------------ */
/* Multiplication in Z_q[x]/(x^n - 1) using schoolbook                */
/* ------------------------------------------------------------------ */

void ntru_poly_mul(ntru_poly_t *r, const ntru_poly_t *a,
                   const ntru_poly_t *b, const ntru_params_t *p)
{
    int n = p->n;
    int mask = p->q - 1;
    int32_t tmp[NTRU_MAX_N];

    memset(tmp, 0, (size_t)n * sizeof(int32_t));

    for (int i = 0; i < n; i++) {
        if (a->coeffs[i] == 0)
            continue;
        for (int j = 0; j < n; j++) {
            int idx = i + j;
            if (idx >= n)
                idx -= n;
            tmp[idx] += (int32_t)a->coeffs[i] * (int32_t)b->coeffs[j];
        }
    }

    for (int i = 0; i < n; i++) {
        r->coeffs[i] = (int16_t)(tmp[i] & mask);
    }
}

/* ------------------------------------------------------------------ */
/* Modular reduction                                                   */
/* ------------------------------------------------------------------ */

void ntru_poly_mod_q(ntru_poly_t *r, const ntru_params_t *p)
{
    int q = p->q;
    int half_q = q >> 1;
    int mask = q - 1;

    for (int i = 0; i < p->n; i++) {
        int16_t c = (int16_t)(r->coeffs[i] & mask);
        if (c >= half_q)
            c -= (int16_t)q;
        r->coeffs[i] = c;
    }
}

void ntru_poly_mod3(ntru_poly_t *r, int n)
{
    for (int i = 0; i < n; i++) {
        int c = r->coeffs[i] % 3;
        if (c < 0) c += 3;
        if (c == 2) c = -1;
        r->coeffs[i] = (int16_t)c;
    }
}

void ntru_poly_lift(ntru_poly_t *r, int n)
{
    /* Center-lift: ensure coefficients are in {-1, 0, 1} */
    for (int i = 0; i < n; i++) {
        int c = r->coeffs[i] % 3;
        if (c < 0) c += 3;
        if (c == 2) c = -1;
        r->coeffs[i] = (int16_t)c;
    }
}

/* ------------------------------------------------------------------ */
/* Inverse modulo q (power of 2) using Newton's method                 */
/*                                                                     */
/* Start with inverse mod 2, then lift: inv mod 2^k -> inv mod 2^(2k) */
/* using f_inv = f_inv * (2 - f * f_inv) mod 2^(2k).                  */
/* ------------------------------------------------------------------ */

/*
 * Multiply two polynomials mod (x^n - 1) with modular reduction mod m.
 */
static void poly_mul_mod_m(int16_t *r, const int16_t *a,
                           const int16_t *b, int n, int mod)
{
    int32_t tmp[NTRU_MAX_N];
    memset(tmp, 0, (size_t)n * sizeof(int32_t));

    for (int i = 0; i < n; i++) {
        if (a[i] == 0) continue;
        for (int j = 0; j < n; j++) {
            int idx = i + j;
            if (idx >= n) idx -= n;
            tmp[idx] += (int32_t)a[i] * (int32_t)b[j];
        }
    }

    int mask = mod - 1;
    for (int i = 0; i < n; i++) {
        r[i] = (int16_t)(tmp[i] & mask);
    }
}

int ntru_poly_inv_mod_q(ntru_poly_t *r, const ntru_poly_t *f,
                        const ntru_params_t *p)
{
    int n = p->n;
    int q = p->q;

    /*
     * Step 1: Compute inverse of f mod 2 in Z_2[x]/(x^n - 1).
     * Use the extended Euclidean algorithm in Z_2[x]/(x^n - 1).
     *
     * For simplicity, use iterative inversion starting with a guess.
     */

    /* Start with f_inv = f mod 2 (works if f(1) is odd) */
    ntru_poly_t inv;
    ntru_poly_t tmp_poly;
    int16_t two_arr[NTRU_MAX_N];

    ntru_poly_zero(&inv);
    inv.coeffs[0] = 1; /* initial guess */

    /*
     * Newton's method to find inverse mod 2:
     * In Z_2[x]/(x^n - 1), check that sum of coefficients of f is odd.
     */
    int sum = 0;
    for (int i = 0; i < n; i++)
        sum += (f->coeffs[i] & 1);
    if ((sum & 1) == 0)
        return -1; /* f not invertible mod 2 */

    /* Extended GCD approach for mod 2:
     * Use the polynomial "almost inverse" method. */
    int16_t b_arr[NTRU_MAX_N], c_arr[NTRU_MAX_N];
    int16_t f_arr[NTRU_MAX_N], g_arr[NTRU_MAX_N];

    memset(b_arr, 0, sizeof(b_arr));
    memset(c_arr, 0, sizeof(c_arr));
    memset(f_arr, 0, sizeof(f_arr));
    memset(g_arr, 0, sizeof(g_arr));

    b_arr[0] = 1;
    for (int i = 0; i < n; i++)
        f_arr[i] = (int16_t)(f->coeffs[i] & 1);
    g_arr[0] = 1; /* x^n - 1 mod 2 = x^n + 1, with g representing x^n - 1 */
    g_arr[n] = 0; /* We work in the quotient ring directly */

    /* Actually, let's use a simpler approach: Newton lifting.
     * Start with any inverse mod 2 and lift to mod q.
     *
     * For mod 2: f_inv = 1 works if f[0] is odd. Then Newton iterate.
     */
    ntru_poly_zero(&inv);
    inv.coeffs[0] = 1;

    /* Verify f[0] is odd */
    if ((f->coeffs[0] & 1) == 0)
        return -1;

    /* Newton iterate: inv = inv * (2 - f * inv) mod 2^k, starting from k=1 */
    int mod = 2;
    while (mod < q) {
        int next_mod = mod * mod;
        if (next_mod > q) next_mod = q;
        /* But we want to double the precision each step */
        next_mod = mod << 1;
        if (next_mod > q) next_mod = q;

        /* tmp = f * inv mod next_mod */
        poly_mul_mod_m(tmp_poly.coeffs, f->coeffs, inv.coeffs, n, next_mod);

        /* two - tmp */
        memset(two_arr, 0, sizeof(two_arr));
        two_arr[0] = 2;

        int mask = next_mod - 1;
        for (int i = 0; i < n; i++) {
            two_arr[i] = (int16_t)((two_arr[i] - tmp_poly.coeffs[i]) & mask);
        }

        /* inv = inv * (2 - f*inv) mod next_mod */
        poly_mul_mod_m(tmp_poly.coeffs, inv.coeffs, two_arr, n, next_mod);
        memcpy(inv.coeffs, tmp_poly.coeffs, (size_t)n * sizeof(int16_t));

        mod = next_mod;
    }

    /* Final reduction mod q */
    int qmask = q - 1;
    for (int i = 0; i < n; i++) {
        r->coeffs[i] = (int16_t)(inv.coeffs[i] & qmask);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Inverse modulo 3                                                    */
/* ------------------------------------------------------------------ */

/*
 * Compute inverse of f in Z_3[x]/(x^n - 1).
 * Uses the "almost inverse" algorithm.
 */
int ntru_poly_inv_mod3(ntru_poly_t *r, const ntru_poly_t *f, int n)
{
    int16_t b[NTRU_MAX_N + 1], c[NTRU_MAX_N + 1];
    int16_t ff[NTRU_MAX_N + 1], g[NTRU_MAX_N + 1];

    memset(b, 0, sizeof(b));
    memset(c, 0, sizeof(c));
    memset(ff, 0, sizeof(ff));
    memset(g, 0, sizeof(g));

    b[0] = 1;
    for (int i = 0; i < n; i++) {
        ff[i] = (int16_t)(((f->coeffs[i] % 3) + 3) % 3);
    }
    g[0] = (int16_t)((-1 + 3) % 3); /* -1 mod 3 = 2 */
    g[n] = 1; /* g = x^n - 1 */

    int df = n - 1, dg = n;
    int k = 0;

    /* Ensure leading coefficient of ff is nonzero */
    while (df >= 0 && ff[df] == 0) df--;
    if (df < 0) return -1;

    while (1) {
        while (df >= 0 && ff[0] == 0) {
            /* ff = ff / x, b = b * x */
            for (int i = 0; i < df; i++) ff[i] = ff[i + 1];
            ff[df] = 0;
            df--;

            /* Shift c up: c = c * x (mod x^n - 1, but we're in a bigger ring here) */
            for (int i = n; i > 0; i--) c[i] = c[i - 1];
            c[0] = 0;

            k++;
        }

        if (df == 0) {
            /* ff = constant, invert it */
            int16_t inv_ff0;
            if (ff[0] == 1) inv_ff0 = 1;
            else if (ff[0] == 2) inv_ff0 = 2;
            else return -1;

            /* r = b * inv_ff0 * x^(-k) mod (x^n - 1) */
            ntru_poly_zero(r);
            for (int i = 0; i <= n; i++) {
                int16_t val = (int16_t)((b[i] * inv_ff0) % 3);
                if (val < 0) val += 3;
                /* Place at position (i - k) mod n */
                int pos = ((i - k) % n + n) % n;
                r->coeffs[pos] = (int16_t)((r->coeffs[pos] + val) % 3);
            }
            /* Convert to {-1, 0, 1} */
            for (int i = 0; i < n; i++) {
                if (r->coeffs[i] == 2) r->coeffs[i] = -1;
            }
            return 0;
        }

        if (df < dg) {
            /* Swap ff,g and b,c and df,dg */
            int16_t tmp[NTRU_MAX_N + 1];
            int td;
            memcpy(tmp, ff, sizeof(tmp));
            memcpy(ff, g, sizeof(ff));
            memcpy(g, tmp, sizeof(g));
            td = df; df = dg; dg = td;

            memcpy(tmp, b, sizeof(tmp));
            memcpy(b, c, sizeof(b));
            memcpy(c, tmp, sizeof(c));
        }

        /* ff = ff - (ff[0] / g[0]) * g */
        int16_t scale;
        if (g[0] == 0) return -1;

        /* In Z_3: ff[0] / g[0] */
        int16_t inv_g0 = (g[0] == 1) ? 1 : 2;
        scale = (int16_t)((ff[0] * inv_g0) % 3);
        if (scale < 0) scale += 3;

        for (int i = 0; i <= dg; i++) {
            ff[i] = (int16_t)(((ff[i] - scale * g[i]) % 3 + 3) % 3);
        }
        for (int i = 0; i <= n; i++) {
            b[i] = (int16_t)(((b[i] - scale * c[i]) % 3 + 3) % 3);
        }

        while (df >= 0 && ff[df] == 0) df--;
        if (df < 0) return -1;
    }
}
