/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU Prime - R3 (mod 3) polynomial arithmetic.
 *
 * Arithmetic in the ring R3 = F_3[x]/(x^p - x - 1), where
 * coefficients are in {-1, 0, 1} representing F_3.
 */

#include <string.h>
#include "ntruprime.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int8_t mod3(int x)
{
    int r = x % 3;
    if (r < 0) r += 3;
    if (r == 2) return -1;
    return (int8_t)r;
}

/* ------------------------------------------------------------------ */
/* Basic operations                                                    */
/* ------------------------------------------------------------------ */

void r3_zero(r3_poly_t *r)
{
    memset(r->coeffs, 0, sizeof(r->coeffs));
}

void r3_add(r3_poly_t *r, const r3_poly_t *a, const r3_poly_t *b, int pp)
{
    for (int i = 0; i < pp; i++) {
        r->coeffs[i] = mod3((int)a->coeffs[i] + (int)b->coeffs[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Multiplication in R3 = F_3[x]/(x^p - x - 1)                       */
/* ------------------------------------------------------------------ */

void r3_mul(r3_poly_t *r, const r3_poly_t *a, const r3_poly_t *b, int pp)
{
    int prod_len = 2 * pp - 1;
    int8_t tmp[2 * SNTRUP_MAX_P];

    memset(tmp, 0, (size_t)prod_len);

    for (int i = 0; i < pp; i++) {
        if (a->coeffs[i] == 0) continue;
        for (int j = 0; j < pp; j++) {
            tmp[i + j] = mod3((int)tmp[i + j] +
                              (int)a->coeffs[i] * (int)b->coeffs[j]);
        }
    }

    /* Reduce modulo (x^p - x - 1): x^p = x + 1 */
    for (int i = prod_len - 1; i >= pp; i--) {
        if (tmp[i] == 0) continue;
        tmp[i - pp + 1] = mod3((int)tmp[i - pp + 1] + (int)tmp[i]);
        tmp[i - pp] = mod3((int)tmp[i - pp] + (int)tmp[i]);
        tmp[i] = 0;
    }

    for (int i = 0; i < pp; i++) {
        r->coeffs[i] = tmp[i];
    }
}

/* ------------------------------------------------------------------ */
/* Reciprocal in R3 = F_3[x]/(x^p - x - 1)                           */
/* ------------------------------------------------------------------ */

/*
 * Compute the reciprocal of a(x) in R3 using the "almost inverse"
 * algorithm adapted for the ring F_3[x]/(x^p - x - 1).
 *
 * Extended GCD of a(x) and (x^p - x - 1) in F_3[x].
 */
int r3_recip(r3_poly_t *r, const r3_poly_t *a, int pp)
{
    int8_t f[SNTRUP_MAX_P + 1], g[SNTRUP_MAX_P + 1];
    int8_t u[SNTRUP_MAX_P + 1], v[SNTRUP_MAX_P + 1];

    memset(f, 0, sizeof(f));
    memset(g, 0, sizeof(g));
    memset(u, 0, sizeof(u));
    memset(v, 0, sizeof(v));

    /* f = a */
    for (int i = 0; i < pp; i++)
        f[i] = a->coeffs[i];

    /* g = x^p - x - 1 */
    g[pp] = 1;
    g[1] = mod3(-1);
    g[0] = mod3(-1);

    /* u = 1, v = 0 */
    u[0] = 1;

    int df = pp - 1;
    while (df >= 0 && f[df] == 0) df--;
    int dg = pp;

    if (df < 0) return -1;

    while (dg >= 0) {
        /* Ensure df >= dg; if not, swap */
        if (df < dg) {
            int8_t sw[SNTRUP_MAX_P + 1];
            int td;

            memcpy(sw, f, sizeof(sw));
            memcpy(f, g, sizeof(f));
            memcpy(g, sw, sizeof(g));
            td = df; df = dg; dg = td;

            memcpy(sw, u, sizeof(sw));
            memcpy(u, v, sizeof(u));
            memcpy(v, sw, sizeof(v));
        }

        if (f[df] == 0) {
            df--;
            if (df < 0) return -1;
            continue;
        }

        /* scale = f[df] / g[dg] in F_3 */
        int8_t inv_gdg = (g[dg] == 1) ? 1 : ((g[dg] == -1) ? -1 : 0);
        if (inv_gdg == 0) return -1;

        int8_t scale = mod3((int)f[df] * (int)inv_gdg);
        int shift = df - dg;

        /* f -= scale * x^shift * g */
        for (int i = 0; i <= dg; i++) {
            f[shift + i] = mod3((int)f[shift + i] - (int)scale * (int)g[i]);
        }

        /* u -= scale * x^shift * v */
        for (int i = 0; i <= pp; i++) {
            if (shift + i <= pp)
                u[shift + i] = mod3((int)u[shift + i] - (int)scale * (int)v[i]);
        }

        while (df >= 0 && f[df] == 0) df--;

        if (df < dg) {
            /* Swap f<->g, u<->v, df<->dg */
            int8_t sw[SNTRUP_MAX_P + 1];
            int td;

            memcpy(sw, f, sizeof(sw));
            memcpy(f, g, sizeof(f));
            memcpy(g, sw, sizeof(g));
            td = df; df = dg; dg = td;

            memcpy(sw, u, sizeof(sw));
            memcpy(u, v, sizeof(u));
            memcpy(v, sw, sizeof(v));
        }
    }

    /* f should be a nonzero constant */
    while (df > 0 && f[df] == 0) df--;
    if (df != 0) return -1;
    if (f[0] == 0) return -1;

    /* r = u / f[0] in F_3 */
    int8_t inv_f0 = (f[0] == 1) ? 1 : -1;
    for (int i = 0; i < pp; i++) {
        r->coeffs[i] = mod3((int)u[i] * (int)inv_f0);
    }

    return 0;
}
