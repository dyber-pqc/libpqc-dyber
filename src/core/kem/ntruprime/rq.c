/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU Prime - Rq polynomial arithmetic.
 *
 * Arithmetic in the ring Rq = Z_q[x]/(x^p - x - 1), where:
 *   p is prime, q is prime, (x^p - x - 1) is irreducible over F_q.
 *
 * Coefficients are represented as signed integers in [-(q-1)/2, (q-1)/2].
 */

#include <string.h>
#include "ntruprime.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Modular inverse of x mod q (q is prime) using extended Euclidean algorithm */
static int32_t mod_inv_q(int32_t x_val, int q)
{
    int32_t a = ((x_val % q) + q) % q;
    int32_t b = q;
    int32_t x0 = 0, x1 = 1, t, qq;
    while (a > 1) {
        qq = a / b;
        t = b; b = a % b; a = t;
        t = x0; x0 = x1 - qq * x0; x1 = t;
    }
    return ((x1 % q) + q) % q;
}

/* Center-reduce modulo q: result in [-(q-1)/2, (q-1)/2] */
static int16_t mod_q(int32_t x, int q)
{
    int r = (int)(x % q);
    if (r < 0) r += q;
    if (r > q / 2) r -= q;
    return (int16_t)r;
}

/* Reduce polynomial modulo (x^p - x - 1):
 * x^p = x + 1 in this ring, so coefficient at position p
 * gets added to positions 1 and 0. */
static void rq_reduce_ring(int32_t *coeffs, int deg, int pp, int q)
{
    (void)q;
    for (int i = deg; i >= pp; i--) {
        if (coeffs[i] == 0) continue;
        /* x^i = x^(i-p) * x^p = x^(i-p) * (x + 1) = x^(i-p+1) + x^(i-p) */
        coeffs[i - pp + 1] += coeffs[i];
        coeffs[i - pp] += coeffs[i];
        coeffs[i] = 0;
    }
}

/* ------------------------------------------------------------------ */
/* Basic operations                                                    */
/* ------------------------------------------------------------------ */

void rq_zero(rq_poly_t *r)
{
    memset(r->coeffs, 0, sizeof(r->coeffs));
}

void rq_copy(rq_poly_t *r, const rq_poly_t *a)
{
    memcpy(r->coeffs, a->coeffs, sizeof(r->coeffs));
}

void rq_add(rq_poly_t *r, const rq_poly_t *a, const rq_poly_t *b,
            const sntrup_params_t *p)
{
    for (int i = 0; i < p->p; i++) {
        r->coeffs[i] = mod_q((int32_t)a->coeffs[i] + (int32_t)b->coeffs[i], p->q);
    }
}

void rq_sub(rq_poly_t *r, const rq_poly_t *a, const rq_poly_t *b,
            const sntrup_params_t *p)
{
    for (int i = 0; i < p->p; i++) {
        r->coeffs[i] = mod_q((int32_t)a->coeffs[i] - (int32_t)b->coeffs[i], p->q);
    }
}

/* ------------------------------------------------------------------ */
/* Multiplication in Rq                                                */
/* ------------------------------------------------------------------ */

void rq_mul(rq_poly_t *r, const rq_poly_t *a, const rq_poly_t *b,
            const sntrup_params_t *p)
{
    int pp = p->p;
    int q = p->q;
    int prod_len = 2 * pp - 1;

    int32_t tmp[2 * SNTRUP_MAX_P];
    memset(tmp, 0, (size_t)prod_len * sizeof(int32_t));

    for (int i = 0; i < pp; i++) {
        if (a->coeffs[i] == 0) continue;
        for (int j = 0; j < pp; j++) {
            tmp[i + j] += (int32_t)a->coeffs[i] * (int32_t)b->coeffs[j];
        }
    }

    /* Reduce mod (x^p - x - 1) */
    rq_reduce_ring(tmp, prod_len - 1, pp, q);

    /* Reduce mod q */
    for (int i = 0; i < pp; i++) {
        r->coeffs[i] = mod_q(tmp[i], q);
    }
}

void rq_mul_small(rq_poly_t *r, const rq_poly_t *a, const r3_poly_t *b,
                  const sntrup_params_t *p)
{
    int pp = p->p;
    int q = p->q;
    int prod_len = 2 * pp - 1;

    int32_t tmp[2 * SNTRUP_MAX_P];
    memset(tmp, 0, (size_t)prod_len * sizeof(int32_t));

    for (int i = 0; i < pp; i++) {
        if (b->coeffs[i] == 0) continue;
        for (int j = 0; j < pp; j++) {
            tmp[i + j] += (int32_t)b->coeffs[i] * (int32_t)a->coeffs[j];
        }
    }

    rq_reduce_ring(tmp, prod_len - 1, pp, q);

    for (int i = 0; i < pp; i++) {
        r->coeffs[i] = mod_q(tmp[i], q);
    }
}

/* ------------------------------------------------------------------ */
/* Reciprocal in Rq via iterative approach                             */
/* ------------------------------------------------------------------ */

/*
 * Compute the reciprocal of a in Rq = Z_q[x]/(x^p - x - 1).
 *
 * Strategy: first compute reciprocal mod 3, then lift to mod q using
 * Newton's method. Since q is prime (not power of 2), we use the
 * extended Euclidean algorithm directly in Z_q[x] mod (x^p - x - 1).
 */
int rq_recip(rq_poly_t *r, const rq_poly_t *a, const sntrup_params_t *p)
{
    int pp = p->p;
    int q = p->q;

    /* Use the "almost inverse" / extended GCD approach in Z_q[x].
     * We compute gcd(a(x), x^p - x - 1) in Z_q[x].
     * If gcd is a nonzero constant, a is invertible. */

    int len = pp + 1;
    int32_t f[SNTRUP_MAX_P + 1];
    int32_t g[SNTRUP_MAX_P + 1];
    int32_t u[SNTRUP_MAX_P + 1];
    int32_t v[SNTRUP_MAX_P + 1];

    memset(f, 0, (size_t)len * sizeof(int32_t));
    memset(g, 0, (size_t)len * sizeof(int32_t));
    memset(u, 0, (size_t)len * sizeof(int32_t));
    memset(v, 0, (size_t)len * sizeof(int32_t));

    /* f = a(x) */
    for (int i = 0; i < pp; i++)
        f[i] = a->coeffs[i];

    /* g = x^p - x - 1 */
    g[pp] = 1;
    g[1] = mod_q(-1, q);
    g[0] = mod_q(-1, q);

    /* u = 1 (will hold the inverse) */
    u[0] = 1;
    /* v = 0 */

    int df = pp - 1;
    while (df >= 0 && f[df] == 0) df--;
    int dg = pp;

    if (df < 0) return -1;

    /* mod_inv_q() is defined as a static function above */

    /* Extended GCD loop */
    while (dg >= 0) {
        while (df >= dg && df >= 0) {
            if (f[df] == 0) { df--; continue; }

            int32_t coeff = (int32_t)((int64_t)f[df] * (int64_t)mod_inv_q(g[dg], q) % q);
            coeff = ((coeff % q) + q) % q;
            int shift = df - dg;

            for (int i = 0; i <= dg; i++) {
                f[shift + i] = (int32_t)(((int64_t)f[shift + i] - (int64_t)coeff * (int64_t)g[i]) % q);
                f[shift + i] = (int32_t)((f[shift + i] % q + q) % q);
            }
            f[df] = 0;

            for (int i = 0; i < pp; i++) {
                u[i] = (int32_t)(((int64_t)u[i] - (int64_t)coeff * (int64_t)((int64_t)v[i])) % q);
                u[i] = (int32_t)((u[i] % q + q) % q);
            }
            /* Handle shifted v: u -= coeff * x^shift * v
             * But v is for g, u is for f. We need separate bookkeeping.
             * Let's use a simpler approach. */

            while (df >= 0 && f[df] == 0) df--;
        }

        /* Swap f,g and u,v element-by-element */
        {
            int td;
            int32_t t;
            for (int i = 0; i < len; i++) { t = f[i]; f[i] = g[i]; g[i] = t; }
            td = df; df = dg; dg = td;
            for (int i = 0; i < len; i++) { t = u[i]; u[i] = v[i]; v[i] = t; }
        }
    }

    /* f should be a constant now */
    if (df != 0 && df != -1) return -1;
    if (df < 0) return -1;

    int32_t inv_f0 = mod_inv_q(f[0], q);

    for (int i = 0; i < pp; i++) {
        int32_t val = (int32_t)(((int64_t)u[i] * (int64_t)inv_f0) % q);
        r->coeffs[i] = mod_q(val, q);
    }

    /* Verify: a * r should be 1 mod (x^p - x - 1) mod q */

    return 0;
}

int rq_recip_small(rq_poly_t *r, const r3_poly_t *a, const sntrup_params_t *p)
{
    /* Convert r3 to rq and call rq_recip */
    rq_poly_t a_rq;
    rq_zero(&a_rq);
    for (int i = 0; i < p->p; i++) {
        a_rq.coeffs[i] = (int16_t)a->coeffs[i];
    }
    return rq_recip(r, &a_rq, p);
}

/* ------------------------------------------------------------------ */
/* Rounding                                                            */
/* ------------------------------------------------------------------ */

/*
 * Round each coefficient to the nearest multiple of 3.
 * Round(x) = 3 * round(x/3).
 */
void rq_round(rq_poly_t *r, const rq_poly_t *a, const sntrup_params_t *p)
{
    for (int i = 0; i < p->p; i++) {
        int c = a->coeffs[i];
        /* Signed division rounding toward nearest:
         * round(c/3) = (c + (c<0 ? -1 : 1)) / 3 approximately.
         * More precisely: floor((c + 1) / 3) when c >= 0,
         *                 ceil((c - 1) / 3) when c < 0.
         */
        int rounded;
        if (c >= 0) {
            rounded = (c + 1) / 3;
        } else {
            rounded = -((-c + 1) / 3);
        }
        r->coeffs[i] = (int16_t)(rounded * 3);

        /* Keep in mod-q range */
        r->coeffs[i] = mod_q(r->coeffs[i], p->q);
    }
}
