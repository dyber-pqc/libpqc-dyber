/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- NTRU equation solver.
 *
 * Solves f*G - g*F = q  mod (x^n + 1) for polynomials F, G given
 * small polynomials f, g.
 *
 * Algorithm:
 *   1. Descend by computing field norms at each level, halving the
 *      degree.  Uses modular arithmetic (one 30-bit prime) and int32_t
 *      (truncated) field norms.
 *   2. At the base case (degree 1), solve f0*G0 - g0*F0 = q using
 *      extended GCD on the modular residues.
 *   3. Lift from level 1 back to level logn using FFT-based Babai
 *      rounding with the stored int32_t field norms.  The Babai
 *      reduction corrects for the modular approximation at each step.
 */

#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "fndsa.h"
#include "fndsa_params.h"
#include "fft.h"

/* Working prime.  Must be > 2*q and fit in int64_t after squaring. */
#define MOD_P  1073741789LL  /* prime near 2^30 */

static int64_t modp(int64_t x) {
    int64_t r = x % MOD_P;
    return r < 0 ? r + MOD_P : r;
}

static int64_t modp_mul(int64_t a, int64_t b) {
    return modp(modp(a) * modp(b));
}

/* ------------------------------------------------------------------ */
/* Extended GCD                                                         */
/* ------------------------------------------------------------------ */

/*
 * Compute gcd(a, b) and Bezout coefficients u, v such that
 *   u*a + v*b = gcd(a, b).
 */
static int64_t
xgcd(int64_t a, int64_t b, int64_t *u, int64_t *v)
{
    int64_t u0 = 1, u1 = 0, v0 = 0, v1 = 1;
    if (a < 0) { int64_t r = xgcd(-a, b, u, v); *u = -(*u); return r; }
    if (b < 0) { int64_t r = xgcd(a, -b, u, v); *v = -(*v); return r; }
    while (b != 0) {
        int64_t q = a / b, t;
        t = a - q * b; a = b; b = t;
        t = u0 - q * u1; u0 = u1; u1 = t;
        t = v0 - q * v1; v0 = v1; v1 = t;
    }
    *u = u0;
    *v = v0;
    return a;
}

/* ------------------------------------------------------------------ */
/* Field norm mod P                                                     */
/* ------------------------------------------------------------------ */

static void
field_norm_modp(int64_t *out, const int64_t *f, size_t hn)
{
    size_t i, j;
    memset(out, 0, hn * sizeof(int64_t));

    for (i = 0; i < hn; i++)
        for (j = 0; j < hn; j++) {
            size_t idx = i + j;
            int64_t p = modp_mul(f[2 * i], f[2 * j]);
            if (idx >= hn) { idx -= hn; out[idx] = modp(out[idx] - p); }
            else { out[idx] = modp(out[idx] + p); }
        }

    for (i = 0; i < hn; i++)
        for (j = 0; j < hn; j++) {
            size_t idx = i + j + 1;
            int64_t p = modp_mul(f[2 * i + 1], f[2 * j + 1]);
            if (idx >= hn) { idx -= hn; out[idx] = modp(out[idx] + p); }
            else { out[idx] = modp(out[idx] - p); }
        }
}

/* ------------------------------------------------------------------ */
/* FFT-based Babai lift                                                 */
/* ------------------------------------------------------------------ */

static int
ntru_lift_fft(unsigned logn,
              const int32_t *f, const int32_t *g,
              int32_t *F, int32_t *G,
              const int32_t *Fp, const int32_t *Gp,
              double *tmp)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;
    double *t0 = tmp, *t1 = t0 + n, *t2 = t1 + n, *t3 = t2 + n, *t4 = t3 + n;

    /* F(x) = Fp(x^2) * g(-x),  G(x) = Gp(x^2) * f(-x). */
    memset(t2, 0, n * sizeof(double));
    for (i = 0; i < hn; i++)
        t2[2 * i] = (double)Fp[i];

    memset(t3, 0, n * sizeof(double));
    for (i = 0; i < hn; i++)
        t3[2 * i] = (double)Gp[i];

    for (i = 0; i < n; i++)
        t0[i] = (double)g[i] * ((i & 1) ? -1.0 : 1.0);
    for (i = 0; i < n; i++)
        t1[i] = (double)f[i] * ((i & 1) ? -1.0 : 1.0);

    fndsa_fft_forward(t0, logn);
    fndsa_fft_forward(t1, logn);
    fndsa_fft_forward(t2, logn);
    fndsa_fft_forward(t3, logn);
    fndsa_fft_mul(t2, t0, logn);
    fndsa_fft_mul(t3, t1, logn);
    fndsa_fft_inverse(t2, logn);
    fndsa_fft_inverse(t3, logn);

    for (i = 0; i < n; i++) {
        F[i] = (int32_t)floor(t2[i] + 0.5);
        G[i] = (int32_t)floor(t3[i] + 0.5);
    }

    /* Babai reduction. */
    {
        int iter;
        for (iter = 0; iter < 10; iter++) {
            int any = 0;
            size_t j;
            int64_t *Fn, *Gn;

            for (i = 0; i < n; i++) t0[i] = (double)f[i];
            fndsa_fft_forward(t0, logn);

            for (i = 0; i < n; i++) t1[i] = (double)g[i];
            fndsa_fft_forward(t1, logn);

            memcpy(t4, t0, n * sizeof(double));
            fndsa_fft_mul_selfadj(t4, logn);
            memcpy(t3, t1, n * sizeof(double));
            fndsa_fft_mul_selfadj(t3, logn);
            fndsa_fft_add(t4, t3, logn);

            for (i = 0; i < n; i++) t2[i] = (double)F[i];
            fndsa_fft_forward(t2, logn);
            fndsa_fft_mul_adj(t2, t0, logn);

            for (i = 0; i < n; i++) t3[i] = (double)G[i];
            fndsa_fft_forward(t3, logn);
            fndsa_fft_mul_adj(t3, t1, logn);

            fndsa_fft_add(t2, t3, logn);
            fndsa_fft_div(t2, t4, logn);
            fndsa_fft_inverse(t2, logn);

            Fn = (int64_t *)malloc(n * sizeof(int64_t));
            Gn = (int64_t *)malloc(n * sizeof(int64_t));
            if (!Fn || !Gn) { free(Fn); free(Gn); return -1; }

            for (i = 0; i < n; i++) { Fn[i] = F[i]; Gn[i] = G[i]; }

            for (i = 0; i < n; i++) {
                int32_t ki = (int32_t)floor(t2[i] + 0.5);
                if (ki == 0) continue;
                any = 1;
                for (j = 0; j < n; j++) {
                    size_t idx = i + j;
                    int64_t kf = (int64_t)ki * f[j];
                    int64_t kg = (int64_t)ki * g[j];
                    if (idx >= n) {
                        idx -= n;
                        Fn[idx] += kf;
                        Gn[idx] += kg;
                    } else {
                        Fn[idx] -= kf;
                        Gn[idx] -= kg;
                    }
                }
            }

            for (i = 0; i < n; i++) {
                F[i] = (int32_t)Fn[i];
                G[i] = (int32_t)Gn[i];
            }
            free(Fn);
            free(Gn);

            if (!any) break;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Main solver                                                          */
/* ------------------------------------------------------------------ */

int
fndsa_solve_ntru(unsigned logn,
                 const int32_t *f, const int32_t *g,
                 int32_t *F, int32_t *G,
                 double *tmp)
{
    size_t n = (size_t)1 << logn;
    unsigned lv;
    size_t i;
    int rc;

    /* int32_t field norms for the Babai lift at each level. */
    int32_t *fi32[FNDSA_MAX_LOGN + 1];
    int32_t *gi32[FNDSA_MAX_LOGN + 1];

    /* Modular field norms for the base-case solution. */
    int64_t *fmod[FNDSA_MAX_LOGN + 1];
    int64_t *gmod[FNDSA_MAX_LOGN + 1];

    memset(fi32, 0, sizeof(fi32));
    memset(gi32, 0, sizeof(gi32));
    memset(fmod, 0, sizeof(fmod));
    memset(gmod, 0, sizeof(gmod));

    /* Top level. */
    fi32[logn] = (int32_t *)malloc(n * sizeof(int32_t));
    gi32[logn] = (int32_t *)malloc(n * sizeof(int32_t));
    fmod[logn] = (int64_t *)malloc(n * sizeof(int64_t));
    gmod[logn] = (int64_t *)malloc(n * sizeof(int64_t));
    if (!fi32[logn] || !gi32[logn] || !fmod[logn] || !gmod[logn])
        { rc = -1; goto done; }

    for (i = 0; i < n; i++) {
        fi32[logn][i] = f[i];
        gi32[logn][i] = g[i];
        fmod[logn][i] = modp((int64_t)f[i]);
        gmod[logn][i] = modp((int64_t)g[i]);
    }

    /* ------------------------------------------------------------ */
    /* Descend: compute field norms at each level.                    */
    /* ------------------------------------------------------------ */
    for (lv = logn; lv > 0; lv--) {
        size_t cn = (size_t)1 << lv;
        size_t chn = cn >> 1;
        int64_t *tmp64;

        fi32[lv - 1] = (int32_t *)malloc(chn * sizeof(int32_t));
        gi32[lv - 1] = (int32_t *)malloc(chn * sizeof(int32_t));
        fmod[lv - 1] = (int64_t *)malloc(chn * sizeof(int64_t));
        gmod[lv - 1] = (int64_t *)malloc(chn * sizeof(int64_t));
        if (!fi32[lv - 1] || !gi32[lv - 1] || !fmod[lv - 1] || !gmod[lv - 1])
            { rc = -1; goto done; }

        /* int32_t field norms (truncated -- Babai tolerates this). */
        tmp64 = (int64_t *)calloc(chn, sizeof(int64_t));
        if (!tmp64) { rc = -1; goto done; }
        for (i = 0; i < chn; i++) {
            size_t j;
            for (j = 0; j < chn; j++) {
                size_t idx = i + j;
                int64_t p = (int64_t)fi32[lv][2 * i] * (int64_t)fi32[lv][2 * j];
                if (idx >= chn) { idx -= chn; tmp64[idx] -= p; }
                else { tmp64[idx] += p; }
            }
        }
        for (i = 0; i < chn; i++) {
            size_t j;
            for (j = 0; j < chn; j++) {
                size_t idx = i + j + 1;
                int64_t p = (int64_t)fi32[lv][2 * i + 1] * (int64_t)fi32[lv][2 * j + 1];
                if (idx >= chn) { idx -= chn; tmp64[idx] += p; }
                else { tmp64[idx] -= p; }
            }
        }
        for (i = 0; i < chn; i++) fi32[lv - 1][i] = (int32_t)tmp64[i];
        free(tmp64);

        tmp64 = (int64_t *)calloc(chn, sizeof(int64_t));
        if (!tmp64) { rc = -1; goto done; }
        for (i = 0; i < chn; i++) {
            size_t j;
            for (j = 0; j < chn; j++) {
                size_t idx = i + j;
                int64_t p = (int64_t)gi32[lv][2 * i] * (int64_t)gi32[lv][2 * j];
                if (idx >= chn) { idx -= chn; tmp64[idx] -= p; }
                else { tmp64[idx] += p; }
            }
        }
        for (i = 0; i < chn; i++) {
            size_t j;
            for (j = 0; j < chn; j++) {
                size_t idx = i + j + 1;
                int64_t p = (int64_t)gi32[lv][2 * i + 1] * (int64_t)gi32[lv][2 * j + 1];
                if (idx >= chn) { idx -= chn; tmp64[idx] += p; }
                else { tmp64[idx] -= p; }
            }
        }
        for (i = 0; i < chn; i++) gi32[lv - 1][i] = (int32_t)tmp64[i];
        free(tmp64);

        /* Modular field norms (exact mod P). */
        field_norm_modp(fmod[lv - 1], fmod[lv], chn);
        field_norm_modp(gmod[lv - 1], gmod[lv], chn);
    }

    /* ------------------------------------------------------------ */
    /* Base case: solve f0*G0 - g0*F0 = q.                           */
    /*                                                                */
    /* We have f0 mod P and g0 mod P.  We use xgcd on these modular  */
    /* residues to find Bezout coefficients, then compute F0, G0.     */
    /* The resulting (F0, G0) satisfies the equation mod P.  Since    */
    /* |F0|, |G0| might be up to P/2, the Babai lift at subsequent   */
    /* levels will reduce them.                                       */
    /* ------------------------------------------------------------ */
    {
        int64_t f0_mod = fmod[0][0];
        int64_t g0_mod = gmod[0][0];
        int64_t f0_s, g0_s;
        int64_t u, v, d, scale;
        int64_t G0, F0;

        /* Convert to centered representation. */
        f0_s = (f0_mod > MOD_P / 2) ? f0_mod - MOD_P : f0_mod;
        g0_s = (g0_mod > MOD_P / 2) ? g0_mod - MOD_P : g0_mod;

        if (f0_s == 0 && g0_s == 0) {
            rc = -1;
            goto done;
        }

        d = xgcd(f0_s, g0_s, &u, &v);
        if (d < 0) { d = -d; u = -u; v = -v; }

        if (d == 0 || (FNDSA_Q % d) != 0) {
            /* gcd doesn't divide q -- bad key parameters. */
            rc = -1;
            goto done;
        }

        scale = FNDSA_Q / d;

        /* u * f0_s + v * g0_s = d
         * f0 * (u*scale) + g0 * (v*scale) = q  (mod P)
         * f0 * G0 - g0 * F0 = q
         * => G0 = u*scale,  F0 = -v*scale */
        G0 = u * scale;
        F0 = -v * scale;

        /* Reduce by g0_s, f0_s to get smaller values.
         * (F0 + k*f0_s, G0 + k*g0_s) is also a solution for any k. */
        if (g0_s != 0) {
            /* Find k such that |G0 + k*g0_s| is minimised. */
            int64_t k = -G0 / g0_s;
            int64_t best = G0 + k * g0_s;
            int64_t alt1 = best + g0_s;
            int64_t alt2 = best - g0_s;
            int64_t abest = (best < 0) ? -best : best;
            int64_t a1 = (alt1 < 0) ? -alt1 : alt1;
            int64_t a2 = (alt2 < 0) ? -alt2 : alt2;
            if (a1 < abest) { best = alt1; k++; }
            if (a2 < abest) { best = alt2; k--; }
            G0 += k * g0_s;
            F0 += k * f0_s;
        }

        G[0] = (int32_t)G0;
        F[0] = (int32_t)F0;
    }

    /* ------------------------------------------------------------ */
    /* Lift from level 1 up to level logn.                            */
    /*                                                                */
    /* Always use the int32_t field norms for the lift.  At top       */
    /* levels these are exact; at deeper levels the truncation is     */
    /* tolerated by the Babai correction.                             */
    /* ------------------------------------------------------------ */
    for (lv = 1; lv <= logn; lv++) {
        size_t cn = (size_t)1 << lv;
        size_t chn = cn >> 1;
        int32_t *Fp = (int32_t *)malloc(chn * sizeof(int32_t));
        int32_t *Gp = (int32_t *)malloc(chn * sizeof(int32_t));

        if (!Fp || !Gp) {
            free(Fp); free(Gp);
            rc = -1; goto done;
        }

        memcpy(Fp, F, chn * sizeof(int32_t));
        memcpy(Gp, G, chn * sizeof(int32_t));

        rc = ntru_lift_fft(lv, fi32[lv], gi32[lv], F, G, Fp, Gp, tmp);
        free(Fp);
        free(Gp);
        if (rc != 0) goto done;
    }

    rc = 0;

done:
    for (lv = 0; lv <= logn; lv++) {
        free(fi32[lv]);
        free(gi32[lv]);
        free(fmod[lv]);
        free(gmod[lv]);
    }
    return rc;
}
