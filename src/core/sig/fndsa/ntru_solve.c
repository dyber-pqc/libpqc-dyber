/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- NTRU equation solver for key generation.
 *
 * Given small polynomials f, g in Z[x]/(x^n + 1), find F, G such that
 *     f*G - g*F = q   (mod x^n + 1)
 *
 * The algorithm is the recursive approach from Falcon:
 *   1. Compute field norms f' = N(f), g' = N(g) at each recursion
 *      level, halving the degree until degree 1.
 *   2. At the base case (n=1) solve the Bezout identity directly
 *      with the extended GCD.
 *   3. Lift back using Babai's nearest-plane with FFT arithmetic.
 *
 * The field norm N(f) for f in Z[x]/(x^n+1) is computed as
 *     N(f)(x) = f(sqrt(x)) * f(-sqrt(x))    in Z[x]/(x^{n/2}+1).
 * Equivalently, if f = f_even(x^2) + x*f_odd(x^2) then
 *     N(f) = f_even^2 - x * f_odd^2    in Z[x]/(x^{n/2}+1).
 */

#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "fndsa.h"
#include "fndsa_params.h"
#include "fft.h"

/* ------------------------------------------------------------------ */
/* Extended GCD for the base case (integers)                            */
/* ------------------------------------------------------------------ */

/*
 * Extended GCD: compute gcd(a, b) and Bezout coefficients u, v
 * such that a*u + b*v = gcd(a,b).
 * Returns gcd.
 */
static int64_t
xgcd(int64_t a, int64_t b, int64_t *u, int64_t *v)
{
    int64_t u0 = 1, u1 = 0;
    int64_t v0 = 0, v1 = 1;

    if (a < 0) {
        int64_t r = xgcd(-a, b, u, v);
        *u = -(*u);
        return r;
    }
    if (b < 0) {
        int64_t r = xgcd(a, -b, u, v);
        *v = -(*v);
        return r;
    }

    while (b != 0) {
        int64_t q = a / b;
        int64_t t;

        t = a - q * b; a = b; b = t;
        t = u0 - q * u1; u0 = u1; u1 = t;
        t = v0 - q * v1; v0 = v1; v1 = t;
    }

    *u = u0;
    *v = v0;
    return a;
}

/* ------------------------------------------------------------------ */
/* Field norm: Z[x]/(x^n+1) -> Z[x]/(x^{n/2}+1)                       */
/* ------------------------------------------------------------------ */

/*
 * Compute the field norm of f (int32_t coefficients, degree < n = 2^logn).
 * Output is written to out (degree < n/2 = 2^(logn-1)).
 * Uses the formula:  N(f) = f_even^2 - x * f_odd^2.
 *
 * The computation in Z[x]/(x^{n/2}+1):
 *   f_even[i] = f[2*i]
 *   f_odd[i]  = f[2*i+1]
 *   out[i] = sum over j of f_even[j]*f_even[i-j] - f_odd[j]*f_odd[i-j-1]
 * where indices wrap with the sign change from x^{n/2} = -1.
 *
 * We do this with simple O(n^2) convolution for the small sizes
 * encountered during recursion (n/2 at each level).  For the top
 * level the caller uses FFT-based arithmetic instead.
 */
static void
field_norm_small(int32_t *out, const int32_t *f, unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i, j;
    int64_t tmp[FNDSA_MAX_N / 2];

    memset(tmp, 0, hn * sizeof(int64_t));

    /* f_even^2 */
    for (i = 0; i < hn; i++) {
        for (j = 0; j < hn; j++) {
            size_t idx = i + j;
            int64_t prod = (int64_t)f[2 * i] * (int64_t)f[2 * j];
            if (idx >= hn) {
                idx -= hn;
                tmp[idx] -= prod;  /* x^{n/2} = -1 */
            } else {
                tmp[idx] += prod;
            }
        }
    }

    /* - x * f_odd^2:  multiply by x means shift indices by 1. */
    for (i = 0; i < hn; i++) {
        for (j = 0; j < hn; j++) {
            size_t idx = i + j + 1;  /* +1 for the x factor */
            int64_t prod = (int64_t)f[2 * i + 1] * (int64_t)f[2 * j + 1];
            if (idx >= hn) {
                idx -= hn;
                /* -x * (...) and x^{n/2}=-1 => double negation = + */
                tmp[idx] += prod;
            } else {
                tmp[idx] -= prod;
            }
        }
    }

    for (i = 0; i < hn; i++)
        out[i] = (int32_t)tmp[i];
}

/* ------------------------------------------------------------------ */
/* Babai lift: given (F', G') for (f', g'), compute (F, G) for (f, g)   */
/* ------------------------------------------------------------------ */

/*
 * Lift the NTRU solution from degree n/2 to degree n.
 *
 * Given f, g of degree < n and F', G' of degree < n/2 satisfying
 *     f'*G' - g'*F' = q    in Z[x]/(x^{n/2}+1)
 * where f' = N(f), g' = N(g), compute F, G of degree < n such that
 *     f*G - g*F = q    in Z[x]/(x^n+1).
 *
 * The lift formula:
 *     F(x) = F'(x^2) * f_adj(x)    (in a suitable sense)
 *     G(x) = G'(x^2) * g_adj(x)
 * where f_adj is the "adjoint" of f under the automorphism x -> -x.
 * Then Babai reduction is applied to keep the coefficients small.
 *
 * We use FFT arithmetic for the multiplications and Babai reduction.
 */
static int
ntru_lift(unsigned logn,
          const int32_t *f, const int32_t *g,
          int32_t *F, int32_t *G,
          const int32_t *Fp, const int32_t *Gp,
          double *tmp)
{
    size_t n  = (size_t)1 << logn;
    size_t hn = n >> 1;
    size_t i;

    /*
     * Layout in tmp[]:
     *   t0[0..n-1]   : scratch for f in FFT
     *   t1[0..n-1]   : scratch for g in FFT
     *   t2[0..n-1]   : scratch for F
     *   t3[0..n-1]   : scratch for G
     *   t4[0..n-1]   : scratch for Babai reduction
     */
    double *t0 = tmp;
    double *t1 = t0 + n;
    double *t2 = t1 + n;
    double *t3 = t2 + n;
    double *t4 = t3 + n;

    /*
     * Step 1: embed F'(x^2) into degree-n polynomial.
     * F'(x^2) has nonzero coefficients only at even indices.
     */
    memset(t2, 0, n * sizeof(double));
    for (i = 0; i < hn; i++)
        t2[2 * i] = (double)Fp[i];

    memset(t3, 0, n * sizeof(double));
    for (i = 0; i < hn; i++)
        t3[2 * i] = (double)Gp[i];

    /*
     * Step 2: multiply by adjoint.
     * f_adj(x) is f evaluated at -x, which flips the sign of odd
     * coefficients: f_adj[i] = (-1)^i * f[i].
     *
     * F(x) = F'(x^2) * f_adj(x)  mod (x^n + 1).
     * But actually the correct lift formula in Falcon is:
     *     F(x) = F'(x^2) * g(-x) / q   ??? No.
     *
     * The standard Falcon lift is:
     *   Let f*(x) = f(-x) (the "adjoint" map).  Then
     *     N(f) = f * f*  in the quotient ring.
     *   If (Fp, Gp) solves  N(f)*Gp - N(g)*Fp = q, then
     *     F = Fp(x^2) * g*    and   G = Gp(x^2) * f*
     *   ... adjusted by Babai reduction.
     *
     * Actually the correct lift (from the Falcon spec) is:
     *     F_lift(x) = Fp(x^2) * adj(g)(x)
     *     G_lift(x) = Gp(x^2) * adj(f)(x)
     * where adj(f)(x) = f(-x) for the ring Z[x]/(x^n+1).
     * Then apply Babai reduction to shrink coefficients.
     */

    /* Build adj(g) and adj(f) in t0, t1. */
    for (i = 0; i < n; i++) {
        t0[i] = (double)g[i] * ((i & 1) ? -1.0 : 1.0);  /* adj(g) */
        t1[i] = (double)f[i] * ((i & 1) ? -1.0 : 1.0);  /* adj(f) */
    }

    /* FFT everything. */
    fndsa_fft_forward(t0, logn);  /* adj(g) */
    fndsa_fft_forward(t1, logn);  /* adj(f) */
    fndsa_fft_forward(t2, logn);  /* Fp(x^2) */
    fndsa_fft_forward(t3, logn);  /* Gp(x^2) */

    /* F_lift = Fp(x^2) * adj(g) */
    fndsa_fft_mul(t2, t0, logn);
    /* G_lift = Gp(x^2) * adj(f) */
    fndsa_fft_mul(t3, t1, logn);

    /* Convert back to coefficient domain. */
    fndsa_fft_inverse(t2, logn);
    fndsa_fft_inverse(t3, logn);

    /* Round to integers. */
    for (i = 0; i < n; i++) {
        F[i] = (int32_t)floor(t2[i] + 0.5);
        G[i] = (int32_t)floor(t3[i] + 0.5);
    }

    /*
     * Step 3: Babai reduction.
     * We reduce (F, G) modulo the lattice basis [[f, g], [F_0, G_0]]
     * where the current (F, G) might have large coefficients.
     *
     * The reduction loop:
     *   Compute k = round( (F*adj(f) + G*adj(g)) / (f*adj(f) + g*adj(g)) )
     *   F -= k*f,  G -= k*g.
     * We iterate until convergence (a few iterations suffice).
     */
    {
        int iter;
        for (iter = 0; iter < 10; iter++) {
            double maxadj = 0.0;

            /* Compute f*adj(f) + g*adj(g) in FFT domain => t4. */
            for (i = 0; i < n; i++)
                t0[i] = (double)f[i];
            fndsa_fft_forward(t0, logn);
            memcpy(t4, t0, n * sizeof(double));
            fndsa_fft_mul_selfadj(t4, logn);

            for (i = 0; i < n; i++)
                t1[i] = (double)g[i];
            fndsa_fft_forward(t1, logn);
            {
                double *t5 = t1;  /* reuse */
                double tmp_arr[FNDSA_MAX_N];
                memcpy(tmp_arr, t1, n * sizeof(double));
                fndsa_fft_mul_selfadj(tmp_arr, logn);
                fndsa_fft_add(t4, tmp_arr, logn);
            }

            /* Compute F*adj(f) + G*adj(g) in FFT domain => t2. */
            for (i = 0; i < n; i++)
                t2[i] = (double)F[i];
            fndsa_fft_forward(t2, logn);

            /* t0 still holds FFT(f). Multiply F by adj(f). */
            fndsa_fft_mul_adj(t2, t0, logn);

            for (i = 0; i < n; i++)
                t3[i] = (double)G[i];
            fndsa_fft_forward(t3, logn);

            /* t1 was reused; recompute FFT(g). */
            for (i = 0; i < n; i++)
                t1[i] = (double)g[i];
            fndsa_fft_forward(t1, logn);

            fndsa_fft_mul_adj(t3, t1, logn);
            fndsa_fft_add(t2, t3, logn);

            /* k = round(t2 / t4). */
            fndsa_fft_div(t2, t4, logn);
            fndsa_fft_inverse(t2, logn);

            /* Round k to integers and subtract k*f from F, k*g from G. */
            {
                int32_t k_poly[FNDSA_MAX_N];
                int any_nonzero = 0;

                for (i = 0; i < n; i++) {
                    int32_t ki = (int32_t)floor(t2[i] + 0.5);
                    k_poly[i] = ki;
                    if (ki != 0) any_nonzero = 1;
                    if (fabs(t2[i]) > maxadj)
                        maxadj = fabs(t2[i]);
                }

                if (!any_nonzero)
                    break;

                /*
                 * F -= k*f, G -= k*g.
                 * Polynomial multiplication mod x^n+1.
                 */
                {
                    int64_t Fnew[FNDSA_MAX_N];
                    int64_t Gnew[FNDSA_MAX_N];
                    size_t j;

                    for (i = 0; i < n; i++) {
                        Fnew[i] = (int64_t)F[i];
                        Gnew[i] = (int64_t)G[i];
                    }

                    for (i = 0; i < n; i++) {
                        if (k_poly[i] == 0) continue;
                        for (j = 0; j < n; j++) {
                            size_t idx = i + j;
                            int64_t kf = (int64_t)k_poly[i] * (int64_t)f[j];
                            int64_t kg = (int64_t)k_poly[i] * (int64_t)g[j];
                            if (idx >= n) {
                                idx -= n;
                                Fnew[idx] += kf;  /* x^n = -1 */
                                Gnew[idx] += kg;
                            } else {
                                Fnew[idx] -= kf;
                                Gnew[idx] -= kg;
                            }
                        }
                    }

                    for (i = 0; i < n; i++) {
                        F[i] = (int32_t)Fnew[i];
                        G[i] = (int32_t)Gnew[i];
                    }
                }
            }
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Recursive NTRU solver                                                */
/* ------------------------------------------------------------------ */

/*
 * Solve f*G - g*F = q mod (x^n + 1) recursively.
 *
 * f, g: input polynomials (int32_t, degree < 2^logn).
 * F, G: output polynomials (int32_t, degree < 2^logn).
 * tmp:  workspace (must have enough space).
 *
 * Returns 0 on success, nonzero on failure (e.g. if gcd != 1).
 */
int
fndsa_solve_ntru(unsigned logn,
                 const int32_t *f, const int32_t *g,
                 int32_t *F, int32_t *G,
                 double *tmp)
{
    size_t n = (size_t)1 << logn;

    if (logn == 0) {
        /*
         * Base case: n = 1.
         * Solve f[0]*G[0] - g[0]*F[0] = q, i.e. a Bezout identity.
         */
        int64_t u, v;
        int64_t d = xgcd((int64_t)f[0], (int64_t)g[0], &u, &v);

        if (d != 1 && d != -1) {
            /* gcd(f[0], g[0]) must be +/-1 for the NTRU equation
             * to have a solution. */
            return -1;
        }

        /* f*v - g*(-u) = d  =>  f*(q*v/d) - g*(-q*u/d) = q. */
        G[0] = (int32_t)((int64_t)FNDSA_Q * v / d);
        F[0] = (int32_t)((int64_t)FNDSA_Q * (-u) / d);
        return 0;
    }

    {
        size_t hn = n >> 1;
        int32_t fp[FNDSA_MAX_N / 2];
        int32_t gp[FNDSA_MAX_N / 2];
        int32_t Fp[FNDSA_MAX_N / 2];
        int32_t Gp[FNDSA_MAX_N / 2];
        int rc;

        /* Compute field norms f' = N(f), g' = N(g). */
        field_norm_small(fp, f, logn);
        field_norm_small(gp, g, logn);

        /* Recursively solve for (Fp, Gp) at half the degree. */
        rc = fndsa_solve_ntru(logn - 1, fp, gp, Fp, Gp, tmp);
        if (rc != 0)
            return rc;

        /* Lift (Fp, Gp) to (F, G) at the full degree. */
        return ntru_lift(logn, f, g, F, G, Fp, Gp, tmp);
    }
}
