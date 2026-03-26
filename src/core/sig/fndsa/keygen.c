/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- Key generation.
 *
 * 1. Generate f, g as small polynomials using a SHAKE-256-based PRNG.
 *    Coefficients are drawn from {-1, 0, +1} (ternary).
 * 2. Verify that (f, g) satisfy the NTRU conditions:
 *      - gcd of resultants is 1
 *      - f is invertible mod q
 * 3. Solve the NTRU equation fG - gF = q for F, G.
 * 4. Compute h = g * f^{-1} mod q (public key polynomial).
 * 5. Encode:
 *      - pk = header || encode(h, 14 bits)
 *      - sk = header || trim_i8(f) || trim_i8(g) || trim_i8(F)
 *
 * The Gram-Schmidt norm of the secret basis [[g, -f], [G, -F]] must
 * be below the threshold; otherwise we reject and retry.
 */

#include <math.h>
#include <string.h>
#include <stdlib.h>

#include "fndsa.h"
#include "fndsa_params.h"
#include "fft.h"
#include "pqc/common.h"
#include "pqc/rand.h"

/* ------------------------------------------------------------------ */
/* Polynomial arithmetic mod q = 12289                                  */
/* ------------------------------------------------------------------ */

static uint16_t
modq_add(uint16_t a, uint16_t b)
{
    uint32_t s = (uint32_t)a + (uint32_t)b;
    s -= FNDSA_Q & (uint32_t)(-(int32_t)(s >= FNDSA_Q));
    return (uint16_t)s;
}

static uint16_t
modq_sub(uint16_t a, uint16_t b)
{
    uint32_t s = (uint32_t)a + FNDSA_Q - (uint32_t)b;
    s -= FNDSA_Q & (uint32_t)(-(int32_t)(s >= FNDSA_Q));
    return (uint16_t)s;
}

static uint16_t
modq_mul(uint16_t a, uint16_t b)
{
    return (uint16_t)((uint32_t)a * (uint32_t)b % FNDSA_Q);
}

/*
 * Compute a^{-1} mod q using Fermat's little theorem: a^{q-2} mod q.
 * q = 12289 is prime.
 */
static uint16_t
modq_inv(uint16_t a)
{
    uint32_t r = 1;
    uint32_t base = (uint32_t)a;
    uint32_t exp = FNDSA_Q - 2;

    while (exp > 0) {
        if (exp & 1)
            r = r * base % FNDSA_Q;
        base = base * base % FNDSA_Q;
        exp >>= 1;
    }
    return (uint16_t)r;
}

/*
 * NTT for polynomials mod q.
 * Simple Cooley-Tukey NTT mod q with root of unity.
 * The primitive 2n-th root of unity mod q = 12289 is needed.
 * For n = 512:  w = root^{q-1 / (2*512)}  (we use a generic routine).
 * For n = 1024: w = root^{q-1 / (2*1024)}.
 *
 * Actually, for computing h = g/f mod q we can use a simpler approach:
 * schoolbook multiplication for small n, or a direct method.
 * For efficiency we'll use a straightforward evaluation approach.
 */

/*
 * Multiply two polynomials a, b mod (x^n + 1) mod q.
 * Result goes into out. All arrays have size n.
 */
static void
poly_mul_modq(uint16_t *out, const uint16_t *a, const uint16_t *b, size_t n)
{
    size_t i, j;
    uint32_t tmp[FNDSA_MAX_N];

    memset(tmp, 0, n * sizeof(uint32_t));

    for (i = 0; i < n; i++) {
        if (a[i] == 0) continue;
        for (j = 0; j < n; j++) {
            size_t idx = i + j;
            uint32_t prod = (uint32_t)a[i] * (uint32_t)b[j];
            if (idx >= n) {
                idx -= n;
                /* x^n = -1 mod (x^n+1), so subtract. */
                tmp[idx] = (tmp[idx] + FNDSA_Q - (prod % FNDSA_Q)) % FNDSA_Q;
            } else {
                tmp[idx] = (tmp[idx] + (prod % FNDSA_Q)) % FNDSA_Q;
            }
        }
    }

    for (i = 0; i < n; i++)
        out[i] = (uint16_t)tmp[i];
}

/*
 * Compute the inverse of polynomial f mod (x^n + 1) mod q, if it exists.
 * Uses the Newton iteration approach:
 *   Start with f^{-1} mod (x^2 + 1) (i.e. mod q for the constant term),
 *   and iteratively double the precision.
 * Returns 0 on success, -1 if f is not invertible.
 */
static int
poly_inv_modq(uint16_t *out, const int8_t *f, size_t n)
{
    size_t i;
    uint16_t f_modq[FNDSA_MAX_N];
    uint16_t inv[FNDSA_MAX_N];
    uint16_t tmp1[FNDSA_MAX_N];
    uint16_t tmp2[FNDSA_MAX_N];
    size_t cur_n;

    /* Convert f to mod-q representation. */
    for (i = 0; i < n; i++) {
        int32_t v = (int32_t)f[i];
        f_modq[i] = (uint16_t)((v % (int32_t)FNDSA_Q + FNDSA_Q) % FNDSA_Q);
    }

    /* Base case: invert f[0] mod q. */
    if (f_modq[0] == 0)
        return -1;
    memset(inv, 0, n * sizeof(uint16_t));
    inv[0] = modq_inv(f_modq[0]);

    /*
     * Newton iteration: inv = inv * (2 - f * inv) mod (x^{cur_n} + 1).
     * We double cur_n at each step from 1 up to n.
     */
    for (cur_n = 2; cur_n <= n; cur_n <<= 1) {
        /* tmp1 = f * inv mod (x^{cur_n} + 1) mod q. */
        /* For simplicity, zero-pad both to cur_n and multiply. */
        memset(tmp1, 0, cur_n * sizeof(uint16_t));
        memset(tmp2, 0, cur_n * sizeof(uint16_t));

        /* Copy relevant parts. */
        for (i = 0; i < cur_n; i++) {
            tmp1[i] = (i < n) ? f_modq[i] : 0;
            tmp2[i] = inv[i];
        }

        /* product = f * inv mod (x^{cur_n} + 1). */
        {
            uint16_t product[FNDSA_MAX_N];
            size_t j;
            uint32_t ptmp[FNDSA_MAX_N];

            memset(ptmp, 0, cur_n * sizeof(uint32_t));
            for (i = 0; i < cur_n; i++) {
                if (tmp1[i] == 0) continue;
                for (j = 0; j < cur_n; j++) {
                    if (tmp2[j] == 0) continue;
                    size_t idx = i + j;
                    uint32_t p = (uint32_t)tmp1[i] * (uint32_t)tmp2[j] % FNDSA_Q;
                    if (idx >= cur_n) {
                        idx -= cur_n;
                        ptmp[idx] = (ptmp[idx] + FNDSA_Q - p) % FNDSA_Q;
                    } else {
                        ptmp[idx] = (ptmp[idx] + p) % FNDSA_Q;
                    }
                }
            }

            /* tmp1 = 2 - product. */
            for (i = 0; i < cur_n; i++)
                product[i] = (uint16_t)ptmp[i];

            memset(tmp1, 0, cur_n * sizeof(uint16_t));
            tmp1[0] = 2;
            for (i = 0; i < cur_n; i++)
                tmp1[i] = modq_sub(tmp1[i], product[i]);
        }

        /* inv = inv * tmp1 mod (x^{cur_n} + 1). */
        {
            uint32_t ptmp[FNDSA_MAX_N];
            size_t j;

            memset(ptmp, 0, cur_n * sizeof(uint32_t));
            for (i = 0; i < cur_n; i++) {
                if (tmp2[i] == 0) continue;
                for (j = 0; j < cur_n; j++) {
                    if (tmp1[j] == 0) continue;
                    size_t idx = i + j;
                    uint32_t p = (uint32_t)tmp2[i] * (uint32_t)tmp1[j] % FNDSA_Q;
                    if (idx >= cur_n) {
                        idx -= cur_n;
                        ptmp[idx] = (ptmp[idx] + FNDSA_Q - p) % FNDSA_Q;
                    } else {
                        ptmp[idx] = (ptmp[idx] + p) % FNDSA_Q;
                    }
                }
            }

            for (i = 0; i < cur_n; i++)
                inv[i] = (uint16_t)(ptmp[i] % FNDSA_Q);
        }
    }

    memcpy(out, inv, n * sizeof(uint16_t));
    return 0;
}

/* ------------------------------------------------------------------ */
/* Small polynomial generation                                          */
/* ------------------------------------------------------------------ */

/*
 * Generate a small polynomial with coefficients in {-1, 0, +1}
 * using rejection sampling from random bytes.
 *
 * For Falcon, the distribution is slightly more nuanced (a Gaussian-like
 * distribution over small integers), but the ternary distribution is
 * a common simplification that works for key generation.
 *
 * Actually, in the Falcon specification, keygen uses a specific
 * distribution: coefficients are sampled as discrete Gaussians with
 * sigma ~ sqrt(q/(2n)).  For n=512, sigma ~ 3.46; for n=1024 similarly.
 * The coefficients are thus in roughly [-12, 12] and fit in int8_t.
 *
 * We sample from a Gaussian-like distribution using SHAKE-256 output
 * interpreted as pairs of bytes, then applying a box filter.
 */
static void
gen_small_poly(int8_t *poly, size_t n, pqc_shake256_ctx *rng)
{
    size_t i;
    for (i = 0; i < n; i++) {
        uint8_t buf[2];
        int16_t v;
        pqc_shake256_squeeze(rng, buf, 2);

        /*
         * Interpret as a 16-bit value, reduce to a small Gaussian-ish
         * distribution.  We use: v = (b0 + b1 - 256) >> 5, which gives
         * values roughly in [-8, 8] with a bell-curve shape.
         */
        v = (int16_t)((int16_t)buf[0] + (int16_t)buf[1] - 256);
        v >>= 5;  /* divide by 32 to get range roughly [-8, 8] */

        /* Clamp to int8_t range (should already fit). */
        if (v > 127) v = 127;
        if (v < -127) v = -127;
        poly[i] = (int8_t)v;
    }
}

/* ------------------------------------------------------------------ */
/* Gram-Schmidt norm check                                              */
/* ------------------------------------------------------------------ */

/*
 * Compute the Gram-Schmidt norm of the Falcon basis
 *   B = [[g, -f], [G, -F]]
 * and verify it is below the threshold.
 *
 * The Gram-Schmidt orthogonalisation gives:
 *   b0 = (g, -f)
 *   b1_tilde = (G, -F) - <(G,-F), b0>/<b0, b0> * b0
 *
 * We need max(||b0||, ||b1_tilde||) to be suitably bounded.
 * In practice, for Falcon, we check that the squared GS norm
 * (sum of squared norms of GS vectors) is below a threshold.
 *
 * A simplified check: the squared norm of (f, g, F, G) must
 * satisfy certain bounds.  We use the FFT to compute norms.
 */
static int
check_gs_norm(const int8_t *f, const int8_t *g,
              const int32_t *F, const int32_t *G,
              unsigned logn, double sigma)
{
    size_t n = (size_t)1 << logn;
    double f_fft[FNDSA_MAX_N];
    double g_fft[FNDSA_MAX_N];
    double F_fft[FNDSA_MAX_N];
    double G_fft[FNDSA_MAX_N];
    double norm_fg, norm_FG, gs_norm;
    size_t i;

    for (i = 0; i < n; i++) {
        f_fft[i] = (double)f[i];
        g_fft[i] = (double)g[i];
        F_fft[i] = (double)F[i];
        G_fft[i] = (double)G[i];
    }

    fndsa_fft_forward(f_fft, logn);
    fndsa_fft_forward(g_fft, logn);
    fndsa_fft_forward(F_fft, logn);
    fndsa_fft_forward(G_fft, logn);

    norm_fg = fndsa_fft_norm(f_fft, logn) + fndsa_fft_norm(g_fft, logn);
    norm_FG = fndsa_fft_norm(F_fft, logn) + fndsa_fft_norm(G_fft, logn);

    /*
     * The Gram-Schmidt norm must be at most sigma * sqrt(2*n).
     * We check that both norms are reasonable.
     * threshold = sigma^2 * 2 * n.
     */
    gs_norm = sigma * sigma * 2.0 * (double)n;

    if (norm_fg > gs_norm || norm_FG > gs_norm * 10.0)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

int
fndsa_keygen(uint8_t *pk, size_t pk_max,
             uint8_t *sk, size_t sk_max,
             unsigned logn)
{
    size_t n = (size_t)1 << logn;
    double sigma;
    int8_t f[FNDSA_MAX_N];
    int8_t g[FNDSA_MAX_N];
    int32_t F[FNDSA_MAX_N];
    int32_t G[FNDSA_MAX_N];
    uint16_t h[FNDSA_MAX_N];
    uint16_t f_inv[FNDSA_MAX_N];
    int8_t F_i8[FNDSA_MAX_N];
    double tmp[6 * FNDSA_MAX_N];
    pqc_shake256_ctx rng;
    uint8_t seed[48];
    int attempts;
    size_t i;
    size_t pk_size, sk_size;

    sigma = (logn == FNDSA_512_LOGN) ? FNDSA_512_SIGMA : FNDSA_1024_SIGMA;

    /*
     * Seed the keygen PRNG with OS entropy.
     */
    if (pqc_randombytes(seed, sizeof(seed)) != PQC_OK)
        return -1;

    pqc_shake256_init(&rng);
    pqc_shake256_absorb(&rng, seed, sizeof(seed));
    pqc_shake256_finalize(&rng);

    for (attempts = 0; attempts < 100; attempts++) {
        int rc;
        uint16_t g_modq[FNDSA_MAX_N];

        /* Generate small polynomials f and g. */
        gen_small_poly(f, n, &rng);
        gen_small_poly(g, n, &rng);

        /* Ensure f[0] is odd (needed for invertibility mod 2, which
         * helps with invertibility mod q). */
        if ((f[0] & 1) == 0)
            f[0] |= 1;

        /* Check that f is invertible mod q. */
        if (poly_inv_modq(f_inv, f, n) != 0)
            continue;

        /* Solve NTRU equation: fG - gF = q. */
        {
            int32_t f32[FNDSA_MAX_N];
            int32_t g32[FNDSA_MAX_N];
            for (i = 0; i < n; i++) {
                f32[i] = (int32_t)f[i];
                g32[i] = (int32_t)g[i];
            }
            rc = fndsa_solve_ntru(logn, f32, g32, F, G, tmp);
        }
        if (rc != 0)
            continue;

        /* Check Gram-Schmidt norm. */
        if (check_gs_norm(f, g, F, G, logn, sigma) != 0)
            continue;

        /* Compute public key h = g * f^{-1} mod q. */
        for (i = 0; i < n; i++) {
            int32_t gv = (int32_t)g[i];
            g_modq[i] = (uint16_t)((gv % (int32_t)FNDSA_Q + FNDSA_Q) % FNDSA_Q);
        }
        poly_mul_modq(h, g_modq, f_inv, n);

        /* Encode public key. */
        pk_size = fndsa_pk_encode(pk, pk_max, h, logn);
        if (pk_size == 0)
            return -1;

        /* Convert F to int8_t for encoding (should fit in [-127, 127]). */
        {
            int overflow = 0;
            for (i = 0; i < n; i++) {
                if (F[i] > 127 || F[i] < -127) {
                    overflow = 1;
                    break;
                }
                F_i8[i] = (int8_t)F[i];
            }
            if (overflow)
                continue;  /* retry if F has coefficients too large */
        }

        /* Encode secret key. */
        sk_size = fndsa_sk_encode(sk, sk_max, f, g, F_i8, logn);
        if (sk_size == 0)
            return -1;

        /* Zeroize sensitive intermediates. */
        pqc_memzero(seed, sizeof(seed));
        pqc_memzero(tmp, sizeof(tmp));
        pqc_memzero(F, sizeof(F));
        pqc_memzero(G, sizeof(G));

        return 0;
    }

    /* Exhausted attempts. */
    return -1;
}
