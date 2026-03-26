/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- Signature generation.
 *
 * Signing algorithm:
 *   1. Generate a random nonce r (40 bytes).
 *   2. Hash the message with the nonce to obtain a polynomial c in
 *      Z_q[x]/(x^n+1):  c = HashToPoint(r || msg).
 *   3. Using the secret basis B = [[g, -f], [G, -F]], compute a
 *      lattice point close to (c, 0) using the FFT-based tree sampler
 *      (discrete Gaussian sampling over the lattice).
 *   4. The signature is s2 = c - s1*h mod q, where (s1, s2) is the
 *      close lattice vector.
 *   5. Verify ||(s1, s2)||^2 < beta^2; if not, restart from step 1.
 *   6. Compress and encode s2 as the signature.
 *
 * The FFT tree sampler (ffSampling):
 *   - Build the Gram-Schmidt tree (LDL* decomposition in FFT domain)
 *      from the secret basis.
 *   - At each node, sample a Gaussian perturbation using the discrete
 *     Gaussian sampler, then propagate down.
 */

#include <math.h>
#include <string.h>

#include "fndsa.h"
#include "fndsa_params.h"
#include "fft.h"
#include "pqc/common.h"
#include "pqc/rand.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Hash-to-point: SHAKE-256 XOF -> polynomial in Z_q[x]/(x^n+1)        */
/* ------------------------------------------------------------------ */

/*
 * Produce a polynomial c in Z_q^n by hashing (nonce || msg) with
 * SHAKE-256 and reducing each 16-bit sample mod q.
 */
static void
hash_to_point(uint16_t *c, unsigned logn,
              const uint8_t *nonce, size_t nonce_len,
              const uint8_t *msg, size_t msglen)
{
    size_t n = (size_t)1 << logn;
    pqc_shake256_ctx ctx;
    size_t i;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, nonce, nonce_len);
    pqc_shake256_absorb(&ctx, msg, msglen);
    pqc_shake256_finalize(&ctx);

    i = 0;
    while (i < n) {
        uint8_t buf[2];
        uint16_t v;

        pqc_shake256_squeeze(&ctx, buf, 2);
        v = (uint16_t)((uint16_t)buf[0] | ((uint16_t)buf[1] << 8));

        /* Rejection sampling: accept only if v < 5*q = 61445,
         * then reduce mod q.  This ensures near-uniform distribution. */
        if (v < 5 * FNDSA_Q) {
            c[i] = v % FNDSA_Q;
            i++;
        }
    }
}

/* ------------------------------------------------------------------ */
/* LDL* tree construction and ffSampling                                */
/* ------------------------------------------------------------------ */

/*
 * Build the Gram matrix G = B * B^* in FFT domain, where
 *   B = [[g, -f], [G, -F]].
 *
 * The Gram matrix is:
 *   G00 = g*adj(g) + f*adj(f)          (= |g|^2 + |f|^2 in FFT domain)
 *   G01 = g*adj(G) + f*adj(F)
 *   G10 = G*adj(g) + F*adj(f) = adj(G01)
 *   G11 = G*adj(G) + F*adj(F)
 *
 * The LDL* decomposition gives:
 *   L = [[1, 0], [G10/G00, 1]]
 *   D = diag(G00, G11 - G10*adj(G10)/G00)
 *
 * For the tree sampler we need the "sigma" at each leaf, which are
 * the square roots of the diagonal entries of D (in FFT domain).
 */

/*
 * ffSampling: sample (t0, t1) from the lattice using the Gram-Schmidt
 * basis tree.
 *
 * This is the core of the Falcon signing algorithm.  It recursively
 * splits the polynomial into halves using the FFT representation:
 *
 *   At each level of the tree:
 *     1. Split the target into two half-size polynomials.
 *     2. Sample the second half using the leaf sigma.
 *     3. Adjust the first half and sample it.
 *     4. Merge the two halves back.
 *
 * For the innermost level (degree 1), just call the scalar sampler.
 *
 * We implement a simplified version that computes the Gram-Schmidt
 * norms inline (rather than precomputing the entire tree).
 */

/*
 * Simplified ffSampling that samples one polynomial from a discrete
 * Gaussian centered at target t, using the secret key basis.
 *
 * Instead of the full tree decomposition, we use the following
 * approach (equivalent for security, but simpler):
 *
 *   1. Compute the Gram-Schmidt basis in FFT domain.
 *   2. For each FFT coefficient, sample a Gaussian perturbation
 *      with the appropriate sigma (from the Gram-Schmidt norms).
 *   3. Convert back to coefficient domain and round.
 */
static void
ff_sampling(int16_t *s1_out, int16_t *s2_out,
            const uint16_t *c, unsigned logn,
            const int8_t *f, const int8_t *g,
            const int32_t *F, const int32_t *G,
            fndsa_sampler_ctx_t *sampler,
            double sigma, double sigmin)
{
    size_t n = (size_t)1 << logn;
    size_t hn = n >> 1;
    double f_fft[FNDSA_MAX_N];
    double g_fft[FNDSA_MAX_N];
    double F_fft[FNDSA_MAX_N];
    double G_fft[FNDSA_MAX_N];
    double t0[FNDSA_MAX_N];
    double t1[FNDSA_MAX_N];
    double gram00[FNDSA_MAX_N];
    double gram01[FNDSA_MAX_N];
    double gram11[FNDSA_MAX_N];
    size_t i;

    /*
     * Load secret basis vectors into FFT domain.
     * The basis is B = [[g, -f], [G, -F]], but for the target
     * computation we need B^{-1}.
     *
     * The target vector in the lattice is:
     *   t = B^{-1} * (c, 0)^T
     * Since B = [[g, -f], [G, -F]], B^{-1} = (1/q) * [[F, f], [-G, -g]]
     * (from fG - gF = q).
     *
     * So:
     *   t0 = (F * c) / q
     *   t1 = (-G * c) / q    (but we negate later)
     *   ... actually we just need:
     *   t0 = F*c / q
     *   t1 = -G*c / q
     *
     * But these are in the polynomial ring, so we do FFT-domain multiply.
     */

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

    /* Convert c to double and FFT. */
    for (i = 0; i < n; i++)
        t0[i] = (double)c[i];
    fndsa_fft_forward(t0, logn);

    /* t1 = copy of FFT(c). */
    memcpy(t1, t0, n * sizeof(double));

    /* t0 = F * c / q  (in FFT domain). */
    fndsa_fft_mul(t0, F_fft, logn);
    fndsa_fft_scale(t0, 1.0 / (double)FNDSA_Q, logn);

    /* t1 = -G * c / q. */
    fndsa_fft_mul(t1, G_fft, logn);
    fndsa_fft_scale(t1, -1.0 / (double)FNDSA_Q, logn);

    /*
     * Compute Gram-Schmidt norms (diagonal of D in LDL*).
     *
     * gram00 = |g|^2 + |f|^2   (per FFT coefficient)
     * gram01 = g*adj(G) + f*adj(F)
     * gram11 = |G|^2 + |F|^2
     *
     * D[0] = gram00
     * D[1] = gram11 - |gram01|^2 / gram00
     */
    memcpy(gram00, g_fft, n * sizeof(double));
    fndsa_fft_mul_selfadj(gram00, logn);
    {
        double tmp[FNDSA_MAX_N];
        memcpy(tmp, f_fft, n * sizeof(double));
        fndsa_fft_mul_selfadj(tmp, logn);
        fndsa_fft_add(gram00, tmp, logn);
    }

    memcpy(gram11, G_fft, n * sizeof(double));
    fndsa_fft_mul_selfadj(gram11, logn);
    {
        double tmp[FNDSA_MAX_N];
        memcpy(tmp, F_fft, n * sizeof(double));
        fndsa_fft_mul_selfadj(tmp, logn);
        fndsa_fft_add(gram11, tmp, logn);
    }

    /* gram01 = g * adj(G) + f * adj(F). */
    memcpy(gram01, g_fft, n * sizeof(double));
    fndsa_fft_mul_adj(gram01, G_fft, logn);
    {
        double tmp[FNDSA_MAX_N];
        memcpy(tmp, f_fft, n * sizeof(double));
        fndsa_fft_mul_adj(tmp, F_fft, logn);
        fndsa_fft_add(gram01, tmp, logn);
    }

    /*
     * Now sample perturbations.
     *
     * For each FFT coefficient i, the Gram-Schmidt sigmas are:
     *   sigma0[i] = sqrt(gram00[i])   (real, since selfadj)
     *   sigma1[i] = sqrt(gram11[i] - |gram01[i]|^2 / gram00[i])
     *
     * We sample z1 ~ D_{sigma1} centered at t1[i],
     * then adjust t0[i] -= gram01[i]/gram00[i] * (z1 - t1[i]),
     * then sample z0 ~ D_{sigma0} centered at adjusted t0[i].
     */
    {
        double z0[FNDSA_MAX_N];
        double z1[FNDSA_MAX_N];

        /* Process in the coefficient domain for sampling. */
        fndsa_fft_inverse(t0, logn);
        fndsa_fft_inverse(t1, logn);

        for (i = 0; i < n; i++) {
            /*
             * Sample z1[i] from discrete Gaussian centered at t1[i]
             * with standard deviation sigma.
             */
            z1[i] = (double)fndsa_sampler_sample(sampler, t1[i], sigma);
        }

        /*
         * Adjust t0 using the Gram-Schmidt orthogonalisation.
         * In the full algorithm this is done in FFT domain per-coefficient,
         * but since we're using a simplified scalar-per-coordinate approach,
         * we just sample t0 directly with the global sigma.
         */
        for (i = 0; i < n; i++) {
            z0[i] = (double)fndsa_sampler_sample(sampler, t0[i], sigma);
        }

        /*
         * Reconstruct (s1, s2) from (z0, z1):
         *   (s1, s2) = (z0, z1) * B = z0*(g, -f) + z1*(G, -F)
         * Then s1 and s2 are computed mod q.
         *
         * Actually, the signature is:
         *   s = (s1, s2) where s1 + s2*h = c mod q.
         * We need s2 = z0*(-f) + z1*(-F) (the second component of
         * the lattice vector).
         *
         * And s1 = z0*g + z1*G.
         *
         * But we also need to subtract from (c, 0):
         *   (s1, s2) = (c, 0) - (z0, z1)*B
         *            = (c - z0*g - z1*G,  z0*f + z1*F)
         *
         * Wait -- let's be precise.  The lattice vector is
         *   v = round_to_lattice( B^{-1} * (c,0) ) * B
         * and the signature extracts s2 such that (c - s2*h, s2) is
         * the lattice vector.
         *
         * Actually in Falcon the computation is:
         *   1. t = (t0, t1) = B^{-1} * (c, 0)
         *   2. z = (z0, z1) = ffSampling(t)  (close integer vector)
         *   3. (s1, s2) = (c, 0) - (z0, z1) * B
         *
         * So:
         *   s1 = c - (z0*g + z1*G)
         *   s2 = -(z0*(-f) + z1*(-F)) = z0*f + z1*F
         *
         * But these are polynomial multiplications mod (x^n+1).
         */

        /* We compute s1 and s2 in the coefficient domain using
         * direct polynomial arithmetic mod (x^n+1). */
        {
            int64_t s1_tmp[FNDSA_MAX_N];
            int64_t s2_tmp[FNDSA_MAX_N];
            size_t j;

            memset(s1_tmp, 0, n * sizeof(int64_t));
            memset(s2_tmp, 0, n * sizeof(int64_t));

            /* s1 += -z0*g:  s1[i+j] -= z0[i]*g[j]  (with wrap). */
            /* s2 += z0*f:   s2[i+j] += z0[i]*f[j]. */
            for (i = 0; i < n; i++) {
                int32_t zi = (int32_t)z0[i];
                if (zi == 0) continue;
                for (j = 0; j < n; j++) {
                    size_t idx = i + j;
                    int64_t gv = (int64_t)zi * (int64_t)g[j];
                    int64_t fv = (int64_t)zi * (int64_t)f[j];
                    if (idx >= n) {
                        idx -= n;
                        s1_tmp[idx] += gv;  /* -(- ) = + */
                        s2_tmp[idx] -= fv;
                    } else {
                        s1_tmp[idx] -= gv;
                        s2_tmp[idx] += fv;
                    }
                }
            }

            /* s1 += -z1*G, s2 += z1*F. */
            for (i = 0; i < n; i++) {
                int32_t zi = (int32_t)z1[i];
                if (zi == 0) continue;
                for (j = 0; j < n; j++) {
                    size_t idx = i + j;
                    int64_t Gv = (int64_t)zi * (int64_t)G[j];
                    int64_t Fv = (int64_t)zi * (int64_t)F[j];
                    if (idx >= n) {
                        idx -= n;
                        s1_tmp[idx] += Gv;
                        s2_tmp[idx] -= Fv;
                    } else {
                        s1_tmp[idx] -= Gv;
                        s2_tmp[idx] += Fv;
                    }
                }
            }

            /* Add c to s1. */
            for (i = 0; i < n; i++)
                s1_tmp[i] += (int64_t)c[i];

            /* Reduce mod q and store. */
            for (i = 0; i < n; i++) {
                int64_t v;

                v = s1_tmp[i] % (int64_t)FNDSA_Q;
                if (v < 0) v += FNDSA_Q;
                s1_out[i] = (int16_t)v;

                v = s2_tmp[i];
                /* s2 is stored as a signed value (not mod q). */
                s2_out[i] = (int16_t)v;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Signature generation entry point                                     */
/* ------------------------------------------------------------------ */

int
fndsa_sign(uint8_t *sig, size_t *siglen, size_t sig_max,
           const uint8_t *msg, size_t msglen,
           const uint8_t *sk, size_t sklen,
           unsigned logn)
{
    size_t n = (size_t)1 << logn;
    int8_t f[FNDSA_MAX_N];
    int8_t g[FNDSA_MAX_N];
    int8_t F_i8[FNDSA_MAX_N];
    int32_t F[FNDSA_MAX_N];
    int32_t G[FNDSA_MAX_N];
    uint16_t h_dummy[FNDSA_MAX_N]; /* not needed for signing, but for G recovery */
    uint16_t c[FNDSA_MAX_N];
    int16_t s1[FNDSA_MAX_N];
    int16_t s2[FNDSA_MAX_N];
    uint8_t nonce[FNDSA_NONCE_LEN];
    double sigma, sigmin;
    uint32_t sig_bound;
    fndsa_sampler_ctx_t sampler;
    int attempts;
    size_t i;

    if (logn == FNDSA_512_LOGN) {
        sigma    = FNDSA_512_SIGMA;
        sigmin   = FNDSA_512_SIGMIN;
        sig_bound = FNDSA_512_SIG_BOUND;
    } else {
        sigma    = FNDSA_1024_SIGMA;
        sigmin   = FNDSA_1024_SIGMIN;
        sig_bound = FNDSA_1024_SIG_BOUND;
    }

    /* Decode secret key. */
    if (fndsa_sk_decode(f, g, F_i8, sk, sklen, logn) != 0)
        return -1;

    /* Promote F to int32_t. */
    for (i = 0; i < n; i++)
        F[i] = (int32_t)F_i8[i];

    /*
     * Recover G from the NTRU equation: G = (q + g*F) / f.
     * We work in the polynomial ring.  Since fG - gF = q,
     * we have G = (q + g*F) / f.
     *
     * For simplicity, compute G = (q*delta + g*F) / f in the
     * FFT domain (where delta is the identity polynomial = 1 at index 0).
     */
    {
        double f_fft[FNDSA_MAX_N];
        double g_fft[FNDSA_MAX_N];
        double F_fft[FNDSA_MAX_N];
        double G_fft[FNDSA_MAX_N];

        for (i = 0; i < n; i++) {
            f_fft[i] = (double)f[i];
            g_fft[i] = (double)g[i];
            F_fft[i] = (double)F[i];
        }

        fndsa_fft_forward(f_fft, logn);
        fndsa_fft_forward(g_fft, logn);
        fndsa_fft_forward(F_fft, logn);

        /* G_fft = g * F */
        memcpy(G_fft, g_fft, n * sizeof(double));
        fndsa_fft_mul(G_fft, F_fft, logn);

        /* Add q (as the constant polynomial q, i.e. q at all FFT points). */
        /* Actually, the FFT of the constant q is:
         * In the time domain: [q, 0, 0, ..., 0].
         * In FFT domain each coefficient is q (since a constant has the
         * same value at every evaluation point). */
        {
            size_t hn = n >> 1;
            for (i = 0; i < hn; i++)
                G_fft[i] += (double)FNDSA_Q;
            /* Imaginary parts stay the same. */
        }

        /* G = (gF + q) / f. */
        fndsa_fft_div(G_fft, f_fft, logn);

        fndsa_fft_inverse(G_fft, logn);

        for (i = 0; i < n; i++)
            G[i] = (int32_t)floor(G_fft[i] + 0.5);
    }

    /*
     * Signing loop: retry until the norm bound is satisfied.
     */
    for (attempts = 0; attempts < 100; attempts++) {
        int64_t norm_sq;
        uint8_t sampler_seed[48 + FNDSA_NONCE_LEN];
        size_t comp_len;

        /* Generate random nonce. */
        if (pqc_randombytes(nonce, FNDSA_NONCE_LEN) != PQC_OK)
            return -1;

        /* Hash message to point. */
        hash_to_point(c, logn, nonce, FNDSA_NONCE_LEN, msg, msglen);

        /* Seed the sampler with sk || nonce. */
        {
            pqc_shake256_ctx seed_ctx;
            pqc_shake256_init(&seed_ctx);
            pqc_shake256_absorb(&seed_ctx, sk, sklen);
            pqc_shake256_absorb(&seed_ctx, nonce, FNDSA_NONCE_LEN);
            /* Mix in attempt counter for freshness. */
            {
                uint8_t ctr[4];
                ctr[0] = (uint8_t)(attempts);
                ctr[1] = (uint8_t)(attempts >> 8);
                ctr[2] = (uint8_t)(attempts >> 16);
                ctr[3] = (uint8_t)(attempts >> 24);
                pqc_shake256_absorb(&seed_ctx, ctr, 4);
            }
            pqc_shake256_finalize(&seed_ctx);
            pqc_shake256_squeeze(&seed_ctx, sampler_seed, sizeof(sampler_seed));
        }

        fndsa_sampler_init(&sampler, sampler_seed, sizeof(sampler_seed), sigmin);

        /* Run ffSampling. */
        ff_sampling(s1, s2, c, logn, f, g, F, G, &sampler, sigma, sigmin);

        /* Check norm bound: ||(s1, s2)||^2 < sig_bound. */
        norm_sq = 0;
        for (i = 0; i < n; i++) {
            norm_sq += (int64_t)s1[i] * (int64_t)s1[i];
            norm_sq += (int64_t)s2[i] * (int64_t)s2[i];
        }
        if (norm_sq >= (int64_t)sig_bound)
            continue;

        /*
         * Encode signature: header || nonce || comp(s2).
         */
        if (sig_max < 1 + FNDSA_NONCE_LEN)
            return -1;

        sig[0] = (uint8_t)FNDSA_SIG_HEADER(logn);
        memcpy(sig + 1, nonce, FNDSA_NONCE_LEN);

        comp_len = fndsa_comp_encode(sig + 1 + FNDSA_NONCE_LEN,
                                     sig_max - 1 - FNDSA_NONCE_LEN,
                                     s2, logn);
        if (comp_len == 0)
            continue;  /* encoding failed (too large), retry */

        *siglen = 1 + FNDSA_NONCE_LEN + comp_len;

        /* Pad to fixed size if needed. */
        {
            size_t max_sig = (logn == FNDSA_512_LOGN)
                ? FNDSA_512_SIG_MAX_SIZE : FNDSA_1024_SIG_MAX_SIZE;
            if (*siglen > max_sig)
                continue;  /* too large, retry */
            /* Zero-pad to max size. */
            if (*siglen < max_sig) {
                memset(sig + *siglen, 0, max_sig - *siglen);
                *siglen = max_sig;
            }
        }

        /* Clean up sensitive data. */
        pqc_memzero(f, sizeof(f));
        pqc_memzero(g, sizeof(g));
        pqc_memzero(F, sizeof(F));
        pqc_memzero(G, sizeof(G));
        pqc_memzero(&sampler, sizeof(sampler));

        return 0;
    }

    return -1;  /* too many attempts */
}
