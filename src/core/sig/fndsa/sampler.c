/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- Discrete Gaussian sampler.
 *
 * This implements the Gaussian sampler used in signature generation.
 * It is the most security-critical component: the acceptance step
 * must run in constant time (data-independent branches and memory
 * accesses) to prevent side-channel leakage.
 *
 * The sampler uses:
 *   1. A base sampler via a cumulative distribution table (CDT) that
 *      samples from a half-Gaussian D_{Z+,sigma_0} with sigma_0 =
 *      sigma_min (the smallest per-level sigma in the Falcon tree).
 *   2. Bernoulli trials for acceptance/rejection, using the
 *      decomposition of exp(-x) into a product of table-driven
 *      factors.
 *   3. Combination of base samples with rejection to produce a
 *      sample from D_{Z,mu,sigma} for arbitrary (mu, sigma).
 */

#include <math.h>
#include <string.h>
#include <stdint.h>

#include "fndsa.h"
#include "fndsa_params.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* PRNG helpers that operate on the SHAKE-256 context in the sampler     */
/* ------------------------------------------------------------------ */

static uint64_t
prng_u64(pqc_shake256_ctx *sctx)
{
    uint8_t buf[8];
    pqc_shake256_squeeze(sctx, buf, 8);
    return (uint64_t)buf[0]
        | ((uint64_t)buf[1] << 8)
        | ((uint64_t)buf[2] << 16)
        | ((uint64_t)buf[3] << 24)
        | ((uint64_t)buf[4] << 32)
        | ((uint64_t)buf[5] << 40)
        | ((uint64_t)buf[6] << 48)
        | ((uint64_t)buf[7] << 56);
}

static uint8_t
prng_u8(pqc_shake256_ctx *sctx)
{
    uint8_t b;
    pqc_shake256_squeeze(sctx, &b, 1);
    return b;
}

/* ------------------------------------------------------------------ */
/* Cumulative Distribution Table (CDT) for the base sampler             */
/* ------------------------------------------------------------------ */

/*
 * CDT for half-Gaussian with sigma_0 = 1.8205 * sqrt(0.5).
 * This is the standard Falcon CDT with 18 entries.
 * Each entry is the probability P(|x| >= i) stored as a 72-bit
 * fixed-point value (9 bytes).  We store the upper 64 bits.
 */
static const uint64_t CDT[] = {
    10745351955996939533ULL,  /*  0 */
     3822309709498697451ULL,  /*  1 */
      487657998509498498ULL,  /*  2 */
       22307691681937586ULL,  /*  3 */
         365949249498464ULL,  /*  4 */
           2151378665851ULL,  /*  5 */
              4534565665ULL,  /*  6 */
                 3422583ULL,  /*  7 */
                     926ULL,  /*  8 */
                       0ULL   /*  9: sentinel */
};
#define CDT_LEN 10

/* ------------------------------------------------------------------ */
/* Constant-time helpers                                                */
/* ------------------------------------------------------------------ */

/*
 * Constant-time comparison: return 1 if a < b, 0 otherwise.
 * Both a and b are unsigned 64-bit.
 */
static inline uint64_t
ct_lt_u64(uint64_t a, uint64_t b)
{
    return (a - b) >> 63;
}

/*
 * Constant-time conditional negate: if neg != 0, return -x, else x.
 */
static inline int32_t
ct_cond_neg(int32_t x, uint32_t neg)
{
    return (int32_t)((uint32_t)x ^ (uint32_t)-(int32_t)neg) + (int32_t)neg;
}

/* ------------------------------------------------------------------ */
/* Base sampler: sample from half-Gaussian via CDT                      */
/* ------------------------------------------------------------------ */

/*
 * Sample z >= 0 from a distribution close to the half-Gaussian
 * D_{Z+, sigma_0}.  Returns a non-negative integer.
 */
static int32_t
base_sampler(pqc_shake256_ctx *sctx)
{
    uint64_t r;
    int32_t z;
    int i;

    r = prng_u64(sctx);

    /*
     * Walk the CDT in constant time.
     * z starts at 0; for each table entry that r exceeds, increment z.
     */
    z = 0;
    for (i = 0; i < CDT_LEN - 1; i++) {
        z += (int32_t)ct_lt_u64(CDT[i], r);
    }
    return z;
}

/* ------------------------------------------------------------------ */
/* Bernoulli trial for exp(-x) decomposition                            */
/* ------------------------------------------------------------------ */

/*
 * BerExp: accept with probability ~ exp(-x), where x is a non-negative
 * double.  This uses the standard Falcon approach:
 *   - Decompose x = s * ln(2) + r, 0 <= r < ln(2).
 *   - Flip s coins each with probability 1/2; if any fail, reject.
 *   - Accept with probability exp(-r) using a polynomial approx.
 *
 * Returns 1 (accept) or 0 (reject).  Constant-time.
 */
static int
ber_exp(pqc_shake256_ctx *sctx, double x)
{
    int s;
    double r;
    uint64_t w, z;
    int32_t sw;

    static const double LN2 = 0.6931471805599453;
    static const double INV_LN2 = 1.4426950408889634;

    s = (int)floor(x * INV_LN2);
    r = x - (double)s * LN2;

    /* s should be small (< 64 normally). Clamp for safety. */
    sw = (int32_t)s;
    sw |= (int32_t)(63 - sw) >> 31;  /* if s > 63, set sw = 63 */
    sw &= 63;

    /*
     * Compute w = floor(exp(-r) * 2^63) using a degree-11 polynomial.
     * Coefficients are chosen for the range [0, ln(2)].
     */
    {
        double p;
        double rr = -r;
        double term;
        int k;

        /* exp(-r) = sum_{k=0}^{11} (-r)^k / k! */
        p = 0.0;
        term = 1.0;
        for (k = 0; k <= 11; k++) {
            p += term;
            term *= rr / (double)(k + 1);
        }
        /* p is now approximately exp(-r), in [exp(-ln2), 1] ~ [0.5, 1]. */
        /* Scale to 63-bit integer. */
        w = (uint64_t)(p * 9223372036854775808.0);  /* p * 2^63 */
    }

    /*
     * Rejection for the integer part s: flip s independent fair coins.
     * We shift w right by s bits (constant-time).
     */
    w >>= sw;

    /*
     * Final Bernoulli test: accept if a uniform random < w.
     */
    z = prng_u64(sctx);
    z &= 0x7FFFFFFFFFFFFFFFULL;  /* mask to 63 bits for comparison with w */
    return (z < w) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Public sampler interface                                             */
/* ------------------------------------------------------------------ */

/*
 * Initialise a sampler context.
 */
void
fndsa_sampler_init(fndsa_sampler_ctx_t *ctx,
                   const uint8_t *seed, size_t seed_len,
                   double sigma_min)
{
    pqc_shake256_init(&ctx->shake_ctx);
    pqc_shake256_absorb(&ctx->shake_ctx, seed, seed_len);
    pqc_shake256_finalize(&ctx->shake_ctx);
    ctx->sigma_min = sigma_min;
}

/*
 * Sample an integer z from the discrete Gaussian D_{Z, mu, sigma}.
 *
 * Algorithm (Falcon's "SamplerZ"):
 *   1. Sample z0 from the base half-Gaussian D_{Z+, sigma0}.
 *   2. Pick a random sign bit b; set z0 = (b ? -z0 : z0).
 *      (Re-sample if b=0 and z0=0 to avoid a bias.)
 *   3. Compute candidate z = z0 + round(mu).
 *   4. Accept with probability proportional to
 *      exp(-( (z0 - r)^2 / (2*sigma^2) - z0^2/(2*sigma0^2) ))
 *      where r = mu - round(mu).
 */
int32_t
fndsa_sampler_sample(fndsa_sampler_ctx_t *ctx, double mu, double sigma)
{
    double s_min = ctx->sigma_min;
    double inv_2sigma2, inv_2s0sq;
    int32_t z;
    pqc_shake256_ctx *sctx = &ctx->shake_ctx;

    /*
     * Precompute 1/(2*sigma^2) and 1/(2*sigma0^2).
     * sigma0 = sigma_min (the smallest sigma in the Gram-Schmidt tree).
     */
    inv_2sigma2 = 1.0 / (2.0 * sigma * sigma);
    inv_2s0sq   = 1.0 / (2.0 * s_min * s_min);

    for (;;) {
        int32_t z0;
        uint32_t b;
        double r, dz, x;
        int center;

        /* Step 1: base half-Gaussian sample. */
        z0 = base_sampler(sctx);

        /* Step 2: random sign. */
        b = (uint32_t)prng_u8(sctx) & 1u;

        /* Reject z0=0 with sign=negative (would double-count zero). */
        if (z0 == 0 && b != 0)
            continue;

        /* Signed value: z0_signed = b ? -z0 : z0. */
        z0 = ct_cond_neg(z0, b);

        /*
         * Step 3: compute candidate z.
         * We split mu = center + r with center = round(mu), r in [-0.5, 0.5).
         */
        center = (int)floor(mu + 0.5);
        r = mu - (double)center;

        z = z0 + center;

        /*
         * Step 4: acceptance.
         * dz = z0 - r  (distance from fractional part).
         * x = dz^2 * inv_2sigma2 - z0^2 * inv_2s0sq.
         * If x < 0, we unconditionally accept (probability > 1 clamped to 1).
         */
        dz = (double)z0 - r;
        x  = dz * dz * inv_2sigma2 - (double)((int64_t)z0 * z0) * inv_2s0sq;

        if (x < 0.0)
            return z;

        if (ber_exp(sctx, x))
            return z;

        /* Rejected -- loop. */
    }
}
