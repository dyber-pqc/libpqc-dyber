/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU - Polynomial sampling using SHAKE-256.
 *
 * Samples ternary polynomials (coefficients in {-1, 0, 1}) with either:
 *   - Fixed Hamming weight (for NTRU-HPS)
 *   - Unbounded ternary distribution (for NTRU-HRSS)
 */

#include <string.h>
#include "ntru.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Sample fixed-weight ternary polynomial (NTRU-HPS)                   */
/* ------------------------------------------------------------------ */

/*
 * Generates a polynomial with exactly 'weight' coefficients equal to +1
 * and 'weight' coefficients equal to -1, rest zero.
 * Total nonzero coefficients: 2 * weight.
 *
 * Uses SHAKE-256 to derive random bytes for a Fisher-Yates shuffle.
 */
void ntru_sample_fixed_weight(ntru_poly_t *r, const uint8_t *seed,
                              size_t seedlen, int n, int weight)
{
    ntru_poly_zero(r);

    /* Create initial array: weight +1s, weight -1s, rest 0s */
    for (int i = 0; i < weight; i++) {
        r->coeffs[i] = 1;
        r->coeffs[weight + i] = -1;
    }

    /* Derive randomness from seed */
    uint8_t rand_buf[4096]; /* Fixed-size stack buffer */
    (void)rand_buf; /* Buffer available but SHAKE squeeze is used directly below */

    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seedlen);
    pqc_shake256_finalize(&ctx);

    /* Fisher-Yates shuffle */
    for (int i = n - 1; i > 0; i--) {
        uint8_t rbuf[4];
        pqc_shake256_squeeze(&ctx, rbuf, 4);
        uint32_t rv = ((uint32_t)rbuf[0]) |
                      ((uint32_t)rbuf[1] << 8) |
                      ((uint32_t)rbuf[2] << 16) |
                      ((uint32_t)rbuf[3] << 24);
        int j = (int)(rv % (uint32_t)(i + 1));

        int16_t tmp = r->coeffs[i];
        r->coeffs[i] = r->coeffs[j];
        r->coeffs[j] = tmp;
    }
}

/* ------------------------------------------------------------------ */
/* Sample ternary polynomial (NTRU-HRSS)                               */
/* ------------------------------------------------------------------ */

/*
 * Generates a ternary polynomial where each coefficient is independently
 * sampled as -1, 0, or +1 from pairs of random bits.
 * Bit pair (b0, b1): 00 -> 0, 01 -> 1, 10 -> -1, 11 -> 0.
 */
void ntru_sample_ternary(ntru_poly_t *r, const uint8_t *seed,
                         size_t seedlen, int n)
{
    ntru_poly_zero(r);

    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seedlen);
    pqc_shake256_finalize(&ctx);

    for (int i = 0; i < n; i++) {
        uint8_t byte;
        pqc_shake256_squeeze(&ctx, &byte, 1);

        int b0 = byte & 1;
        int b1 = (byte >> 1) & 1;

        /* 00->0, 01->1, 10->-1, 11->0 */
        r->coeffs[i] = (int16_t)(b0 - b1);
        /* If b0==b1, result is 0; if b0=1,b1=0 -> 1; b0=0,b1=1 -> -1 */
    }
}

/* ------------------------------------------------------------------ */
/* Sample uniform polynomial mod q                                     */
/* ------------------------------------------------------------------ */

void ntru_sample_uniform(ntru_poly_t *r, const uint8_t *seed,
                         size_t seedlen, const ntru_params_t *p)
{
    ntru_poly_zero(r);

    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seedlen);
    pqc_shake256_finalize(&ctx);

    int q = p->q;
    int mask = q - 1;

    for (int i = 0; i < p->n; i++) {
        uint8_t buf[2];
        pqc_shake256_squeeze(&ctx, buf, 2);
        uint16_t val = (uint16_t)(((uint16_t)buf[0] | ((uint16_t)buf[1] << 8)) & (uint16_t)mask);
        r->coeffs[i] = (int16_t)val;
    }
}
