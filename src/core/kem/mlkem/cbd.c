/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Centered Binomial Distribution sampling for ML-KEM (FIPS 203).
 *
 * CBD_eta(B) produces a polynomial whose coefficients are in
 * {-eta, ..., eta}, sampled from 2*eta bits each.
 */

#include "core/kem/mlkem/cbd.h"

/* ------------------------------------------------------------------ */
/*  Helper: load 3 / 4 bytes as a little-endian integer                 */
/* ------------------------------------------------------------------ */

static uint32_t load32_le(const uint8_t x[4])
{
    return (uint32_t)x[0]
         | ((uint32_t)x[1] << 8)
         | ((uint32_t)x[2] << 16)
         | ((uint32_t)x[3] << 24);
}

static uint32_t load24_le(const uint8_t x[3])
{
    return (uint32_t)x[0]
         | ((uint32_t)x[1] << 8)
         | ((uint32_t)x[2] << 16);
}

/* ================================================================= */
/*  CBD_2                                                              */
/* ================================================================= */

/*
 * Each coefficient uses 4 random bits: two bits for each of two
 * Bernoulli(1/2) sums, then the difference.
 *
 * 32 bits yield 8 coefficients, so 256 coefficients need 128 bytes.
 */
void pqc_mlkem_cbd2(pqc_mlkem_poly *r, const uint8_t buf[128])
{
    unsigned int i, j;
    uint32_t t, d;

    for (i = 0; i < PQC_MLKEM_N / 8; i++) {
        t = load32_le(buf + 4 * i);
        d  = t & 0x55555555u;
        d += (t >> 1) & 0x55555555u;

        for (j = 0; j < 8; j++) {
            int16_t a = (int16_t)((d >>  (4 * j + 0)) & 0x3);
            int16_t b = (int16_t)((d >>  (4 * j + 2)) & 0x3);
            r->coeffs[8 * i + j] = a - b;
        }
    }
}

/* ================================================================= */
/*  CBD_3                                                              */
/* ================================================================= */

/*
 * Each coefficient uses 6 random bits: three bits for each of two
 * Bernoulli(1/2) sums, then the difference.
 *
 * 24 bits yield 4 coefficients, so 256 coefficients need 192 bytes.
 */
void pqc_mlkem_cbd3(pqc_mlkem_poly *r, const uint8_t buf[192])
{
    unsigned int i, j;
    uint32_t t, d;

    for (i = 0; i < PQC_MLKEM_N / 4; i++) {
        t = load24_le(buf + 3 * i);
        d  = t & 0x00249249u;
        d += (t >> 1) & 0x00249249u;
        d += (t >> 2) & 0x00249249u;

        for (j = 0; j < 4; j++) {
            int16_t a = (int16_t)((d >> (6 * j + 0)) & 0x7);
            int16_t b = (int16_t)((d >> (6 * j + 3)) & 0x7);
            r->coeffs[4 * i + j] = a - b;
        }
    }
}

/* ================================================================= */
/*  Dispatch by eta                                                    */
/* ================================================================= */

void pqc_mlkem_cbd_eta(pqc_mlkem_poly *r, const uint8_t *buf, unsigned int eta)
{
    if (eta == 2) {
        pqc_mlkem_cbd2(r, buf);
    } else { /* eta == 3 */
        pqc_mlkem_cbd3(r, buf);
    }
}
