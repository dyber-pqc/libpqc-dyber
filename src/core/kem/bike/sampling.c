/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE - Error vector and sparse polynomial sampling.
 *
 * Samples random sparse vectors of a given Hamming weight
 * using rejection sampling with SHAKE256 as the PRNG.
 */

#include <string.h>
#include "bike.h"
#include "pqc/common.h"
#include "bike_params.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Sample a sparse polynomial with exactly 'weight' bits set            */
/* ------------------------------------------------------------------ */

void bike_sample_sparse(uint64_t *poly, uint32_t weight, uint32_t r,
                        const uint8_t *seed, size_t seedlen)
{
    uint32_t r_words = (r + 63) / 64;
    memset(poly, 0, r_words * sizeof(uint64_t));

    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seedlen);
    pqc_shake256_finalize(&ctx);

    uint32_t count = 0;
    while (count < weight) {
        uint8_t buf[4];
        pqc_shake256_squeeze(&ctx, buf, 4);

        uint32_t pos = ((uint32_t)buf[0]) |
                       ((uint32_t)buf[1] << 8) |
                       ((uint32_t)buf[2] << 16) |
                       ((uint32_t)buf[3] << 24);

        /* Rejection sampling: reject if pos >= r */
        pos = pos & 0x7FFFFFFF; /* Mask to 31 bits */
        if (pos >= r) continue;

        /* Check for duplicates by testing the bit */
        if ((poly[pos / 64] >> (pos % 64)) & 1) continue;

        poly[pos / 64] |= (uint64_t)1 << (pos % 64);
        count++;
    }

    pqc_memzero(&ctx, sizeof(ctx));
}

/* ------------------------------------------------------------------ */
/* Sample a random error vector with weight t, split into (e0, e1)      */
/*                                                                      */
/* The error is a vector (e0 | e1) of length 2r with Hamming weight t.  */
/* ------------------------------------------------------------------ */

void bike_sample_error(uint64_t *e0, uint64_t *e1,
                       uint32_t t, uint32_t r,
                       const uint8_t *seed, size_t seedlen)
{
    uint32_t r_words = (r + 63) / 64;
    memset(e0, 0, r_words * sizeof(uint64_t));
    memset(e1, 0, r_words * sizeof(uint64_t));

    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seedlen);
    pqc_shake256_finalize(&ctx);

    uint32_t count = 0;
    while (count < t) {
        uint8_t buf[4];
        pqc_shake256_squeeze(&ctx, buf, 4);

        uint32_t val = ((uint32_t)buf[0]) |
                       ((uint32_t)buf[1] << 8) |
                       ((uint32_t)buf[2] << 16) |
                       ((uint32_t)buf[3] << 24);

        /* Position in the 2r-bit vector */
        val = val & 0x7FFFFFFF;
        if (val >= 2 * r) continue;

        uint32_t pos = val % r;
        uint64_t *target = (val < r) ? e0 : e1;

        /* Check duplicate */
        if ((target[pos / 64] >> (pos % 64)) & 1) continue;

        target[pos / 64] |= (uint64_t)1 << (pos % 64);
        count++;
    }

    pqc_memzero(&ctx, sizeof(ctx));
}
