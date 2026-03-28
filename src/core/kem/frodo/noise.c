/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FrodoKEM - Error sampling from a discrete distribution.
 *
 * Samples noise entries from a centered binomial/rounded Gaussian
 * distribution using a CDF table. The sampling uses SHAKE-256 as
 * the underlying PRNG.
 */

#include <stdlib.h>
#include <string.h>
#include "frodo.h"
#include "pqc/common.h"
#include "frodo_params.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Sample a matrix of noise values                                      */
/*                                                                      */
/* out: matrix of (rows x cols) uint16_t values (mod q)                */
/* The sampling uses SHAKE-256(seed || nonce) to generate randomness.   */
/* ------------------------------------------------------------------ */

void frodo_sample_noise(uint16_t *out, uint32_t rows, uint32_t cols,
                        const uint8_t *seed, size_t seedlen,
                        uint8_t nonce, uint32_t q,
                        const uint16_t *cdf, uint32_t cdf_len)
{
    uint32_t n_elems = rows * cols;
    uint16_t q_mask = (uint16_t)(q - 1);

    /* Prepare the seed: seed || nonce */
    uint8_t input[64]; /* seedlen + 1, with max 63 */
    if (seedlen > sizeof(input) - 1) seedlen = sizeof(input) - 1;
    memcpy(input, seed, seedlen);
    input[seedlen] = nonce;

    /* Generate 2 bytes per sample for the uniform value + sign */
    uint32_t rand_bytes_needed = n_elems * 2;
    uint8_t *rand_buf = (uint8_t *)malloc(rand_bytes_needed);
    if (!rand_buf) {
        memset(out, 0, n_elems * sizeof(uint16_t));
        return;
    }

    pqc_shake256(rand_buf, rand_bytes_needed, input, seedlen + 1);

    for (uint32_t i = 0; i < n_elems; i++) {
        uint16_t u = (uint16_t)rand_buf[2 * i] |
                     ((uint16_t)rand_buf[2 * i + 1] << 8);
        uint8_t sign = (uint8_t)(u >> 15);
        u &= 0x7FFF;

        /* Sample from CDF */
        int16_t e = 0;
        for (uint32_t k = 0; k < cdf_len; k++) {
            e += (int16_t)(cdf[k] <= u);
        }
        if (sign) {
            e = (int16_t)(-e);
        }

        /* Store as uint16_t mod q */
        out[i] = (uint16_t)((int32_t)e + q) & q_mask;
    }

    pqc_memzero(rand_buf, rand_bytes_needed);
    free(rand_buf);
}
