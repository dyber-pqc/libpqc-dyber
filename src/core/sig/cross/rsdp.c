/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * CROSS - RSDP (Restricted Syndrome Decoding Problem) operations.
 *
 * Provides:
 * - Parity-check matrix H expansion from seed
 * - Syndrome computation: s = H * e mod z
 * - Weight-restricted error vector sampling
 */

#include <string.h>
#include <stdint.h>
#include "cross.h"
#include "pqc/common.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Expand parity-check matrix H from seed.                              */
/*                                                                      */
/* H is (n-k) x n over F_z in systematic form [I_{n-k} | P].           */
/* Stored as (n-k) * n uint16_t values packed into uint8_t pairs,       */
/* but for simplicity we use uint8_t elements (sufficient for z<256,    */
/* and use 16-bit reduction for z>=256).                                */
/* ------------------------------------------------------------------ */

void cross_rsdp_expand_H(uint8_t *H, int n, int k, int z,
                          const uint8_t *seed, size_t seed_len)
{
    int rows = n - k;
    size_t H_size = (size_t)rows * (size_t)n;
    pqc_shake256_ctx ctx;
    size_t gen_len;
    uint8_t *buf;
    int i, j;

    /* Zero H */
    memset(H, 0, H_size * 2); /* 2 bytes per element for z>=256 */

    /* Generate the non-identity part P */
    gen_len = (size_t)rows * (size_t)k * 2;
    buf = (uint8_t *)pqc_calloc(1, gen_len);
    if (!buf) return;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seed_len);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, buf, gen_len);

    /* Build systematic form [I | P] */
    for (i = 0; i < rows; i++) {
        /* Identity part */
        H[(i * n + i) * 2] = 0;
        H[(i * n + i) * 2 + 1] = 1;

        /* P part */
        for (j = 0; j < k; j++) {
            uint16_t val = ((uint16_t)buf[(i * k + j) * 2] << 8) |
                           buf[(i * k + j) * 2 + 1];
            val %= (uint16_t)z;
            H[(i * n + rows + j) * 2] = (uint8_t)(val >> 8);
            H[(i * n + rows + j) * 2 + 1] = (uint8_t)(val & 0xFF);
        }
    }

    pqc_free(buf, gen_len);
    pqc_memzero(&ctx, sizeof(ctx));
}

/* ------------------------------------------------------------------ */
/* Compute syndrome s = H * e mod z.                                    */
/*                                                                      */
/* H: (n-k) x n matrix, elements as 2-byte big-endian values.          */
/* e: n elements as 2-byte big-endian.                                  */
/* syndrome: (n-k) elements as 2-byte big-endian.                       */
/* ------------------------------------------------------------------ */

void cross_rsdp_compute_syndrome(uint8_t *syndrome, const uint8_t *H,
                                  const uint8_t *e, int n, int k, int z)
{
    int rows = n - k;
    int i, j;

    for (i = 0; i < rows; i++) {
        uint32_t sum = 0;
        for (j = 0; j < n; j++) {
            uint16_t h_val = ((uint16_t)H[(i * n + j) * 2] << 8) |
                             H[(i * n + j) * 2 + 1];
            uint16_t e_val = ((uint16_t)e[j * 2] << 8) | e[j * 2 + 1];
            sum += (uint32_t)h_val * (uint32_t)e_val;
        }
        uint16_t result = (uint16_t)(sum % (uint32_t)z);
        syndrome[i * 2] = (uint8_t)(result >> 8);
        syndrome[i * 2 + 1] = (uint8_t)(result & 0xFF);
    }
}

/* ------------------------------------------------------------------ */
/* Sample a weight-restricted error vector.                             */
/*                                                                      */
/* e has n components over F_z^* (non-zero elements).                   */
/* Exactly w components are non-zero.                                   */
/* ------------------------------------------------------------------ */

void cross_rsdp_sample_error(uint8_t *e, int n, int w, int z,
                              const uint8_t *seed, size_t seed_len)
{
    pqc_shake256_ctx ctx;
    uint8_t buf[4];
    int filled = 0;
    int i;

    /* Zero all elements */
    memset(e, 0, (size_t)n * 2);

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seed_len);
    pqc_shake256_finalize(&ctx);

    /*
     * Fisher-Yates-like: fill first w positions with random non-zero
     * F_z elements, then permute.
     */
    for (i = 0; i < w; i++) {
        uint16_t val;
        do {
            pqc_shake256_squeeze(&ctx, buf, 2);
            val = ((uint16_t)(buf[0]) << 8 | buf[1]) % (uint16_t)z;
        } while (val == 0);
        e[i * 2] = (uint8_t)(val >> 8);
        e[i * 2 + 1] = (uint8_t)(val & 0xFF);
    }

    /* Permute using remaining SHAKE output */
    for (i = n - 1; i > 0; i--) {
        pqc_shake256_squeeze(&ctx, buf, 4);
        uint32_t r = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                     ((uint32_t)buf[2] << 8) | buf[3];
        int j_pos = (int)(r % (uint32_t)(i + 1));
        /* Swap e[i] and e[j_pos] */
        uint8_t t0 = e[i * 2];
        uint8_t t1 = e[i * 2 + 1];
        e[i * 2] = e[j_pos * 2];
        e[i * 2 + 1] = e[j_pos * 2 + 1];
        e[j_pos * 2] = t0;
        e[j_pos * 2 + 1] = t1;
    }

    (void)filled;
    pqc_memzero(&ctx, sizeof(ctx));
}
