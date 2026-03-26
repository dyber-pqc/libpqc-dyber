/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * UOV - Key generation.
 *
 * Expands a secret seed into:
 * - The central map (m upper-triangular quadratic forms over GF(256))
 * - The affine transformation T (an invertible o x n matrix)
 *
 * The public key P_pub is derived as P_pub_i(x) = F_i(T * x) where
 * F_i are the central map polynomials.
 */

#include <string.h>
#include <stdint.h>
#include "uov.h"
#include "pqc/common.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Expand secret key seed into central map and transformation T.        */
/*                                                                      */
/* central_map: output, m * tri_size GF(256) elements.                  */
/* T: output, o * n GF(256) elements (row-major).                       */
/* sk_seed: input seed.                                                 */
/* params: UOV parameter set.                                           */
/* ------------------------------------------------------------------ */

void uov_expand_sk(uint8_t *central_map, uint8_t *T,
                   const uint8_t *sk_seed, const uov_params_t *params)
{
    int n = params->n;
    int o = params->o;
    size_t tri_size = (size_t)n * ((size_t)n + 1) / 2;
    size_t cm_size = (size_t)o * tri_size;   /* m = o */
    size_t T_size = (size_t)o * (size_t)n;
    pqc_shake256_ctx ctx;
    uint8_t domain;

    /* Expand central map */
    pqc_shake256_init(&ctx);
    domain = 0x00;
    pqc_shake256_absorb(&ctx, &domain, 1);
    pqc_shake256_absorb(&ctx, sk_seed, (size_t)params->seed_len);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, central_map, cm_size);

    /* Expand T matrix */
    pqc_shake256_init(&ctx);
    domain = 0x01;
    pqc_shake256_absorb(&ctx, &domain, 1);
    pqc_shake256_absorb(&ctx, sk_seed, (size_t)params->seed_len);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, T, T_size);

    /*
     * Make T have the form [I_o | T'], i.e., the last o columns
     * form an identity matrix.  This ensures invertibility.
     */
    {
        int i, j;
        for (i = 0; i < o; i++) {
            for (j = 0; j < o; j++) {
                T[i * n + (n - o) + j] = (i == j) ? 1 : 0;
            }
        }
    }

    pqc_memzero(&ctx, sizeof(ctx));
}
