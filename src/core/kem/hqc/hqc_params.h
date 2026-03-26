/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC parameter definitions for all security levels.
 */

#ifndef PQC_HQC_PARAMS_H
#define PQC_HQC_PARAMS_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Shared constants                                                     */
/* ------------------------------------------------------------------ */

#define HQC_SHARED_SECRET_BYTES  64
#define HQC_SEED_BYTES           40
#define HQC_SHA512_BYTES         64
#define HQC_SALT_SIZE_BYTES      16
#define HQC_SALT_SIZE_BITS       128

/* Reed-Muller code: RM(1, 7) encodes 8 bits into 128 bits */
#define HQC_RM_PARAM_M           7
#define HQC_RM_CODEWORD_BITS     128
#define HQC_RM_MESSAGE_BITS      8

/* ------------------------------------------------------------------ */
/* HQC-128 parameters (NIST Level 1)                                    */
/* ------------------------------------------------------------------ */

#define HQC_128_PARAM_N          17669
#define HQC_128_PARAM_N1         46
#define HQC_128_PARAM_N2         384
#define HQC_128_PARAM_N1N2       (HQC_128_PARAM_N1 * HQC_128_PARAM_N2)
#define HQC_128_PARAM_W          66
#define HQC_128_PARAM_WR         77
#define HQC_128_PARAM_WE         77
#define HQC_128_PARAM_DELTA      17
#define HQC_128_PARAM_M          (HQC_128_PARAM_DELTA + 1)
#define HQC_128_PARAM_GF_MUL_ORDER  ((1 << HQC_128_PARAM_M) - 1)
#define HQC_128_PARAM_K          (HQC_128_PARAM_N1 - 2 * HQC_128_PARAM_DELTA)
#define HQC_128_PARAM_G          (2 * HQC_128_PARAM_DELTA)
#define HQC_128_PARAM_FFT        8

/* Byte sizes for HQC-128 */
#define HQC_128_N_BYTES          ((HQC_128_PARAM_N + 7) / 8)
#define HQC_128_N1N2_BYTES       ((HQC_128_PARAM_N1N2 + 7) / 8)
#define HQC_128_K_BYTES          ((HQC_128_PARAM_K * 8 + 7) / 8)
#define HQC_128_INFO_BYTES       (HQC_128_K_BYTES)
#define HQC_128_PK_BYTES         2249
#define HQC_128_SK_BYTES         2289
#define HQC_128_CT_BYTES         4481

/* ------------------------------------------------------------------ */
/* HQC-192 parameters (NIST Level 3)                                    */
/* ------------------------------------------------------------------ */

#define HQC_192_PARAM_N          35851
#define HQC_192_PARAM_N1         56
#define HQC_192_PARAM_N2         640
#define HQC_192_PARAM_N1N2       (HQC_192_PARAM_N1 * HQC_192_PARAM_N2)
#define HQC_192_PARAM_W          100
#define HQC_192_PARAM_WR         117
#define HQC_192_PARAM_WE         117
#define HQC_192_PARAM_DELTA      24
#define HQC_192_PARAM_M          (HQC_192_PARAM_DELTA + 1)
#define HQC_192_PARAM_GF_MUL_ORDER  ((1 << HQC_192_PARAM_M) - 1)
#define HQC_192_PARAM_K          (HQC_192_PARAM_N1 - 2 * HQC_192_PARAM_DELTA)
#define HQC_192_PARAM_G          (2 * HQC_192_PARAM_DELTA)
#define HQC_192_PARAM_FFT        8

/* Byte sizes for HQC-192 */
#define HQC_192_N_BYTES          ((HQC_192_PARAM_N + 7) / 8)
#define HQC_192_N1N2_BYTES       ((HQC_192_PARAM_N1N2 + 7) / 8)
#define HQC_192_K_BYTES          ((HQC_192_PARAM_K * 8 + 7) / 8)
#define HQC_192_INFO_BYTES       (HQC_192_K_BYTES)
#define HQC_192_PK_BYTES         4522
#define HQC_192_SK_BYTES         4562
#define HQC_192_CT_BYTES         9026

/* ------------------------------------------------------------------ */
/* HQC-256 parameters (NIST Level 5)                                    */
/* ------------------------------------------------------------------ */

#define HQC_256_PARAM_N          57637
#define HQC_256_PARAM_N1         90
#define HQC_256_PARAM_N2         640
#define HQC_256_PARAM_N1N2       (HQC_256_PARAM_N1 * HQC_256_PARAM_N2)
#define HQC_256_PARAM_W          131
#define HQC_256_PARAM_WR         153
#define HQC_256_PARAM_WE         153
#define HQC_256_PARAM_DELTA      29
#define HQC_256_PARAM_M          (HQC_256_PARAM_DELTA + 1)
#define HQC_256_PARAM_GF_MUL_ORDER  ((1 << HQC_256_PARAM_M) - 1)
#define HQC_256_PARAM_K          (HQC_256_PARAM_N1 - 2 * HQC_256_PARAM_DELTA)
#define HQC_256_PARAM_G          (2 * HQC_256_PARAM_DELTA)
#define HQC_256_PARAM_FFT        8

/* Byte sizes for HQC-256 */
#define HQC_256_N_BYTES          ((HQC_256_PARAM_N + 7) / 8)
#define HQC_256_N1N2_BYTES       ((HQC_256_PARAM_N1N2 + 7) / 8)
#define HQC_256_K_BYTES          ((HQC_256_PARAM_K * 8 + 7) / 8)
#define HQC_256_INFO_BYTES       (HQC_256_K_BYTES)
#define HQC_256_PK_BYTES         7245
#define HQC_256_SK_BYTES         7285
#define HQC_256_CT_BYTES         14469

/* ------------------------------------------------------------------ */
/* Maximum parameter sizes (for stack allocation)                       */
/* ------------------------------------------------------------------ */

#define HQC_MAX_N                HQC_256_PARAM_N
#define HQC_MAX_N_BYTES          HQC_256_N_BYTES
#define HQC_MAX_N1               HQC_256_PARAM_N1
#define HQC_MAX_N2               HQC_256_PARAM_N2
#define HQC_MAX_N1N2             HQC_256_PARAM_N1N2
#define HQC_MAX_N1N2_BYTES       HQC_256_N1N2_BYTES
#define HQC_MAX_DELTA            HQC_256_PARAM_DELTA
#define HQC_MAX_M                HQC_256_PARAM_M
#define HQC_MAX_K                HQC_256_PARAM_K
#define HQC_MAX_GF_MUL_ORDER    HQC_256_PARAM_GF_MUL_ORDER
#define HQC_MAX_PK_BYTES        HQC_256_PK_BYTES
#define HQC_MAX_SK_BYTES        HQC_256_SK_BYTES
#define HQC_MAX_CT_BYTES        HQC_256_CT_BYTES

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t n;
    uint32_t n1;
    uint32_t n2;
    uint32_t n1n2;
    uint32_t w;
    uint32_t wr;
    uint32_t we;
    uint32_t delta;
    uint32_t m;           /* GF(2^m) field extension degree */
    uint32_t gf_mul_order;
    uint32_t k;           /* RS message symbols */
    uint32_t g;           /* RS redundancy = 2*delta */
    uint32_t n_bytes;
    uint32_t n1n2_bytes;
    uint32_t k_bytes;
    uint32_t pk_bytes;
    uint32_t sk_bytes;
    uint32_t ct_bytes;
    uint16_t gf_poly;    /* Irreducible polynomial for GF(2^m) */
} hqc_params_t;

/* Irreducible polynomials for GF(2^m) */
#define HQC_GF_POLY_M18   0x43801u  /* x^18 + x^13 + x^12 + x^11 + 1 */
#define HQC_GF_POLY_M25   0x2000023u /* x^25 + x^5 + x + 1 (approx) */
#define HQC_GF_POLY_M30   0x40000007u /* x^30 + x^2 + x + 1 */

static inline void hqc_params_init_128(hqc_params_t *p)
{
    p->n = HQC_128_PARAM_N;
    p->n1 = HQC_128_PARAM_N1;
    p->n2 = HQC_128_PARAM_N2;
    p->n1n2 = HQC_128_PARAM_N1N2;
    p->w = HQC_128_PARAM_W;
    p->wr = HQC_128_PARAM_WR;
    p->we = HQC_128_PARAM_WE;
    p->delta = HQC_128_PARAM_DELTA;
    p->m = HQC_128_PARAM_M;
    p->gf_mul_order = HQC_128_PARAM_GF_MUL_ORDER;
    p->k = HQC_128_PARAM_K;
    p->g = HQC_128_PARAM_G;
    p->n_bytes = HQC_128_N_BYTES;
    p->n1n2_bytes = HQC_128_N1N2_BYTES;
    p->k_bytes = HQC_128_K_BYTES;
    p->pk_bytes = HQC_128_PK_BYTES;
    p->sk_bytes = HQC_128_SK_BYTES;
    p->ct_bytes = HQC_128_CT_BYTES;
    p->gf_poly = 0x43;  /* x^8 + x^6 + x + 1 -- used for RM GF(2^8) sub-ops */
}

static inline void hqc_params_init_192(hqc_params_t *p)
{
    p->n = HQC_192_PARAM_N;
    p->n1 = HQC_192_PARAM_N1;
    p->n2 = HQC_192_PARAM_N2;
    p->n1n2 = HQC_192_PARAM_N1N2;
    p->w = HQC_192_PARAM_W;
    p->wr = HQC_192_PARAM_WR;
    p->we = HQC_192_PARAM_WE;
    p->delta = HQC_192_PARAM_DELTA;
    p->m = HQC_192_PARAM_M;
    p->gf_mul_order = HQC_192_PARAM_GF_MUL_ORDER;
    p->k = HQC_192_PARAM_K;
    p->g = HQC_192_PARAM_G;
    p->n_bytes = HQC_192_N_BYTES;
    p->n1n2_bytes = HQC_192_N1N2_BYTES;
    p->k_bytes = HQC_192_K_BYTES;
    p->pk_bytes = HQC_192_PK_BYTES;
    p->sk_bytes = HQC_192_SK_BYTES;
    p->ct_bytes = HQC_192_CT_BYTES;
    p->gf_poly = 0x43;
}

static inline void hqc_params_init_256(hqc_params_t *p)
{
    p->n = HQC_256_PARAM_N;
    p->n1 = HQC_256_PARAM_N1;
    p->n2 = HQC_256_PARAM_N2;
    p->n1n2 = HQC_256_PARAM_N1N2;
    p->w = HQC_256_PARAM_W;
    p->wr = HQC_256_PARAM_WR;
    p->we = HQC_256_PARAM_WE;
    p->delta = HQC_256_PARAM_DELTA;
    p->m = HQC_256_PARAM_M;
    p->gf_mul_order = HQC_256_PARAM_GF_MUL_ORDER;
    p->k = HQC_256_PARAM_K;
    p->g = HQC_256_PARAM_G;
    p->n_bytes = HQC_256_N_BYTES;
    p->n1n2_bytes = HQC_256_N1N2_BYTES;
    p->k_bytes = HQC_256_K_BYTES;
    p->pk_bytes = HQC_256_PK_BYTES;
    p->sk_bytes = HQC_256_SK_BYTES;
    p->ct_bytes = HQC_256_CT_BYTES;
    p->gf_poly = 0x43;
}

#endif /* PQC_HQC_PARAMS_H */
