/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE parameter definitions for all security levels.
 */

#ifndef PQC_BIKE_PARAMS_H
#define PQC_BIKE_PARAMS_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* Shared constants                                                     */
/* ------------------------------------------------------------------ */

#define BIKE_SHARED_SECRET_BYTES  32
#define BIKE_SEED_BYTES           32
#define BIKE_MAX_DECODE_ITERS     100  /* Maximum bit-flipping iterations */
#define BIKE_NB_ITER              5    /* BGF iterations per round */
#define BIKE_TAU                  3    /* Threshold parameter for BGF */

/* ------------------------------------------------------------------ */
/* BIKE-L1 parameters (NIST Level 1)                                    */
/* ------------------------------------------------------------------ */

#define BIKE_L1_R         12323
#define BIKE_L1_W         142
#define BIKE_L1_T         134
#define BIKE_L1_L         256

#define BIKE_L1_R_BYTES   ((BIKE_L1_R + 7) / 8)
#define BIKE_L1_R_WORDS   ((BIKE_L1_R + 63) / 64)
#define BIKE_L1_PK_BYTES  BIKE_L1_R_BYTES
#define BIKE_L1_SK_BYTES  (BIKE_SEED_BYTES + 2 * BIKE_L1_R_BYTES + BIKE_SHARED_SECRET_BYTES)
#define BIKE_L1_CT_BYTES  (BIKE_L1_R_BYTES + BIKE_SHARED_SECRET_BYTES)

/* ------------------------------------------------------------------ */
/* BIKE-L3 parameters (NIST Level 3)                                    */
/* ------------------------------------------------------------------ */

#define BIKE_L3_R         24659
#define BIKE_L3_W         206
#define BIKE_L3_T         199
#define BIKE_L3_L         256

#define BIKE_L3_R_BYTES   ((BIKE_L3_R + 7) / 8)
#define BIKE_L3_R_WORDS   ((BIKE_L3_R + 63) / 64)
#define BIKE_L3_PK_BYTES  BIKE_L3_R_BYTES
#define BIKE_L3_SK_BYTES  (BIKE_SEED_BYTES + 2 * BIKE_L3_R_BYTES + BIKE_SHARED_SECRET_BYTES)
#define BIKE_L3_CT_BYTES  (BIKE_L3_R_BYTES + BIKE_SHARED_SECRET_BYTES)

/* ------------------------------------------------------------------ */
/* BIKE-L5 parameters (NIST Level 5)                                    */
/* ------------------------------------------------------------------ */

#define BIKE_L5_R         40973
#define BIKE_L5_W         274
#define BIKE_L5_T         264
#define BIKE_L5_L         256

#define BIKE_L5_R_BYTES   ((BIKE_L5_R + 7) / 8)
#define BIKE_L5_R_WORDS   ((BIKE_L5_R + 63) / 64)
#define BIKE_L5_PK_BYTES  BIKE_L5_R_BYTES
#define BIKE_L5_SK_BYTES  (BIKE_SEED_BYTES + 2 * BIKE_L5_R_BYTES + BIKE_SHARED_SECRET_BYTES)
#define BIKE_L5_CT_BYTES  (BIKE_L5_R_BYTES + BIKE_SHARED_SECRET_BYTES)

/* ------------------------------------------------------------------ */
/* Maximum parameter sizes                                              */
/* ------------------------------------------------------------------ */

#define BIKE_MAX_R         BIKE_L5_R
#define BIKE_MAX_R_BYTES   BIKE_L5_R_BYTES
#define BIKE_MAX_R_WORDS   BIKE_L5_R_WORDS
#define BIKE_MAX_W         BIKE_L5_W
#define BIKE_MAX_T         BIKE_L5_T
#define BIKE_MAX_PK_BYTES   BIKE_L5_PK_BYTES
#define BIKE_MAX_SK_BYTES   BIKE_L5_SK_BYTES
#define BIKE_MAX_CT_BYTES   BIKE_L5_CT_BYTES

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t r;           /* Block length (prime) */
    uint32_t w;           /* Row weight of H */
    uint32_t t;           /* Error weight */
    uint32_t l;           /* Shared secret bit length */
    uint32_t r_bytes;
    uint32_t r_words;     /* ceil(r/64) */
    uint32_t pk_bytes;
    uint32_t sk_bytes;
    uint32_t ct_bytes;
    uint32_t half_w;      /* w/2 */
} bike_params_t;

static inline void bike_params_init_l1(bike_params_t *p)
{
    p->r = BIKE_L1_R;
    p->w = BIKE_L1_W;
    p->t = BIKE_L1_T;
    p->l = BIKE_L1_L;
    p->r_bytes = BIKE_L1_R_BYTES;
    p->r_words = BIKE_L1_R_WORDS;
    p->pk_bytes = BIKE_L1_PK_BYTES;
    p->sk_bytes = BIKE_L1_SK_BYTES;
    p->ct_bytes = BIKE_L1_CT_BYTES;
    p->half_w = BIKE_L1_W / 2;
}

static inline void bike_params_init_l3(bike_params_t *p)
{
    p->r = BIKE_L3_R;
    p->w = BIKE_L3_W;
    p->t = BIKE_L3_T;
    p->l = BIKE_L3_L;
    p->r_bytes = BIKE_L3_R_BYTES;
    p->r_words = BIKE_L3_R_WORDS;
    p->pk_bytes = BIKE_L3_PK_BYTES;
    p->sk_bytes = BIKE_L3_SK_BYTES;
    p->ct_bytes = BIKE_L3_CT_BYTES;
    p->half_w = BIKE_L3_W / 2;
}

static inline void bike_params_init_l5(bike_params_t *p)
{
    p->r = BIKE_L5_R;
    p->w = BIKE_L5_W;
    p->t = BIKE_L5_T;
    p->l = BIKE_L5_L;
    p->r_bytes = BIKE_L5_R_BYTES;
    p->r_words = BIKE_L5_R_WORDS;
    p->pk_bytes = BIKE_L5_PK_BYTES;
    p->sk_bytes = BIKE_L5_SK_BYTES;
    p->ct_bytes = BIKE_L5_CT_BYTES;
    p->half_w = BIKE_L5_W / 2;
}

#endif /* PQC_BIKE_PARAMS_H */
