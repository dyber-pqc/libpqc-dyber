/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FrodoKEM parameter definitions for all security levels.
 */

#ifndef PQC_FRODO_PARAMS_H
#define PQC_FRODO_PARAMS_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* Common constants                                                     */
/* ------------------------------------------------------------------ */

#define FRODO_N_BAR          8     /* Number of columns in B, S', E' */
#define FRODO_SEED_A_BYTES   16    /* Seed for matrix A */
#define FRODO_BYTES_SEED_SE  32    /* Seed for S, E generation (after expansion) */

/* ------------------------------------------------------------------ */
/* FrodoKEM-640 parameters (NIST Level 1)                               */
/* ------------------------------------------------------------------ */

#define FRODO_640_N            640
#define FRODO_640_LOG_Q        15
#define FRODO_640_Q            (1 << FRODO_640_LOG_Q)  /* 32768 */
#define FRODO_640_B            2
#define FRODO_640_LEN_MU       128   /* bits: n_bar * n_bar * B = 8*8*2 */
#define FRODO_640_LEN_SS       16    /* shared secret bytes */
#define FRODO_640_LEN_SEEDSE   32    /* bytes */
#define FRODO_640_LEN_S        16    /* bytes, secret value s for rejection */
#define FRODO_640_LEN_K        16    /* bytes */
#define FRODO_640_LEN_PKH      16    /* bytes */

/* Derived sizes */
#define FRODO_640_PK_BYTES     9616   /* seedA(16) + B(n*n_bar*log_q/8) */
#define FRODO_640_SK_BYTES     19888  /* s(len_s) + pk + S^T + pkh */
#define FRODO_640_CT_BYTES     9720   /* C1(n_bar*n*logq/8) + C2(n_bar*n_bar*logq/8) */

/* Matrix dimensions (in uint16_t elements) */
#define FRODO_640_MATRIX_A_ELEMS   (FRODO_640_N * FRODO_640_N)
#define FRODO_640_MATRIX_B_ELEMS   (FRODO_640_N * FRODO_N_BAR)
#define FRODO_640_MATRIX_C_ELEMS   (FRODO_N_BAR * FRODO_N_BAR)

/* ------------------------------------------------------------------ */
/* FrodoKEM-976 parameters (NIST Level 3)                               */
/* ------------------------------------------------------------------ */

#define FRODO_976_N            976
#define FRODO_976_LOG_Q        16
#define FRODO_976_Q            (1 << FRODO_976_LOG_Q)  /* 65536 */
#define FRODO_976_B            3
#define FRODO_976_LEN_MU       192   /* bits: 8*8*3 */
#define FRODO_976_LEN_SS       24
#define FRODO_976_LEN_SEEDSE   32
#define FRODO_976_LEN_S        24
#define FRODO_976_LEN_K        24
#define FRODO_976_LEN_PKH      24

#define FRODO_976_PK_BYTES     15632
#define FRODO_976_SK_BYTES     31296
#define FRODO_976_CT_BYTES     15744

#define FRODO_976_MATRIX_A_ELEMS   (FRODO_976_N * FRODO_976_N)
#define FRODO_976_MATRIX_B_ELEMS   (FRODO_976_N * FRODO_N_BAR)
#define FRODO_976_MATRIX_C_ELEMS   (FRODO_N_BAR * FRODO_N_BAR)

/* ------------------------------------------------------------------ */
/* FrodoKEM-1344 parameters (NIST Level 5)                              */
/* ------------------------------------------------------------------ */

#define FRODO_1344_N           1344
#define FRODO_1344_LOG_Q       16
#define FRODO_1344_Q           (1 << FRODO_1344_LOG_Q)  /* 65536 */
#define FRODO_1344_B           4
#define FRODO_1344_LEN_MU      256   /* bits: 8*8*4 */
#define FRODO_1344_LEN_SS      32
#define FRODO_1344_LEN_SEEDSE  32
#define FRODO_1344_LEN_S       32
#define FRODO_1344_LEN_K       32
#define FRODO_1344_LEN_PKH     32

#define FRODO_1344_PK_BYTES    21520
#define FRODO_1344_SK_BYTES    43088
#define FRODO_1344_CT_BYTES    21632

#define FRODO_1344_MATRIX_A_ELEMS   (FRODO_1344_N * FRODO_1344_N)
#define FRODO_1344_MATRIX_B_ELEMS   (FRODO_1344_N * FRODO_N_BAR)
#define FRODO_1344_MATRIX_C_ELEMS   (FRODO_N_BAR * FRODO_N_BAR)

/* ------------------------------------------------------------------ */
/* Maximum parameter sizes                                              */
/* ------------------------------------------------------------------ */

#define FRODO_MAX_N            FRODO_1344_N
#define FRODO_MAX_LOG_Q        16
#define FRODO_MAX_Q            (1 << FRODO_MAX_LOG_Q)
#define FRODO_MAX_B            FRODO_1344_B
#define FRODO_MAX_LEN_MU       (FRODO_1344_LEN_MU)
#define FRODO_MAX_LEN_SS       FRODO_1344_LEN_SS
#define FRODO_MAX_LEN_S        FRODO_1344_LEN_S
#define FRODO_MAX_LEN_K        FRODO_1344_LEN_K
#define FRODO_MAX_LEN_PKH      FRODO_1344_LEN_PKH
#define FRODO_MAX_PK_BYTES     FRODO_1344_PK_BYTES
#define FRODO_MAX_SK_BYTES     FRODO_1344_SK_BYTES
#define FRODO_MAX_CT_BYTES     FRODO_1344_CT_BYTES

/* ------------------------------------------------------------------ */
/* Matrix A generation mode                                             */
/* ------------------------------------------------------------------ */

typedef enum {
    FRODO_MATRIX_A_SHAKE = 0,
    FRODO_MATRIX_A_AES   = 1,
} frodo_matrix_a_mode_t;

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t n;
    uint32_t log_q;
    uint32_t q;
    uint32_t b;           /* Extracted bits parameter */
    uint32_t len_mu;      /* Message length in bits */
    uint32_t len_ss;      /* Shared secret bytes */
    uint32_t len_seedse;  /* seedSE bytes */
    uint32_t len_s;       /* s bytes */
    uint32_t len_k;       /* k bytes */
    uint32_t len_pkh;     /* pk hash bytes */
    uint32_t pk_bytes;
    uint32_t sk_bytes;
    uint32_t ct_bytes;
    frodo_matrix_a_mode_t matrix_a_mode;
} frodo_params_t;

static inline void frodo_params_init_640(frodo_params_t *p,
                                          frodo_matrix_a_mode_t mode)
{
    p->n = FRODO_640_N;
    p->log_q = FRODO_640_LOG_Q;
    p->q = FRODO_640_Q;
    p->b = FRODO_640_B;
    p->len_mu = FRODO_640_LEN_MU;
    p->len_ss = FRODO_640_LEN_SS;
    p->len_seedse = FRODO_640_LEN_SEEDSE;
    p->len_s = FRODO_640_LEN_S;
    p->len_k = FRODO_640_LEN_K;
    p->len_pkh = FRODO_640_LEN_PKH;
    p->pk_bytes = FRODO_640_PK_BYTES;
    p->sk_bytes = FRODO_640_SK_BYTES;
    p->ct_bytes = FRODO_640_CT_BYTES;
    p->matrix_a_mode = mode;
}

static inline void frodo_params_init_976(frodo_params_t *p,
                                          frodo_matrix_a_mode_t mode)
{
    p->n = FRODO_976_N;
    p->log_q = FRODO_976_LOG_Q;
    p->q = FRODO_976_Q;
    p->b = FRODO_976_B;
    p->len_mu = FRODO_976_LEN_MU;
    p->len_ss = FRODO_976_LEN_SS;
    p->len_seedse = FRODO_976_LEN_SEEDSE;
    p->len_s = FRODO_976_LEN_S;
    p->len_k = FRODO_976_LEN_K;
    p->len_pkh = FRODO_976_LEN_PKH;
    p->pk_bytes = FRODO_976_PK_BYTES;
    p->sk_bytes = FRODO_976_SK_BYTES;
    p->ct_bytes = FRODO_976_CT_BYTES;
    p->matrix_a_mode = mode;
}

static inline void frodo_params_init_1344(frodo_params_t *p,
                                           frodo_matrix_a_mode_t mode)
{
    p->n = FRODO_1344_N;
    p->log_q = FRODO_1344_LOG_Q;
    p->q = FRODO_1344_Q;
    p->b = FRODO_1344_B;
    p->len_mu = FRODO_1344_LEN_MU;
    p->len_ss = FRODO_1344_LEN_SS;
    p->len_seedse = FRODO_1344_LEN_SEEDSE;
    p->len_s = FRODO_1344_LEN_S;
    p->len_k = FRODO_1344_LEN_K;
    p->len_pkh = FRODO_1344_LEN_PKH;
    p->pk_bytes = FRODO_1344_PK_BYTES;
    p->sk_bytes = FRODO_1344_SK_BYTES;
    p->ct_bytes = FRODO_1344_CT_BYTES;
    p->matrix_a_mode = mode;
}

/* ------------------------------------------------------------------ */
/* Error distribution CDF tables                                        */
/*                                                                      */
/* These give the CDF of the discrete Gaussian (rounded) used for       */
/* error sampling. CDF[i] = Pr[|X| <= i] * 2^16 (approximately).       */
/* ------------------------------------------------------------------ */

/* Frodo-640: sigma = 2.8, CDF table length = 13 */
#define FRODO_640_CDF_LEN  13
static const uint16_t frodo_640_cdf[FRODO_640_CDF_LEN] = {
    4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525,
    32689, 32745, 32762, 32766, 32767
};

/* Frodo-976: sigma = 2.3, CDF table length = 11 */
#define FRODO_976_CDF_LEN  11
static const uint16_t frodo_976_cdf[FRODO_976_CDF_LEN] = {
    5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731,
    32760, 32766, 32767
};

/* Frodo-1344: sigma = 1.4, CDF table length = 7 */
#define FRODO_1344_CDF_LEN  7
static const uint16_t frodo_1344_cdf[FRODO_1344_CDF_LEN] = {
    9142, 23462, 30338, 32361, 32725, 32765, 32767
};

#endif /* PQC_FRODO_PARAMS_H */
