/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU parameter definitions.
 *
 * Two families:
 *   NTRU-HPS (product-form): n=509/677/821, q=2048/2048/4096
 *   NTRU-HRSS (HRSS variant): n=701, q=8192
 */

#ifndef PQC_NTRU_PARAMS_H
#define PQC_NTRU_PARAMS_H

/* ------------------------------------------------------------------ */
/* Common                                                              */
/* ------------------------------------------------------------------ */

#define NTRU_P          3       /* small modulus for message space */
#define NTRU_SS_BYTES   32      /* shared secret size */

/* ------------------------------------------------------------------ */
/* NTRU-HPS-2048-509                                                   */
/* ------------------------------------------------------------------ */
#define NTRU_HPS2048509_N           509
#define NTRU_HPS2048509_Q           2048
#define NTRU_HPS2048509_LOG_Q       11
#define NTRU_HPS2048509_WEIGHT_F    ((NTRU_HPS2048509_N - 1) / 3)  /* ~169 */
#define NTRU_HPS2048509_WEIGHT_R    ((NTRU_HPS2048509_N - 1) / 3)

#define NTRU_HPS2048509_PK_BYTES    699
#define NTRU_HPS2048509_SK_BYTES    935
#define NTRU_HPS2048509_CT_BYTES    699

/* ------------------------------------------------------------------ */
/* NTRU-HPS-2048-677                                                   */
/* ------------------------------------------------------------------ */
#define NTRU_HPS2048677_N           677
#define NTRU_HPS2048677_Q           2048
#define NTRU_HPS2048677_LOG_Q       11
#define NTRU_HPS2048677_WEIGHT_F    ((NTRU_HPS2048677_N - 1) / 3)  /* ~225 */
#define NTRU_HPS2048677_WEIGHT_R    ((NTRU_HPS2048677_N - 1) / 3)

#define NTRU_HPS2048677_PK_BYTES    930
#define NTRU_HPS2048677_SK_BYTES    1234
#define NTRU_HPS2048677_CT_BYTES    930

/* ------------------------------------------------------------------ */
/* NTRU-HPS-4096-821                                                   */
/* ------------------------------------------------------------------ */
#define NTRU_HPS4096821_N           821
#define NTRU_HPS4096821_Q           4096
#define NTRU_HPS4096821_LOG_Q       12
#define NTRU_HPS4096821_WEIGHT_F    ((NTRU_HPS4096821_N - 1) / 3)  /* ~273 */
#define NTRU_HPS4096821_WEIGHT_R    ((NTRU_HPS4096821_N - 1) / 3)

#define NTRU_HPS4096821_PK_BYTES    1230
#define NTRU_HPS4096821_SK_BYTES    1590
#define NTRU_HPS4096821_CT_BYTES    1230

/* ------------------------------------------------------------------ */
/* NTRU-HRSS-701                                                       */
/* ------------------------------------------------------------------ */
#define NTRU_HRSS701_N              701
#define NTRU_HRSS701_Q              8192
#define NTRU_HRSS701_LOG_Q          13

#define NTRU_HRSS701_PK_BYTES       1138
#define NTRU_HRSS701_SK_BYTES       1450
#define NTRU_HRSS701_CT_BYTES       1138

/* ------------------------------------------------------------------ */
/* Maximum values across all sets                                      */
/* ------------------------------------------------------------------ */
#define NTRU_MAX_N      821
#define NTRU_MAX_Q      8192
#define NTRU_MAX_LOG_Q  13

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                         */
/* ------------------------------------------------------------------ */
typedef struct {
    int n;
    int q;
    int log_q;
    int is_hrss;        /* 1 for HRSS, 0 for HPS */
    int weight;         /* weight for f,g in HPS (0 for HRSS) */
    int pk_bytes;
    int sk_bytes;
    int ct_bytes;
} ntru_params_t;

#endif /* PQC_NTRU_PARAMS_H */
