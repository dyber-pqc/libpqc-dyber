/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece parameter definitions.
 *
 * Five parameter sets from the Classic McEliece submission:
 *   mceliece348864  : m=12, t=64,  n=3488
 *   mceliece460896  : m=13, t=96,  n=4608
 *   mceliece6688128 : m=13, t=128, n=6688
 *   mceliece6960119 : m=13, t=119, n=6960
 *   mceliece8192128 : m=13, t=128, n=8192
 */

#ifndef PQC_MCELIECE_PARAMS_H
#define PQC_MCELIECE_PARAMS_H

/* ------------------------------------------------------------------ */
/* mceliece348864 : m=12, t=64, n=3488, k=2720                       */
/* ------------------------------------------------------------------ */
#define MCELIECE_348864_M           12
#define MCELIECE_348864_T           64
#define MCELIECE_348864_N           3488
#define MCELIECE_348864_K           (MCELIECE_348864_N - MCELIECE_348864_M * MCELIECE_348864_T)  /* 2720 */
#define MCELIECE_348864_FIELD_SIZE  (1 << MCELIECE_348864_M)  /* 4096 */

#define MCELIECE_348864_PK_BYTES    261120  /* k/8 * (n-k) = row-major systematic form */
#define MCELIECE_348864_SK_BYTES    6492
#define MCELIECE_348864_CT_BYTES    128     /* ceil(n/8) for the syndrome  */
#define MCELIECE_348864_SS_BYTES    32

/* ------------------------------------------------------------------ */
/* mceliece460896 : m=13, t=96, n=4608, k=3360                       */
/* ------------------------------------------------------------------ */
#define MCELIECE_460896_M           13
#define MCELIECE_460896_T           96
#define MCELIECE_460896_N           4608
#define MCELIECE_460896_K           (MCELIECE_460896_N - MCELIECE_460896_M * MCELIECE_460896_T)  /* 3360 */
#define MCELIECE_460896_FIELD_SIZE  (1 << MCELIECE_460896_M)  /* 8192 */

#define MCELIECE_460896_PK_BYTES    524160
#define MCELIECE_460896_SK_BYTES    13608
#define MCELIECE_460896_CT_BYTES    188
#define MCELIECE_460896_SS_BYTES    32

/* ------------------------------------------------------------------ */
/* mceliece6688128 : m=13, t=128, n=6688, k=5024                     */
/* ------------------------------------------------------------------ */
#define MCELIECE_6688128_M          13
#define MCELIECE_6688128_T          128
#define MCELIECE_6688128_N          6688
#define MCELIECE_6688128_K          (MCELIECE_6688128_N - MCELIECE_6688128_M * MCELIECE_6688128_T)  /* 5024 */
#define MCELIECE_6688128_FIELD_SIZE (1 << MCELIECE_6688128_M)  /* 8192 */

#define MCELIECE_6688128_PK_BYTES   1044992
#define MCELIECE_6688128_SK_BYTES   13932
#define MCELIECE_6688128_CT_BYTES   240
#define MCELIECE_6688128_SS_BYTES   32

/* ------------------------------------------------------------------ */
/* mceliece6960119 : m=13, t=119, n=6960, k=5413                     */
/* ------------------------------------------------------------------ */
#define MCELIECE_6960119_M          13
#define MCELIECE_6960119_T          119
#define MCELIECE_6960119_N          6960
#define MCELIECE_6960119_K          (MCELIECE_6960119_N - MCELIECE_6960119_M * MCELIECE_6960119_T)  /* 5413 */
#define MCELIECE_6960119_FIELD_SIZE (1 << MCELIECE_6960119_M)  /* 8192 */

#define MCELIECE_6960119_PK_BYTES   1047319
#define MCELIECE_6960119_SK_BYTES   13948
#define MCELIECE_6960119_CT_BYTES   226
#define MCELIECE_6960119_SS_BYTES   32

/* ------------------------------------------------------------------ */
/* mceliece8192128 : m=13, t=128, n=8192, k=6528                     */
/* ------------------------------------------------------------------ */
#define MCELIECE_8192128_M          13
#define MCELIECE_8192128_T          128
#define MCELIECE_8192128_N          8192
#define MCELIECE_8192128_K          (MCELIECE_8192128_N - MCELIECE_8192128_M * MCELIECE_8192128_T)  /* 6528 */
#define MCELIECE_8192128_FIELD_SIZE (1 << MCELIECE_8192128_M)  /* 8192 */

#define MCELIECE_8192128_PK_BYTES   1357824
#define MCELIECE_8192128_SK_BYTES   14120
#define MCELIECE_8192128_CT_BYTES   240
#define MCELIECE_8192128_SS_BYTES   32

/* ------------------------------------------------------------------ */
/* Runtime parameter structure for multi-variant code                  */
/* ------------------------------------------------------------------ */
typedef struct {
    int m;              /* extension degree */
    int t;              /* error-correcting capability */
    int n;              /* code length */
    int k;              /* code dimension = n - m*t */
    int field_size;     /* 2^m */
    int pk_bytes;
    int sk_bytes;
    int ct_bytes;
    int ss_bytes;
} mceliece_params_t;

/* Maximum across all parameter sets */
#define MCELIECE_MAX_M      13
#define MCELIECE_MAX_T      128
#define MCELIECE_MAX_N      8192
#define MCELIECE_MAX_K      6528
#define MCELIECE_MAX_FIELD  8192

#endif /* PQC_MCELIECE_PARAMS_H */
