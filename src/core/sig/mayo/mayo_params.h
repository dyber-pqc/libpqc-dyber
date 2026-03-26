/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * MAYO parameter definitions.
 *
 * MAYO is a multivariate quadratic signature scheme based on the
 * Oil & Vinegar framework with whipping (multi-copy) construction.
 * q = 16 for all parameter sets.
 */

#ifndef PQC_MAYO_PARAMS_H
#define PQC_MAYO_PARAMS_H

/* GF(16) characteristic */
#define PQC_MAYO_Q                  16

/* ------------------------------------------------------------------ */
/* MAYO-1: n=66, m=64, o=8, k=9, q=16, Level 1                        */
/* v = n - o = 58                                                       */
/* ------------------------------------------------------------------ */

#define PQC_MAYO1_N                 66
#define PQC_MAYO1_M                 64
#define PQC_MAYO1_O                 8
#define PQC_MAYO1_V                 58
#define PQC_MAYO1_K                 9
#define PQC_MAYO1_PUBLICKEYBYTES    1168
#define PQC_MAYO1_SECRETKEYBYTES    24
#define PQC_MAYO1_SIGBYTES          321

/* ------------------------------------------------------------------ */
/* MAYO-2: n=78, m=64, o=18, k=4, q=16, Level 1                        */
/* v = n - o = 60                                                       */
/* ------------------------------------------------------------------ */

#define PQC_MAYO2_N                 78
#define PQC_MAYO2_M                 64
#define PQC_MAYO2_O                 18
#define PQC_MAYO2_V                 60
#define PQC_MAYO2_K                 4
#define PQC_MAYO2_PUBLICKEYBYTES    5488
#define PQC_MAYO2_SECRETKEYBYTES    24
#define PQC_MAYO2_SIGBYTES          180

/* ------------------------------------------------------------------ */
/* MAYO-3: n=99, m=96, o=10, k=11, q=16, Level 3                       */
/* v = n - o = 89                                                       */
/* ------------------------------------------------------------------ */

#define PQC_MAYO3_N                 99
#define PQC_MAYO3_M                 96
#define PQC_MAYO3_O                 10
#define PQC_MAYO3_V                 89
#define PQC_MAYO3_K                 11
#define PQC_MAYO3_PUBLICKEYBYTES    2656
#define PQC_MAYO3_SECRETKEYBYTES    32
#define PQC_MAYO3_SIGBYTES          577

/* ------------------------------------------------------------------ */
/* MAYO-5: n=133, m=128, o=12, k=12, q=16, Level 5                     */
/* v = n - o = 121                                                      */
/* ------------------------------------------------------------------ */

#define PQC_MAYO5_N                 133
#define PQC_MAYO5_M                 128
#define PQC_MAYO5_O                 12
#define PQC_MAYO5_V                 121
#define PQC_MAYO5_K                 12
#define PQC_MAYO5_PUBLICKEYBYTES    5008
#define PQC_MAYO5_SECRETKEYBYTES    40
#define PQC_MAYO5_SIGBYTES          838

/* ------------------------------------------------------------------ */
/* Maximum across all parameter sets (for static allocation)            */
/* ------------------------------------------------------------------ */

#define PQC_MAYO_MAX_N              133
#define PQC_MAYO_MAX_M              128
#define PQC_MAYO_MAX_O              18
#define PQC_MAYO_MAX_V              121
#define PQC_MAYO_MAX_K              12

#endif /* PQC_MAYO_PARAMS_H */
