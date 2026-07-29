/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SNOVA parameter definitions.
 *
 * SNOVA is a non-commutative ring variant of UOV.  Variables and
 * coefficients live in the ring of l x l matrices over GF(16).
 * v = number of vinegar ring-variables, o = number of oil ring-variables.
 * n = v + o total ring-variables.
 */

#ifndef PQC_SNOVA_PARAMS_H
#define PQC_SNOVA_PARAMS_H

#define PQC_SNOVA_Q   16

/*
 * Signature encoding: 16-byte salt followed by n ring elements, each
 * l*l GF(16) nibbles, packed two per byte.
 *
 * These sizes MUST be derived from the parameters rather than written
 * out by hand: the serialiser in snova_sign_impl computes the packed
 * length from (n, l) at runtime, and a hand-written constant that
 * disagrees with it is a heap buffer overflow in every call to sign().
 */
#define PQC_SNOVA_SIGBYTES(n, l) \
    (16 + (((size_t)(n) * (size_t)(l) * (size_t)(l) + 1) / 2))

/* ------------------------------------------------------------------ */
/* SNOVA-24-5-4: v=24, o=5, l=4, q=16, Level 1                         */
/* n = v + o = 29                                                       */
/* ------------------------------------------------------------------ */

#define PQC_SNOVA_24_5_4_V                  24
#define PQC_SNOVA_24_5_4_O                  5
#define PQC_SNOVA_24_5_4_N                  29
#define PQC_SNOVA_24_5_4_L                  4
#define PQC_SNOVA_24_5_4_PUBLICKEYBYTES     1016
#define PQC_SNOVA_24_5_4_SECRETKEYBYTES     48
/* 16 + ceil(29 * 4 * 4 / 2) = 16 + 232 = 248 */
#define PQC_SNOVA_24_5_4_SIGBYTES \
    PQC_SNOVA_SIGBYTES(PQC_SNOVA_24_5_4_N, PQC_SNOVA_24_5_4_L)

/* ------------------------------------------------------------------ */
/* SNOVA-25-8-3: v=25, o=8, l=3, q=16, Level 3                         */
/* n = v + o = 33                                                       */
/* ------------------------------------------------------------------ */

#define PQC_SNOVA_25_8_3_V                  25
#define PQC_SNOVA_25_8_3_O                  8
#define PQC_SNOVA_25_8_3_N                  33
#define PQC_SNOVA_25_8_3_L                  3
#define PQC_SNOVA_25_8_3_PUBLICKEYBYTES     1400
#define PQC_SNOVA_25_8_3_SECRETKEYBYTES     48
/* 16 + ceil(33 * 3 * 3 / 2) = 16 + 149 = 165 */
#define PQC_SNOVA_25_8_3_SIGBYTES \
    PQC_SNOVA_SIGBYTES(PQC_SNOVA_25_8_3_N, PQC_SNOVA_25_8_3_L)

/* ------------------------------------------------------------------ */
/* SNOVA-28-17-3: v=28, o=17, l=3, q=16, Level 5                       */
/* n = v + o = 45                                                       */
/* ------------------------------------------------------------------ */

#define PQC_SNOVA_28_17_3_V                 28
#define PQC_SNOVA_28_17_3_O                 17
#define PQC_SNOVA_28_17_3_N                 45
#define PQC_SNOVA_28_17_3_L                 3
#define PQC_SNOVA_28_17_3_PUBLICKEYBYTES    5872
#define PQC_SNOVA_28_17_3_SECRETKEYBYTES    64
/* 16 + ceil(45 * 3 * 3 / 2) = 16 + 203 = 219 */
#define PQC_SNOVA_28_17_3_SIGBYTES \
    PQC_SNOVA_SIGBYTES(PQC_SNOVA_28_17_3_N, PQC_SNOVA_28_17_3_L)

/* ------------------------------------------------------------------ */
/* Maximum values for static buffers                                    */
/* ------------------------------------------------------------------ */

#define PQC_SNOVA_MAX_V     28
#define PQC_SNOVA_MAX_O     17
#define PQC_SNOVA_MAX_N     45
#define PQC_SNOVA_MAX_L     4

#endif /* PQC_SNOVA_PARAMS_H */
