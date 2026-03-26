/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Streamlined NTRU Prime parameter definitions.
 *
 * Five parameter sets (sntrup):
 *   sntrup761  : p=761,  q=4591, w=286
 *   sntrup857  : p=857,  q=5167, w=322
 *   sntrup953  : p=953,  q=6343, w=396
 *   sntrup1013 : p=1013, q=7177, w=448
 *   sntrup1277 : p=1277, q=7879, w=492
 *
 * Ring: Z_q[x]/(x^p - x - 1) where p is prime, q is prime,
 * and (x^p - x - 1) is irreducible over F_q.
 */

#ifndef PQC_NTRUPRIME_PARAMS_H
#define PQC_NTRUPRIME_PARAMS_H

/* ------------------------------------------------------------------ */
/* sntrup761                                                           */
/* ------------------------------------------------------------------ */
#define SNTRUP761_P             761
#define SNTRUP761_Q             4591
#define SNTRUP761_W             286
#define SNTRUP761_ROUND_BYTES   1007   /* encoding of Rounded(q) coeffs */
#define SNTRUP761_SMALL_BYTES   191    /* encoding of small coeffs */

#define SNTRUP761_PK_BYTES      1158
#define SNTRUP761_SK_BYTES      1763
#define SNTRUP761_CT_BYTES      1039
#define SNTRUP761_SS_BYTES      32

/* ------------------------------------------------------------------ */
/* sntrup857                                                           */
/* ------------------------------------------------------------------ */
#define SNTRUP857_P             857
#define SNTRUP857_Q             5167
#define SNTRUP857_W             322
#define SNTRUP857_ROUND_BYTES   1152
#define SNTRUP857_SMALL_BYTES   215

#define SNTRUP857_PK_BYTES      1322
#define SNTRUP857_SK_BYTES      1999
#define SNTRUP857_CT_BYTES      1184
#define SNTRUP857_SS_BYTES      32

/* ------------------------------------------------------------------ */
/* sntrup953                                                           */
/* ------------------------------------------------------------------ */
#define SNTRUP953_P             953
#define SNTRUP953_Q             6343
#define SNTRUP953_W             396
#define SNTRUP953_ROUND_BYTES   1317
#define SNTRUP953_SMALL_BYTES   239

#define SNTRUP953_PK_BYTES      1505
#define SNTRUP953_SK_BYTES      2254
#define SNTRUP953_CT_BYTES      1349
#define SNTRUP953_SS_BYTES      32

/* ------------------------------------------------------------------ */
/* sntrup1013                                                          */
/* ------------------------------------------------------------------ */
#define SNTRUP1013_P            1013
#define SNTRUP1013_Q            7177
#define SNTRUP1013_W            448
#define SNTRUP1013_ROUND_BYTES  1423
#define SNTRUP1013_SMALL_BYTES  254

#define SNTRUP1013_PK_BYTES     1623
#define SNTRUP1013_SK_BYTES     2417
#define SNTRUP1013_CT_BYTES     1455
#define SNTRUP1013_SS_BYTES     32

/* ------------------------------------------------------------------ */
/* sntrup1277                                                          */
/* ------------------------------------------------------------------ */
#define SNTRUP1277_P            1277
#define SNTRUP1277_Q            7879
#define SNTRUP1277_W            492
#define SNTRUP1277_ROUND_BYTES  1815
#define SNTRUP1277_SMALL_BYTES  320

#define SNTRUP1277_PK_BYTES     2067
#define SNTRUP1277_SK_BYTES     3059
#define SNTRUP1277_CT_BYTES     1847
#define SNTRUP1277_SS_BYTES     32

/* ------------------------------------------------------------------ */
/* Maximum values                                                      */
/* ------------------------------------------------------------------ */
#define SNTRUP_MAX_P    1277
#define SNTRUP_MAX_Q    7879
#define SNTRUP_MAX_W    492

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                         */
/* ------------------------------------------------------------------ */
typedef struct {
    int p;              /* polynomial degree (prime) */
    int q;              /* large modulus (prime) */
    int w;              /* weight of small polynomial */
    int round_bytes;    /* encoded size of Rq element */
    int small_bytes;    /* encoded size of small element */
    int pk_bytes;
    int sk_bytes;
    int ct_bytes;
    int ss_bytes;
} sntrup_params_t;

#endif /* PQC_NTRUPRIME_PARAMS_H */
