/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * CROSS (Codes and Restricted Objects Signature Scheme) parameter definitions.
 *
 * CROSS is a code-based signature scheme relying on the Restricted
 * Syndrome Decoding Problem (RSDP).  It uses a commit-and-prove
 * (cut-and-choose) framework with Merkle trees.
 *
 * Variants: 128/192/256-bit security, fast and small trade-offs.
 * The prime field F_z is used (z depends on security level).
 */

#ifndef PQC_CROSS_PARAMS_H
#define PQC_CROSS_PARAMS_H

/* ------------------------------------------------------------------ */
/* CROSS-RSDP-128: Level 1                                              */
/* Field: F_127, n=127, k=76, w=76, t=163/252                          */
/* ------------------------------------------------------------------ */

#define PQC_CROSS_RSDP_128_Z                127
#define PQC_CROSS_RSDP_128_N                127
#define PQC_CROSS_RSDP_128_K                76
#define PQC_CROSS_RSDP_128_W                76
#define PQC_CROSS_RSDP_128_PUBLICKEYBYTES   77
#define PQC_CROSS_RSDP_128_SECRETKEYBYTES   32
#define PQC_CROSS_RSDP_128_FAST_T           163
#define PQC_CROSS_RSDP_128_FAST_SIGBYTES    12912
#define PQC_CROSS_RSDP_128_SMALL_T          252
#define PQC_CROSS_RSDP_128_SMALL_SIGBYTES   9236

/* ------------------------------------------------------------------ */
/* CROSS-RSDP-192: Level 3                                              */
/* Field: F_509, n=187, k=111, w=111                                    */
/* ------------------------------------------------------------------ */

#define PQC_CROSS_RSDP_192_Z                509
#define PQC_CROSS_RSDP_192_N                187
#define PQC_CROSS_RSDP_192_K                111
#define PQC_CROSS_RSDP_192_W                111
#define PQC_CROSS_RSDP_192_PUBLICKEYBYTES   115
#define PQC_CROSS_RSDP_192_SECRETKEYBYTES   48
#define PQC_CROSS_RSDP_192_FAST_T           229
#define PQC_CROSS_RSDP_192_FAST_SIGBYTES    23220
#define PQC_CROSS_RSDP_192_SMALL_T          377
#define PQC_CROSS_RSDP_192_SMALL_SIGBYTES   16308

/* ------------------------------------------------------------------ */
/* CROSS-RSDP-256: Level 5                                              */
/* Field: F_509, n=251, k=150, w=150                                    */
/* ------------------------------------------------------------------ */

#define PQC_CROSS_RSDP_256_Z                509
#define PQC_CROSS_RSDP_256_N                251
#define PQC_CROSS_RSDP_256_K                150
#define PQC_CROSS_RSDP_256_W                150
#define PQC_CROSS_RSDP_256_PUBLICKEYBYTES   153
#define PQC_CROSS_RSDP_256_SECRETKEYBYTES   64
#define PQC_CROSS_RSDP_256_FAST_T           293
#define PQC_CROSS_RSDP_256_FAST_SIGBYTES    37088
#define PQC_CROSS_RSDP_256_SMALL_T          503
#define PQC_CROSS_RSDP_256_SMALL_SIGBYTES   25564

/* ------------------------------------------------------------------ */
/* Hash sizes                                                           */
/* ------------------------------------------------------------------ */

#define PQC_CROSS_128_HASH_BYTES    32
#define PQC_CROSS_192_HASH_BYTES    48
#define PQC_CROSS_256_HASH_BYTES    64

/* Maximum values for static allocation */
#define PQC_CROSS_MAX_N     251
#define PQC_CROSS_MAX_K     150
#define PQC_CROSS_MAX_T     503

#endif /* PQC_CROSS_PARAMS_H */
