/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * CROSS (Codes and Restricted Objects Signature Scheme) parameter definitions.
 */

#ifndef PQC_CROSS_PARAMS_H
#define PQC_CROSS_PARAMS_H

/* ------------------------------------------------------------------ */
/* CROSS-RSDP-128: Level 1                                              */
/* ------------------------------------------------------------------ */

#define PQC_CROSS_RSDP_128_PUBLICKEYBYTES    77
#define PQC_CROSS_RSDP_128_SECRETKEYBYTES    32
#define PQC_CROSS_RSDP_128_FAST_SIGBYTES     12912
#define PQC_CROSS_RSDP_128_SMALL_SIGBYTES    9236

/* ------------------------------------------------------------------ */
/* CROSS-RSDP-192: Level 3                                              */
/* ------------------------------------------------------------------ */

#define PQC_CROSS_RSDP_192_PUBLICKEYBYTES    115
#define PQC_CROSS_RSDP_192_SECRETKEYBYTES    48
#define PQC_CROSS_RSDP_192_FAST_SIGBYTES     23220
#define PQC_CROSS_RSDP_192_SMALL_SIGBYTES    16308

/* ------------------------------------------------------------------ */
/* CROSS-RSDP-256: Level 5                                              */
/* ------------------------------------------------------------------ */

#define PQC_CROSS_RSDP_256_PUBLICKEYBYTES    153
#define PQC_CROSS_RSDP_256_SECRETKEYBYTES    64
#define PQC_CROSS_RSDP_256_FAST_SIGBYTES     37088
#define PQC_CROSS_RSDP_256_SMALL_SIGBYTES    25564

#endif /* PQC_CROSS_PARAMS_H */
