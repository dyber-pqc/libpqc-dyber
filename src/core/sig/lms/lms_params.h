/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * LMS (Leighton-Micali Signature) parameter definitions.
 * RFC 8554 / NIST SP 800-208.
 */

#ifndef PQC_LMS_PARAMS_H
#define PQC_LMS_PARAMS_H

/* ------------------------------------------------------------------ */
/* Hash sizes                                                           */
/* ------------------------------------------------------------------ */

#define PQC_LMS_SHA256_N        32      /* SHA-256 output length        */
#define PQC_LMS_I_LEN           16      /* tree identifier length       */

/* ------------------------------------------------------------------ */
/* LM-OTS Winternitz parameter w=8 (SHA256_N32_W8)                      */
/* ------------------------------------------------------------------ */

#define PQC_LMOTS_W             8
#define PQC_LMOTS_P             34

/* ------------------------------------------------------------------ */
/* Tree heights                                                         */
/* ------------------------------------------------------------------ */

#define PQC_LMS_H10             10
#define PQC_LMS_H15             15
#define PQC_LMS_H20             20
#define PQC_LMS_H25             25

/* ------------------------------------------------------------------ */
/* Key and signature sizes                                              */
/* ------------------------------------------------------------------ */

#define PQC_LMS_SHA256_PUBLICKEYBYTES     56
#define PQC_LMS_SHA256_SECRETKEYBYTES     64

#define PQC_LMS_SHA256_H10_SIGBYTES       2644
#define PQC_LMS_SHA256_H15_SIGBYTES       4012
#define PQC_LMS_SHA256_H20_SIGBYTES       5380
#define PQC_LMS_SHA256_H25_SIGBYTES       6748

#endif /* PQC_LMS_PARAMS_H */
