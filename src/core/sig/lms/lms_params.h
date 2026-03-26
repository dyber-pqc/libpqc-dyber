/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * LMS (Leighton-Micali Signature) parameter definitions.
 * RFC 8554 / NIST SP 800-208.
 *
 * LMS uses a Merkle tree of height h over LM-OTS one-time signatures.
 * LM-OTS uses a Winternitz chain of parameter w with p chains.
 */

#ifndef PQC_LMS_PARAMS_H
#define PQC_LMS_PARAMS_H

/* ------------------------------------------------------------------ */
/* Hash sizes                                                           */
/* ------------------------------------------------------------------ */

#define PQC_LMS_SHA256_N        32      /* SHA-256 output length        */
#define PQC_LMS_I_LEN           16      /* tree identifier length       */

/* ------------------------------------------------------------------ */
/* LM-OTS type IDs (RFC 8554 Section 4)                                 */
/* ------------------------------------------------------------------ */

#define PQC_LMOTS_SHA256_N32_W1     1
#define PQC_LMOTS_SHA256_N32_W2     2
#define PQC_LMOTS_SHA256_N32_W4     3
#define PQC_LMOTS_SHA256_N32_W8     4

/* ------------------------------------------------------------------ */
/* LM-OTS Winternitz parameter w=8 (SHA256_N32_W8)                      */
/* p = ceil(8n/w) + ceil(floor(lg((2^w - 1)*ceil(8n/w)))/w) + 1        */
/* For w=8, n=32: p = 32 + 2 = 34                                      */
/* ------------------------------------------------------------------ */

#define PQC_LMOTS_W             8
#define PQC_LMOTS_P             34
#define PQC_LMOTS_LS            0       /* left-shift for checksum      */
#define PQC_LMOTS_SIGBYTES      (4 + PQC_LMS_SHA256_N + PQC_LMOTS_P * PQC_LMS_SHA256_N)

/* ------------------------------------------------------------------ */
/* LMS type IDs (RFC 8554 Section 5)                                    */
/* ------------------------------------------------------------------ */

#define PQC_LMS_SHA256_M32_H5   5
#define PQC_LMS_SHA256_M32_H10  6
#define PQC_LMS_SHA256_M32_H15  7
#define PQC_LMS_SHA256_M32_H20  8
#define PQC_LMS_SHA256_M32_H25  9

/* ------------------------------------------------------------------ */
/* Tree heights                                                         */
/* ------------------------------------------------------------------ */

#define PQC_LMS_H10             10
#define PQC_LMS_H15             15
#define PQC_LMS_H20             20
#define PQC_LMS_H25             25

/* ------------------------------------------------------------------ */
/* Key and signature sizes                                              */
/*                                                                      */
/* Public key: u32(LMS_type) + u32(LMOTS_type) + I[16] + T[1] (root)  */
/*           = 4 + 4 + 16 + 32 = 56 bytes                              */
/*                                                                      */
/* Secret key: I[16] + SEED[32] + u32(q) + u32(LMS_type) +            */
/*             u32(LMOTS_type) = 16 + 32 + 4 + 4 + 4 + 4 = 64 bytes   */
/*                                                                      */
/* Signature: u32(q) + LMOTS_sig + u32(LMS_type) + path[h][n]          */
/*          = 4 + LMOTS_SIGBYTES + 4 + h*32                            */
/* ------------------------------------------------------------------ */

#define PQC_LMS_SHA256_PUBLICKEYBYTES     56
#define PQC_LMS_SHA256_SECRETKEYBYTES     64

#define PQC_LMS_SHA256_H10_SIGBYTES       (8 + PQC_LMOTS_SIGBYTES + PQC_LMS_H10 * PQC_LMS_SHA256_N)
#define PQC_LMS_SHA256_H15_SIGBYTES       (8 + PQC_LMOTS_SIGBYTES + PQC_LMS_H15 * PQC_LMS_SHA256_N)
#define PQC_LMS_SHA256_H20_SIGBYTES       (8 + PQC_LMOTS_SIGBYTES + PQC_LMS_H20 * PQC_LMS_SHA256_N)
#define PQC_LMS_SHA256_H25_SIGBYTES       (8 + PQC_LMOTS_SIGBYTES + PQC_LMS_H25 * PQC_LMS_SHA256_N)

#define PQC_LMS_MAX_H                     25

#endif /* PQC_LMS_PARAMS_H */
