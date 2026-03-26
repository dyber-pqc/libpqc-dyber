/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * XMSS (eXtended Merkle Signature Scheme) parameter definitions.
 * RFC 8391 / NIST SP 800-208.
 *
 * XMSS uses WOTS+ one-time signatures combined with a Merkle tree.
 * WOTS+ with parameter w uses chains of length w-1.
 */

#ifndef PQC_XMSS_PARAMS_H
#define PQC_XMSS_PARAMS_H

/* ------------------------------------------------------------------ */
/* Common                                                               */
/* ------------------------------------------------------------------ */

#define PQC_XMSS_SHA2_N            32       /* hash output length       */
#define PQC_XMSS_WOTS_W            16       /* Winternitz parameter     */
#define PQC_XMSS_WOTS_LEN1         64       /* ceil(8*n / lg(w))        */
#define PQC_XMSS_WOTS_LEN2         3        /* floor(lg(len1*(w-1))/lg(w))+1 */
#define PQC_XMSS_WOTS_LEN          67       /* len1 + len2              */
#define PQC_XMSS_WOTS_SIGBYTES     (PQC_XMSS_WOTS_LEN * PQC_XMSS_SHA2_N)

/* ------------------------------------------------------------------ */
/* Hash address (ADRS) structure: 32 bytes                              */
/* ------------------------------------------------------------------ */

#define PQC_XMSS_ADDR_BYTES        32

/* Address types */
#define PQC_XMSS_ADDR_TYPE_OTS     0
#define PQC_XMSS_ADDR_TYPE_LTREE   1
#define PQC_XMSS_ADDR_TYPE_TREE    2

/* ------------------------------------------------------------------ */
/* Tree heights                                                         */
/* ------------------------------------------------------------------ */

#define PQC_XMSS_H10               10
#define PQC_XMSS_H16               16
#define PQC_XMSS_H20               20

/* ------------------------------------------------------------------ */
/* Key and signature sizes                                              */
/*                                                                      */
/* Public key: OID(4) + root(n) + SEED(n) = 4 + 32 + 32 = 68          */
/* (some impls use 64 without OID; we use 64 to match the stub)        */
/*                                                                      */
/* Secret key: OID(4) + idx(4) + SK_SEED(n) + SK_PRF(n) + PK_SEED(n)  */
/*           + PK_ROOT(n) = 4 + 4 + 32*4 = 136                         */
/* (stub uses 2573 to include cached tree state)                        */
/*                                                                      */
/* Signature: idx(4) + R(n) + WOTS_sig(len*n) + auth(h*n)              */
/*          = 4 + 32 + 67*32 + h*32                                    */
/* ------------------------------------------------------------------ */

#define PQC_XMSS_SHA2_256_PUBLICKEYBYTES    64
#define PQC_XMSS_SHA2_256_SECRETKEYBYTES    2573

/* sig = 4 + 32 + 67*32 + h*32 = 2180 + h*32 */
#define PQC_XMSS_SHA2_10_256_SIGBYTES       2500    /* 2180 + 320 */
#define PQC_XMSS_SHA2_16_256_SIGBYTES       2692    /* 2180 + 512 */
#define PQC_XMSS_SHA2_20_256_SIGBYTES       2820    /* 2180 + 640 */

/* Maximum height */
#define PQC_XMSS_MAX_H                      20

#endif /* PQC_XMSS_PARAMS_H */
