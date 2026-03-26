/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * XMSS (eXtended Merkle Signature Scheme) parameter definitions.
 * RFC 8391 / NIST SP 800-208.
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

/* ------------------------------------------------------------------ */
/* Key and signature sizes                                              */
/* ------------------------------------------------------------------ */

#define PQC_XMSS_SHA2_256_PUBLICKEYBYTES    64
#define PQC_XMSS_SHA2_256_SECRETKEYBYTES    2573

#define PQC_XMSS_SHA2_10_256_SIGBYTES       2500
#define PQC_XMSS_SHA2_16_256_SIGBYTES       2692
#define PQC_XMSS_SHA2_20_256_SIGBYTES       2820

#endif /* PQC_XMSS_PARAMS_H */
