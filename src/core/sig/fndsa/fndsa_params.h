/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) parameter definitions.
 */

#ifndef PQC_FNDSA_PARAMS_H
#define PQC_FNDSA_PARAMS_H

/* ------------------------------------------------------------------ */
/* Common parameters                                                    */
/* ------------------------------------------------------------------ */

/* Modulus for the polynomial ring Z_q[x]/(x^n+1). */
#define FNDSA_Q             12289

/* Inverse of q modulo 2^16, used in Montgomery/Barrett reductions. */
#define FNDSA_Q_INV         12287  /* q^{-1} mod 2^16 */

/* ------------------------------------------------------------------ */
/* FN-DSA-512 (logn = 9, n = 512)                                       */
/* ------------------------------------------------------------------ */

#define FNDSA_512_LOGN          9
#define FNDSA_512_N             512

/* Gaussian sampling parameter sigma (std. dev) and sigmin. */
#define FNDSA_512_SIGMA         165.736
#define FNDSA_512_SIGMIN        1.277

/* Encoded sizes in bytes. */
#define FNDSA_512_PK_SIZE       897
#define FNDSA_512_SK_SIZE       1281
#define FNDSA_512_SIG_MAX_SIZE  666

/* Squared norm bound for (s1, s2): floor(1.8205^2 * 2 * 512 * q). */
#define FNDSA_512_SIG_BOUND     34034726

/* Number of bits per coefficient in trim_i8 encoding. */
#define FNDSA_512_SK_BITS       4

/* ------------------------------------------------------------------ */
/* FN-DSA-1024 (logn = 10, n = 1024)                                    */
/* ------------------------------------------------------------------ */

#define FNDSA_1024_LOGN         10
#define FNDSA_1024_N            1024

#define FNDSA_1024_SIGMA        168.388
#define FNDSA_1024_SIGMIN       1.298

#define FNDSA_1024_PK_SIZE      1793
#define FNDSA_1024_SK_SIZE      2305
#define FNDSA_1024_SIG_MAX_SIZE 1280

/* Squared norm bound for (s1, s2). */
#define FNDSA_1024_SIG_BOUND    70265242

#define FNDSA_1024_SK_BITS      4

/* ------------------------------------------------------------------ */
/* Derived helper macros                                                */
/* ------------------------------------------------------------------ */

/* Maximum degree supported. */
#define FNDSA_MAX_LOGN  10
#define FNDSA_MAX_N     (1 << FNDSA_MAX_LOGN)

/* Public-key header byte encodes logn. */
#define FNDSA_PK_HEADER(logn)  (0x00 + (logn))

/* Signature header byte. */
#define FNDSA_SIG_HEADER(logn) (0x30 + (logn))

/* Secret-key header byte. */
#define FNDSA_SK_HEADER(logn)  (0x50 + (logn))

/* Nonce length in bytes (used as salt in hash-to-point). */
#define FNDSA_NONCE_LEN  40

/* Number of bits per coefficient for public-key encoding (mod q). */
#define FNDSA_PK_COEFF_BITS  14

/* Temporary workspace requirement (generous upper bound). */
#define FNDSA_TMP_SIZE(logn)  ((size_t)((6 * (1 << (logn))) + 4096) * sizeof(double))

#endif /* PQC_FNDSA_PARAMS_H */
