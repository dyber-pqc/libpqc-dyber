/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Number Theoretic Transform for ML-DSA (q = 8380417).
 */

#ifndef PQC_MLDSA_NTT_H
#define PQC_MLDSA_NTT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQC_MLDSA_MONT      (-4186625)   /* 2^32 mod q                 */
#define PQC_MLDSA_QINV      58728449     /* q^{-1} mod 2^32            */

/**
 * Forward NTT. Input coefficients in [-6283009, 6283009].
 * Output coefficients in Montgomery domain.
 */
void pqc_mldsa_ntt(int32_t a[256]);

/**
 * Inverse NTT. Input coefficients in Montgomery domain.
 * Output in normal domain, coefficients in [-6283009, 6283009].
 */
void pqc_mldsa_invntt(int32_t a[256]);

/**
 * Montgomery reduction: (a * 2^{-32}) mod q.
 */
int32_t pqc_mldsa_montgomery_reduce(int64_t a);

/**
 * Barrett reduction: a mod q for |a| < 2^31.
 */
int32_t pqc_mldsa_barrett_reduce(int32_t a);

/**
 * Pointwise Montgomery multiplication of two NTT-domain polynomials.
 */
void pqc_mldsa_poly_pointwise_montgomery(int32_t c[256],
                                          const int32_t a[256],
                                          const int32_t b[256]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_NTT_H */
