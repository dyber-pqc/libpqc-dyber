/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Number Theoretic Transform for ML-DSA (q = 8380417).
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
 */

#ifndef PQC_MLDSA_NTT_H
#define PQC_MLDSA_NTT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Montgomery constants */
#define PQC_MLDSA_MONT      (-4186625)   /* 2^32 mod q                 */
#define PQC_MLDSA_QINV      58728449     /* q^{-1} mod 2^32            */

/**
 * Forward NTT. Input coefficients in normal domain.
 * Output coefficients in bitreversed Montgomery domain.
 * No modular reduction after additions/subtractions.
 */
void pqc_mldsa_ntt(int32_t a[256]);

/**
 * Inverse NTT and multiplication by Montgomery factor 2^32.
 * Input coefficients in Montgomery domain.
 * Output coefficients bounded by q in absolute value.
 */
void pqc_mldsa_invntt(int32_t a[256]);

/**
 * Montgomery reduction: compute (a * 2^{-32}) mod q.
 * For -2^{31}*q <= a <= q*2^{31}, returns r with -q < r < q.
 */
int32_t pqc_mldsa_montgomery_reduce(int64_t a);

/**
 * Reduce coefficient modulo q to representative in [-6283008, 6283008].
 */
int32_t pqc_mldsa_reduce32(int32_t a);

/**
 * Add q if input coefficient is negative.
 */
int32_t pqc_mldsa_caddq(int32_t a);

/**
 * Compute standard representative r = a mod^+ q.
 */
int32_t pqc_mldsa_freeze(int32_t a);

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
