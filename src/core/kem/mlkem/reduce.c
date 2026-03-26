/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Barrett and Montgomery reductions for ML-KEM (q = 3329).
 */

#include "core/kem/mlkem/reduce.h"

/*
 * Barrett reduction.
 *
 * v = floor(2^26 / q) + 1 = 20159.
 * For |a| < 2^15 we compute t = floor((a * v) >> 26) and return a - t*q.
 * The result is in [0, q) for non-negative a and in (-q, q) in general;
 * callers that need canonical [0, q) should apply a conditional addition.
 */
int16_t pqc_mlkem_barrett_reduce(int16_t a)
{
    int16_t t;
    const int16_t v = 20159; /* floor(2^26 / q + 0.5) */

    t  = (int16_t)(((int32_t)v * a + (1 << 25)) >> 26);
    t *= PQC_MLKEM_Q;
    return a - t;
}

/*
 * Montgomery reduction.
 *
 * Given 32-bit a, returns (a * 2^{-16}) mod q in [-q+1, q-1].
 * QINV = q^{-1} mod 2^16 = 62209 (equivalently -3327 mod 2^16).
 */
int16_t pqc_mlkem_montgomery_reduce(int32_t a)
{
    int16_t t;

    t = (int16_t)((int16_t)a * (int16_t)PQC_MLKEM_QINV);
    t = (int16_t)((a - (int32_t)t * PQC_MLKEM_Q) >> 16);
    return t;
}
