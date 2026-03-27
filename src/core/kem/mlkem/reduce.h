/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Modular arithmetic helpers for ML-KEM (FIPS 203).
 * Barrett and Montgomery reductions modulo q = 3329.
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#ifndef PQC_MLKEM_REDUCE_H
#define PQC_MLKEM_REDUCE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQC_MLKEM_MONT  (-1044) /* 2^16 mod q */
#define PQC_MLKEM_QINV  (-3327) /* q^{-1} mod 2^16 */

/**
 * Montgomery reduction.
 *
 * Given a 32-bit integer a, computes 16-bit integer congruent to
 * a * R^{-1} (mod q), where R = 2^16.
 */
int16_t pqc_mlkem_montgomery_reduce(int32_t a);

/**
 * Barrett reduction.
 *
 * For a 16-bit signed integer a, returns a centered representative
 * congruent to a mod q in {-(q-1)/2, ..., (q-1)/2}.
 */
int16_t pqc_mlkem_barrett_reduce(int16_t a);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_REDUCE_H */
