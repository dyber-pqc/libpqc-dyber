/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Modular arithmetic helpers for ML-KEM (FIPS 203).
 * Barrett and Montgomery reductions modulo q = 3329.
 */

#ifndef PQC_MLKEM_REDUCE_H
#define PQC_MLKEM_REDUCE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQC_MLKEM_Q         3329
#define PQC_MLKEM_MONT      (-1044)  /* 2^16 mod q  (== 3329 - 1044 = 2285 unsigned) */
#define PQC_MLKEM_QINV      62209    /* q^{-1} mod 2^16 */

/**
 * Barrett reduction.
 *
 * For any 16-bit signed integer @p a with |a| < 2^15, returns
 * a value r congruent to a mod q in {0, ..., q-1}.
 *
 * Uses the approximation floor(a / q) ~ (a * v) >> 26
 * where v = floor(2^26 / q) + 1 = 20159.
 */
int16_t pqc_mlkem_barrett_reduce(int16_t a);

/**
 * Montgomery reduction.
 *
 * Given a 32-bit integer @p a, computes 16-bit integer congruent to
 * a * 2^{-16} (mod q).
 *
 * Requires |a| <= q * 2^15.
 */
int16_t pqc_mlkem_montgomery_reduce(int32_t a);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_REDUCE_H */
