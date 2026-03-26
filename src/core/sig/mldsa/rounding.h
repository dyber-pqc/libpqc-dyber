/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Rounding and decomposition for ML-DSA (FIPS 204).
 */

#ifndef PQC_MLDSA_ROUNDING_H
#define PQC_MLDSA_ROUNDING_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Power2Round: decompose a mod q into (a1, a0) such that
 * a = a1 * 2^D + a0, with -2^{D-1} < a0 <= 2^{D-1}.
 *
 * @param a   Coefficient (assumed reduced mod q).
 * @param a0  Output low bits.
 * @return    High bits a1.
 */
int32_t pqc_mldsa_power2round(int32_t *a0, int32_t a);

/**
 * Decompose: for a mod q, compute high and low bits a1, a0 such that
 * a mod q = a1 * 2*gamma2 + a0, with -gamma2 < a0 <= gamma2.
 *
 * @param a       Coefficient (assumed reduced mod q, non-negative).
 * @param a0      Output low bits.
 * @param gamma2  Rounding parameter.
 * @return        High bits a1.
 */
int32_t pqc_mldsa_decompose(int32_t *a0, int32_t a, int32_t gamma2);

/**
 * Compute hint bit. Returns 1 if adding z to r changes the high bits
 * of r (as determined by Decompose with parameter gamma2).
 *
 * @param a0      Low bits.
 * @param a1      Candidate high bits.
 * @param gamma2  Rounding parameter.
 * @return        1 if hint is needed, 0 otherwise.
 */
unsigned pqc_mldsa_make_hint(int32_t a0, int32_t a1, int32_t gamma2);

/**
 * Use hint to recover correct high bits.
 *
 * @param a       Original value.
 * @param hint    Hint bit (0 or 1).
 * @param gamma2  Rounding parameter.
 * @return        Corrected high bits.
 */
int32_t pqc_mldsa_use_hint(int32_t a, unsigned hint, int32_t gamma2);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_ROUNDING_H */
