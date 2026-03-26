/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Number Theoretic Transform (NTT) for ML-KEM (FIPS 203).
 * Operates on polynomials of degree < 256 in Z_q[X], q = 3329,
 * primitive 256th root of unity zeta = 17.
 */

#ifndef PQC_MLKEM_NTT_H
#define PQC_MLKEM_NTT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Precomputed twiddle factors (zeta^{BitRev(i)} in Montgomery form)
 * used by both forward and inverse NTT.  128 entries.
 */
extern const int16_t pqc_mlkem_zetas[128];

/**
 * Forward NTT.
 *
 * In-place transformation of 256 coefficients.
 * Input coefficients are assumed to be in normal domain,
 * output is in the NTT domain (bit-reversed order).
 *
 * Input bounds: |r[i]| < q  for all i.
 */
void pqc_mlkem_ntt(int16_t r[256]);

/**
 * Inverse NTT.
 *
 * In-place transformation from NTT domain back to normal domain.
 * Includes the multiplication by n^{-1} = 128^{-1} mod q.
 *
 * Output bounds: |r[i]| < q  for all i.
 */
void pqc_mlkem_invntt(int16_t r[256]);

/**
 * Multiplication of two NTT-domain elements in a single
 * degree-1 base case (two coefficients).
 *
 * Computes  r0 = a0*b0 + a1*b1*zeta,  r1 = a0*b1 + a1*b0
 * where zeta is the twiddle factor for this base case.
 * All arithmetic in Montgomery domain.
 */
void pqc_mlkem_basemul(int16_t r[2],
                        const int16_t a[2],
                        const int16_t b[2],
                        int16_t zeta);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_NTT_H */
