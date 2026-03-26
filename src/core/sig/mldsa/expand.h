/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Seed expansion for ML-DSA (FIPS 204).
 */

#ifndef PQC_MLDSA_EXPAND_H
#define PQC_MLDSA_EXPAND_H

#include <stdint.h>

#include "core/sig/mldsa/mldsa_params.h"
#include "core/sig/mldsa/poly.h"
#include "core/sig/mldsa/polyvec.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Expand matrix A from seed rho using SHAKE-128.
 * Each A[i][j] is stored in mat[i * l + j] in NTT domain.
 *
 * @param mat   Output matrix (k*l polynomials in NTT domain).
 * @param rho   32-byte public seed.
 * @param k     Number of rows.
 * @param l     Number of columns.
 */
void pqc_mldsa_expand_a(pqc_mldsa_poly *mat,
                         const uint8_t rho[PQC_MLDSA_SEEDBYTES],
                         unsigned k, unsigned l);

/**
 * Expand secret vector s from seed rhoprime using SHAKE-256.
 *
 * @param s       Output polynomial vector.
 * @param seed    64-byte seed (rhoprime).
 * @param eta     Coefficient bound.
 * @param dim     Dimension of vector.
 * @param offset  Nonce offset (0 for s1, l for s2).
 */
void pqc_mldsa_expand_s(pqc_mldsa_polyvecl *s,
                         const uint8_t seed[PQC_MLDSA_CRHBYTES],
                         unsigned eta, unsigned dim, unsigned offset);

/**
 * Expand mask vector y from seed rhoprime using SHAKE-256.
 *
 * @param y       Output polynomial vector (l polynomials).
 * @param seed    64-byte seed (rhoprime).
 * @param kappa   Nonce base value.
 * @param gamma1  Coefficient bound for mask.
 * @param l       Dimension of vector.
 */
void pqc_mldsa_expand_mask(pqc_mldsa_polyvecl *y,
                            const uint8_t seed[PQC_MLDSA_CRHBYTES],
                            uint16_t kappa,
                            int32_t gamma1, unsigned l);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_EXPAND_H */
