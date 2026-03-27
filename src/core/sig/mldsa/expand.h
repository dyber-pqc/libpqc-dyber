/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Seed expansion for ML-DSA (FIPS 204).
 * This header is maintained for backward compatibility.
 * Actual expansion is done via polyvec.h functions.
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
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
 * Sample secret vector with coefficients in [-eta, eta].
 *
 * @param s       Output polynomial vector (l or k polynomials).
 * @param seed    64-byte seed (rhoprime).
 * @param eta     Coefficient bound.
 * @param dim     Number of polynomials to sample.
 * @param nonce   Starting nonce.
 */
void pqc_mldsa_expand_s(pqc_mldsa_polyvecl *s,
                         const uint8_t seed[PQC_MLDSA_CRHBYTES],
                         unsigned eta, unsigned dim, uint16_t nonce);

/**
 * Sample mask vector y with coefficients in [-(gamma1-1), gamma1].
 *
 * @param y       Output polynomial vector (l polynomials).
 * @param seed    64-byte seed (rhoprime).
 * @param nonce   Nonce base (kappa).
 * @param gamma1  Mask range.
 * @param l       Number of polynomials.
 */
void pqc_mldsa_expand_mask(pqc_mldsa_polyvecl *y,
                            const uint8_t seed[PQC_MLDSA_CRHBYTES],
                            uint16_t nonce,
                            int32_t gamma1, unsigned l);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_EXPAND_H */
