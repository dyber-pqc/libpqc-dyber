/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial operations for ML-DSA.
 */

#ifndef PQC_MLDSA_POLY_H
#define PQC_MLDSA_POLY_H

#include <stdint.h>
#include <stddef.h>

#include "core/sig/mldsa/mldsa_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Polynomial type                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    int32_t coeffs[PQC_MLDSA_N];
} pqc_mldsa_poly;

/* ------------------------------------------------------------------ */
/* Basic operations                                                     */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_add(pqc_mldsa_poly *c,
                         const pqc_mldsa_poly *a,
                         const pqc_mldsa_poly *b);

void pqc_mldsa_poly_sub(pqc_mldsa_poly *c,
                         const pqc_mldsa_poly *a,
                         const pqc_mldsa_poly *b);

void pqc_mldsa_poly_shiftl(pqc_mldsa_poly *a);

/* ------------------------------------------------------------------ */
/* NTT domain                                                           */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_ntt(pqc_mldsa_poly *a);
void pqc_mldsa_poly_invntt(pqc_mldsa_poly *a);

void pqc_mldsa_poly_pointwise(pqc_mldsa_poly *c,
                               const pqc_mldsa_poly *a,
                               const pqc_mldsa_poly *b);

/* ------------------------------------------------------------------ */
/* Reduction                                                            */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_reduce(pqc_mldsa_poly *a);
void pqc_mldsa_poly_caddq(pqc_mldsa_poly *a);

/* ------------------------------------------------------------------ */
/* Decomposition and rounding                                           */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_power2round(pqc_mldsa_poly *a1,
                                 pqc_mldsa_poly *a0,
                                 const pqc_mldsa_poly *a);

void pqc_mldsa_poly_decompose(pqc_mldsa_poly *a1,
                               pqc_mldsa_poly *a0,
                               const pqc_mldsa_poly *a,
                               int32_t gamma2);

unsigned pqc_mldsa_poly_make_hint(pqc_mldsa_poly *h,
                                   const pqc_mldsa_poly *a0,
                                   const pqc_mldsa_poly *a1,
                                   int32_t gamma2);

void pqc_mldsa_poly_use_hint(pqc_mldsa_poly *b,
                              const pqc_mldsa_poly *a,
                              const pqc_mldsa_poly *hint,
                              int32_t gamma2);

/* ------------------------------------------------------------------ */
/* Norm check                                                           */
/* ------------------------------------------------------------------ */

int pqc_mldsa_poly_chknorm(const pqc_mldsa_poly *a, int32_t bound);

/* ------------------------------------------------------------------ */
/* Sampling                                                             */
/* ------------------------------------------------------------------ */

/**
 * Sample polynomial with uniformly random coefficients in [0, q-1]
 * from a seed using SHAKE-128 (rejection sampling).
 */
void pqc_mldsa_poly_uniform(pqc_mldsa_poly *a,
                             const uint8_t seed[PQC_MLDSA_SEEDBYTES],
                             uint16_t nonce);

/**
 * Sample polynomial with coefficients in [-eta, eta]
 * from a seed using SHAKE-256.
 */
void pqc_mldsa_poly_uniform_eta(pqc_mldsa_poly *a,
                                 const uint8_t seed[PQC_MLDSA_CRHBYTES],
                                 uint16_t nonce,
                                 unsigned eta);

/**
 * Sample polynomial with coefficients in [-gamma1+1, gamma1]
 * from a seed using SHAKE-256 (mask vector).
 */
void pqc_mldsa_poly_uniform_gamma1(pqc_mldsa_poly *a,
                                    const uint8_t seed[PQC_MLDSA_CRHBYTES],
                                    uint16_t nonce,
                                    int32_t gamma1);

/**
 * Generate sparse challenge polynomial with exactly tau +/-1 entries.
 */
void pqc_mldsa_poly_challenge(pqc_mldsa_poly *c,
                               const uint8_t *seed,
                               unsigned seedlen,
                               unsigned tau);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_POLY_H */
