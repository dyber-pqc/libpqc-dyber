/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial vector operations for ML-DSA.
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
 */

#ifndef PQC_MLDSA_POLYVEC_H
#define PQC_MLDSA_POLYVEC_H

#include "core/sig/mldsa/poly.h"
#include "core/sig/mldsa/mldsa_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Polynomial vector types (max dimension)                              */
/* ------------------------------------------------------------------ */

typedef struct {
    pqc_mldsa_poly vec[PQC_MLDSA_K_MAX];
} pqc_mldsa_polyveck;

typedef struct {
    pqc_mldsa_poly vec[PQC_MLDSA_L_MAX];
} pqc_mldsa_polyvecl;

/* ------------------------------------------------------------------ */
/* Element-wise operations (l-vectors)                                  */
/* ------------------------------------------------------------------ */

void pqc_mldsa_polyvecl_add(pqc_mldsa_polyvecl *w,
                             const pqc_mldsa_polyvecl *u,
                             const pqc_mldsa_polyvecl *v,
                             unsigned l);

void pqc_mldsa_polyvecl_ntt(pqc_mldsa_polyvecl *v, unsigned l);
void pqc_mldsa_polyvecl_invntt(pqc_mldsa_polyvecl *v, unsigned l);
void pqc_mldsa_polyvecl_reduce(pqc_mldsa_polyvecl *v, unsigned l);

void pqc_mldsa_polyvecl_pointwise_poly(pqc_mldsa_polyvecl *r,
                                        const pqc_mldsa_poly *a,
                                        const pqc_mldsa_polyvecl *v,
                                        unsigned l);

/**
 * Pointwise multiply vectors of polynomials of length l, multiply
 * resulting vector by 2^{-32} and add (accumulate) polynomials.
 * Input/output vectors are in NTT domain.
 */
void pqc_mldsa_polyvecl_pointwise_acc(pqc_mldsa_poly *w,
                                       const pqc_mldsa_polyvecl *u,
                                       const pqc_mldsa_polyvecl *v,
                                       unsigned l);

int pqc_mldsa_polyvecl_chknorm(const pqc_mldsa_polyvecl *v,
                                int32_t bound, unsigned l);

/* ------------------------------------------------------------------ */
/* Element-wise operations (k-vectors)                                  */
/* ------------------------------------------------------------------ */

void pqc_mldsa_polyveck_add(pqc_mldsa_polyveck *w,
                             const pqc_mldsa_polyveck *u,
                             const pqc_mldsa_polyveck *v,
                             unsigned k);

void pqc_mldsa_polyveck_sub(pqc_mldsa_polyveck *w,
                             const pqc_mldsa_polyveck *u,
                             const pqc_mldsa_polyveck *v,
                             unsigned k);

void pqc_mldsa_polyveck_ntt(pqc_mldsa_polyveck *v, unsigned k);
void pqc_mldsa_polyveck_invntt(pqc_mldsa_polyveck *v, unsigned k);
void pqc_mldsa_polyveck_reduce(pqc_mldsa_polyveck *v, unsigned k);
void pqc_mldsa_polyveck_caddq(pqc_mldsa_polyveck *v, unsigned k);
void pqc_mldsa_polyveck_shiftl(pqc_mldsa_polyveck *v, unsigned k);

void pqc_mldsa_polyveck_pointwise_poly(pqc_mldsa_polyveck *r,
                                        const pqc_mldsa_poly *a,
                                        const pqc_mldsa_polyveck *v,
                                        unsigned k);

int pqc_mldsa_polyveck_chknorm(const pqc_mldsa_polyveck *v,
                                int32_t bound, unsigned k);

void pqc_mldsa_polyveck_power2round(pqc_mldsa_polyveck *v1,
                                     pqc_mldsa_polyveck *v0,
                                     const pqc_mldsa_polyveck *v,
                                     unsigned k);

void pqc_mldsa_polyveck_decompose(pqc_mldsa_polyveck *v1,
                                   pqc_mldsa_polyveck *v0,
                                   const pqc_mldsa_polyveck *v,
                                   int32_t gamma2, unsigned k);

unsigned pqc_mldsa_polyveck_make_hint(pqc_mldsa_polyveck *h,
                                       const pqc_mldsa_polyveck *v0,
                                       const pqc_mldsa_polyveck *v1,
                                       int32_t gamma2, unsigned k);

void pqc_mldsa_polyveck_use_hint(pqc_mldsa_polyveck *w,
                                  const pqc_mldsa_polyveck *v,
                                  const pqc_mldsa_polyveck *h,
                                  int32_t gamma2, unsigned k);

/* ------------------------------------------------------------------ */
/* Pack w1 into byte array                                              */
/* ------------------------------------------------------------------ */

void pqc_mldsa_polyveck_pack_w1(uint8_t *r,
                                 const pqc_mldsa_polyveck *w1,
                                 unsigned k, int32_t gamma2,
                                 size_t polyw1_packed);

/* ------------------------------------------------------------------ */
/* Matrix-vector product: t = A * s  (A in NTT domain)                  */
/* A is stored row-major: mat[i] is the i-th row (a polyvecl).          */
/* ------------------------------------------------------------------ */

void pqc_mldsa_polyvec_matrix_expand(pqc_mldsa_polyvecl *mat,
                                      const uint8_t rho[PQC_MLDSA_SEEDBYTES],
                                      unsigned k, unsigned l);

void pqc_mldsa_polyvec_matrix_pointwise(
    pqc_mldsa_polyveck *t,
    const pqc_mldsa_polyvecl *mat,
    const pqc_mldsa_polyvecl *s,
    unsigned k, unsigned l);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_POLYVEC_H */
