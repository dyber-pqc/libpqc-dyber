/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Key and signature serialization for ML-DSA (FIPS 204).
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
 */

#ifndef PQC_MLDSA_PACKING_H
#define PQC_MLDSA_PACKING_H

#include <stdint.h>

#include "core/sig/mldsa/mldsa_params.h"
#include "core/sig/mldsa/poly.h"
#include "core/sig/mldsa/polyvec.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Individual polynomial packing                                        */
/* ------------------------------------------------------------------ */

void pqc_mldsa_polyt1_pack(uint8_t *r, const pqc_mldsa_poly *a);
void pqc_mldsa_polyt1_unpack(pqc_mldsa_poly *r, const uint8_t *a);

void pqc_mldsa_polyt0_pack(uint8_t *r, const pqc_mldsa_poly *a);
void pqc_mldsa_polyt0_unpack(pqc_mldsa_poly *r, const uint8_t *a);

void pqc_mldsa_polyeta_pack(uint8_t *r, const pqc_mldsa_poly *a,
                             unsigned eta);
void pqc_mldsa_polyeta_unpack(pqc_mldsa_poly *r, const uint8_t *a,
                               unsigned eta);

void pqc_mldsa_polyz_pack(uint8_t *r, const pqc_mldsa_poly *a,
                           int32_t gamma1);
void pqc_mldsa_polyz_unpack(pqc_mldsa_poly *r, const uint8_t *a,
                             int32_t gamma1);

void pqc_mldsa_polyw1_pack(uint8_t *r, const pqc_mldsa_poly *a,
                            int32_t gamma2);

/* ------------------------------------------------------------------ */
/* Public key packing: pk = rho || t1                                   */
/* ------------------------------------------------------------------ */

void pqc_mldsa_pack_pk(uint8_t *pk,
                        const uint8_t rho[PQC_MLDSA_SEEDBYTES],
                        const pqc_mldsa_polyveck *t1,
                        unsigned k);

void pqc_mldsa_unpack_pk(uint8_t rho[PQC_MLDSA_SEEDBYTES],
                          pqc_mldsa_polyveck *t1,
                          const uint8_t *pk,
                          unsigned k);

/* ------------------------------------------------------------------ */
/* Secret key packing: sk = rho || K || tr || s1 || s2 || t0            */
/* ------------------------------------------------------------------ */

void pqc_mldsa_pack_sk(uint8_t *sk,
                        const uint8_t rho[PQC_MLDSA_SEEDBYTES],
                        const uint8_t tr[PQC_MLDSA_TRBYTES],
                        const uint8_t K[PQC_MLDSA_SEEDBYTES],
                        const pqc_mldsa_polyveck *t0,
                        const pqc_mldsa_polyvecl *s1,
                        const pqc_mldsa_polyveck *s2,
                        const pqc_mldsa_params_t *params);

void pqc_mldsa_unpack_sk(uint8_t rho[PQC_MLDSA_SEEDBYTES],
                          uint8_t tr[PQC_MLDSA_TRBYTES],
                          uint8_t K[PQC_MLDSA_SEEDBYTES],
                          pqc_mldsa_polyveck *t0,
                          pqc_mldsa_polyvecl *s1,
                          pqc_mldsa_polyveck *s2,
                          const uint8_t *sk,
                          const pqc_mldsa_params_t *params);

/* ------------------------------------------------------------------ */
/* Signature packing: sig = c_tilde || z || h                           */
/* ------------------------------------------------------------------ */

void pqc_mldsa_pack_sig(uint8_t *sig,
                         const uint8_t *ctilde,
                         const pqc_mldsa_polyvecl *z,
                         const pqc_mldsa_polyveck *h,
                         const pqc_mldsa_params_t *params);

int pqc_mldsa_unpack_sig(uint8_t *ctilde,
                          pqc_mldsa_polyvecl *z,
                          pqc_mldsa_polyveck *h,
                          const uint8_t *sig,
                          const pqc_mldsa_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_PACKING_H */
