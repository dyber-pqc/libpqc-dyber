/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Seed expansion for ML-DSA (FIPS 204).
 */

#include "core/sig/mldsa/expand.h"
#include "core/sig/mldsa/poly.h"
#include "core/sig/mldsa/mldsa_params.h"

/* ------------------------------------------------------------------ */
/* ExpandA: generate matrix A from rho using SHAKE-128                  */
/* Each A[i][j] = SampleNTT(rho || j || i) (FIPS 204 Algorithm 26)     */
/* ------------------------------------------------------------------ */

void pqc_mldsa_expand_a(pqc_mldsa_poly *mat,
                         const uint8_t rho[PQC_MLDSA_SEEDBYTES],
                         unsigned k, unsigned l)
{
    unsigned i, j;
    uint16_t nonce;

    for (i = 0; i < k; i++) {
        for (j = 0; j < l; j++) {
            /* Nonce = (j << 8) | i per FIPS 204 */
            nonce = (uint16_t)((j << 8) | i);
            pqc_mldsa_poly_uniform(&mat[i * l + j], rho, nonce);
        }
    }
}

/* ------------------------------------------------------------------ */
/* ExpandS: generate secret vectors from rhoprime                       */
/* s[i] = SampleInBall(rhoprime, offset + i)                           */
/* ------------------------------------------------------------------ */

void pqc_mldsa_expand_s(pqc_mldsa_polyvecl *s,
                         const uint8_t seed[PQC_MLDSA_CRHBYTES],
                         unsigned eta, unsigned dim, unsigned offset)
{
    unsigned i;
    for (i = 0; i < dim; i++) {
        pqc_mldsa_poly_uniform_eta(&s->vec[i], seed,
                                    (uint16_t)(offset + i), eta);
    }
}

/* ------------------------------------------------------------------ */
/* ExpandMask: generate mask vector y from rhoprime                     */
/* ------------------------------------------------------------------ */

void pqc_mldsa_expand_mask(pqc_mldsa_polyvecl *y,
                            const uint8_t seed[PQC_MLDSA_CRHBYTES],
                            uint16_t kappa,
                            int32_t gamma1, unsigned l)
{
    unsigned i;
    for (i = 0; i < l; i++) {
        pqc_mldsa_poly_uniform_gamma1(&y->vec[i], seed,
                                       (uint16_t)(kappa + i), gamma1);
    }
}
