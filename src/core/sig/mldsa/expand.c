/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Seed expansion for ML-DSA (FIPS 204).
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
 */

#include "core/sig/mldsa/expand.h"
#include "core/sig/mldsa/poly.h"
#include "core/sig/mldsa/mldsa_params.h"

/* ------------------------------------------------------------------ */
/* ExpandS: generate secret vectors from rhoprime                       */
/* s[i] = SampleInBall(rhoprime, nonce + i)                            */
/* ------------------------------------------------------------------ */

void pqc_mldsa_expand_s(pqc_mldsa_polyvecl *s,
                         const uint8_t seed[PQC_MLDSA_CRHBYTES],
                         unsigned eta, unsigned dim, uint16_t nonce)
{
    unsigned int i;
    for (i = 0; i < dim; ++i) {
        pqc_mldsa_poly_uniform_eta(&s->vec[i], seed,
                                    (uint16_t)(nonce + i), eta);
    }
}

/* ------------------------------------------------------------------ */
/* ExpandMask: generate mask vector y from rhoprime                     */
/* Per reference: y[i] = SampleGamma1(rhoprime, L*nonce + i)           */
/* ------------------------------------------------------------------ */

void pqc_mldsa_expand_mask(pqc_mldsa_polyvecl *y,
                            const uint8_t seed[PQC_MLDSA_CRHBYTES],
                            uint16_t nonce,
                            int32_t gamma1, unsigned l)
{
    unsigned int i;
    for (i = 0; i < l; ++i) {
        pqc_mldsa_poly_uniform_gamma1(&y->vec[i], seed,
                                       (uint16_t)(l * nonce + i), gamma1);
    }
}
