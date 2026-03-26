/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE internal interface.
 */

#ifndef PQC_BIKE_H
#define PQC_BIKE_H

#include <stddef.h>
#include <stdint.h>
#include "bike_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* GF(2)[x] / (x^r - 1) polynomial arithmetic (gf2x.c)                */
/* ------------------------------------------------------------------ */

/* o = a XOR b (addition in GF(2)) */
void bike_gf2x_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    uint32_t r_words);

/* o = a * b mod (x^r - 1) */
void bike_gf2x_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    uint32_t r);

/* o = a^{-1} mod (x^r - 1) in GF(2)[x], r prime */
int  bike_gf2x_inv(uint64_t *o, const uint64_t *a, uint32_t r);

/* Reduce mod (x^r - 1): clear bits >= r and fold */
void bike_gf2x_mod(uint64_t *a, uint32_t r);

/* ------------------------------------------------------------------ */
/* Bit-flipping decoder (decode.c)                                      */
/* ------------------------------------------------------------------ */

/* Black-Gray-Flip decoder.
 * Returns 0 on success (error vector found), -1 on decoding failure.
 * e0, e1 are output error vector halves (each r bits).
 * syndrome is H * c^T.
 * h0, h1 are the secret key polynomials. */
int bike_decode(uint64_t *e0, uint64_t *e1,
                const uint64_t *syndrome,
                const uint64_t *h0, const uint64_t *h1,
                const bike_params_t *params);

/* Compute syndrome s = e0*h0 + e1*h1 mod (x^r - 1) -- or equivalently
 * s = c0 + c1*h0 with the ciphertext interpretation. */
void bike_compute_syndrome(uint64_t *syndrome,
                           const uint64_t *c0, const uint64_t *c1,
                           const uint64_t *h0,
                           const bike_params_t *params);

/* ------------------------------------------------------------------ */
/* Sampling (sampling.c)                                                */
/* ------------------------------------------------------------------ */

/* Sample a polynomial with exactly 'weight' bits set, uniform positions */
void bike_sample_sparse(uint64_t *poly, uint32_t weight, uint32_t r,
                        const uint8_t *seed, size_t seedlen);

/* Sample a random error vector with weight t, split into (e0, e1) */
void bike_sample_error(uint64_t *e0, uint64_t *e1,
                       uint32_t t, uint32_t r,
                       const uint8_t *seed, size_t seedlen);

/* ------------------------------------------------------------------ */
/* Core KEM operations                                                  */
/* ------------------------------------------------------------------ */

void bike_keygen_internal(uint8_t *pk, uint8_t *sk,
                          const bike_params_t *params);
void bike_encaps_internal(uint8_t *ct, uint8_t *ss,
                          const uint8_t *pk,
                          const bike_params_t *params);
int  bike_decaps_internal(uint8_t *ss, const uint8_t *ct,
                          const uint8_t *sk,
                          const bike_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* PQC_BIKE_H */
