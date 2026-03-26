/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU internal interface.
 */

#ifndef PQC_NTRU_H
#define PQC_NTRU_H

#include <stddef.h>
#include <stdint.h>

#include "ntru_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Polynomial representation                                           */
/* coeffs[0..n-1] in Z_q, stored as int16_t                           */
/* ------------------------------------------------------------------ */

typedef struct {
    int16_t coeffs[NTRU_MAX_N];
} ntru_poly_t;

/* ------------------------------------------------------------------ */
/* Polynomial operations  (poly.c)                                     */
/* ------------------------------------------------------------------ */

void ntru_poly_zero(ntru_poly_t *r);
void ntru_poly_copy(ntru_poly_t *r, const ntru_poly_t *a);

/* r = a + b in Z_q[x]/(x^n - 1) */
void ntru_poly_add(ntru_poly_t *r, const ntru_poly_t *a,
                   const ntru_poly_t *b, const ntru_params_t *p);

/* r = a - b in Z_q[x]/(x^n - 1) */
void ntru_poly_sub(ntru_poly_t *r, const ntru_poly_t *a,
                   const ntru_poly_t *b, const ntru_params_t *p);

/* r = a * b in Z_q[x]/(x^n - 1) */
void ntru_poly_mul(ntru_poly_t *r, const ntru_poly_t *a,
                   const ntru_poly_t *b, const ntru_params_t *p);

/* Reduce coefficients mod q to [-q/2, q/2) */
void ntru_poly_mod_q(ntru_poly_t *r, const ntru_params_t *p);

/* Reduce coefficients mod 3 to {-1, 0, 1} */
void ntru_poly_mod3(ntru_poly_t *r, int n);

/* Lift: from mod-3 to centered representation */
void ntru_poly_lift(ntru_poly_t *r, int n);

/* Inverse of f in Z_q[x]/(x^n - 1) (returns 0 on success, -1 if not invertible) */
int ntru_poly_inv_mod_q(ntru_poly_t *r, const ntru_poly_t *f,
                        const ntru_params_t *p);

/* Inverse of f in Z_3[x]/(x^n - 1) */
int ntru_poly_inv_mod3(ntru_poly_t *r, const ntru_poly_t *f, int n);

/* ------------------------------------------------------------------ */
/* OWCPA  (owcpa.c)                                                    */
/* ------------------------------------------------------------------ */

int ntru_owcpa_keygen(uint8_t *pk, uint8_t *sk,
                      const ntru_params_t *p);

int ntru_owcpa_encrypt(uint8_t *ct, const ntru_poly_t *r,
                       const ntru_poly_t *m, const uint8_t *pk,
                       const ntru_params_t *p);

int ntru_owcpa_decrypt(ntru_poly_t *m, const uint8_t *ct,
                       const uint8_t *sk, const ntru_params_t *p);

/* ------------------------------------------------------------------ */
/* Pack/unpack  (pack.c)                                               */
/* ------------------------------------------------------------------ */

void ntru_pack_poly_q(uint8_t *out, const ntru_poly_t *a,
                      const ntru_params_t *p);
void ntru_unpack_poly_q(ntru_poly_t *r, const uint8_t *in,
                        const ntru_params_t *p);

void ntru_pack_trits(uint8_t *out, const ntru_poly_t *a, int n);
void ntru_unpack_trits(ntru_poly_t *r, const uint8_t *in, int n);

/* ------------------------------------------------------------------ */
/* Sampling  (sample.c)                                                */
/* ------------------------------------------------------------------ */

/* Sample ternary polynomial of fixed weight (HPS) */
void ntru_sample_fixed_weight(ntru_poly_t *r, const uint8_t *seed,
                              size_t seedlen, int n, int weight);

/* Sample ternary polynomial (HRSS) */
void ntru_sample_ternary(ntru_poly_t *r, const uint8_t *seed,
                         size_t seedlen, int n);

/* Sample uniform polynomial mod q */
void ntru_sample_uniform(ntru_poly_t *r, const uint8_t *seed,
                         size_t seedlen, const ntru_params_t *p);

#ifdef __cplusplus
}
#endif

#endif /* PQC_NTRU_H */
