/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU Prime internal interface.
 */

#ifndef PQC_NTRUPRIME_H
#define PQC_NTRUPRIME_H

#include <stddef.h>
#include <stdint.h>

#include "ntruprime_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Polynomial types                                                    */
/* ------------------------------------------------------------------ */

/* Polynomial in Rq = Z_q[x]/(x^p - x - 1) */
typedef struct {
    int16_t coeffs[SNTRUP_MAX_P];
} rq_poly_t;

/* Small polynomial in R3 = F_3[x]/(x^p - x - 1), coeffs in {-1,0,1} */
typedef struct {
    int8_t coeffs[SNTRUP_MAX_P];
} r3_poly_t;

/* ------------------------------------------------------------------ */
/* Rq arithmetic  (rq.c)                                               */
/* ------------------------------------------------------------------ */

void rq_zero(rq_poly_t *r);
void rq_copy(rq_poly_t *r, const rq_poly_t *a);

/* r = a + b in Rq */
void rq_add(rq_poly_t *r, const rq_poly_t *a, const rq_poly_t *b,
            const sntrup_params_t *p);

/* r = a - b in Rq */
void rq_sub(rq_poly_t *r, const rq_poly_t *a, const rq_poly_t *b,
            const sntrup_params_t *p);

/* r = a * b in Rq */
void rq_mul(rq_poly_t *r, const rq_poly_t *a, const rq_poly_t *b,
            const sntrup_params_t *p);

/* r = a * small in Rq (multiply Rq by R3) */
void rq_mul_small(rq_poly_t *r, const rq_poly_t *a, const r3_poly_t *b,
                  const sntrup_params_t *p);

/* r = reciprocal of a in Rq (returns 0 on success, -1 if not invertible) */
int rq_recip(rq_poly_t *r, const rq_poly_t *a, const sntrup_params_t *p);

/* r = reciprocal of small a in Rq */
int rq_recip_small(rq_poly_t *r, const r3_poly_t *a, const sntrup_params_t *p);

/* Round: map each coefficient to nearest multiple of 3 */
void rq_round(rq_poly_t *r, const rq_poly_t *a, const sntrup_params_t *p);

/* ------------------------------------------------------------------ */
/* R3 arithmetic  (r3.c)                                               */
/* ------------------------------------------------------------------ */

void r3_zero(r3_poly_t *r);

/* r = a + b in R3 */
void r3_add(r3_poly_t *r, const r3_poly_t *a, const r3_poly_t *b, int pp);

/* r = a * b in R3 */
void r3_mul(r3_poly_t *r, const r3_poly_t *a, const r3_poly_t *b, int pp);

/* r = reciprocal of a in R3 (returns 0 on success) */
int r3_recip(r3_poly_t *r, const r3_poly_t *a, int pp);

/* ------------------------------------------------------------------ */
/* Encoding  (encode.c)                                                */
/* ------------------------------------------------------------------ */

/* Encode Rq polynomial (rounded) */
void sntrup_encode_rq(uint8_t *out, const rq_poly_t *a,
                      const sntrup_params_t *p);

/* Decode Rq polynomial (rounded) */
void sntrup_decode_rq(rq_poly_t *r, const uint8_t *in,
                      const sntrup_params_t *p);

/* Encode small polynomial */
void sntrup_encode_small(uint8_t *out, const r3_poly_t *a, int pp);

/* Decode small polynomial */
void sntrup_decode_small(r3_poly_t *r, const uint8_t *in, int pp);

#ifdef __cplusplus
}
#endif

#endif /* PQC_NTRUPRIME_H */
