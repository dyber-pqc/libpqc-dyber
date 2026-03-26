/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Field arithmetic for NIST P-256.
 * p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 * 4-limb 64-bit representation.
 */

#ifndef PQC_FIELD_P256_H
#define PQC_FIELD_P256_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Field element: 4 x 64-bit limbs, little-endian (limb[0] is least significant) */
typedef uint64_t p256_fe[4];

/* The prime p for P-256 */
extern const p256_fe P256_P;

/* The curve order n for P-256 */
extern const p256_fe P256_N;

/* Load/store */
void p256_fe_frombytes(p256_fe h, const uint8_t s[32]);
void p256_fe_tobytes(uint8_t s[32], const p256_fe h);

/* Constants */
void p256_fe_zero(p256_fe h);
void p256_fe_one(p256_fe h);
void p256_fe_copy(p256_fe h, const p256_fe f);

/* Arithmetic mod p */
void p256_fe_add(p256_fe h, const p256_fe f, const p256_fe g);
void p256_fe_sub(p256_fe h, const p256_fe f, const p256_fe g);
void p256_fe_mul(p256_fe h, const p256_fe f, const p256_fe g);
void p256_fe_sq(p256_fe h, const p256_fe f);
void p256_fe_inv(p256_fe h, const p256_fe f);
void p256_fe_neg(p256_fe h, const p256_fe f);

/* Comparison */
int p256_fe_is_zero(const p256_fe f);
int p256_fe_cmp(const p256_fe f, const p256_fe g);

/* Conditional operations */
void p256_fe_cmov(p256_fe f, const p256_fe g, uint64_t b);

/* Scalar arithmetic mod n (group order) */
void p256_scalar_frombytes(p256_fe h, const uint8_t s[32]);
void p256_scalar_tobytes(uint8_t s[32], const p256_fe h);
void p256_scalar_mul(p256_fe h, const p256_fe f, const p256_fe g);
void p256_scalar_add(p256_fe h, const p256_fe f, const p256_fe g);
void p256_scalar_inv(p256_fe h, const p256_fe f);

/* Point on P-256 in Jacobian coordinates (X, Y, Z) where x=X/Z^2, y=Y/Z^3 */
typedef struct {
    p256_fe X;
    p256_fe Y;
    p256_fe Z;
} p256_point;

/* Point operations */
void p256_point_zero(p256_point *p);
int  p256_point_is_zero(const p256_point *p);
void p256_point_double(p256_point *r, const p256_point *p);
void p256_point_add(p256_point *r, const p256_point *p, const p256_point *q);
void p256_point_scalar_mult(p256_point *r, const uint8_t k[32],
                             const p256_point *p);
void p256_point_scalar_mult_base(p256_point *r, const uint8_t k[32]);
int  p256_point_encode(uint8_t out[65], const p256_point *p);
int  p256_point_decode(p256_point *p, const uint8_t in[65]);

/* Affine recovery */
void p256_point_to_affine(uint8_t x[32], uint8_t y[32], const p256_point *p);

#ifdef __cplusplus
}
#endif

#endif /* PQC_FIELD_P256_H */
