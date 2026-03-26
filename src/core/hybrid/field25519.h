/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Field arithmetic for Curve25519: GF(2^255 - 19).
 * 5-limb 51-bit representation.
 */

#ifndef PQC_FIELD25519_H
#define PQC_FIELD25519_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Field element: 5 limbs of up to 51 bits each */
typedef uint64_t fe25519[5];

/* Encode / decode */
void fe25519_frombytes(fe25519 h, const uint8_t s[32]);
void fe25519_tobytes(uint8_t s[32], const fe25519 h);

/* Constants */
void fe25519_0(fe25519 h);
void fe25519_1(fe25519 h);
void fe25519_copy(fe25519 h, const fe25519 f);

/* Arithmetic */
void fe25519_add(fe25519 h, const fe25519 f, const fe25519 g);
void fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g);
void fe25519_neg(fe25519 h, const fe25519 f);
void fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g);
void fe25519_sq(fe25519 h, const fe25519 f);
void fe25519_inv(fe25519 out, const fe25519 z);
void fe25519_pow2523(fe25519 out, const fe25519 z);
void fe25519_mul121666(fe25519 h, const fe25519 f);

/* Carry reduction */
void fe25519_reduce(fe25519 h, const fe25519 f);

/* Constant-time operations */
void fe25519_cswap(fe25519 f, fe25519 g, uint64_t b);
void fe25519_cmov(fe25519 f, const fe25519 g, uint64_t b);

/* Predicates */
int fe25519_isnegative(const fe25519 f);
int fe25519_iszero(const fe25519 f);

#ifdef __cplusplus
}
#endif

#endif /* PQC_FIELD25519_H */
