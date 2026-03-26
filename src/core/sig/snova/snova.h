/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SNOVA internal interface.
 */

#ifndef PQC_SNOVA_H
#define PQC_SNOVA_H

#include <stddef.h>
#include <stdint.h>

#include "snova_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    int v;          /* vinegar ring-variables    */
    int o;          /* oil ring-variables (= m)  */
    int n;          /* total ring-variables      */
    int l;          /* ring dimension (l x l)    */
    size_t pk_len;
    size_t sk_len;
    size_t sig_len;
    int seed_len;
} snova_params_t;

/* ------------------------------------------------------------------ */
/* GF(16) arithmetic (reuse from ring.c)                                */
/* ------------------------------------------------------------------ */

uint8_t snova_gf16_add(uint8_t a, uint8_t b);
uint8_t snova_gf16_mul(uint8_t a, uint8_t b);
uint8_t snova_gf16_inv(uint8_t a);

/* ------------------------------------------------------------------ */
/* Ring operations (ring.c)                                             */
/* Non-commutative ring = l x l matrices over GF(16)                    */
/* ------------------------------------------------------------------ */

void snova_ring_add(uint8_t *c, const uint8_t *a, const uint8_t *b, int l);
void snova_ring_mul(uint8_t *c, const uint8_t *a, const uint8_t *b, int l);
void snova_ring_zero(uint8_t *a, int l);
void snova_ring_identity(uint8_t *a, int l);
int  snova_ring_inv(uint8_t *out, const uint8_t *in, int l);

/* ------------------------------------------------------------------ */
/* Block matrix operations (matrix.c)                                   */
/* ------------------------------------------------------------------ */

void snova_block_mat_mul(uint8_t *C, const uint8_t *A, const uint8_t *B,
                         int rows_a, int cols_a, int cols_b, int l);
int  snova_block_gauss_elim(uint8_t *mat, int rows, int cols, int l);

#ifdef __cplusplus
}
#endif

#endif /* PQC_SNOVA_H */
