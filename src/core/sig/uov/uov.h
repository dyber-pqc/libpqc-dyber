/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * UOV internal interface.
 */

#ifndef PQC_UOV_H
#define PQC_UOV_H

#include <stddef.h>
#include <stdint.h>

#include "uov_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    int n;          /* total variables (v + o)   */
    int v;          /* vinegar variables         */
    int o;          /* oil variables (= m)       */
    size_t pk_len;
    size_t sk_len;
    size_t sig_len;
    int seed_len;   /* PRNG seed length          */
} uov_params_t;

/* ------------------------------------------------------------------ */
/* GF(256) arithmetic (gf256.c)                                         */
/* ------------------------------------------------------------------ */

uint8_t gf256_add(uint8_t a, uint8_t b);
uint8_t gf256_mul(uint8_t a, uint8_t b);
uint8_t gf256_inv(uint8_t a);

/* ------------------------------------------------------------------ */
/* Multivariate quadratic operations (mq.c)                             */
/* ------------------------------------------------------------------ */

void uov_mq_evaluate(uint8_t *result, const uint8_t *P,
                      const uint8_t *x, int n, int m);

/* ------------------------------------------------------------------ */
/* Key generation (keygen.c)                                            */
/* ------------------------------------------------------------------ */

void uov_expand_sk(uint8_t *central_map, uint8_t *T,
                   const uint8_t *sk_seed, const uov_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* PQC_UOV_H */
