/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * MAYO internal interface.
 */

#ifndef PQC_MAYO_H
#define PQC_MAYO_H

#include <stddef.h>
#include <stdint.h>

#include "mayo_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* MAYO parameter set runtime structure                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    int n;          /* total variables       */
    int m;          /* equations             */
    int o;          /* oil variables         */
    int v;          /* vinegar variables     */
    int k;          /* whipping copies       */
    size_t pk_len;  /* public key bytes      */
    size_t sk_len;  /* secret key bytes      */
    size_t sig_len; /* signature bytes       */
    int seed_len;   /* seed length in bytes  */
} mayo_params_t;

/* ------------------------------------------------------------------ */
/* GF(16) arithmetic (gf16.c)                                           */
/* ------------------------------------------------------------------ */

uint8_t gf16_add(uint8_t a, uint8_t b);
uint8_t gf16_mul(uint8_t a, uint8_t b);
uint8_t gf16_inv(uint8_t a);

/* ------------------------------------------------------------------ */
/* Matrix operations over GF(16) (matrix_gf16.c)                       */
/*                                                                      */
/* Elements are packed: two nibbles per byte (high nibble first).        */
/* For odd-dimension rows the last byte uses only the high nibble.      */
/* "Unpacked" routines work on uint8_t arrays with one element each.    */
/* ------------------------------------------------------------------ */

void mayo_mat_mul(uint8_t *c, const uint8_t *a, const uint8_t *b,
                  int rows_a, int cols_a, int cols_b);
void mayo_mat_add(uint8_t *c, const uint8_t *a, const uint8_t *b, int rows, int cols);
int  mayo_mat_gauss_elim(uint8_t *mat, int rows, int cols);
void mayo_mat_transpose(uint8_t *out, const uint8_t *in, int rows, int cols);

/* ------------------------------------------------------------------ */
/* Oil space operations (oil.c)                                         */
/* ------------------------------------------------------------------ */

void mayo_compute_oil_space(uint8_t *oil, const uint8_t *sk_seed,
                            const mayo_params_t *params);

/* ------------------------------------------------------------------ */
/* Vinegar variable operations (vinegar.c)                              */
/* ------------------------------------------------------------------ */

void mayo_sample_vinegar(uint8_t *v_vals, int v_count,
                         const uint8_t *salt, size_t salt_len);
void mayo_vinegar_substitute(uint8_t *target, const uint8_t *P,
                             const uint8_t *v_vals,
                             const mayo_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MAYO_H */
