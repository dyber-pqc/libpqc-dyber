/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FrodoKEM internal interface.
 */

#ifndef PQC_FRODO_H
#define PQC_FRODO_H

#include <stddef.h>
#include <stdint.h>
#include "frodo_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Matrix generation (matrix.c)                                         */
/* ------------------------------------------------------------------ */

/* Generate matrix A (n x n) from a seed using SHAKE-128 */
void frodo_gen_matrix_shake(uint16_t *A, uint32_t n,
                            const uint8_t *seed);

/* Generate matrix A (n x n) from a seed using AES-128-ECB */
void frodo_gen_matrix_aes(uint16_t *A, uint32_t n,
                          const uint8_t *seed);

/* Matrix multiply: C (rows_a x cols_b) = A (rows_a x inner) * B (inner x cols_b) mod q */
void frodo_matrix_mul(uint16_t *C,
                      const uint16_t *A, uint32_t rows_a, uint32_t inner,
                      const uint16_t *B, uint32_t cols_b,
                      uint32_t q);

/* Matrix add: C = A + B mod q, element-wise */
void frodo_matrix_add(uint16_t *C,
                      const uint16_t *A, const uint16_t *B,
                      uint32_t rows, uint32_t cols, uint32_t q);

/* Matrix subtract: C = A - B mod q */
void frodo_matrix_sub(uint16_t *C,
                      const uint16_t *A, const uint16_t *B,
                      uint32_t rows, uint32_t cols, uint32_t q);

/* Transpose: B (cols x rows) = A^T (rows x cols) */
void frodo_matrix_transpose(uint16_t *B, const uint16_t *A,
                            uint32_t rows, uint32_t cols);

/* ------------------------------------------------------------------ */
/* Noise sampling (noise.c)                                             */
/* ------------------------------------------------------------------ */

/* Sample a matrix (rows x cols) of noise from the CDF table using SHAKE256 */
void frodo_sample_noise(uint16_t *out, uint32_t rows, uint32_t cols,
                        const uint8_t *seed, size_t seedlen,
                        uint8_t nonce, uint32_t q,
                        const uint16_t *cdf, uint32_t cdf_len);

/* ------------------------------------------------------------------ */
/* Packing (pack.c)                                                     */
/* ------------------------------------------------------------------ */

/* Pack a matrix of q-bit coefficients into bytes */
void frodo_pack(uint8_t *out, const uint16_t *in,
                uint32_t n_elems, uint32_t log_q);

/* Unpack bytes into a matrix of q-bit coefficients */
void frodo_unpack(uint16_t *out, const uint8_t *in,
                  uint32_t n_elems, uint32_t log_q);

/* ------------------------------------------------------------------ */
/* Message encoding/decoding                                            */
/* ------------------------------------------------------------------ */

/* Encode message bits into n_bar x n_bar matrix (each entry in {0, q/2^B}) */
void frodo_encode(uint16_t *out, const uint8_t *msg,
                  uint32_t len_mu_bits, uint32_t b, uint32_t q);

/* Decode n_bar x n_bar matrix back to message bits */
void frodo_decode(uint8_t *msg, const uint16_t *in,
                  uint32_t len_mu_bits, uint32_t b, uint32_t q);

/* ------------------------------------------------------------------ */
/* Core KEM operations                                                  */
/* ------------------------------------------------------------------ */

void frodo_keygen_internal(uint8_t *pk, uint8_t *sk,
                           const frodo_params_t *params,
                           const uint16_t *cdf, uint32_t cdf_len);
void frodo_encaps_internal(uint8_t *ct, uint8_t *ss,
                           const uint8_t *pk,
                           const frodo_params_t *params,
                           const uint16_t *cdf, uint32_t cdf_len);
int  frodo_decaps_internal(uint8_t *ss, const uint8_t *ct,
                           const uint8_t *sk,
                           const frodo_params_t *params,
                           const uint16_t *cdf, uint32_t cdf_len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_FRODO_H */
