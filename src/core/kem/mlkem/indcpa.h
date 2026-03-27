/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * IND-CPA-secure public-key encryption (K-PKE) for ML-KEM (FIPS 203).
 *
 * This is the inner PKE that the Fujisaki-Okamoto transform in mlkem.c
 * wraps to achieve IND-CCA2 security.
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#ifndef PQC_MLKEM_INDCPA_H
#define PQC_MLKEM_INDCPA_H

#include <stdint.h>

#include "core/kem/mlkem/mlkem_params.h"
#include "core/kem/mlkem/polyvec.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate the matrix A (or A^T) from a seed.
 * This is exposed for benchmarking; normally only used internally.
 *
 * @param a          Output: array of k polyvecs (k x k matrix in NTT domain)
 * @param seed       Input: public seed rho (PQC_MLKEM_SYMBYTES bytes)
 * @param k          Module rank (2, 3, or 4)
 * @param transposed If nonzero, generate A^T instead of A
 */
void pqc_mlkem_gen_matrix(pqc_mlkem_polyvec *a,
                           const uint8_t seed[PQC_MLKEM_SYMBYTES],
                           unsigned int k,
                           int transposed);

/**
 * K-PKE.KeyGen (deterministic, from coins).
 *
 * @param pk     Output: public key  (params->indcpa_pk_bytes bytes).
 * @param sk     Output: secret key  (params->indcpa_sk_bytes bytes).
 * @param coins  Input: 32-byte randomness seed d.
 * @param params Parameter set descriptor.
 */
void pqc_mlkem_indcpa_keypair_derand(uint8_t *pk,
                                      uint8_t *sk,
                                      const uint8_t coins[PQC_MLKEM_SYMBYTES],
                                      const pqc_mlkem_params_t *params);

/**
 * K-PKE.Encrypt (Algorithm 13 in FIPS 203).
 *
 * @param ct      Output: ciphertext (params->indcpa_bytes bytes).
 * @param msg     Input:  32-byte message (the pre-shared-secret m).
 * @param pk      Input:  public key.
 * @param coins   Input:  32-byte random coins (deterministic encryption).
 * @param params  Parameter set descriptor.
 */
void pqc_mlkem_indcpa_enc(uint8_t *ct,
                           const uint8_t msg[PQC_MLKEM_SYMBYTES],
                           const uint8_t *pk,
                           const uint8_t coins[PQC_MLKEM_SYMBYTES],
                           const pqc_mlkem_params_t *params);

/**
 * K-PKE.Decrypt (Algorithm 14 in FIPS 203).
 *
 * @param msg     Output: 32-byte recovered message.
 * @param ct      Input:  ciphertext.
 * @param sk      Input:  secret key.
 * @param params  Parameter set descriptor.
 */
void pqc_mlkem_indcpa_dec(uint8_t msg[PQC_MLKEM_SYMBYTES],
                           const uint8_t *ct,
                           const uint8_t *sk,
                           const pqc_mlkem_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_INDCPA_H */
