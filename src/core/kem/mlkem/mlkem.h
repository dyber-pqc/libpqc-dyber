/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-KEM (FIPS 203) - Module-Lattice-Based Key-Encapsulation Mechanism.
 *
 * Public interface for ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
 */

#ifndef PQC_MLKEM_H
#define PQC_MLKEM_H

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "core/kem/mlkem/mlkem_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  ML-KEM.KeyGen (Algorithm 16 in FIPS 203)                            */
/* ------------------------------------------------------------------ */

/**
 * Generate an ML-KEM keypair.
 *
 * @param params  One of &PQC_MLKEM_512, &PQC_MLKEM_768, &PQC_MLKEM_1024.
 * @param pk      Output: public key  (params->pk_bytes bytes).
 * @param sk      Output: secret key  (params->sk_bytes bytes).
 *
 * @return PQC_OK on success, or a negative error code.
 *
 * The secret key layout is:
 *   sk_pke || pk || H(pk) || z
 * where z is used for implicit rejection in decapsulation.
 */
pqc_status_t pqc_mlkem_keygen(const pqc_mlkem_params_t *params,
                               uint8_t *pk,
                               uint8_t *sk);

/* ------------------------------------------------------------------ */
/*  ML-KEM.Encaps (Algorithm 17 in FIPS 203)                            */
/* ------------------------------------------------------------------ */

/**
 * Encapsulate: produce a ciphertext and shared secret from a public key.
 *
 * @param params  Parameter set.
 * @param ct      Output: ciphertext   (params->ct_bytes bytes).
 * @param ss      Output: shared secret (params->ss_bytes = 32 bytes).
 * @param pk      Input:  public key.
 *
 * @return PQC_OK on success.
 */
pqc_status_t pqc_mlkem_encaps(const pqc_mlkem_params_t *params,
                               uint8_t *ct,
                               uint8_t *ss,
                               const uint8_t *pk);

/* ------------------------------------------------------------------ */
/*  ML-KEM.Decaps (Algorithm 18 in FIPS 203)                            */
/* ------------------------------------------------------------------ */

/**
 * Decapsulate: recover a shared secret from a ciphertext and secret key.
 *
 * Uses the Fujisaki-Okamoto transform with implicit rejection:
 * if the ciphertext does not match re-encryption, the output is
 * a pseudorandom value derived from z and the ciphertext, so that
 * the caller cannot distinguish failure from success (IND-CCA2).
 *
 * @param params  Parameter set.
 * @param ss      Output: shared secret (params->ss_bytes = 32 bytes).
 * @param ct      Input:  ciphertext.
 * @param sk      Input:  secret key.
 *
 * @return PQC_OK always (implicit rejection, no observable failure).
 */
pqc_status_t pqc_mlkem_decaps(const pqc_mlkem_params_t *params,
                               uint8_t *ss,
                               const uint8_t *ct,
                               const uint8_t *sk);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_H */
