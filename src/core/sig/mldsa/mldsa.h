/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-DSA (FIPS 204) - Module-Lattice-Based Digital Signature Algorithm.
 * Public interface for key generation, signing, and verification.
 */

#ifndef PQC_MLDSA_H
#define PQC_MLDSA_H

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "core/sig/mldsa/mldsa_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generate an ML-DSA key pair.
 *
 * @param params  Parameter set (PQC_MLDSA_44, PQC_MLDSA_65, PQC_MLDSA_87).
 * @param pk      Output public key (params->pk_bytes).
 * @param sk      Output secret key (params->sk_bytes).
 * @return PQC_OK on success.
 */
pqc_status_t pqc_mldsa_keygen(const pqc_mldsa_params_t *params,
                               uint8_t *pk, uint8_t *sk);

/**
 * Generate an ML-DSA signature.
 *
 * @param params   Parameter set.
 * @param sig      Output signature buffer (params->sig_bytes).
 * @param siglen   Actual signature length written (output).
 * @param msg      Message to sign.
 * @param msglen   Length of message in bytes.
 * @param sk       Secret key.
 * @return PQC_OK on success.
 */
pqc_status_t pqc_mldsa_sign(const pqc_mldsa_params_t *params,
                             uint8_t *sig, size_t *siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *sk);

/**
 * Verify an ML-DSA signature.
 *
 * @param params   Parameter set.
 * @param msg      Message that was signed.
 * @param msglen   Length of message in bytes.
 * @param sig      Signature to verify.
 * @param siglen   Length of signature in bytes.
 * @param pk       Public key.
 * @return PQC_OK if valid, PQC_ERROR_VERIFICATION_FAILED otherwise.
 */
pqc_status_t pqc_mldsa_verify(const pqc_mldsa_params_t *params,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *sig, size_t siglen,
                               const uint8_t *pk);

/**
 * Register all ML-DSA variants with the signature vtable system.
 * Called during pqc_init().
 *
 * @return 0 on success, nonzero on failure.
 */
int pqc_sig_mldsa_register(void);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLDSA_H */
