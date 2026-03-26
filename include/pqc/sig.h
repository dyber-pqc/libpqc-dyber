/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Unified Digital Signature API.
 */

#ifndef PQC_SIG_H
#define PQC_SIG_H

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Signature context                                                           */
/* -------------------------------------------------------------------------- */

typedef struct pqc_sig_s PQC_SIG;

/* Create a new signature context for the specified algorithm */
PQC_API PQC_SIG *pqc_sig_new(const char *algorithm);

/* Free a signature context (zeroizes internal state) */
PQC_API void pqc_sig_free(PQC_SIG *sig);

/* -------------------------------------------------------------------------- */
/* Signature properties                                                        */
/* -------------------------------------------------------------------------- */

PQC_API const char *pqc_sig_algorithm(const PQC_SIG *sig);
PQC_API size_t pqc_sig_public_key_size(const PQC_SIG *sig);
PQC_API size_t pqc_sig_secret_key_size(const PQC_SIG *sig);
PQC_API size_t pqc_sig_max_signature_size(const PQC_SIG *sig);
PQC_API pqc_security_level_t pqc_sig_security_level(const PQC_SIG *sig);
PQC_API int pqc_sig_is_stateful(const PQC_SIG *sig);

/* -------------------------------------------------------------------------- */
/* Signature operations                                                        */
/* -------------------------------------------------------------------------- */

/*
 * Generate a keypair.
 *   public_key: buffer of pqc_sig_public_key_size() bytes (output)
 *   secret_key: buffer of pqc_sig_secret_key_size() bytes (output)
 */
PQC_API pqc_status_t pqc_sig_keygen(const PQC_SIG *sig,
                                     uint8_t *public_key,
                                     uint8_t *secret_key);

/*
 * Sign a message.
 *   signature:     buffer of pqc_sig_max_signature_size() bytes (output)
 *   signature_len: actual signature length (output)
 *   message:       the message to sign
 *   message_len:   length of the message
 *   secret_key:    the signer's secret key
 */
PQC_API pqc_status_t pqc_sig_sign(const PQC_SIG *sig,
                                   uint8_t *signature,
                                   size_t *signature_len,
                                   const uint8_t *message,
                                   size_t message_len,
                                   const uint8_t *secret_key);

/*
 * Verify a signature.
 *   message:       the message that was signed
 *   message_len:   length of the message
 *   signature:     the signature to verify
 *   signature_len: length of the signature
 *   public_key:    the signer's public key
 *
 * Returns PQC_OK if valid, PQC_ERROR_VERIFICATION_FAILED if invalid.
 */
PQC_API pqc_status_t pqc_sig_verify(const PQC_SIG *sig,
                                     const uint8_t *message,
                                     size_t message_len,
                                     const uint8_t *signature,
                                     size_t signature_len,
                                     const uint8_t *public_key);

/*
 * Sign with stateful scheme (updates secret_key state).
 * Only valid for stateful algorithms (LMS, XMSS).
 * The secret_key is modified in-place to advance the state.
 */
PQC_API pqc_status_t pqc_sig_sign_stateful(const PQC_SIG *sig,
                                            uint8_t *signature,
                                            size_t *signature_len,
                                            const uint8_t *message,
                                            size_t message_len,
                                            uint8_t *secret_key);

#ifdef __cplusplus
}
#endif

#endif /* PQC_SIG_H */
