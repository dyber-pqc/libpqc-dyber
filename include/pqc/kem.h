/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Unified Key Encapsulation Mechanism (KEM) API.
 */

#ifndef PQC_KEM_H
#define PQC_KEM_H

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* KEM context                                                                 */
/* -------------------------------------------------------------------------- */

typedef struct pqc_kem_s PQC_KEM;

/* Create a new KEM context for the specified algorithm */
PQC_API PQC_KEM *pqc_kem_new(const char *algorithm);

/* Free a KEM context (zeroizes internal state) */
PQC_API void pqc_kem_free(PQC_KEM *kem);

/* -------------------------------------------------------------------------- */
/* KEM properties                                                              */
/* -------------------------------------------------------------------------- */

PQC_API const char *pqc_kem_algorithm(const PQC_KEM *kem);
PQC_API size_t pqc_kem_public_key_size(const PQC_KEM *kem);
PQC_API size_t pqc_kem_secret_key_size(const PQC_KEM *kem);
PQC_API size_t pqc_kem_ciphertext_size(const PQC_KEM *kem);
PQC_API size_t pqc_kem_shared_secret_size(const PQC_KEM *kem);
PQC_API pqc_security_level_t pqc_kem_security_level(const PQC_KEM *kem);

/* -------------------------------------------------------------------------- */
/* KEM operations                                                              */
/* -------------------------------------------------------------------------- */

/*
 * Generate a keypair.
 *   public_key: buffer of pqc_kem_public_key_size() bytes (output)
 *   secret_key: buffer of pqc_kem_secret_key_size() bytes (output)
 */
PQC_API pqc_status_t pqc_kem_keygen(const PQC_KEM *kem,
                                     uint8_t *public_key,
                                     uint8_t *secret_key);

/*
 * Encapsulate: generate shared secret and ciphertext from public key.
 *   ciphertext:    buffer of pqc_kem_ciphertext_size() bytes (output)
 *   shared_secret: buffer of pqc_kem_shared_secret_size() bytes (output)
 *   public_key:    the recipient's public key
 */
PQC_API pqc_status_t pqc_kem_encaps(const PQC_KEM *kem,
                                     uint8_t *ciphertext,
                                     uint8_t *shared_secret,
                                     const uint8_t *public_key);

/*
 * Decapsulate: recover shared secret from ciphertext using secret key.
 *   shared_secret: buffer of pqc_kem_shared_secret_size() bytes (output)
 *   ciphertext:    the ciphertext from encapsulation
 *   secret_key:    the recipient's secret key
 */
PQC_API pqc_status_t pqc_kem_decaps(const PQC_KEM *kem,
                                     uint8_t *shared_secret,
                                     const uint8_t *ciphertext,
                                     const uint8_t *secret_key);

#ifdef __cplusplus
}
#endif

#endif /* PQC_KEM_H */
