/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hybrid KEM schemes (PQC + classical) - stub implementation.
 *
 * Hybrid KEMs combine a post-quantum KEM with a classical key agreement.
 * The combined shared secret is derived from both components so that
 * security holds even if one primitive is broken.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t hybrid_mlkem768_x25519_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t hybrid_mlkem768_x25519_encaps(uint8_t *ct, uint8_t *ss,
                                                    const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t hybrid_mlkem768_x25519_decaps(uint8_t *ss, const uint8_t *ct,
                                                    const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t hybrid_mlkem1024_p256_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t hybrid_mlkem1024_p256_encaps(uint8_t *ct, uint8_t *ss,
                                                   const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t hybrid_mlkem1024_p256_decaps(uint8_t *ss, const uint8_t *ct,
                                                   const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/*
 * ML-KEM-768 + X25519:
 * pk = ML-KEM-768 pk (1184) + X25519 pk (32) = 1216
 * sk = ML-KEM-768 sk (2400) + X25519 sk (32) = 2432
 * ct = ML-KEM-768 ct (1088) + X25519 ephemeral pk (32) = 1120
 * ss = 64 (KDF output from both shared secrets)
 */
static const pqc_kem_vtable_t hybrid_mlkem768_x25519_vtable = {
    .algorithm_name    = PQC_KEM_HYBRID_MLKEM768_X25519,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "Hybrid (FIPS 203 + RFC 7748)",
    .public_key_size   = 1216,
    .secret_key_size   = 2432,
    .ciphertext_size   = 1120,
    .shared_secret_size = 64,
    .keygen = hybrid_mlkem768_x25519_keygen,
    .encaps = hybrid_mlkem768_x25519_encaps,
    .decaps = hybrid_mlkem768_x25519_decaps,
};

/*
 * ML-KEM-1024 + P-256 (ECDH):
 * pk = ML-KEM-1024 pk (1568) + P-256 uncompressed pk (65) = 1633
 * sk = ML-KEM-1024 sk (3168) + P-256 sk (65) = 3233
 * ct = ML-KEM-1024 ct (1568) + P-256 ephemeral pk (65) = 1633
 * ss = 64 (KDF output from both shared secrets)
 */
static const pqc_kem_vtable_t hybrid_mlkem1024_p256_vtable = {
    .algorithm_name    = PQC_KEM_HYBRID_MLKEM1024_P256,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "Hybrid (FIPS 203 + FIPS 186-5)",
    .public_key_size   = 1633,
    .secret_key_size   = 3233,
    .ciphertext_size   = 1633,
    .shared_secret_size = 64,
    .keygen = hybrid_mlkem1024_p256_keygen,
    .encaps = hybrid_mlkem1024_p256_encaps,
    .decaps = hybrid_mlkem1024_p256_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_hybrid_kem_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&hybrid_mlkem768_x25519_vtable);
    rc |= pqc_kem_add_vtable(&hybrid_mlkem1024_p256_vtable);
    return rc;
}
