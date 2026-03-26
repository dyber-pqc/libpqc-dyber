/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hybrid signature schemes (PQC + classical) - stub implementation.
 *
 * Hybrid signatures concatenate a post-quantum signature with a
 * classical one.  Verification requires both to succeed.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t hybrid_sig_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t hybrid_sig_stub_sign(uint8_t *sig, size_t *siglen,
                                          const uint8_t *msg, size_t msglen,
                                          const uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t hybrid_sig_stub_verify(const uint8_t *msg, size_t msglen,
                                            const uint8_t *sig, size_t siglen,
                                            const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/*
 * ML-DSA-65 + Ed25519:
 * pk = ML-DSA-65 pk (1952) + Ed25519 pk (32) = 1984
 * sk = ML-DSA-65 sk (4032) + Ed25519 sk (32) = 4064
 * sig = ML-DSA-65 sig (3309) + Ed25519 sig (64) = 3373
 */
static const pqc_sig_vtable_t hybrid_mldsa65_ed25519_vtable = {
    .algorithm_name     = PQC_SIG_HYBRID_MLDSA65_ED25519,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "Hybrid (FIPS 204 + EdDSA)",
    .is_stateful        = 0,
    .public_key_size    = 1984,
    .secret_key_size    = 4064,
    .max_signature_size = 3373,
    .keygen  = hybrid_sig_stub_keygen,
    .sign    = hybrid_sig_stub_sign,
    .verify  = hybrid_sig_stub_verify,
    .sign_stateful = NULL,
};

/*
 * ML-DSA-87 + ECDSA-P256:
 * pk = ML-DSA-87 pk (2592) + P-256 uncompressed pk (64) = 2656
 * sk = ML-DSA-87 sk (4896) + P-256 sk (64) = 4960
 * sig = ML-DSA-87 sig (4627) + ECDSA-P256 sig (64) = 4691
 */
static const pqc_sig_vtable_t hybrid_mldsa87_p256_vtable = {
    .algorithm_name     = PQC_SIG_HYBRID_MLDSA87_P256,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "Hybrid (FIPS 204 + FIPS 186-5)",
    .is_stateful        = 0,
    .public_key_size    = 2656,
    .secret_key_size    = 4960,
    .max_signature_size = 4691,
    .keygen  = hybrid_sig_stub_keygen,
    .sign    = hybrid_sig_stub_sign,
    .verify  = hybrid_sig_stub_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_hybrid_sig_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&hybrid_mldsa65_ed25519_vtable);
    rc |= pqc_sig_add_vtable(&hybrid_mldsa87_p256_vtable);
    return rc;
}
