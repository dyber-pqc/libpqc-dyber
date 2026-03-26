/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * XMSS (eXtended Merkle Signature Scheme) - stateful hash-based
 * signature stub. RFC 8391 / NIST SP 800-208.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t xmss_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t xmss_stub_verify(const uint8_t *msg, size_t msglen,
                                      const uint8_t *sig, size_t siglen,
                                      const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t xmss_stub_sign_stateful(uint8_t *sig, size_t *siglen,
                                              const uint8_t *msg, size_t msglen,
                                              uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/*
 * XMSS-SHA2-10-256: h=10, n=32, w=16
 * pk = 64 bytes, sk = 2573 bytes (includes state), sig = 2500 bytes
 */
static const pqc_sig_vtable_t xmss_sha2_10_256_vtable = {
    .algorithm_name     = PQC_SIG_XMSS_SHA2_10_256,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = 64,
    .secret_key_size    = 2573,
    .max_signature_size = 2500,
    .keygen         = xmss_stub_keygen,
    .sign           = NULL,
    .verify         = xmss_stub_verify,
    .sign_stateful  = xmss_stub_sign_stateful,
};

/*
 * XMSS-SHA2-16-256: h=16, n=32, w=16
 * sig = 2692 bytes
 */
static const pqc_sig_vtable_t xmss_sha2_16_256_vtable = {
    .algorithm_name     = PQC_SIG_XMSS_SHA2_16_256,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = 64,
    .secret_key_size    = 2573,
    .max_signature_size = 2692,
    .keygen         = xmss_stub_keygen,
    .sign           = NULL,
    .verify         = xmss_stub_verify,
    .sign_stateful  = xmss_stub_sign_stateful,
};

/*
 * XMSS-SHA2-20-256: h=20, n=32, w=16
 * sig = 2820 bytes
 */
static const pqc_sig_vtable_t xmss_sha2_20_256_vtable = {
    .algorithm_name     = PQC_SIG_XMSS_SHA2_20_256,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = 64,
    .secret_key_size    = 2573,
    .max_signature_size = 2820,
    .keygen         = xmss_stub_keygen,
    .sign           = NULL,
    .verify         = xmss_stub_verify,
    .sign_stateful  = xmss_stub_sign_stateful,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_xmss_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&xmss_sha2_10_256_vtable);
    rc |= pqc_sig_add_vtable(&xmss_sha2_16_256_vtable);
    rc |= pqc_sig_add_vtable(&xmss_sha2_20_256_vtable);
    return rc;
}
