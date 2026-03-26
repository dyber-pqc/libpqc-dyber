/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * LMS (Leighton-Micali Signature) - stateful hash-based signature stub.
 * RFC 8554 / NIST SP 800-208.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t lms_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t lms_stub_verify(const uint8_t *msg, size_t msglen,
                                     const uint8_t *sig, size_t siglen,
                                     const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t lms_stub_sign_stateful(uint8_t *sig, size_t *siglen,
                                            const uint8_t *msg, size_t msglen,
                                            uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/*
 * LMS-SHA256-H10: tree height 10 (1024 signatures), n=32, w=8
 */
static const pqc_sig_vtable_t lms_sha256_h10_vtable = {
    .algorithm_name     = PQC_SIG_LMS_SHA256_H10,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = 56,
    .secret_key_size    = 64,
    .max_signature_size = 2644,
    .keygen         = lms_stub_keygen,
    .sign           = NULL,
    .verify         = lms_stub_verify,
    .sign_stateful  = lms_stub_sign_stateful,
};

/*
 * LMS-SHA256-H15: tree height 15 (32768 signatures)
 */
static const pqc_sig_vtable_t lms_sha256_h15_vtable = {
    .algorithm_name     = PQC_SIG_LMS_SHA256_H15,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = 56,
    .secret_key_size    = 64,
    .max_signature_size = 4012,
    .keygen         = lms_stub_keygen,
    .sign           = NULL,
    .verify         = lms_stub_verify,
    .sign_stateful  = lms_stub_sign_stateful,
};

/*
 * LMS-SHA256-H20: tree height 20 (1048576 signatures)
 */
static const pqc_sig_vtable_t lms_sha256_h20_vtable = {
    .algorithm_name     = PQC_SIG_LMS_SHA256_H20,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = 56,
    .secret_key_size    = 64,
    .max_signature_size = 5380,
    .keygen         = lms_stub_keygen,
    .sign           = NULL,
    .verify         = lms_stub_verify,
    .sign_stateful  = lms_stub_sign_stateful,
};

/*
 * LMS-SHA256-H25: tree height 25 (33554432 signatures)
 */
static const pqc_sig_vtable_t lms_sha256_h25_vtable = {
    .algorithm_name     = PQC_SIG_LMS_SHA256_H25,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = 56,
    .secret_key_size    = 64,
    .max_signature_size = 6748,
    .keygen         = lms_stub_keygen,
    .sign           = NULL,
    .verify         = lms_stub_verify,
    .sign_stateful  = lms_stub_sign_stateful,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_lms_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&lms_sha256_h10_vtable);
    rc |= pqc_sig_add_vtable(&lms_sha256_h15_vtable);
    rc |= pqc_sig_add_vtable(&lms_sha256_h20_vtable);
    rc |= pqc_sig_add_vtable(&lms_sha256_h25_vtable);
    return rc;
}
