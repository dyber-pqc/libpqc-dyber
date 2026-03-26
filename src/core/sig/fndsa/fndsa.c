/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206, formerly Falcon) - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t fndsa_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t fndsa_stub_sign(uint8_t *sig, size_t *siglen,
                                     const uint8_t *msg, size_t msglen,
                                     const uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t fndsa_stub_verify(const uint8_t *msg, size_t msglen,
                                       const uint8_t *sig, size_t siglen,
                                       const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* FN-DSA-512: n=512, q=12289 */
static const pqc_sig_vtable_t fndsa512_vtable = {
    .algorithm_name     = PQC_SIG_FN_DSA_512,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "FIPS 206",
    .is_stateful        = 0,
    .public_key_size    = 897,
    .secret_key_size    = 1281,
    .max_signature_size = 666,
    .keygen  = fndsa_stub_keygen,
    .sign    = fndsa_stub_sign,
    .verify  = fndsa_stub_verify,
    .sign_stateful = NULL,
};

/* FN-DSA-1024: n=1024, q=12289 */
static const pqc_sig_vtable_t fndsa1024_vtable = {
    .algorithm_name     = PQC_SIG_FN_DSA_1024,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "FIPS 206",
    .is_stateful        = 0,
    .public_key_size    = 1793,
    .secret_key_size    = 2305,
    .max_signature_size = 1280,
    .keygen  = fndsa_stub_keygen,
    .sign    = fndsa_stub_sign,
    .verify  = fndsa_stub_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_fndsa_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&fndsa512_vtable);
    rc |= pqc_sig_add_vtable(&fndsa1024_vtable);
    return rc;
}
