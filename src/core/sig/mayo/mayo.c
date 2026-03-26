/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * MAYO multivariate signature scheme - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t mayo_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mayo_stub_sign(uint8_t *sig, size_t *siglen,
                                    const uint8_t *msg, size_t msglen,
                                    const uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mayo_stub_verify(const uint8_t *msg, size_t msglen,
                                      const uint8_t *sig, size_t siglen,
                                      const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* MAYO-1: n=66, m=64, o=8, k=9, q=16 */
static const pqc_sig_vtable_t mayo1_vtable = {
    .algorithm_name     = PQC_SIG_MAYO_1,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "MAYO (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 1168,
    .secret_key_size    = 24,
    .max_signature_size = 321,
    .keygen  = mayo_stub_keygen,
    .sign    = mayo_stub_sign,
    .verify  = mayo_stub_verify,
    .sign_stateful = NULL,
};

/* MAYO-2: n=78, m=64, o=18, k=4, q=16 */
static const pqc_sig_vtable_t mayo2_vtable = {
    .algorithm_name     = PQC_SIG_MAYO_2,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "MAYO (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 5488,
    .secret_key_size    = 24,
    .max_signature_size = 180,
    .keygen  = mayo_stub_keygen,
    .sign    = mayo_stub_sign,
    .verify  = mayo_stub_verify,
    .sign_stateful = NULL,
};

/* MAYO-3: n=99, m=96, o=10, k=11, q=16 */
static const pqc_sig_vtable_t mayo3_vtable = {
    .algorithm_name     = PQC_SIG_MAYO_3,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "MAYO (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 2656,
    .secret_key_size    = 32,
    .max_signature_size = 577,
    .keygen  = mayo_stub_keygen,
    .sign    = mayo_stub_sign,
    .verify  = mayo_stub_verify,
    .sign_stateful = NULL,
};

/* MAYO-5: n=133, m=128, o=12, k=12, q=16 */
static const pqc_sig_vtable_t mayo5_vtable = {
    .algorithm_name     = PQC_SIG_MAYO_5,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "MAYO (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 5008,
    .secret_key_size    = 40,
    .max_signature_size = 838,
    .keygen  = mayo_stub_keygen,
    .sign    = mayo_stub_sign,
    .verify  = mayo_stub_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_mayo_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&mayo1_vtable);
    rc |= pqc_sig_add_vtable(&mayo2_vtable);
    rc |= pqc_sig_add_vtable(&mayo3_vtable);
    rc |= pqc_sig_add_vtable(&mayo5_vtable);
    return rc;
}
