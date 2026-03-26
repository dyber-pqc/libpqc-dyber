/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SNOVA (Symmetric-key-based Non-linear multivariate scheme Over
 * Vinegar-like Algebra) signature - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t snova_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t snova_stub_sign(uint8_t *sig, size_t *siglen,
                                     const uint8_t *msg, size_t msglen,
                                     const uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t snova_stub_verify(const uint8_t *msg, size_t msglen,
                                       const uint8_t *sig, size_t siglen,
                                       const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* SNOVA-24-5-4: v=24, o=5, l=4, q=16, Level 1 */
static const pqc_sig_vtable_t snova_24_5_4_vtable = {
    .algorithm_name     = PQC_SIG_SNOVA_24_5_4,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "SNOVA (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 1016,
    .secret_key_size    = 48,
    .max_signature_size = 100,
    .keygen  = snova_stub_keygen,
    .sign    = snova_stub_sign,
    .verify  = snova_stub_verify,
    .sign_stateful = NULL,
};

/* SNOVA-25-8-3: v=25, o=8, l=3, q=16, Level 3 */
static const pqc_sig_vtable_t snova_25_8_3_vtable = {
    .algorithm_name     = PQC_SIG_SNOVA_25_8_3,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "SNOVA (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 1400,
    .secret_key_size    = 48,
    .max_signature_size = 164,
    .keygen  = snova_stub_keygen,
    .sign    = snova_stub_sign,
    .verify  = snova_stub_verify,
    .sign_stateful = NULL,
};

/* SNOVA-28-17-3: v=28, o=17, l=3, q=16, Level 5 */
static const pqc_sig_vtable_t snova_28_17_3_vtable = {
    .algorithm_name     = PQC_SIG_SNOVA_28_17_3,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "SNOVA (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 5872,
    .secret_key_size    = 64,
    .max_signature_size = 580,
    .keygen  = snova_stub_keygen,
    .sign    = snova_stub_sign,
    .verify  = snova_stub_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_snova_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&snova_24_5_4_vtable);
    rc |= pqc_sig_add_vtable(&snova_25_8_3_vtable);
    rc |= pqc_sig_add_vtable(&snova_28_17_3_vtable);
    return rc;
}
