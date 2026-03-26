/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * UOV (Unbalanced Oil and Vinegar) signature - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t uov_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t uov_stub_sign(uint8_t *sig, size_t *siglen,
                                   const uint8_t *msg, size_t msglen,
                                   const uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t uov_stub_verify(const uint8_t *msg, size_t msglen,
                                     const uint8_t *sig, size_t siglen,
                                     const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* UOV-Is: (v,o,q) = (112,44,256), Level 1 */
static const pqc_sig_vtable_t uov_is_vtable = {
    .algorithm_name     = PQC_SIG_UOV_I,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "UOV (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 278432,
    .secret_key_size    = 237896,
    .max_signature_size = 96,
    .keygen  = uov_stub_keygen,
    .sign    = uov_stub_sign,
    .verify  = uov_stub_verify,
    .sign_stateful = NULL,
};

/* UOV-IIIs: (v,o,q) = (160,64,256), Level 3 */
static const pqc_sig_vtable_t uov_iiis_vtable = {
    .algorithm_name     = PQC_SIG_UOV_III,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "UOV (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 1225440,
    .secret_key_size    = 1044320,
    .max_signature_size = 200,
    .keygen  = uov_stub_keygen,
    .sign    = uov_stub_sign,
    .verify  = uov_stub_verify,
    .sign_stateful = NULL,
};

/* UOV-Vs: (v,o,q) = (184,72,256), Level 5 */
static const pqc_sig_vtable_t uov_vs_vtable = {
    .algorithm_name     = PQC_SIG_UOV_V,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "UOV (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 2869440,
    .secret_key_size    = 2436704,
    .max_signature_size = 260,
    .keygen  = uov_stub_keygen,
    .sign    = uov_stub_sign,
    .verify  = uov_stub_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_uov_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&uov_is_vtable);
    rc |= pqc_sig_add_vtable(&uov_iiis_vtable);
    rc |= pqc_sig_add_vtable(&uov_vs_vtable);
    return rc;
}
