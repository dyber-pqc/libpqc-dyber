/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * CROSS (Codes and Restricted Objects Signature Scheme) - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t cross_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t cross_stub_sign(uint8_t *sig, size_t *siglen,
                                     const uint8_t *msg, size_t msglen,
                                     const uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t cross_stub_verify(const uint8_t *msg, size_t msglen,
                                       const uint8_t *sig, size_t siglen,
                                       const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* CROSS-RSDP-128-fast */
static const pqc_sig_vtable_t cross_rsdp_128_fast_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_128_FAST,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 77,
    .secret_key_size    = 32,
    .max_signature_size = 12912,
    .keygen  = cross_stub_keygen,
    .sign    = cross_stub_sign,
    .verify  = cross_stub_verify,
    .sign_stateful = NULL,
};

/* CROSS-RSDP-128-small */
static const pqc_sig_vtable_t cross_rsdp_128_small_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_128_SMALL,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 77,
    .secret_key_size    = 32,
    .max_signature_size = 9236,
    .keygen  = cross_stub_keygen,
    .sign    = cross_stub_sign,
    .verify  = cross_stub_verify,
    .sign_stateful = NULL,
};

/* CROSS-RSDP-192-fast */
static const pqc_sig_vtable_t cross_rsdp_192_fast_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_192_FAST,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 115,
    .secret_key_size    = 48,
    .max_signature_size = 23220,
    .keygen  = cross_stub_keygen,
    .sign    = cross_stub_sign,
    .verify  = cross_stub_verify,
    .sign_stateful = NULL,
};

/* CROSS-RSDP-192-small */
static const pqc_sig_vtable_t cross_rsdp_192_small_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_192_SMALL,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 115,
    .secret_key_size    = 48,
    .max_signature_size = 16308,
    .keygen  = cross_stub_keygen,
    .sign    = cross_stub_sign,
    .verify  = cross_stub_verify,
    .sign_stateful = NULL,
};

/* CROSS-RSDP-256-fast */
static const pqc_sig_vtable_t cross_rsdp_256_fast_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_256_FAST,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 153,
    .secret_key_size    = 64,
    .max_signature_size = 37088,
    .keygen  = cross_stub_keygen,
    .sign    = cross_stub_sign,
    .verify  = cross_stub_verify,
    .sign_stateful = NULL,
};

/* CROSS-RSDP-256-small */
static const pqc_sig_vtable_t cross_rsdp_256_small_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_256_SMALL,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = 153,
    .secret_key_size    = 64,
    .max_signature_size = 25564,
    .keygen  = cross_stub_keygen,
    .sign    = cross_stub_sign,
    .verify  = cross_stub_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_cross_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&cross_rsdp_128_fast_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_128_small_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_192_fast_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_192_small_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_256_fast_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_256_small_vtable);
    return rc;
}
