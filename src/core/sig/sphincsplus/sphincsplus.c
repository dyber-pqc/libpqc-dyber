/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPHINCS+ signature scheme - stub implementation.
 * (Pre-standard version; SLH-DSA is the FIPS 205 successor.)
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t sphincs_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t sphincs_stub_sign(uint8_t *sig, size_t *siglen,
                                       const uint8_t *msg, size_t msglen,
                                       const uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t sphincs_stub_verify(const uint8_t *msg, size_t msglen,
                                         const uint8_t *sig, size_t siglen,
                                         const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables — 12 SPHINCS+ parameter sets                                 */
/* ------------------------------------------------------------------ */

static const pqc_sig_vtable_t sphincs_sha2_128s_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHA2_128S,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 32,
    .secret_key_size    = 64,
    .max_signature_size = 7856,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_sha2_128f_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHA2_128F,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 32,
    .secret_key_size    = 64,
    .max_signature_size = 17088,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_sha2_192s_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHA2_192S,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 48,
    .secret_key_size    = 96,
    .max_signature_size = 16224,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_sha2_192f_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHA2_192F,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 48,
    .secret_key_size    = 96,
    .max_signature_size = 35664,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_sha2_256s_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHA2_256S,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 64,
    .secret_key_size    = 128,
    .max_signature_size = 29792,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_sha2_256f_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHA2_256F,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 64,
    .secret_key_size    = 128,
    .max_signature_size = 49856,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_shake_128s_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHAKE_128S,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 32,
    .secret_key_size    = 64,
    .max_signature_size = 7856,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_shake_128f_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHAKE_128F,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 32,
    .secret_key_size    = 64,
    .max_signature_size = 17088,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_shake_192s_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHAKE_192S,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 48,
    .secret_key_size    = 96,
    .max_signature_size = 16224,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_shake_192f_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHAKE_192F,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 48,
    .secret_key_size    = 96,
    .max_signature_size = 35664,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_shake_256s_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHAKE_256S,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 64,
    .secret_key_size    = 128,
    .max_signature_size = 29792,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t sphincs_shake_256f_vtable = {
    .algorithm_name     = PQC_SIG_SPHINCS_SHAKE_256F,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "SPHINCS+ (Round 3)",
    .is_stateful        = 0,
    .public_key_size    = 64,
    .secret_key_size    = 128,
    .max_signature_size = 49856,
    .keygen  = sphincs_stub_keygen,
    .sign    = sphincs_stub_sign,
    .verify  = sphincs_stub_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_sphincsplus_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&sphincs_sha2_128s_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_sha2_128f_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_sha2_192s_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_sha2_192f_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_sha2_256s_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_sha2_256f_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_shake_128s_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_shake_128f_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_shake_192s_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_shake_192f_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_shake_256s_vtable);
    rc |= pqc_sig_add_vtable(&sphincs_shake_256f_vtable);
    return rc;
}
