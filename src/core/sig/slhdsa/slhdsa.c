/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t slhdsa_stub_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t slhdsa_stub_sign(uint8_t *sig, size_t *siglen,
                                      const uint8_t *msg, size_t msglen,
                                      const uint8_t *sk)
{ (void)sig; (void)siglen; (void)msg; (void)msglen; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t slhdsa_stub_verify(const uint8_t *msg, size_t msglen,
                                        const uint8_t *sig, size_t siglen,
                                        const uint8_t *pk)
{ (void)msg; (void)msglen; (void)sig; (void)siglen; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables — 12 SLH-DSA parameter sets (FIPS 205)                      */
/* ------------------------------------------------------------------ */

/* SLH-DSA-SHA2-128s: n=16, h=63, d=7, k=14, a=12, w=16 */
static const pqc_sig_vtable_t slhdsa_sha2_128s_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHA2_128S,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 32,
    .secret_key_size    = 64,
    .max_signature_size = 7856,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHA2-128f: n=16, h=66, d=22, k=33, a=6, w=16 */
static const pqc_sig_vtable_t slhdsa_sha2_128f_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHA2_128F,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 32,
    .secret_key_size    = 64,
    .max_signature_size = 17088,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHA2-192s: n=24, h=63, d=7, k=17, a=14, w=16 */
static const pqc_sig_vtable_t slhdsa_sha2_192s_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHA2_192S,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 48,
    .secret_key_size    = 96,
    .max_signature_size = 16224,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHA2-192f: n=24, h=66, d=22, k=33, a=8, w=16 */
static const pqc_sig_vtable_t slhdsa_sha2_192f_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHA2_192F,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 48,
    .secret_key_size    = 96,
    .max_signature_size = 35664,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHA2-256s: n=32, h=64, d=8, k=22, a=14, w=16 */
static const pqc_sig_vtable_t slhdsa_sha2_256s_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHA2_256S,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 64,
    .secret_key_size    = 128,
    .max_signature_size = 29792,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHA2-256f: n=32, h=68, d=17, k=35, a=9, w=16 */
static const pqc_sig_vtable_t slhdsa_sha2_256f_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHA2_256F,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 64,
    .secret_key_size    = 128,
    .max_signature_size = 49856,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHAKE-128s */
static const pqc_sig_vtable_t slhdsa_shake_128s_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHAKE_128S,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 32,
    .secret_key_size    = 64,
    .max_signature_size = 7856,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHAKE-128f */
static const pqc_sig_vtable_t slhdsa_shake_128f_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHAKE_128F,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 32,
    .secret_key_size    = 64,
    .max_signature_size = 17088,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHAKE-192s */
static const pqc_sig_vtable_t slhdsa_shake_192s_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHAKE_192S,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 48,
    .secret_key_size    = 96,
    .max_signature_size = 16224,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHAKE-192f */
static const pqc_sig_vtable_t slhdsa_shake_192f_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHAKE_192F,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 48,
    .secret_key_size    = 96,
    .max_signature_size = 35664,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHAKE-256s */
static const pqc_sig_vtable_t slhdsa_shake_256s_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHAKE_256S,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 64,
    .secret_key_size    = 128,
    .max_signature_size = 29792,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* SLH-DSA-SHAKE-256f */
static const pqc_sig_vtable_t slhdsa_shake_256f_vtable = {
    .algorithm_name     = PQC_SIG_SLH_DSA_SHAKE_256F,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "FIPS 205",
    .is_stateful        = 0,
    .public_key_size    = 64,
    .secret_key_size    = 128,
    .max_signature_size = 49856,
    .keygen  = slhdsa_stub_keygen,
    .sign    = slhdsa_stub_sign,
    .verify  = slhdsa_stub_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_slhdsa_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_128s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_128f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_192s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_192f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_256s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_256f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_128s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_128f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_192s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_192f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_256s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_256f_vtable);
    return rc;
}
