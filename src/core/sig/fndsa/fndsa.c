/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206, formerly Falcon) -- main entry point.
 *
 * This file provides the top-level API functions that are registered
 * in the library's signature vtable, dispatching to the internal
 * FN-DSA implementations (keygen.c, sign.c, vrfy.c).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"
#include "fndsa.h"
#include "fndsa_params.h"

/* ------------------------------------------------------------------ */
/* FN-DSA-512 wrappers                                                  */
/* ------------------------------------------------------------------ */

static pqc_status_t
fndsa512_keygen(uint8_t *pk, uint8_t *sk)
{
    if (fndsa_keygen(pk, FNDSA_512_PK_SIZE,
                     sk, FNDSA_512_SK_SIZE,
                     FNDSA_512_LOGN) != 0)
        return PQC_ERROR_INTERNAL;
    return PQC_OK;
}

static pqc_status_t
fndsa512_sign(uint8_t *sig, size_t *siglen,
              const uint8_t *msg, size_t msglen,
              const uint8_t *sk)
{
    if (fndsa_sign(sig, siglen, FNDSA_512_SIG_MAX_SIZE,
                   msg, msglen,
                   sk, FNDSA_512_SK_SIZE,
                   FNDSA_512_LOGN) != 0)
        return PQC_ERROR_INTERNAL;
    return PQC_OK;
}

static pqc_status_t
fndsa512_verify(const uint8_t *msg, size_t msglen,
                const uint8_t *sig, size_t siglen,
                const uint8_t *pk)
{
    if (fndsa_verify(msg, msglen,
                     sig, siglen,
                     pk, FNDSA_512_PK_SIZE,
                     FNDSA_512_LOGN) != 0)
        return PQC_ERROR_VERIFICATION_FAILED;
    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* FN-DSA-1024 wrappers                                                 */
/* ------------------------------------------------------------------ */

static pqc_status_t
fndsa1024_keygen(uint8_t *pk, uint8_t *sk)
{
    if (fndsa_keygen(pk, FNDSA_1024_PK_SIZE,
                     sk, FNDSA_1024_SK_SIZE,
                     FNDSA_1024_LOGN) != 0)
        return PQC_ERROR_INTERNAL;
    return PQC_OK;
}

static pqc_status_t
fndsa1024_sign(uint8_t *sig, size_t *siglen,
               const uint8_t *msg, size_t msglen,
               const uint8_t *sk)
{
    if (fndsa_sign(sig, siglen, FNDSA_1024_SIG_MAX_SIZE,
                   msg, msglen,
                   sk, FNDSA_1024_SK_SIZE,
                   FNDSA_1024_LOGN) != 0)
        return PQC_ERROR_INTERNAL;
    return PQC_OK;
}

static pqc_status_t
fndsa1024_verify(const uint8_t *msg, size_t msglen,
                 const uint8_t *sig, size_t siglen,
                 const uint8_t *pk)
{
    if (fndsa_verify(msg, msglen,
                     sig, siglen,
                     pk, FNDSA_1024_PK_SIZE,
                     FNDSA_1024_LOGN) != 0)
        return PQC_ERROR_VERIFICATION_FAILED;
    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* FN-DSA-512: n=512, q=12289 */
static const pqc_sig_vtable_t fndsa512_vtable = {
    .algorithm_name     = PQC_SIG_FN_DSA_512,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "FIPS 206",
    .is_stateful        = 0,
    .public_key_size    = FNDSA_512_PK_SIZE,
    .secret_key_size    = FNDSA_512_SK_SIZE,
    .max_signature_size = FNDSA_512_SIG_MAX_SIZE,
    .keygen  = fndsa512_keygen,
    .sign    = fndsa512_sign,
    .verify  = fndsa512_verify,
    .sign_stateful = NULL,
};

/* FN-DSA-1024: n=1024, q=12289 */
static const pqc_sig_vtable_t fndsa1024_vtable = {
    .algorithm_name     = PQC_SIG_FN_DSA_1024,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "FIPS 206",
    .is_stateful        = 0,
    .public_key_size    = FNDSA_1024_PK_SIZE,
    .secret_key_size    = FNDSA_1024_SK_SIZE,
    .max_signature_size = FNDSA_1024_SIG_MAX_SIZE,
    .keygen  = fndsa1024_keygen,
    .sign    = fndsa1024_sign,
    .verify  = fndsa1024_verify,
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
