/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC (Hamming Quasi-Cyclic) KEM - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations — return PQC_ERROR_NOT_SUPPORTED                    */
/* ------------------------------------------------------------------ */

static pqc_status_t hqc128_keygen(uint8_t *pk, uint8_t *sk)
{
    (void)pk; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t hqc128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    (void)ct; (void)ss; (void)pk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t hqc128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    (void)ss; (void)ct; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t hqc192_keygen(uint8_t *pk, uint8_t *sk)
{
    (void)pk; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t hqc192_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    (void)ct; (void)ss; (void)pk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t hqc192_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    (void)ss; (void)ct; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t hqc256_keygen(uint8_t *pk, uint8_t *sk)
{
    (void)pk; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t hqc256_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    (void)ct; (void)ss; (void)pk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t hqc256_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    (void)ss; (void)ct; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/*
 * HQC-128: n=17669, n1=46, n2=384, w=66, w_r=77, w_e=77
 * pk = 2249 bytes, sk = 2289 bytes, ct = 4481 bytes, ss = 64 bytes
 */
static const pqc_kem_vtable_t hqc128_vtable = {
    .algorithm_name    = PQC_KEM_HQC_128,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "HQC (NIST Round 4)",
    .public_key_size   = 2249,
    .secret_key_size   = 2289,
    .ciphertext_size   = 4481,
    .shared_secret_size = 64,
    .keygen            = hqc128_keygen,
    .encaps            = hqc128_encaps,
    .decaps            = hqc128_decaps,
};

/*
 * HQC-192: n=35851, n1=56, n2=640, w=100, w_r=117, w_e=117
 * pk = 4522 bytes, sk = 4562 bytes, ct = 9026 bytes, ss = 64 bytes
 */
static const pqc_kem_vtable_t hqc192_vtable = {
    .algorithm_name    = PQC_KEM_HQC_192,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "HQC (NIST Round 4)",
    .public_key_size   = 4522,
    .secret_key_size   = 4562,
    .ciphertext_size   = 9026,
    .shared_secret_size = 64,
    .keygen            = hqc192_keygen,
    .encaps            = hqc192_encaps,
    .decaps            = hqc192_decaps,
};

/*
 * HQC-256: n=57637, n1=90, n2=640, w=131, w_r=153, w_e=153
 * pk = 7245 bytes, sk = 7285 bytes, ct = 14469 bytes, ss = 64 bytes
 */
static const pqc_kem_vtable_t hqc256_vtable = {
    .algorithm_name    = PQC_KEM_HQC_256,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "HQC (NIST Round 4)",
    .public_key_size   = 7245,
    .secret_key_size   = 7285,
    .ciphertext_size   = 14469,
    .shared_secret_size = 64,
    .keygen            = hqc256_keygen,
    .encaps            = hqc256_encaps,
    .decaps            = hqc256_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_hqc_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&hqc128_vtable);
    rc |= pqc_kem_add_vtable(&hqc192_vtable);
    rc |= pqc_kem_add_vtable(&hqc256_vtable);
    return rc;
}
