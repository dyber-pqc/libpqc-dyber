/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FrodoKEM - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t frodo640aes_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo640aes_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo640aes_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t frodo640shake_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo640shake_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo640shake_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t frodo976aes_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo976aes_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo976aes_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t frodo976shake_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo976shake_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo976shake_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t frodo1344aes_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo1344aes_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo1344aes_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t frodo1344shake_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo1344shake_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t frodo1344shake_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* FrodoKEM-640-AES: n=640, q=2^15, B=2 */
static const pqc_kem_vtable_t frodo640aes_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_640_AES,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = 9616,
    .secret_key_size   = 19888,
    .ciphertext_size   = 9720,
    .shared_secret_size = 16,
    .keygen = frodo640aes_keygen,
    .encaps = frodo640aes_encaps,
    .decaps = frodo640aes_decaps,
};

static const pqc_kem_vtable_t frodo640shake_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_640_SHAKE,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = 9616,
    .secret_key_size   = 19888,
    .ciphertext_size   = 9720,
    .shared_secret_size = 16,
    .keygen = frodo640shake_keygen,
    .encaps = frodo640shake_encaps,
    .decaps = frodo640shake_decaps,
};

/* FrodoKEM-976-AES: n=976, q=2^16, B=3 */
static const pqc_kem_vtable_t frodo976aes_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_976_AES,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = 15632,
    .secret_key_size   = 31296,
    .ciphertext_size   = 15744,
    .shared_secret_size = 24,
    .keygen = frodo976aes_keygen,
    .encaps = frodo976aes_encaps,
    .decaps = frodo976aes_decaps,
};

static const pqc_kem_vtable_t frodo976shake_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_976_SHAKE,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = 15632,
    .secret_key_size   = 31296,
    .ciphertext_size   = 15744,
    .shared_secret_size = 24,
    .keygen = frodo976shake_keygen,
    .encaps = frodo976shake_encaps,
    .decaps = frodo976shake_decaps,
};

/* FrodoKEM-1344-AES: n=1344, q=2^16, B=4 */
static const pqc_kem_vtable_t frodo1344aes_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_1344_AES,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = 21520,
    .secret_key_size   = 43088,
    .ciphertext_size   = 21632,
    .shared_secret_size = 32,
    .keygen = frodo1344aes_keygen,
    .encaps = frodo1344aes_encaps,
    .decaps = frodo1344aes_decaps,
};

static const pqc_kem_vtable_t frodo1344shake_vtable = {
    .algorithm_name    = PQC_KEM_FRODO_1344_SHAKE,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "FrodoKEM",
    .public_key_size   = 21520,
    .secret_key_size   = 43088,
    .ciphertext_size   = 21632,
    .shared_secret_size = 32,
    .keygen = frodo1344shake_keygen,
    .encaps = frodo1344shake_encaps,
    .decaps = frodo1344shake_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_frodo_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&frodo640aes_vtable);
    rc |= pqc_kem_add_vtable(&frodo640shake_vtable);
    rc |= pqc_kem_add_vtable(&frodo976aes_vtable);
    rc |= pqc_kem_add_vtable(&frodo976shake_vtable);
    rc |= pqc_kem_add_vtable(&frodo1344aes_vtable);
    rc |= pqc_kem_add_vtable(&frodo1344shake_vtable);
    return rc;
}
