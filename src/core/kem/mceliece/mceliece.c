/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece KEM - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t mceliece348864_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece348864_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece348864_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece460896_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece460896_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece460896_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece6688128_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece6688128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece6688128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece6960119_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece6960119_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece6960119_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece8192128_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece8192128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t mceliece8192128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_kem_vtable_t mceliece348864_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_348864,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 261120,
    .secret_key_size   = 6492,
    .ciphertext_size   = 128,
    .shared_secret_size = 32,
    .keygen = mceliece348864_keygen,
    .encaps = mceliece348864_encaps,
    .decaps = mceliece348864_decaps,
};

static const pqc_kem_vtable_t mceliece460896_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_460896,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 524160,
    .secret_key_size   = 13608,
    .ciphertext_size   = 188,
    .shared_secret_size = 32,
    .keygen = mceliece460896_keygen,
    .encaps = mceliece460896_encaps,
    .decaps = mceliece460896_decaps,
};

static const pqc_kem_vtable_t mceliece6688128_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_6688128,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 1044992,
    .secret_key_size   = 13932,
    .ciphertext_size   = 240,
    .shared_secret_size = 32,
    .keygen = mceliece6688128_keygen,
    .encaps = mceliece6688128_encaps,
    .decaps = mceliece6688128_decaps,
};

static const pqc_kem_vtable_t mceliece6960119_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_6960119,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 1047319,
    .secret_key_size   = 13948,
    .ciphertext_size   = 226,
    .shared_secret_size = 32,
    .keygen = mceliece6960119_keygen,
    .encaps = mceliece6960119_encaps,
    .decaps = mceliece6960119_decaps,
};

static const pqc_kem_vtable_t mceliece8192128_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_8192128,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 1357824,
    .secret_key_size   = 14120,
    .ciphertext_size   = 240,
    .shared_secret_size = 32,
    .keygen = mceliece8192128_keygen,
    .encaps = mceliece8192128_encaps,
    .decaps = mceliece8192128_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_mceliece_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&mceliece348864_vtable);
    rc |= pqc_kem_add_vtable(&mceliece460896_vtable);
    rc |= pqc_kem_add_vtable(&mceliece6688128_vtable);
    rc |= pqc_kem_add_vtable(&mceliece6960119_vtable);
    rc |= pqc_kem_add_vtable(&mceliece8192128_vtable);
    return rc;
}
