/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Streamlined NTRU Prime KEM - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t sntrup761_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup761_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup761_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t sntrup857_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup857_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup857_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t sntrup953_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup953_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup953_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t sntrup1013_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup1013_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup1013_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t sntrup1277_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup1277_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t sntrup1277_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* sntrup761: p=761, q=4591, w=286 */
static const pqc_kem_vtable_t sntrup761_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP761,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 1158,
    .secret_key_size   = 1763,
    .ciphertext_size   = 1039,
    .shared_secret_size = 32,
    .keygen = sntrup761_keygen,
    .encaps = sntrup761_encaps,
    .decaps = sntrup761_decaps,
};

/* sntrup857: p=857, q=5167, w=322 */
static const pqc_kem_vtable_t sntrup857_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP857,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 1322,
    .secret_key_size   = 1999,
    .ciphertext_size   = 1184,
    .shared_secret_size = 32,
    .keygen = sntrup857_keygen,
    .encaps = sntrup857_encaps,
    .decaps = sntrup857_decaps,
};

/* sntrup953: p=953, q=6343, w=396 */
static const pqc_kem_vtable_t sntrup953_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP953,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 1505,
    .secret_key_size   = 2254,
    .ciphertext_size   = 1349,
    .shared_secret_size = 32,
    .keygen = sntrup953_keygen,
    .encaps = sntrup953_encaps,
    .decaps = sntrup953_decaps,
};

/* sntrup1013: p=1013, q=7177, w=448 */
static const pqc_kem_vtable_t sntrup1013_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP1013,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 1623,
    .secret_key_size   = 2417,
    .ciphertext_size   = 1455,
    .shared_secret_size = 32,
    .keygen = sntrup1013_keygen,
    .encaps = sntrup1013_encaps,
    .decaps = sntrup1013_decaps,
};

/* sntrup1277: p=1277, q=7879, w=492 */
static const pqc_kem_vtable_t sntrup1277_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP1277,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 2067,
    .secret_key_size   = 3059,
    .ciphertext_size   = 1847,
    .shared_secret_size = 32,
    .keygen = sntrup1277_keygen,
    .encaps = sntrup1277_encaps,
    .decaps = sntrup1277_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_ntruprime_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&sntrup761_vtable);
    rc |= pqc_kem_add_vtable(&sntrup857_vtable);
    rc |= pqc_kem_add_vtable(&sntrup953_vtable);
    rc |= pqc_kem_add_vtable(&sntrup1013_vtable);
    rc |= pqc_kem_add_vtable(&sntrup1277_vtable);
    return rc;
}
