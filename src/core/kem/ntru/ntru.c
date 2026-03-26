/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU KEM - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t ntru_hps2048509_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t ntru_hps2048509_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t ntru_hps2048509_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t ntru_hps2048677_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t ntru_hps2048677_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t ntru_hps2048677_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t ntru_hps4096821_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t ntru_hps4096821_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t ntru_hps4096821_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

static pqc_status_t ntru_hrss701_keygen(uint8_t *pk, uint8_t *sk)
{ (void)pk; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t ntru_hrss701_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ (void)ct; (void)ss; (void)pk; return PQC_ERROR_NOT_SUPPORTED; }
static pqc_status_t ntru_hrss701_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ (void)ss; (void)ct; (void)sk; return PQC_ERROR_NOT_SUPPORTED; }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/* NTRU-HPS-2048-509: n=509, q=2048 */
static const pqc_kem_vtable_t ntru_hps2048509_vtable = {
    .algorithm_name    = PQC_KEM_NTRU_HPS_2048_509,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "NTRU",
    .public_key_size   = 699,
    .secret_key_size   = 935,
    .ciphertext_size   = 699,
    .shared_secret_size = 32,
    .keygen = ntru_hps2048509_keygen,
    .encaps = ntru_hps2048509_encaps,
    .decaps = ntru_hps2048509_decaps,
};

/* NTRU-HPS-2048-677: n=677, q=2048 */
static const pqc_kem_vtable_t ntru_hps2048677_vtable = {
    .algorithm_name    = PQC_KEM_NTRU_HPS_2048_677,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "NTRU",
    .public_key_size   = 930,
    .secret_key_size   = 1234,
    .ciphertext_size   = 930,
    .shared_secret_size = 32,
    .keygen = ntru_hps2048677_keygen,
    .encaps = ntru_hps2048677_encaps,
    .decaps = ntru_hps2048677_decaps,
};

/* NTRU-HPS-4096-821: n=821, q=4096 */
static const pqc_kem_vtable_t ntru_hps4096821_vtable = {
    .algorithm_name    = PQC_KEM_NTRU_HPS_4096_821,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "NTRU",
    .public_key_size   = 1230,
    .secret_key_size   = 1590,
    .ciphertext_size   = 1230,
    .shared_secret_size = 32,
    .keygen = ntru_hps4096821_keygen,
    .encaps = ntru_hps4096821_encaps,
    .decaps = ntru_hps4096821_decaps,
};

/* NTRU-HRSS-701: n=701, q=8192 */
static const pqc_kem_vtable_t ntru_hrss701_vtable = {
    .algorithm_name    = PQC_KEM_NTRU_HRSS_701,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "NTRU",
    .public_key_size   = 1138,
    .secret_key_size   = 1450,
    .ciphertext_size   = 1138,
    .shared_secret_size = 32,
    .keygen = ntru_hrss701_keygen,
    .encaps = ntru_hrss701_encaps,
    .decaps = ntru_hrss701_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_ntru_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&ntru_hps2048509_vtable);
    rc |= pqc_kem_add_vtable(&ntru_hps2048677_vtable);
    rc |= pqc_kem_add_vtable(&ntru_hps4096821_vtable);
    rc |= pqc_kem_add_vtable(&ntru_hrss701_vtable);
    return rc;
}
