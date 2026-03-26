/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE (Bit-Flipping Key Encapsulation) KEM - stub implementation.
 */

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

/* ------------------------------------------------------------------ */
/* Stub operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t bike_l1_keygen(uint8_t *pk, uint8_t *sk)
{
    (void)pk; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t bike_l1_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    (void)ct; (void)ss; (void)pk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t bike_l1_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    (void)ss; (void)ct; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t bike_l3_keygen(uint8_t *pk, uint8_t *sk)
{
    (void)pk; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t bike_l3_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    (void)ct; (void)ss; (void)pk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t bike_l3_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    (void)ss; (void)ct; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t bike_l5_keygen(uint8_t *pk, uint8_t *sk)
{
    (void)pk; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t bike_l5_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    (void)ct; (void)ss; (void)pk;
    return PQC_ERROR_NOT_SUPPORTED;
}

static pqc_status_t bike_l5_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    (void)ss; (void)ct; (void)sk;
    return PQC_ERROR_NOT_SUPPORTED;
}

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/*
 * BIKE-L1: r=12323, w=142, t=134
 * pk = 1541 bytes, sk = 3749 bytes, ct = 1573 bytes, ss = 32 bytes
 */
static const pqc_kem_vtable_t bike_l1_vtable = {
    .algorithm_name    = PQC_KEM_BIKE_L1,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "BIKE (NIST Round 4)",
    .public_key_size   = 1541,
    .secret_key_size   = 3749,
    .ciphertext_size   = 1573,
    .shared_secret_size = 32,
    .keygen            = bike_l1_keygen,
    .encaps            = bike_l1_encaps,
    .decaps            = bike_l1_decaps,
};

/*
 * BIKE-L3: r=24659, w=206, t=199
 * pk = 3083 bytes, sk = 7467 bytes, ct = 3115 bytes, ss = 32 bytes
 */
static const pqc_kem_vtable_t bike_l3_vtable = {
    .algorithm_name    = PQC_KEM_BIKE_L3,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "BIKE (NIST Round 4)",
    .public_key_size   = 3083,
    .secret_key_size   = 7467,
    .ciphertext_size   = 3115,
    .shared_secret_size = 32,
    .keygen            = bike_l3_keygen,
    .encaps            = bike_l3_encaps,
    .decaps            = bike_l3_decaps,
};

/*
 * BIKE-L5: r=40973, w=274, t=264
 * pk = 5122 bytes, sk = 12415 bytes, ct = 5154 bytes, ss = 32 bytes
 */
static const pqc_kem_vtable_t bike_l5_vtable = {
    .algorithm_name    = PQC_KEM_BIKE_L5,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "BIKE (NIST Round 4)",
    .public_key_size   = 5122,
    .secret_key_size   = 12415,
    .ciphertext_size   = 5154,
    .shared_secret_size = 32,
    .keygen            = bike_l5_keygen,
    .encaps            = bike_l5_encaps,
    .decaps            = bike_l5_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_bike_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&bike_l1_vtable);
    rc |= pqc_kem_add_vtable(&bike_l3_vtable);
    rc |= pqc_kem_add_vtable(&bike_l5_vtable);
    return rc;
}
