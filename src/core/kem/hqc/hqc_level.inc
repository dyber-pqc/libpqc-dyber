/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * One HQC parameter set: the vendored reference implementation (ref/,
 * HQC v5.1.0) compiled as a single translation unit, with every external
 * symbol prefixed by level (ref/namespace.h) so all three levels link
 * into one library. The including file defines HQC_LEVEL (1, 3 or 5)
 * and HQC_VTABLE_NAME, the algorithm name it registers.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

#include "ref/namespace.h"

#include "ref/crypto_memset.c"
#include "ref/symmetric.c"
#include "ref/gf.c"
#include "ref/gf2x.c"
#include "ref/vector.c"
#include "ref/reed_muller.c"
#include "ref/reed_solomon.c"
#include "ref/code.c"
#include "ref/parsing.c"
#include "ref/hqc.c"
#include "ref/hqc-kem.c"

static pqc_status_t hqc_level_keygen(uint8_t *pk, uint8_t *sk)
{
    return hqc_kem_keygen(pk, sk) == 0 ? PQC_OK : PQC_ERROR_RNG_FAILED;
}

static pqc_status_t hqc_level_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    return hqc_kem_encaps(ss, ct, pk) == 0 ? PQC_OK : PQC_ERROR_RNG_FAILED;
}

static pqc_status_t hqc_level_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    /*
     * Always PQC_OK: an invalid ciphertext yields the implicit-rejection
     * secret, and reporting which case occurred would hand an attacker a
     * plaintext-checking oracle.
     */
    (void)hqc_kem_decaps(ss, sk, ct);
    return PQC_OK;
}

const pqc_kem_vtable_t HQC_NS(vtable) = {
    .algorithm_name     = HQC_VTABLE_NAME,
    .security_level     = HQC_SECURITY_LEVEL,
    .nist_standard      = "HQC v5.1 (selected by NIST; FIPS 207 pending)",
    .public_key_size    = CRYPTO_PUBLICKEYBYTES,
    .secret_key_size    = CRYPTO_SECRETKEYBYTES,
    .ciphertext_size    = CRYPTO_CIPHERTEXTBYTES,
    .shared_secret_size = CRYPTO_BYTES,
    .keygen             = hqc_level_keygen,
    .encaps             = hqc_level_encaps,
    .decaps             = hqc_level_decaps,
};
