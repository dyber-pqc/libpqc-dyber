/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * TLS Integration — Signature Algorithm definitions
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Defines TLS SignatureScheme entries for ML-DSA and SLH-DSA variants,
 * including key/signature sizes and NIST security level mappings.
 */

#include "pqc_tls_internal.h"

#include <stddef.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Signature algorithm table                                                   */
/* -------------------------------------------------------------------------- */

/*
 * Sizes sourced from FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA):
 *
 * ML-DSA-44:  pk = 1312,  sk = 2560,  sig_max = 2420
 * ML-DSA-65:  pk = 1952,  sk = 4032,  sig_max = 3309
 * ML-DSA-87:  pk = 2592,  sk = 4896,  sig_max = 4627
 *
 * SLH-DSA-SHA2-128s:  pk = 32,  sk = 64,  sig_max = 7856
 * SLH-DSA-SHA2-128f:  pk = 32,  sk = 64,  sig_max = 17088
 * SLH-DSA-SHA2-192s:  pk = 48,  sk = 96,  sig_max = 16224
 * SLH-DSA-SHA2-192f:  pk = 48,  sk = 96,  sig_max = 35664
 * SLH-DSA-SHA2-256s:  pk = 64,  sk = 128, sig_max = 29792
 * SLH-DSA-SHA2-256f:  pk = 64,  sk = 128, sig_max = 49856
 */

static const pqc_tls_sigalg_def_t sigalg_table[] = {
    /* ML-DSA variants (FIPS 204) */
    {
        .sigalg_id      = PQC_TLS_SIGALG_MLDSA44,
        .name           = "ML-DSA-44",
        .pqc_algorithm  = "ML-DSA-44",
        .pk_size        = 1312,
        .sk_size        = 2560,
        .max_sig_size   = 2420,
        .security_level = 2,
    },
    {
        .sigalg_id      = PQC_TLS_SIGALG_MLDSA65,
        .name           = "ML-DSA-65",
        .pqc_algorithm  = "ML-DSA-65",
        .pk_size        = 1952,
        .sk_size        = 4032,
        .max_sig_size   = 3309,
        .security_level = 3,
    },
    {
        .sigalg_id      = PQC_TLS_SIGALG_MLDSA87,
        .name           = "ML-DSA-87",
        .pqc_algorithm  = "ML-DSA-87",
        .pk_size        = 2592,
        .sk_size        = 4896,
        .max_sig_size   = 4627,
        .security_level = 5,
    },

    /* SLH-DSA variants (FIPS 205) — SHA-2 instantiations */
    {
        .sigalg_id      = PQC_TLS_SIGALG_SLHDSA_SHA2_128S,
        .name           = "SLH-DSA-SHA2-128s",
        .pqc_algorithm  = "SLH-DSA-SHA2-128s",
        .pk_size        = 32,
        .sk_size        = 64,
        .max_sig_size   = 7856,
        .security_level = 1,
    },
    {
        .sigalg_id      = PQC_TLS_SIGALG_SLHDSA_SHA2_128F,
        .name           = "SLH-DSA-SHA2-128f",
        .pqc_algorithm  = "SLH-DSA-SHA2-128f",
        .pk_size        = 32,
        .sk_size        = 64,
        .max_sig_size   = 17088,
        .security_level = 1,
    },
    {
        .sigalg_id      = PQC_TLS_SIGALG_SLHDSA_SHA2_192S,
        .name           = "SLH-DSA-SHA2-192s",
        .pqc_algorithm  = "SLH-DSA-SHA2-192s",
        .pk_size        = 48,
        .sk_size        = 96,
        .max_sig_size   = 16224,
        .security_level = 3,
    },
    {
        .sigalg_id      = PQC_TLS_SIGALG_SLHDSA_SHA2_192F,
        .name           = "SLH-DSA-SHA2-192f",
        .pqc_algorithm  = "SLH-DSA-SHA2-192f",
        .pk_size        = 48,
        .sk_size        = 96,
        .max_sig_size   = 35664,
        .security_level = 3,
    },
    {
        .sigalg_id      = PQC_TLS_SIGALG_SLHDSA_SHA2_256S,
        .name           = "SLH-DSA-SHA2-256s",
        .pqc_algorithm  = "SLH-DSA-SHA2-256s",
        .pk_size        = 64,
        .sk_size        = 128,
        .max_sig_size   = 29792,
        .security_level = 5,
    },
    {
        .sigalg_id      = PQC_TLS_SIGALG_SLHDSA_SHA2_256F,
        .name           = "SLH-DSA-SHA2-256f",
        .pqc_algorithm  = "SLH-DSA-SHA2-256f",
        .pk_size        = 64,
        .sk_size        = 128,
        .max_sig_size   = 49856,
        .security_level = 5,
    },
};

static const size_t sigalg_table_len =
    sizeof(sigalg_table) / sizeof(sigalg_table[0]);

/* -------------------------------------------------------------------------- */
/* Lookup functions                                                            */
/* -------------------------------------------------------------------------- */

const pqc_tls_sigalg_def_t *pqc_tls_find_sigalg(uint16_t sigalg_id)
{
    for (size_t i = 0; i < sigalg_table_len; i++) {
        if (sigalg_table[i].sigalg_id == sigalg_id)
            return &sigalg_table[i];
    }
    return NULL;
}

size_t pqc_tls_sigalg_count(void)
{
    return sigalg_table_len;
}

const pqc_tls_sigalg_def_t *pqc_tls_sigalg_at(size_t index)
{
    if (index >= sigalg_table_len)
        return NULL;
    return &sigalg_table[index];
}
