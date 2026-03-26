/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * TLS Integration — Named Group definitions
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Defines TLS NamedGroup entries for pure PQC and hybrid key exchange
 * groups, including key share sizes and security level mappings.
 */

#include "pqc_tls_internal.h"

#include <stddef.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Group table                                                                 */
/* -------------------------------------------------------------------------- */

/*
 * Key share sizes sourced from FIPS 203 (ML-KEM):
 *   ML-KEM-512:  pk = 800,   ct = 768,   ss = 32
 *   ML-KEM-768:  pk = 1184,  ct = 1088,  ss = 32
 *   ML-KEM-1024: pk = 1568,  ct = 1568,  ss = 32
 *
 * Classical sizes:
 *   X25519:  pk = 32, ss = 32
 *   P-256:   pk = 65 (uncompressed), ss = 32
 */

static const pqc_tls_group_def_t group_table[] = {
    /* Pure PQC groups */
    {
        .group_id          = PQC_TLS_GROUP_MLKEM512,
        .name              = "ML-KEM-512",
        .pqc_algorithm     = "ML-KEM-512",
        .is_hybrid         = 0,
        .classical_type    = 0,
        .classical_pk_size = 0,
        .classical_sk_size = 0,
        .classical_ss_size = 0,
        .pqc_pk_size       = 800,
        .pqc_ct_size       = 768,
        .pqc_ss_size       = 32,
        .security_level    = 1,
    },
    {
        .group_id          = PQC_TLS_GROUP_MLKEM768,
        .name              = "ML-KEM-768",
        .pqc_algorithm     = "ML-KEM-768",
        .is_hybrid         = 0,
        .classical_type    = 0,
        .classical_pk_size = 0,
        .classical_sk_size = 0,
        .classical_ss_size = 0,
        .pqc_pk_size       = 1184,
        .pqc_ct_size       = 1088,
        .pqc_ss_size       = 32,
        .security_level    = 3,
    },
    {
        .group_id          = PQC_TLS_GROUP_MLKEM1024,
        .name              = "ML-KEM-1024",
        .pqc_algorithm     = "ML-KEM-1024",
        .is_hybrid         = 0,
        .classical_type    = 0,
        .classical_pk_size = 0,
        .classical_sk_size = 0,
        .classical_ss_size = 0,
        .pqc_pk_size       = 1568,
        .pqc_ct_size       = 1568,
        .pqc_ss_size       = 32,
        .security_level    = 5,
    },

    /* Hybrid groups */
    {
        .group_id          = PQC_TLS_GROUP_X25519_MLKEM768,
        .name              = "X25519+ML-KEM-768",
        .pqc_algorithm     = "ML-KEM-768",
        .is_hybrid         = 1,
        .classical_type    = PQC_TLS_CLASSICAL_X25519,
        .classical_pk_size = 32,
        .classical_sk_size = 32,
        .classical_ss_size = 32,
        .pqc_pk_size       = 1184,
        .pqc_ct_size       = 1088,
        .pqc_ss_size       = 32,
        .security_level    = 3,
    },
    {
        .group_id          = PQC_TLS_GROUP_SECP256R1_MLKEM768,
        .name              = "P-256+ML-KEM-768",
        .pqc_algorithm     = "ML-KEM-768",
        .is_hybrid         = 1,
        .classical_type    = PQC_TLS_CLASSICAL_P256,
        .classical_pk_size = 65,
        .classical_sk_size = 32,
        .classical_ss_size = 32,
        .pqc_pk_size       = 1184,
        .pqc_ct_size       = 1088,
        .pqc_ss_size       = 32,
        .security_level    = 3,
    },
};

static const size_t group_table_len =
    sizeof(group_table) / sizeof(group_table[0]);

/* -------------------------------------------------------------------------- */
/* Lookup functions                                                            */
/* -------------------------------------------------------------------------- */

const pqc_tls_group_def_t *pqc_tls_find_group(uint16_t group_id)
{
    for (size_t i = 0; i < group_table_len; i++) {
        if (group_table[i].group_id == group_id)
            return &group_table[i];
    }
    return NULL;
}

size_t pqc_tls_group_count(void)
{
    return group_table_len;
}

const pqc_tls_group_def_t *pqc_tls_group_at(size_t index)
{
    if (index >= group_table_len)
        return NULL;
    return &group_table[index];
}
