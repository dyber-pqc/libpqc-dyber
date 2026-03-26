/*
 * libpqc-dyber OpenSSL 3.x Provider — TLS Named Group Registration
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Registers PQC and hybrid KEM algorithms as TLS 1.3 named groups
 * using the OpenSSL provider capabilities API.
 *
 * Group ID assignments follow:
 *   - ML-KEM standalone:     0x0200-0x0203 (draft-ietf-tls-hybrid-design)
 *   - X25519+ML-KEM-768:     0x6399 (Chrome/Cloudflare convention, now in
 *                              draft-ietf-tls-mlkem)
 *   - P256+ML-KEM-768:       0x639A
 *   - X25519+ML-KEM-512:     0x6400
 *   - P256+ML-KEM-1024:      0x6401
 */

#include "pqc_provider.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

/* ========================================================================== */
/* TLS group definitions                                                       */
/* ========================================================================== */

/*
 * TLS version constants used by OpenSSL capability reporting.
 * TLS 1.3 = 0x0304, DTLS 1.3 = 0xFEFC (draft)
 */
#define TLS1_3_VERSION   0x0304
#define DTLS1_3_VERSION  0xFEFC

const PQC_TLS_GROUP_INFO pqc_tls_groups[] = {
    /*
     * Standalone ML-KEM groups (pure PQC, no classical hybrid).
     * These use IANA codepoints from the experimental range.
     */
    {
        .name          = "MLKEM512",
        .kem_algorithm = "ML-KEM-512",
        .group_id      = 0x0200,
        .security_bits = 128,
        .min_tls       = TLS1_3_VERSION,
        .max_tls       = 0,           /* 0 = no max */
        .max_dtls      = 0,
        .is_kem        = 1,
    },
    {
        .name          = "MLKEM768",
        .kem_algorithm = "ML-KEM-768",
        .group_id      = 0x0201,
        .security_bits = 192,
        .min_tls       = TLS1_3_VERSION,
        .max_tls       = 0,
        .max_dtls      = 0,
        .is_kem        = 1,
    },
    {
        .name          = "MLKEM1024",
        .kem_algorithm = "ML-KEM-1024",
        .group_id      = 0x0202,
        .security_bits = 256,
        .min_tls       = TLS1_3_VERSION,
        .max_tls       = 0,
        .max_dtls      = 0,
        .is_kem        = 1,
    },
    /*
     * Hybrid groups — combine classical ECDH with ML-KEM.
     * The combined key share concatenates both components.
     */
    {
        .name          = "X25519MLKEM768",
        .kem_algorithm = "ML-KEM-768+X25519",
        .group_id      = 0x6399,
        .security_bits = 192,
        .min_tls       = TLS1_3_VERSION,
        .max_tls       = 0,
        .max_dtls      = 0,
        .is_kem        = 1,
    },
    {
        .name          = "SecP256r1MLKEM768",
        .kem_algorithm = "ML-KEM-768+X25519",  /* maps to P256 hybrid variant */
        .group_id      = 0x639A,
        .security_bits = 128,
        .min_tls       = TLS1_3_VERSION,
        .max_tls       = 0,
        .max_dtls      = 0,
        .is_kem        = 1,
    },
    {
        .name          = "X25519MLKEM512",
        .kem_algorithm = "ML-KEM-768+X25519",  /* reuses hybrid KEM impl */
        .group_id      = 0x6400,
        .security_bits = 128,
        .min_tls       = TLS1_3_VERSION,
        .max_tls       = 0,
        .max_dtls      = 0,
        .is_kem        = 1,
    },
    {
        .name          = "SecP256r1MLKEM1024",
        .kem_algorithm = "ML-KEM-1024+P256",
        .group_id      = 0x6401,
        .security_bits = 256,
        .min_tls       = TLS1_3_VERSION,
        .max_tls       = 0,
        .max_dtls      = 0,
        .is_kem        = 1,
    },
};

const size_t pqc_tls_group_count =
    sizeof(pqc_tls_groups) / sizeof(pqc_tls_groups[0]);

/* ========================================================================== */
/* Capability reporting                                                        */
/* ========================================================================== */

/*
 * Build a flat array of OSSL_PARAM sets, one per group, each terminated
 * by OSSL_PARAM_END, with a final empty OSSL_PARAM_END sentinel marking
 * the end of all groups.
 *
 * Layout:
 *   [group0 params...] OSSL_PARAM_END [group1 params...] OSSL_PARAM_END ... OSSL_PARAM_END
 *
 * This is returned as a static array, lazily initialized on first call.
 */

/*
 * Maximum params per group:
 *   - tls-group-name          (utf8)
 *   - tls-group-name-internal (utf8)
 *   - tls-group-id            (uint)
 *   - tls-group-alg           (utf8)
 *   - tls-group-sec-bits      (uint)
 *   - tls-group-is-kem        (uint)
 *   - tls-group-min-tls       (int)
 *   - tls-group-max-tls       (int)
 *   - tls-group-min-dtls      (int)
 *   - tls-group-max-dtls      (int)
 *   + OSSL_PARAM_END
 * = 11 entries per group
 */
#define PARAMS_PER_GROUP 11
#define MAX_GROUPS 16  /* must be >= pqc_tls_group_count */

/* Static storage for the integer/uint values that OSSL_PARAM points to */
static unsigned int s_group_ids[MAX_GROUPS];
static unsigned int s_sec_bits[MAX_GROUPS];
static unsigned int s_is_kem[MAX_GROUPS];
static int          s_min_tls[MAX_GROUPS];
static int          s_max_tls[MAX_GROUPS];
static int          s_min_dtls[MAX_GROUPS];
static int          s_max_dtls[MAX_GROUPS];

static OSSL_PARAM s_tls_group_params[MAX_GROUPS * PARAMS_PER_GROUP + 1];
static int s_tls_groups_initialized = 0;

const OSSL_PARAM *pqc_tls_group_capability(void *provctx)
{
    (void)provctx;

    if (s_tls_groups_initialized)
        return s_tls_group_params;

    OSSL_PARAM *p = s_tls_group_params;

    for (size_t i = 0; i < pqc_tls_group_count && i < MAX_GROUPS; i++) {
        const PQC_TLS_GROUP_INFO *g = &pqc_tls_groups[i];

        /* Copy scalar values to static storage so OSSL_PARAM can point at them */
        s_group_ids[i] = g->group_id;
        s_sec_bits[i]  = (unsigned int)g->security_bits;
        s_is_kem[i]    = (unsigned int)g->is_kem;
        s_min_tls[i]   = g->min_tls;
        s_max_tls[i]   = g->max_tls;
        s_min_dtls[i]  = 0;           /* PQC groups not in DTLS < 1.3 */
        s_max_dtls[i]  = g->max_dtls;

        *p++ = OSSL_PARAM_construct_utf8_string(
                   OSSL_CAPABILITY_TLS_GROUP_NAME,
                   (char *)g->name, 0);
        *p++ = OSSL_PARAM_construct_utf8_string(
                   OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
                   (char *)g->kem_algorithm, 0);
        *p++ = OSSL_PARAM_construct_uint(
                   OSSL_CAPABILITY_TLS_GROUP_ID,
                   &s_group_ids[i]);
        *p++ = OSSL_PARAM_construct_utf8_string(
                   OSSL_CAPABILITY_TLS_GROUP_ALG,
                   (char *)g->kem_algorithm, 0);
        *p++ = OSSL_PARAM_construct_uint(
                   OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,
                   &s_sec_bits[i]);
        *p++ = OSSL_PARAM_construct_uint(
                   OSSL_CAPABILITY_TLS_GROUP_IS_KEM,
                   &s_is_kem[i]);
        *p++ = OSSL_PARAM_construct_int(
                   OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,
                   &s_min_tls[i]);
        *p++ = OSSL_PARAM_construct_int(
                   OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,
                   &s_max_tls[i]);
        *p++ = OSSL_PARAM_construct_int(
                   OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,
                   &s_min_dtls[i]);
        *p++ = OSSL_PARAM_construct_int(
                   OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,
                   &s_max_dtls[i]);
        *p++ = OSSL_PARAM_construct_end();
    }

    /* Final sentinel — an extra OSSL_PARAM_END with key == NULL */
    *p = OSSL_PARAM_construct_end();

    s_tls_groups_initialized = 1;
    return s_tls_group_params;
}
