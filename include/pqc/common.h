/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Common types, error codes, and version information.
 */

#ifndef PQC_COMMON_H
#define PQC_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include "pqc/export.h"
#include "pqc/pqc_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Version                                                                     */
/* -------------------------------------------------------------------------- */

PQC_API const char *pqc_version(void);
PQC_API int pqc_version_major(void);
PQC_API int pqc_version_minor(void);
PQC_API int pqc_version_patch(void);

/* -------------------------------------------------------------------------- */
/* Error codes                                                                 */
/* -------------------------------------------------------------------------- */

typedef enum {
    PQC_OK = 0,
    PQC_ERROR = -1,
    PQC_ERROR_INVALID_ARGUMENT = -2,
    PQC_ERROR_ALLOC = -3,
    PQC_ERROR_NOT_SUPPORTED = -4,
    PQC_ERROR_INVALID_KEY = -5,
    PQC_ERROR_VERIFICATION_FAILED = -6,
    PQC_ERROR_DECAPSULATION_FAILED = -7,
    PQC_ERROR_RNG_FAILED = -8,
    PQC_ERROR_BUFFER_TOO_SMALL = -9,
    PQC_ERROR_INTERNAL = -10,
    PQC_ERROR_STATE_EXHAUSTED = -11,
} pqc_status_t;

PQC_API const char *pqc_status_string(pqc_status_t status);

/* -------------------------------------------------------------------------- */
/* Algorithm type classification                                               */
/* -------------------------------------------------------------------------- */

typedef enum {
    PQC_ALG_TYPE_KEM = 1,
    PQC_ALG_TYPE_SIG = 2,
    PQC_ALG_TYPE_SIG_STATEFUL = 3,
    PQC_ALG_TYPE_HYBRID_KEM = 4,
    PQC_ALG_TYPE_HYBRID_SIG = 5,
} pqc_alg_type_t;

/* -------------------------------------------------------------------------- */
/* Security level (NIST categories)                                            */
/* -------------------------------------------------------------------------- */

typedef enum {
    PQC_SECURITY_LEVEL_1 = 1, /* At least as hard as AES-128 */
    PQC_SECURITY_LEVEL_2 = 2, /* At least as hard as SHA-256 */
    PQC_SECURITY_LEVEL_3 = 3, /* At least as hard as AES-192 */
    PQC_SECURITY_LEVEL_4 = 4, /* At least as hard as SHA-384 */
    PQC_SECURITY_LEVEL_5 = 5, /* At least as hard as AES-256 */
} pqc_security_level_t;

/* -------------------------------------------------------------------------- */
/* Library initialization and cleanup                                          */
/* -------------------------------------------------------------------------- */

PQC_API pqc_status_t pqc_init(void);
PQC_API void pqc_cleanup(void);

/* -------------------------------------------------------------------------- */
/* Secure memory utilities                                                     */
/* -------------------------------------------------------------------------- */

PQC_API void *pqc_malloc(size_t size);
PQC_API void *pqc_calloc(size_t count, size_t size);
PQC_API void pqc_free(void *ptr, size_t size);
PQC_API void pqc_memzero(void *ptr, size_t size);
PQC_API int pqc_memcmp_ct(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_COMMON_H */
