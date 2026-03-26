/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Platform detection, architecture identification, and CPU feature probing.
 */

#ifndef PQC_PLATFORM_H
#define PQC_PLATFORM_H

#include <stdint.h>

#include "pqc/export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Platform and architecture name strings                                     */
/* -------------------------------------------------------------------------- */

/*
 * Returns a short canonical OS name:
 *   "windows", "linux", "macos", "freebsd", or "unix"
 */
PQC_API const char *pqc_get_platform_name(void);

/*
 * Returns a short canonical architecture name:
 *   "x86_64", "aarch64", "arm", "x86", or "generic"
 */
PQC_API const char *pqc_get_arch_name(void);

/* -------------------------------------------------------------------------- */
/* CPU feature flags                                                          */
/* -------------------------------------------------------------------------- */

typedef struct pqc_cpu_features {
    /* x86/x86_64 SIMD */
    uint32_t has_avx2   : 1;
    uint32_t has_avx512 : 1;
    uint32_t has_sha_ni : 1;
    uint32_t has_pclmul : 1;
    uint32_t has_bmi2   : 1;
    uint32_t has_sse2   : 1;
    uint32_t has_sse41  : 1;
    uint32_t has_aesni  : 1;

    /* ARM SIMD */
    uint32_t has_neon   : 1;
    uint32_t has_sve    : 1;
    uint32_t has_sha2   : 1;  /* ARM SHA2 extension */
    uint32_t has_sha3   : 1;  /* ARM SHA3 extension */
    uint32_t has_aes    : 1;  /* ARM AES extension  */

    uint32_t reserved   : 19;
} pqc_cpu_features_t;

/*
 * Detect CPU features at runtime.  Results are cached after the first call.
 */
PQC_API const pqc_cpu_features_t *pqc_cpu_detect(void);

/* Convenience boolean queries */
PQC_API int pqc_cpu_has_avx2(void);
PQC_API int pqc_cpu_has_avx512(void);
PQC_API int pqc_cpu_has_neon(void);
PQC_API int pqc_cpu_has_sha_ni(void);
PQC_API int pqc_cpu_has_pclmul(void);
PQC_API int pqc_cpu_has_bmi2(void);
PQC_API int pqc_cpu_has_sse2(void);
PQC_API int pqc_cpu_has_sse41(void);
PQC_API int pqc_cpu_has_aesni(void);
PQC_API int pqc_cpu_has_sve(void);

#ifdef __cplusplus
}
#endif

#endif /* PQC_PLATFORM_H */
