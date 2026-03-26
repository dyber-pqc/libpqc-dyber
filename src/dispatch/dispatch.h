/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Runtime CPU feature detection and dispatch.
 */

#ifndef PQC_DISPATCH_H
#define PQC_DISPATCH_H

#include <stdint.h>

typedef struct {
    /* x86_64 features */
    uint32_t has_avx2    : 1;
    uint32_t has_avx512f : 1;
    uint32_t has_sha_ni  : 1;
    uint32_t has_pclmul  : 1;
    uint32_t has_bmi2    : 1;
    uint32_t has_aes_ni  : 1;

    /* ARM features */
    uint32_t has_neon    : 1;
    uint32_t has_sve     : 1;
    uint32_t has_sha2    : 1;  /* ARM SHA2 crypto extension */
    uint32_t has_sha3    : 1;  /* ARM SHA3 crypto extension */
    uint32_t has_aes     : 1;  /* ARM AES crypto extension */

    uint32_t initialized : 1;
} pqc_cpu_features_t;

void pqc_detect_cpu_features(pqc_cpu_features_t *f);
const pqc_cpu_features_t *pqc_get_cpu_features(void);

#endif /* PQC_DISPATCH_H */
