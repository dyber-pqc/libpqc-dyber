/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Cryptographically secure random number generation.
 */

#ifndef PQC_RAND_H
#define PQC_RAND_H

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Generate cryptographically secure random bytes using OS entropy */
PQC_API pqc_status_t pqc_randombytes(uint8_t *buf, size_t len);

/* Custom RNG callback type */
typedef pqc_status_t (*pqc_rng_callback_t)(uint8_t *buf, size_t len, void *ctx);

/* Set a custom RNG (pass NULL to restore default OS RNG) */
PQC_API pqc_status_t pqc_set_rng(pqc_rng_callback_t callback, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* PQC_RAND_H */
