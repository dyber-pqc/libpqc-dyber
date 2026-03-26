/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Internal header for cryptographically secure random number generation.
 */

#ifndef PQC_RAND_INTERNAL_H
#define PQC_RAND_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/rand.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generate random bytes using the OS CSPRNG.
 * This is the low-level backend; pqc_randombytes checks for a custom
 * callback first.
 *
 * Platform dispatch:
 *   Windows  - BCryptGenRandom
 *   Linux    - getrandom(2)
 *   macOS    - arc4random_buf
 *   FreeBSD  - arc4random_buf
 *   Fallback - /dev/urandom
 */
pqc_status_t pqc_os_randombytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_RAND_INTERNAL_H */
