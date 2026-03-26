/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Internal header for secure memory management.
 */

#ifndef PQC_MEM_INTERNAL_H
#define PQC_MEM_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Allocate memory with tracked size for later zeroization.
 * Returns NULL on failure.
 */
void *pqc_malloc(size_t size);

/*
 * Zero-initialized allocation with tracked size.
 * Returns NULL on failure or on overflow of count * size.
 */
void *pqc_calloc(size_t count, size_t size);

/*
 * Securely zeroize and then free memory.
 * If ptr is NULL this is a no-op.
 * size must match the original allocation size.
 */
void pqc_free(void *ptr, size_t size);

/*
 * Guaranteed memory zeroization that will not be optimized away.
 * Uses volatile writes and, where available, platform-specific
 * secure-zero primitives.
 */
void pqc_memzero(void *ptr, size_t size);

/*
 * Constant-time memory comparison (wraps ct_ops).
 * Returns 0 if the first len bytes of a and b are equal, nonzero otherwise.
 */
int pqc_memcmp_ct(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MEM_INTERNAL_H */
