/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Constant-time comparison and conditional copy for ML-KEM (FIPS 203).
 */

#ifndef PQC_MLKEM_VERIFY_H
#define PQC_MLKEM_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Constant-time comparison of two byte arrays.
 *
 * @return 0 if a[0..len-1] == b[0..len-1], nonzero otherwise.
 *         Timing is independent of content.
 */
int pqc_mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len);

/**
 * Constant-time conditional move.
 *
 * If b != 0, copy src[0..len-1] to dst[0..len-1].
 * If b == 0, dst is unchanged.
 * Runs in constant time regardless of b.
 */
void pqc_mlkem_cmov(uint8_t *dst, const uint8_t *src, size_t len, uint8_t b);

#ifdef __cplusplus
}
#endif

#endif /* PQC_MLKEM_VERIFY_H */
