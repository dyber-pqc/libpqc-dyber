/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Constant-time utilities for the ML-KEM Fujisaki-Okamoto transform.
 */

#include "core/kem/mlkem/verify.h"

/*
 * Constant-time byte-array comparison.
 *
 * Accumulates the XOR of all byte pairs; returns 0 iff all bytes match.
 * The accumulator is folded through OR so that timing and control flow
 * are data-independent.
 */
int pqc_mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    uint64_t r = 0;

    for (i = 0; i < len; i++) {
        r |= a[i] ^ b[i];
    }

    /* Returns 0 if equal, 1 if different. */
    r = (~r + 1) >> 63; /* nonzero -> 1, zero -> 0 */
    return (int)r;
}

/*
 * Constant-time conditional copy.
 *
 * If b is nonzero, copies src to dst.  If b is zero, dst is unchanged.
 * Implemented with a mask derived from b without branching.
 */
void pqc_mlkem_cmov(uint8_t *dst, const uint8_t *src, size_t len, uint8_t b)
{
    size_t i;
    /* Map nonzero b to 0xFF, zero b to 0x00, without branches. */
    b = -b;

    for (i = 0; i < len; i++) {
        dst[i] ^= b & (dst[i] ^ src[i]);
    }
}
