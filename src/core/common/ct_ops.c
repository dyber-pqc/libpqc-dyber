/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Constant-time operations for side-channel resistance.
 *
 * All functions use only bitwise arithmetic and avoid any branches,
 * conditional moves, or table lookups that depend on secret data.
 */

#include "core/common/ct_ops.h"

/*
 * Helper: produce an all-ones mask (0xFFFFFFFF) if x is nonzero,
 * or all-zeros (0x00000000) if x is zero.  Branchless.
 *
 * Works by OR-folding x into its sign bit via unsigned negation:
 *   if x != 0  =>  (-x | x) has MSB set  =>  arithmetic shift yields 0xFFFFFFFF
 *   if x == 0  =>  (-x | x) == 0         =>  arithmetic shift yields 0x00000000
 */
static uint32_t
ct_is_nonzero_mask(uint32_t x)
{
    return (uint32_t)((int32_t)((-x) | x) >> 31);
}

/*
 * Helper: produce 0xFFFFFFFF if x == 0, else 0x00000000.
 */
static uint32_t
ct_is_zero_mask(uint32_t x)
{
    return ~ct_is_nonzero_mask(x);
}

uint32_t
pqc_ct_eq(uint32_t a, uint32_t b)
{
    /* XOR gives 0 iff equal; map zero->1, nonzero->0 */
    return (ct_is_zero_mask(a ^ b)) & 1u;
}

uint32_t
pqc_ct_ne(uint32_t a, uint32_t b)
{
    return (ct_is_nonzero_mask(a ^ b)) & 1u;
}

uint32_t
pqc_ct_lt(uint32_t a, uint32_t b)
{
    /*
     * For unsigned a < b:
     *   If a < b, then (a - b) borrows and the MSB is set in the
     *   full 33-bit result.  We capture the borrow using the identity:
     *     borrow = ((a ^ b) ^ ((a - b) ^ b)) has MSB set when a < b
     *   but a simpler approach for uint32:
     *     (a ^ ((a ^ b) | ((a - b) ^ b))) >> 31
     *
     * Classic Hacker's Delight / CT crypto pattern.
     */
    uint32_t d = a - b;
    /* borrow bit: set if a < b */
    uint32_t borrow = (a ^ ((a ^ b) | ((a - b) ^ b)));
    return (borrow >> 31) & 1u;

    (void)d; /* suppress unused warning on some compilers */
}

uint32_t
pqc_ct_select(uint32_t a, uint32_t b, uint32_t selector)
{
    /*
     * mask = 0x00000000 if selector == 0
     * mask = 0xFFFFFFFF if selector == 1
     *
     * result = a ^ (mask & (a ^ b))
     *        = a  when mask == 0
     *        = b  when mask == 0xFFFFFFFF
     */
    uint32_t mask = (uint32_t)(-(int32_t)selector);
    return a ^ (mask & (a ^ b));
}

void
pqc_ct_cmov(uint8_t *dst, const uint8_t *src, size_t len, uint32_t selector)
{
    uint8_t mask = (uint8_t)(-(int32_t)selector);
    size_t i;

    for (i = 0; i < len; i++) {
        dst[i] ^= mask & (dst[i] ^ src[i]);
    }
}

int
pqc_ct_memcmp(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint32_t diff = 0;
    size_t i;

    for (i = 0; i < len; i++) {
        diff |= (uint32_t)(pa[i] ^ pb[i]);
    }

    /*
     * Return 0 if equal, 1 if different.
     * We collapse diff to a single bit without branching.
     */
    return (int)((ct_is_nonzero_mask(diff)) & 1u);
}
