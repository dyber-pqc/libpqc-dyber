/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Constant-time utilities for the ML-KEM Fujisaki-Okamoto transform.
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#include <stddef.h>
#include <stdint.h>
#include "core/kem/mlkem/verify.h"

/*************************************************
* Name:        pqc_mlkem_verify
*
* Description: Compare two arrays for equality in constant time.
*
* Arguments:   const uint8_t *a: pointer to first byte array
*              const uint8_t *b: pointer to second byte array
*              size_t len:       length of the byte arrays
*
* Returns 0 if the byte arrays are equal, 1 otherwise
**************************************************/
int pqc_mlkem_verify(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t i;
    uint8_t r = 0;

    for (i = 0; i < len; i++)
        r |= a[i] ^ b[i];

    return (-(uint64_t)r) >> 63;
}

/*************************************************
* Name:        pqc_mlkem_cmov
*
* Description: Copy len bytes from src to dst if b is 1;
*              don't modify dst if b is 0. Requires b to be in {0,1};
*              assumes two's complement representation of negative integers.
*              Runs in constant time.
*
* Arguments:   uint8_t *dst:      pointer to output byte array
*              const uint8_t *src: pointer to input byte array
*              size_t len:         Amount of bytes to be copied
*              uint8_t b:          Condition bit; has to be in {0,1}
**************************************************/
void pqc_mlkem_cmov(uint8_t *dst, const uint8_t *src, size_t len, uint8_t b)
{
    size_t i;

#if defined(__GNUC__) || defined(__clang__)
    /* Prevent the compiler from inferring that b is 0/1-valued,
     * and handling the two cases with a branch. */
    __asm__("" : "+r"(b) : /* no inputs */);
#endif

    b = -b;
    for (i = 0; i < len; i++)
        dst[i] ^= b & (dst[i] ^ src[i]);
}

/*************************************************
* Name:        pqc_mlkem_cmov_int16
*
* Description: Copy input v to *r if b is 1, don't modify *r if b is 0.
*              Requires b to be in {0,1};
*              Runs in constant time.
*
* Arguments:   int16_t *r:  pointer to output int16_t
*              int16_t v:   input int16_t
*              uint16_t b:  Condition bit; has to be in {0,1}
**************************************************/
void pqc_mlkem_cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
    b = -b;
    *r ^= b & ((*r) ^ v);
}
