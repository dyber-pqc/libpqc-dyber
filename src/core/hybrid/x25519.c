/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * X25519 Diffie-Hellman key agreement (RFC 7748).
 *
 * Scalar multiplication on Curve25519 using the Montgomery ladder.
 * All operations are constant-time.
 */

#include <string.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/rand.h"
#include "field25519.h"

/* X25519 key/shared-secret sizes */
#define X25519_BYTES 32

/* ------------------------------------------------------------------ */
/* Clamp a scalar per RFC 7748 Section 5                                */
/* ------------------------------------------------------------------ */

static void x25519_clamp(uint8_t e[32])
{
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;
}

/* ------------------------------------------------------------------ */
/* Montgomery ladder scalar multiplication                              */
/*                                                                      */
/* Computes q = n * p  where p is an x-coordinate on Curve25519.        */
/* Uses differential addition with projective (X:Z) coordinates.        */
/* ------------------------------------------------------------------ */

static void x25519_scalar_mult(uint8_t q[32], const uint8_t n[32],
                                const uint8_t p[32])
{
    uint8_t e[32];
    memcpy(e, n, 32);
    x25519_clamp(e);

    fe25519 x1, x2, z2, x3, z3, tmp0, tmp1;

    fe25519_frombytes(x1, p);
    fe25519_1(x2);           /* x2 = 1  (point at infinity projective) */
    fe25519_0(z2);           /* z2 = 0 */
    fe25519_copy(x3, x1);   /* x3 = u */
    fe25519_1(z3);           /* z3 = 1 */

    uint64_t swap = 0;

    /* Iterate from bit 254 down to 0 */
    for (int pos = 254; pos >= 0; pos--) {
        uint64_t b = (e[pos / 8] >> (pos & 7)) & 1;

        /* Constant-time conditional swap */
        swap ^= b;
        fe25519_cswap(x2, x3, swap);
        fe25519_cswap(z2, z3, swap);
        swap = b;

        /* Montgomery ladder step */
        fe25519 A, AA, B, BB, E, C, D, DA, CB;

        fe25519_add(A, x2, z2);
        fe25519_sq(AA, A);
        fe25519_sub(B, x2, z2);
        fe25519_sq(BB, B);
        fe25519_sub(E, AA, BB);
        fe25519_add(C, x3, z3);
        fe25519_sub(D, x3, z3);
        fe25519_mul(DA, D, A);
        fe25519_mul(CB, C, B);

        fe25519_add(tmp0, DA, CB);
        fe25519_sq(x3, tmp0);

        fe25519_sub(tmp0, DA, CB);
        fe25519_sq(tmp0, tmp0);
        fe25519_mul(z3, x1, tmp0);

        fe25519_mul(x2, AA, BB);
        fe25519_mul121666(tmp1, E);
        fe25519_add(tmp1, AA, tmp1);
        fe25519_mul(z2, E, tmp1);
    }

    /* Final swap */
    fe25519_cswap(x2, x3, swap);
    fe25519_cswap(z2, z3, swap);

    /* Recover affine x-coordinate: x = x2 * z2^{-1} */
    fe25519_inv(z2, z2);
    fe25519_mul(x2, x2, z2);
    fe25519_tobytes(q, x2);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

/*
 * The base point for Curve25519 is u=9.
 */
static const uint8_t x25519_basepoint[32] = { 9 };

int x25519_keygen(uint8_t pk[32], uint8_t sk[32])
{
    pqc_status_t rc = pqc_randombytes(sk, X25519_BYTES);
    if (rc != PQC_OK)
        return (int)rc;

    x25519_scalar_mult(pk, sk, x25519_basepoint);
    return 0;
}

int x25519_shared_secret(uint8_t ss[32], const uint8_t pk[32],
                          const uint8_t sk[32])
{
    x25519_scalar_mult(ss, sk, pk);

    /* Check for all-zero output (low-order point contribution) */
    uint8_t zero_check = 0;
    for (int i = 0; i < 32; i++)
        zero_check |= ss[i];

    if (zero_check == 0)
        return -1;

    return 0;
}
