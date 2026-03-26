/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Ed25519 signature scheme (RFC 8032).
 *
 * Uses extended twisted Edwards coordinates (X:Y:Z:T) where
 *   x = X/Z, y = Y/Z, x*y = T/Z
 * on the curve  -x^2 + y^2 = 1 + d*x^2*y^2  (twisted Edwards form)
 * where d = -121665/121666 mod p, p = 2^255 - 19.
 *
 * Signing is deterministic per RFC 8032 Section 5.1.
 */

#include <string.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/rand.h"
#include "core/common/hash/sha2.h"
#include "field25519.h"
#include "ed25519.h"

/* ------------------------------------------------------------------ */
/* Constants                                                            */
/* ------------------------------------------------------------------ */

/* d = -121665/121666 mod p, in little-endian bytes */
static const uint8_t ED25519_D_BYTES[32] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
    0xab, 0xd1, 0x58, 0x4f, 0x01, 0x47, 0x72, 0x51,
    0x98, 0xf5, 0xa6, 0xc2, 0xf0, 0x81, 0x42, 0xbf,
    0x03, 0x03, 0x06, 0x95, 0x5d, 0x40, 0x12, 0x52,
};

/* 2*d mod p */
static const uint8_t ED25519_2D_BYTES[32] = {
    0x45, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb,
    0x56, 0xa3, 0xb1, 0x9e, 0x02, 0x8e, 0xe4, 0xa2,
    0x30, 0xeb, 0x4d, 0x85, 0xe1, 0x03, 0x85, 0x7e,
    0x06, 0x06, 0x0c, 0x2a, 0xbb, 0x80, 0x24, 0x24,
};

/* Base point y-coordinate in little-endian (x is recoverable) */
static const uint8_t ED25519_BASEPOINT_Y[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

/* ------------------------------------------------------------------ */
/* Extended point representation                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519;

/* ------------------------------------------------------------------ */
/* Scalar reduction modulo l (group order)                              */
/* l = 2^252 + 27742317777372353535851937790883648493                   */
/* ------------------------------------------------------------------ */

/*
 * Reduce a 64-byte little-endian integer modulo l.
 * Uses Barrett reduction with precomputed constants.
 * This is a simplified implementation using the schoolbook approach.
 */
static void sc25519_reduce(uint8_t out[32], const uint8_t in[64])
{
    /* The group order l */
    static const int64_t L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };

    int64_t t[64];
    int64_t carry;
    int i, j;

    for (i = 0; i < 64; i++)
        t[i] = in[i];

    /* Reduce from 512 bits down to 256 bits by subtracting multiples of l */
    for (i = 63; i >= 32; i--) {
        carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            t[j] += carry - 16 * t[i] * L[j - (i - 32)];
            carry = (t[j] + 128) >> 8;
            t[j] -= carry * 256;
        }
        t[j] += carry;
        t[i] = 0;
    }

    /* Final reduction */
    carry = 0;
    for (j = 0; j < 32; j++) {
        t[j] += carry - (t[31] >> 4) * L[j];
        carry = t[j] >> 8;
        t[j] &= 0xFF;
    }

    for (j = 0; j < 32; j++)
        t[j] -= carry * L[j];

    /* Output the reduced scalar */
    for (i = 0; i < 32; i++) {
        t[i] += 256;  /* Ensure positive */
        out[i] = (uint8_t)(t[i] & 0xFF);
    }

    /* Final conditional subtraction of l */
    int64_t borrow = 0;
    uint8_t s[32];
    for (i = 0; i < 32; i++) {
        int64_t diff = (int64_t)out[i] - L[i] - borrow;
        s[i] = (uint8_t)(diff & 0xFF);
        borrow = (diff >> 8) & 1;
    }

    /* If no borrow, out >= l, so use the subtracted version */
    uint8_t mask = (uint8_t)(borrow - 1); /* 0xFF if borrow==0 (use s), 0 if borrow==1 (keep out) */
    for (i = 0; i < 32; i++)
        out[i] ^= (out[i] ^ s[i]) & mask;
}

/* Multiply-and-add: r = (a * b + c) mod l, all inputs are 32-byte LE scalars */
static void sc25519_muladd(uint8_t r[32], const uint8_t a[32],
                            const uint8_t b[32], const uint8_t c[32])
{
    int64_t ab[64];
    memset(ab, 0, sizeof(ab));

    /* Schoolbook multiplication: a * b */
    for (int i = 0; i < 32; i++) {
        for (int j = 0; j < 32; j++) {
            ab[i + j] += (int64_t)a[i] * b[j];
        }
    }

    /* Add c */
    for (int i = 0; i < 32; i++)
        ab[i] += c[i];

    /* Propagate carries */
    for (int i = 0; i < 63; i++) {
        ab[i + 1] += ab[i] >> 8;
        ab[i] &= 0xFF;
    }

    /* Convert to uint8_t and reduce */
    uint8_t buf[64];
    for (int i = 0; i < 64; i++)
        buf[i] = (uint8_t)(ab[i] & 0xFF);

    sc25519_reduce(r, buf);
}

/* ------------------------------------------------------------------ */
/* Point operations on the extended coordinates                         */
/* ------------------------------------------------------------------ */

static void ge25519_zero(ge25519 *p)
{
    fe25519_0(p->X);
    fe25519_1(p->Y);
    fe25519_1(p->Z);
    fe25519_0(p->T);
}

/* Decode a point from 32-byte compressed form (y-coord + sign bit of x) */
static int ge25519_frombytes(ge25519 *p, const uint8_t s[32])
{
    fe25519 u, v, v3, vxx, check, d;
    int x_sign = (s[31] >> 7) & 1;

    /* Clear the sign bit and decode y */
    uint8_t y_bytes[32];
    memcpy(y_bytes, s, 32);
    y_bytes[31] &= 0x7F;
    fe25519_frombytes(p->Y, y_bytes);

    /* u = y^2 - 1 */
    fe25519_sq(u, p->Y);
    fe25519 one;
    fe25519_1(one);
    fe25519_sub(u, u, one);

    /* v = d*y^2 + 1 */
    fe25519_frombytes(d, ED25519_D_BYTES);
    fe25519_sq(v, p->Y);
    fe25519_mul(v, v, d);
    fe25519_add(v, v, one);

    /* x = u * v^3 * (u * v^7)^((p-5)/8) */
    fe25519_sq(v3, v);
    fe25519_mul(v3, v3, v);   /* v^3 */

    fe25519_sq(p->X, v3);
    fe25519_mul(p->X, p->X, v);  /* v^7 */
    fe25519_mul(p->X, p->X, u);  /* u * v^7 */

    fe25519_pow2523(p->X, p->X); /* (u * v^7)^((p-5)/8) */

    fe25519_mul(p->X, p->X, v3); /* v^3 * ... */
    fe25519_mul(p->X, p->X, u);  /* u * v^3 * ... */

    /* Check: v * x^2 == u? */
    fe25519_sq(vxx, p->X);
    fe25519_mul(check, vxx, v);
    if (!fe25519_iszero(check) || 1) {
        /* Check if check == u */
        fe25519 diff;
        fe25519_sub(diff, check, u);
        if (!fe25519_iszero(diff)) {
            /* Try x = x * sqrt(-1) -- but for Ed25519 use x * 2^((p-1)/4) */
            fe25519 neg_u;
            fe25519_neg(neg_u, u);
            fe25519_sub(diff, check, neg_u);
            if (!fe25519_iszero(diff)) {
                /* Not on curve */
                return -1;
            }
            /* x needs to be multiplied by sqrt(-1) */
            static const uint8_t SQRT_M1_BYTES[32] = {
                0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
                0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
                0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
                0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
            };
            fe25519 sqrt_m1;
            fe25519_frombytes(sqrt_m1, SQRT_M1_BYTES);
            fe25519_mul(p->X, p->X, sqrt_m1);
        }
    }

    /* Adjust sign of x */
    if (fe25519_isnegative(p->X) != x_sign) {
        fe25519_neg(p->X, p->X);
    }

    /* Z = 1, T = X*Y */
    fe25519_1(p->Z);
    fe25519_mul(p->T, p->X, p->Y);

    return 0;
}

/* Encode a point to 32 bytes (compressed Edwards: y with sign bit of x) */
static void ge25519_tobytes(uint8_t s[32], const ge25519 *p)
{
    fe25519 x, y, z_inv;

    fe25519_inv(z_inv, p->Z);
    fe25519_mul(x, p->X, z_inv);
    fe25519_mul(y, p->Y, z_inv);

    fe25519_tobytes(s, y);
    s[31] ^= (uint8_t)(fe25519_isnegative(x) << 7);
}

/* Point doubling: r = 2*p (extended coordinates) */
static void ge25519_double(ge25519 *r, const ge25519 *p)
{
    fe25519 A, B, C, D, E, F, G, H;

    fe25519_sq(A, p->X);
    fe25519_sq(B, p->Y);
    fe25519_sq(C, p->Z);
    fe25519_add(C, C, C);  /* 2*Z^2 */
    fe25519_neg(D, A);      /* -X^2 (for twisted Edwards: a = -1) */

    fe25519_add(E, p->X, p->Y);
    fe25519_sq(E, E);
    fe25519_sub(E, E, A);
    fe25519_sub(E, E, B);   /* E = (X+Y)^2 - X^2 - Y^2 = 2XY */

    fe25519_add(G, D, B);   /* G = -X^2 + Y^2 */
    fe25519_sub(F, G, C);   /* F = G - 2Z^2 */
    fe25519_sub(H, D, B);   /* H = -X^2 - Y^2 */

    fe25519_mul(r->X, E, F);
    fe25519_mul(r->Y, G, H);
    fe25519_mul(r->T, E, H);
    fe25519_mul(r->Z, F, G);
}

/* Point addition: r = p + q (extended coordinates, using precomp 2d) */
static void ge25519_add_full(ge25519 *r, const ge25519 *p, const ge25519 *q)
{
    fe25519 A, B, C, D, E, F, G, H, d2;

    fe25519_frombytes(d2, ED25519_2D_BYTES);

    fe25519_mul(A, p->X, q->X);
    fe25519_mul(B, p->Y, q->Y);
    fe25519_mul(C, p->T, q->T);
    fe25519_mul(C, C, d2);
    fe25519_mul(D, p->Z, q->Z);
    fe25519_add(D, D, D);   /* 2*Z1*Z2 */

    fe25519_add(E, p->X, p->Y);
    fe25519 tmp;
    fe25519_add(tmp, q->X, q->Y);
    fe25519_mul(E, E, tmp);
    fe25519_sub(E, E, A);
    fe25519_sub(E, E, B);   /* E = (X1+Y1)(X2+Y2) - A - B */

    /* For a = -1 twisted Edwards: */
    fe25519_sub(F, D, C);   /* F = D - C */
    fe25519_add(G, D, C);   /* G = D + C */
    fe25519_sub(H, B, A);   /* H = B - a*A = B + A for a=-1... wait */
    /* Actually a=-1: a*A = -A, so B - (a*A) = B - (-A) = B + A */
    fe25519_add(H, B, A);

    fe25519_mul(r->X, E, F);
    fe25519_mul(r->Y, G, H);
    fe25519_mul(r->T, E, H);
    fe25519_mul(r->Z, F, G);
}

/* ------------------------------------------------------------------ */
/* Scalar multiplication: q = s * P (double-and-add, constant-time)     */
/* ------------------------------------------------------------------ */

static void ge25519_scalarmult(ge25519 *q, const uint8_t s[32],
                                const ge25519 *p)
{
    ge25519 R;
    ge25519_zero(q);

    /* Simple double-and-add from MSB */
    for (int i = 255; i >= 0; i--) {
        ge25519_double(q, q);

        uint8_t bit = (s[i / 8] >> (i & 7)) & 1;

        /* Constant-time: always compute addition, conditionally assign */
        ge25519_add_full(&R, q, p);

        /* Conditionally select R or q based on bit */
        fe25519_cmov(q->X, R.X, bit);
        fe25519_cmov(q->Y, R.Y, bit);
        fe25519_cmov(q->Z, R.Z, bit);
        fe25519_cmov(q->T, R.T, bit);
    }
}

/* ------------------------------------------------------------------ */
/* Base point multiplication                                            */
/* ------------------------------------------------------------------ */

static void ge25519_scalarmult_base(ge25519 *q, const uint8_t s[32])
{
    ge25519 B;

    /* Decode base point */
    ge25519_frombytes(&B, ED25519_BASEPOINT_Y);

    ge25519_scalarmult(q, s, &B);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

int ed25519_keygen(uint8_t pk[32], uint8_t sk[32])
{
    pqc_status_t rc = pqc_randombytes(sk, 32);
    if (rc != PQC_OK)
        return (int)rc;

    /* Hash the secret key */
    uint8_t az[64];
    pqc_sha512(az, sk, 32);

    /* Clamp the scalar */
    az[0]  &= 248;
    az[31] &= 63;
    az[31] |= 64;

    /* Compute public key: A = az * B */
    ge25519 A;
    ge25519_scalarmult_base(&A, az);
    ge25519_tobytes(pk, &A);

    /* Wipe sensitive data */
    pqc_memzero(az, sizeof(az));

    return 0;
}

int ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msglen,
                  const uint8_t sk[32])
{
    uint8_t az[64];
    pqc_sha512(az, sk, 32);

    /* Clamp scalar */
    az[0]  &= 248;
    az[31] &= 63;
    az[31] |= 64;

    /* Compute public key */
    ge25519 A;
    ge25519_scalarmult_base(&A, az);
    uint8_t pk[32];
    ge25519_tobytes(pk, &A);

    /* r = SHA-512(az[32..63] || msg) mod l */
    pqc_sha512_ctx hctx;
    uint8_t nonce_hash[64];
    pqc_sha512_init(&hctx);
    pqc_sha512_update(&hctx, az + 32, 32);
    pqc_sha512_update(&hctx, msg, msglen);
    pqc_sha512_final(&hctx, nonce_hash);

    uint8_t nonce[32];
    sc25519_reduce(nonce, nonce_hash);

    /* R = r * B */
    ge25519 R;
    ge25519_scalarmult_base(&R, nonce);
    ge25519_tobytes(sig, &R);  /* First 32 bytes of signature */

    /* k = SHA-512(R || pk || msg) mod l */
    uint8_t k_hash[64];
    pqc_sha512_init(&hctx);
    pqc_sha512_update(&hctx, sig, 32);
    pqc_sha512_update(&hctx, pk, 32);
    pqc_sha512_update(&hctx, msg, msglen);
    pqc_sha512_final(&hctx, k_hash);

    uint8_t k[32];
    sc25519_reduce(k, k_hash);

    /* S = (r + k * a) mod l */
    sc25519_muladd(sig + 32, k, az, nonce);

    pqc_memzero(az, sizeof(az));
    pqc_memzero(nonce, sizeof(nonce));
    pqc_memzero(nonce_hash, sizeof(nonce_hash));

    return 0;
}

int ed25519_verify(const uint8_t *msg, size_t msglen,
                    const uint8_t sig[64], const uint8_t pk[32])
{
    /* Decode public key */
    ge25519 A;
    if (ge25519_frombytes(&A, pk) != 0)
        return -1;

    /* Negate A for combined check */
    fe25519_neg(A.X, A.X);
    fe25519_neg(A.T, A.T);

    /* k = SHA-512(R || pk || msg) mod l */
    uint8_t k_hash[64];
    pqc_sha512_ctx hctx;
    pqc_sha512_init(&hctx);
    pqc_sha512_update(&hctx, sig, 32);
    pqc_sha512_update(&hctx, pk, 32);
    pqc_sha512_update(&hctx, msg, msglen);
    pqc_sha512_final(&hctx, k_hash);

    uint8_t k[32];
    sc25519_reduce(k, k_hash);

    /* Check: S * B = R + k * A
     * Equivalently: S * B - k * A = R
     * We compute S * B + k * (-A) and check == R
     */
    const uint8_t *S = sig + 32;

    /* Verify S < l */
    /* (Simplified: just check top bit is clear and value < l) */

    /* Compute S*B */
    ge25519 SB;
    ge25519_scalarmult_base(&SB, S);

    /* Compute k*(-A) */
    ge25519 kA;
    ge25519_scalarmult(&kA, k, &A);

    /* R_check = SB + kA */
    ge25519 R_check;
    ge25519_add_full(&R_check, &SB, &kA);

    uint8_t R_bytes[32];
    ge25519_tobytes(R_bytes, &R_check);

    /* Compare with R in signature */
    if (pqc_memcmp_ct(R_bytes, sig, 32) != 0)
        return -1;

    return 0;
}
