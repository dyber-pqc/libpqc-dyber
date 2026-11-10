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

/*
 * d = -121665/121666 mod p, in little-endian bytes:
 * 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
 * (RFC 8032 section 5.1).
 */
static const uint8_t ED25519_D_BYTES[32] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
    0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
    0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
};

/*
 * 2*d mod p:
 * 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159
 */
static const uint8_t ED25519_2D_BYTES[32] = {
    0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb,
    0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
    0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19,
    0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24,
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

    /*
     * The loop above subtracted floor(t / 2^252) * l, which can overshoot
     * by one l because l > 2^252; carry is then -1 and l is added back.
     * The bytes are no longer normalised after that, so the carries have
     * to be propagated while writing the result. (Masking each byte on
     * its own, as this function used to, drops them.)
     */
    for (j = 0; j < 32; j++)
        t[j] -= carry * L[j];

    for (i = 0; i < 32; i++) {
        t[i + 1] += t[i] >> 8;
        out[i] = (uint8_t)(t[i] & 0xFF);
    }
}

/* Returns 1 if the 32-byte little-endian scalar s is below l, else 0. */
static int sc25519_is_canonical(const uint8_t s[32])
{
    static const uint8_t L[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    };
    unsigned borrow = 0;

    /* s - l borrows out of the top byte exactly when s < l */
    for (int i = 0; i < 32; i++)
        borrow = (((unsigned)s[i] - L[i] - borrow) >> 8) & 1;

    return (int)borrow;
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

/*
 * Decode a point from 32-byte compressed form (y-coord + sign bit of x),
 * RFC 8032 section 5.1.3. Returns 0 on success, -1 if the encoding is not
 * a point on the curve or is not canonical.
 */
static int ge25519_frombytes(ge25519 *p, const uint8_t s[32])
{
    fe25519 u, v, v3, vxx, check, d;
    int x_sign = (s[31] >> 7) & 1;

    /*
     * Bit 255 is the sign of x, not part of y. fe25519_frombytes ignores
     * it; clear it anyway so the canonical check below compares like
     * with like.
     */
    uint8_t y_bytes[32], y_canon[32];
    memcpy(y_bytes, s, 32);
    y_bytes[31] &= 0x7F;
    fe25519_frombytes(p->Y, y_bytes);

    /* Reject y >= p: re-encoding reduces, so a mismatch means non-canonical */
    fe25519_tobytes(y_canon, p->Y);
    if (memcmp(y_canon, y_bytes, 32) != 0)
        return -1;

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
    fe25519 diff;
    fe25519_sq(vxx, p->X);
    fe25519_mul(check, vxx, v);
    fe25519_sub(diff, check, u);
    if (!fe25519_iszero(diff)) {
        /* v * x^2 == -u means x is off by a factor of sqrt(-1) */
        fe25519_add(diff, check, u);
        if (!fe25519_iszero(diff)) {
            /* u/v is not a square: no such point */
            return -1;
        }
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

    /* x = 0 has no negative: the sign bit must be clear (RFC 8032 5.1.3) */
    if (fe25519_iszero(p->X) && x_sign)
        return -1;

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

/*
 * Point addition: r = p + q in extended coordinates, for a = -1
 * (Hisil-Wong-Carter-Dawson 2008, section 3.1; "add-2008-hwcd-3").
 * The formula is complete on this curve, so it also doubles and handles
 * the neutral element. r may alias p or q.
 *
 *   A = (Y1-X1)(Y2-X2)   B = (Y1+X1)(Y2+X2)
 *   C = 2d*T1*T2         D = 2*Z1*Z2
 *   E = B-A  F = D-C  G = D+C  H = B+A
 *   X3 = E*F  Y3 = G*H  T3 = E*H  Z3 = F*G
 *
 * E = 2(X1Y2 + Y1X2) and H = 2(Y1Y2 + X1X2) carry the same factor of 2 as
 * C and D. The earlier code mixed this variant's C and D with the
 * un-doubled E and H of the plain formula, which halves both affine
 * coordinates of every sum.
 */
static void ge25519_add_full(ge25519 *r, const ge25519 *p, const ge25519 *q)
{
    fe25519 A, B, C, D, E, F, G, H, d2, t0, t1;

    fe25519_frombytes(d2, ED25519_2D_BYTES);

    fe25519_sub(t0, p->Y, p->X);
    fe25519_sub(t1, q->Y, q->X);
    fe25519_mul(A, t0, t1);
    fe25519_add(t0, p->Y, p->X);
    fe25519_add(t1, q->Y, q->X);
    fe25519_mul(B, t0, t1);
    fe25519_mul(C, p->T, q->T);
    fe25519_mul(C, C, d2);
    fe25519_mul(D, p->Z, q->Z);
    fe25519_add(D, D, D);

    fe25519_sub(E, B, A);
    fe25519_sub(F, D, C);
    fe25519_add(G, D, C);
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

    /*
     * Reject S >= l (RFC 8032 section 5.1.7). Without this, (R, S + l)
     * verifies whenever (R, S) does, so signatures are malleable.
     */
    if (!sc25519_is_canonical(S))
        return -1;

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
