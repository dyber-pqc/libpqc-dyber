/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Field arithmetic for NIST P-256.
 * p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 *   = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
 *
 * Representation: 4 limbs of 64 bits each (little-endian).
 * Reduction uses the special structure of the NIST prime.
 *
 * Group order n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 *
 * Field and scalar multiplication, addition and subtraction are
 * branch-free. The point arithmetic is not: p256_point_scalar_mult() is
 * a plain double-and-add whose sequence of operations depends on the
 * scalar. See the note there.
 */

#include <string.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/rand.h"
#include "field_p256.h"

/* ------------------------------------------------------------------ */
/* The NIST P-256 prime (little-endian limbs)                           */
/* ------------------------------------------------------------------ */

const p256_fe P256_P = {
    0xFFFFFFFFFFFFFFFFULL,  /* limb 0 */
    0x00000000FFFFFFFFULL,  /* limb 1 */
    0x0000000000000000ULL,  /* limb 2 */
    0xFFFFFFFF00000001ULL,  /* limb 3 */
};

/* The group order n (little-endian limbs) */
const p256_fe P256_N = {
    0xF3B9CAC2FC632551ULL,
    0xBCE6FAADA7179E84ULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFF00000000ULL,
};

/* Generator point coordinates (affine, big-endian hex to little-endian limbs) */
/* Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296 */
static const p256_fe P256_GX = {
    0xF4A13945D898C296ULL,
    0x77037D812DEB33A0ULL,
    0xF8BCE6E563A440F2ULL,
    0x6B17D1F2E12C4247ULL,
};

/* Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 */
static const p256_fe P256_GY = {
    0xCBB6406837BF51F5ULL,
    0x2BCE33576B315ECEULL,
    0x8EE7EB4A7C0F9E16ULL,
    0x4FE342E2FE1A7F9BULL,
};

/* ------------------------------------------------------------------ */
/* Load / store (big-endian bytes <-> little-endian limbs)               */
/* ------------------------------------------------------------------ */

void p256_fe_frombytes(p256_fe h, const uint8_t s[32])
{
    /* s is big-endian: s[0..7] is the most significant limb */
    for (int i = 0; i < 4; i++) {
        const uint8_t *b = s + (3 - i) * 8;
        h[i] = ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48)
             | ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32)
             | ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16)
             | ((uint64_t)b[6] << 8)  | ((uint64_t)b[7]);
    }
}

void p256_fe_tobytes(uint8_t s[32], const p256_fe h)
{
    for (int i = 0; i < 4; i++) {
        uint8_t *b = s + (3 - i) * 8;
        uint64_t v = h[i];
        b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
        b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
        b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
        b[6] = (uint8_t)(v >> 8);  b[7] = (uint8_t)v;
    }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

void p256_fe_zero(p256_fe h)
{
    h[0] = h[1] = h[2] = h[3] = 0;
}

void p256_fe_one(p256_fe h)
{
    h[0] = 1; h[1] = h[2] = h[3] = 0;
}

void p256_fe_copy(p256_fe h, const p256_fe f)
{
    h[0] = f[0]; h[1] = f[1]; h[2] = f[2]; h[3] = f[3];
}

int p256_fe_is_zero(const p256_fe f)
{
    uint64_t r = f[0] | f[1] | f[2] | f[3];
    return (r == 0) ? 1 : 0;
}

int p256_fe_cmp(const p256_fe f, const p256_fe g)
{
    for (int i = 3; i >= 0; i--) {
        if (f[i] > g[i]) return 1;
        if (f[i] < g[i]) return -1;
    }
    return 0;
}

void p256_fe_cmov(p256_fe f, const p256_fe g, uint64_t b)
{
    uint64_t mask = (uint64_t)(-(int64_t)b);
    f[0] ^= (f[0] ^ g[0]) & mask;
    f[1] ^= (f[1] ^ g[1]) & mask;
    f[2] ^= (f[2] ^ g[2]) & mask;
    f[3] ^= (f[3] ^ g[3]) & mask;
}

/* ------------------------------------------------------------------ */
/* 256-bit integer helpers                                              */
/* ------------------------------------------------------------------ */

/* r = a + b, returns the carry out (0 or 1) */
static uint64_t add256(p256_fe r, const p256_fe a, const p256_fe b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t s = a[i] + carry;
        uint64_t c1 = (s < carry);
        uint64_t t = s + b[i];
        uint64_t c2 = (t < s);
        r[i] = t;
        carry = c1 | c2;
    }
    return carry;
}

/* r = a - b, returns the borrow out (0 or 1) */
static uint64_t sub256(p256_fe r, const p256_fe a, const p256_fe b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t d = a[i] - b[i];
        uint64_t b1 = (a[i] < b[i]);
        uint64_t e = d - borrow;
        uint64_t b2 = (d < borrow);
        r[i] = e;
        borrow = b1 | b2;
    }
    return borrow;
}

/* 64 x 64 -> 128: *hi:*lo = a * b */
static void mul64x64(uint64_t *hi, uint64_t *lo, uint64_t a, uint64_t b)
{
#ifdef __SIZEOF_INT128__
    unsigned __int128 p = (unsigned __int128)a * b;
    *lo = (uint64_t)p;
    *hi = (uint64_t)(p >> 64);
#else
    uint64_t a0 = (uint32_t)a, a1 = a >> 32;
    uint64_t b0 = (uint32_t)b, b1 = b >> 32;
    uint64_t p00 = a0 * b0;
    uint64_t p01 = a0 * b1;
    uint64_t p10 = a1 * b0;
    uint64_t p11 = a1 * b1;
    /* Cannot overflow: (2^32-1) + (2^32-1) + (2^32-1) < 2^64 */
    uint64_t mid = (p00 >> 32) + (uint32_t)p01 + (uint32_t)p10;
    *lo = (p00 & 0xFFFFFFFFULL) | (mid << 32);
    *hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
#endif
}

/* t[0..7] = f * g, the full 512-bit product */
static void mul256(uint64_t t[8], const p256_fe f, const p256_fe g)
{
    memset(t, 0, 8 * sizeof(uint64_t));

    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t hi, lo;
            mul64x64(&hi, &lo, f[i], g[j]);

            /* hi:lo + t[i+j] + carry fits in 128 bits */
            lo += t[i + j];
            hi += (lo < t[i + j]);
            lo += carry;
            hi += (lo < carry);

            t[i + j] = lo;
            carry = hi;
        }
        t[i + 4] = carry;
    }
}

/* ------------------------------------------------------------------ */
/* Addition and subtraction mod p                                       */
/* ------------------------------------------------------------------ */

/* Both operands must be below p; so is the result. */
void p256_fe_add(p256_fe h, const p256_fe f, const p256_fe g)
{
    uint64_t carry = add256(h, f, g);

    /* If carry or h >= p, subtract p */
    p256_fe tmp;
    uint64_t borrow = sub256(tmp, h, P256_P);

    /* Use result if carry was set or no borrow */
    uint64_t use_sub = carry | (1 - borrow);
    p256_fe_cmov(h, tmp, use_sub);
}

void p256_fe_sub(p256_fe h, const p256_fe f, const p256_fe g)
{
    uint64_t borrow = sub256(h, f, g);

    /* If the subtraction borrowed, add p back */
    p256_fe tmp;
    add256(tmp, h, P256_P);
    p256_fe_cmov(h, tmp, borrow);
}

void p256_fe_neg(p256_fe h, const p256_fe f)
{
    p256_fe zero;
    p256_fe_zero(zero);
    p256_fe_sub(h, zero, f);
}

/* ------------------------------------------------------------------ */
/* Multiplication mod p                                                 */
/* ------------------------------------------------------------------ */

/*
 * 256x256 -> 512-bit multiplication, then reduce mod p using the
 * Solinas reduction for the NIST prime (FIPS 186-4 Appendix D.2.3).
 */
void p256_fe_mul(p256_fe h, const p256_fe f, const p256_fe g)
{
    uint64_t t[8];
    mul256(t, f, g);

    /* Split t[0..7] (64-bit) into c[0..15] (32-bit), little-endian. */
    uint32_t c[16];
    for (int i = 0; i < 8; i++) {
        c[2 * i]     = (uint32_t)t[i];
        c[2 * i + 1] = (uint32_t)(t[i] >> 32);
    }

    /*
     * The result is T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4 (mod p),
     * each term eight 32-bit words, written most significant first:
     *
     * T  = (c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0)
     * S1 = (c15, c14, c13, c12, c11, 0,   0,   0)
     * S2 = (0,   c15, c14, c13, c12, 0,   0,   0)
     * S3 = (c15, c14, 0,   0,   0,   c10, c9,  c8)
     * S4 = (c8,  c13, c15, c14, c13, c11, c10, c9)
     * D1 = (c10, c8,  0,   0,   0,   c13, c12, c11)
     * D2 = (c11, c9,  0,   0,   c15, c14, c13, c12)
     * D3 = (c12, 0,   c10, c9,  c8,  c15, c14, c13)
     * D4 = (c13, 0,   c11, c10, c9,  0,   c15, c14)
     */

    int64_t s[8]; /* 32-bit word accumulators with room for carries */

    /* T */
    s[0] = (int64_t)c[0];
    s[1] = (int64_t)c[1];
    s[2] = (int64_t)c[2];
    s[3] = (int64_t)c[3];
    s[4] = (int64_t)c[4];
    s[5] = (int64_t)c[5];
    s[6] = (int64_t)c[6];
    s[7] = (int64_t)c[7];

    /* + 2*S1 */
    s[3] += 2 * (int64_t)c[11];
    s[4] += 2 * (int64_t)c[12];
    s[5] += 2 * (int64_t)c[13];
    s[6] += 2 * (int64_t)c[14];
    s[7] += 2 * (int64_t)c[15];

    /* + 2*S2 */
    s[3] += 2 * (int64_t)c[12];
    s[4] += 2 * (int64_t)c[13];
    s[5] += 2 * (int64_t)c[14];
    s[6] += 2 * (int64_t)c[15];

    /* + S3 */
    s[0] += (int64_t)c[8];
    s[1] += (int64_t)c[9];
    s[2] += (int64_t)c[10];
    s[6] += (int64_t)c[14];
    s[7] += (int64_t)c[15];

    /* + S4 */
    s[0] += (int64_t)c[9];
    s[1] += (int64_t)c[10];
    s[2] += (int64_t)c[11];
    s[3] += (int64_t)c[13];
    s[4] += (int64_t)c[14];
    s[5] += (int64_t)c[15];
    s[6] += (int64_t)c[13];
    s[7] += (int64_t)c[8];

    /* - D1 */
    s[0] -= (int64_t)c[11];
    s[1] -= (int64_t)c[12];
    s[2] -= (int64_t)c[13];
    s[6] -= (int64_t)c[8];
    s[7] -= (int64_t)c[10];

    /* - D2 */
    s[0] -= (int64_t)c[12];
    s[1] -= (int64_t)c[13];
    s[2] -= (int64_t)c[14];
    s[3] -= (int64_t)c[15];
    s[6] -= (int64_t)c[9];
    s[7] -= (int64_t)c[11];

    /* - D3 */
    s[0] -= (int64_t)c[13];
    s[1] -= (int64_t)c[14];
    s[2] -= (int64_t)c[15];
    s[3] -= (int64_t)c[8];
    s[4] -= (int64_t)c[9];
    s[5] -= (int64_t)c[10];
    s[7] -= (int64_t)c[12];

    /* - D4 */
    s[0] -= (int64_t)c[14];
    s[1] -= (int64_t)c[15];
    s[3] -= (int64_t)c[9];
    s[4] -= (int64_t)c[10];
    s[5] -= (int64_t)c[11];
    s[7] -= (int64_t)c[13];

    /*
     * Carry through the 32-bit words, then fold whatever is left above
     * bit 255 back in using 2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p).
     *
     * The first pass leaves a carry of at most a few units in either
     * direction. Folding it moves the value by less than 2^228, so the
     * second pass can leave a carry of -1, 0 or +1, and folding that
     * cannot produce another: after a +1 the low 256 bits are below
     * 2^228, and after a -1 they are within 2^228 of 2^256. Three passes
     * therefore always end with a zero carry.
     *
     * (This previously stopped after the second pass and discarded its
     * carry, which gave a result off by a multiple of 2^256 for about
     * one random operand pair in 2^32, and far more often for operands
     * with runs of zero or one bits.)
     */
    for (int pass = 0; pass < 3; pass++) {
        int64_t carry = 0;
        for (int i = 0; i < 8; i++) {
            s[i] += carry;
            /* floor division by 2^32, without shifting a negative value */
            carry = (s[i] - (s[i] & 0xFFFFFFFFLL)) / 4294967296LL;
            s[i] &= 0xFFFFFFFFLL;
        }
        s[0] += carry;
        s[3] -= carry;     /* -2^96 */
        s[6] -= carry;     /* -2^192 */
        s[7] += carry;     /* +2^224 */
    }
    /*
     * The last pass had a zero carry out, so the fold above added
     * nothing and every s[i] is a clean 32-bit word.
     */

    h[0] = (uint64_t)s[0] | ((uint64_t)s[1] << 32);
    h[1] = (uint64_t)s[2] | ((uint64_t)s[3] << 32);
    h[2] = (uint64_t)s[4] | ((uint64_t)s[5] << 32);
    h[3] = (uint64_t)s[6] | ((uint64_t)s[7] << 32);

    /* The value is now below 2^256 < 2p: subtract p once if h >= p */
    p256_fe tmp;
    uint64_t borrow = sub256(tmp, h, P256_P);
    p256_fe_cmov(h, tmp, 1 - borrow);
}

void p256_fe_sq(p256_fe h, const p256_fe f)
{
    p256_fe_mul(h, f, f);
}

/* ------------------------------------------------------------------ */
/* Inversion via Fermat: a^{p-2} mod p                                  */
/* ------------------------------------------------------------------ */

void p256_fe_inv(p256_fe h, const p256_fe f)
{
    /*
     * Square-and-multiply over the bits of
     * p - 2 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD.
     * The exponent is public, so branching on its bits leaks nothing.
     */
    uint8_t exp[32];
    p256_fe_tobytes(exp, P256_P);
    exp[31] -= 2;  /* p ends in ...FF, so no borrow */

    p256_fe result, base;
    p256_fe_copy(base, f);     /* h may alias f */
    p256_fe_one(result);
    for (int i = 0; i < 256; i++) {
        p256_fe_sq(result, result);
        int bit = (exp[i / 8] >> (7 - (i & 7))) & 1;
        if (bit)
            p256_fe_mul(result, result, base);
    }

    p256_fe_copy(h, result);
}

/* ------------------------------------------------------------------ */
/* Scalar arithmetic mod n (group order)                                */
/* ------------------------------------------------------------------ */

void p256_scalar_frombytes(p256_fe h, const uint8_t s[32])
{
    p256_fe_frombytes(h, s);
}

void p256_scalar_tobytes(uint8_t s[32], const p256_fe h)
{
    p256_fe_tobytes(s, h);
}

/* h = h mod n for any 256-bit h. n > 2^255, so one subtraction is enough. */
void p256_scalar_reduce(p256_fe h)
{
    p256_fe tmp;
    uint64_t borrow = sub256(tmp, h, P256_N);
    p256_fe_cmov(h, tmp, 1 - borrow);
}

/* Both operands must be below n; so is the result. */
void p256_scalar_add(p256_fe h, const p256_fe f, const p256_fe g)
{
    uint64_t carry = add256(h, f, g);
    p256_fe tmp;
    uint64_t borrow = sub256(tmp, h, P256_N);
    p256_fe_cmov(h, tmp, carry | (1 - borrow));
}

/*
 * h = f * g mod n.
 *
 * The 512-bit product is reduced by folding its upper half down:
 * 2^256 = C (mod n) with C = 2^256 - n < 2^224, so
 *
 *     hi * 2^256 + lo  =  hi * C + lo   (mod n)
 *
 * and each fold shortens the value by 32 bits. Starting from 512 bits,
 * eight folds bring it below 2^258, a ninth below 2^256 + 2^226, and a
 * tenth below 2^256, after which one conditional subtraction of n
 * finishes. The fold count is fixed, so the running time does not depend
 * on the operands.
 *
 * (The previous version kept only the low 256 bits of the product and
 * subtracted n from that a few times, which is not a reduction mod n at
 * all; every ECDSA value computed with it was wrong.)
 */
void p256_scalar_mul(p256_fe h, const p256_fe f, const p256_fe g)
{
    /* C = 2^256 - n */
    static const p256_fe C = {
        0x0C46353D039CDAAFULL,
        0x4319055258E8617BULL,
        0x0000000000000000ULL,
        0x00000000FFFFFFFFULL,
    };
    uint64_t t[8];

    mul256(t, f, g);

    for (int fold = 0; fold < 10; fold++) {
        uint64_t prod[8];
        p256_fe lo = { t[0], t[1], t[2], t[3] };
        p256_fe hi = { t[4], t[5], t[6], t[7] };

        mul256(prod, hi, C);

        /* t = prod + lo; cannot overflow 512 bits, prod < 2^480 */
        uint64_t carry = add256(t, prod, lo);
        for (int i = 4; i < 8; i++) {
            t[i] = prod[i] + carry;
            carry = (t[i] < carry);
        }
    }

    /* t[4..7] are zero now */
    h[0] = t[0]; h[1] = t[1]; h[2] = t[2]; h[3] = t[3];
    p256_scalar_reduce(h);
}

void p256_scalar_inv(p256_fe h, const p256_fe f)
{
    /*
     * Fermat's little theorem: f^(n-2) mod n. The exponent is public;
     * the base is the secret, and every step is a p256_scalar_mul.
     */
    uint8_t exp[32];
    p256_fe_tobytes(exp, P256_N);
    exp[31] -= 2;  /* n ends in ...51, so no borrow */

    p256_fe result, base;
    p256_fe_copy(base, f);     /* h may alias f */
    p256_fe_one(result);
    for (int i = 0; i < 256; i++) {
        p256_scalar_mul(result, result, result);
        int bit = (exp[i / 8] >> (7 - (i & 7))) & 1;
        if (bit)
            p256_scalar_mul(result, result, base);
    }

    p256_fe_copy(h, result);
}

/* ------------------------------------------------------------------ */
/* Point operations (Jacobian coordinates)                              */
/* ------------------------------------------------------------------ */

/* P-256 curve parameter: a = -3, b = ... */
/* For point operations we need a = -3 mod p */

void p256_point_zero(p256_point *p)
{
    p256_fe_zero(p->X);
    p256_fe_one(p->Y);
    p256_fe_zero(p->Z);
}

int p256_point_is_zero(const p256_point *p)
{
    return p256_fe_is_zero(p->Z);
}

/*
 * Point doubling in Jacobian coordinates for a = -3:
 * (NIST P-256 has a = -3)
 *
 * M = 3*X^2 + a*Z^4 = 3*(X + Z^2)*(X - Z^2) (since a = -3)
 * S = 4*X*Y^2
 * X' = M^2 - 2*S
 * Y' = M*(S - X') - 8*Y^4
 * Z' = 2*Y*Z
 *
 * r may alias p, which is how p256_point_scalar_mult() calls it. The
 * outputs are therefore computed into locals and stored at the end;
 * writing r->Y before reading p->Y for Z' used the new Y in place of
 * the old one and broke every scalar multiplication.
 */
void p256_point_double(p256_point *r, const p256_point *p)
{
    if (p256_point_is_zero(p)) {
        p256_point_zero(r);
        return;
    }

    p256_fe M, S, T, Y2, Z2, tmp, X3, Y3, Z3;

    p256_fe_sq(Z2, p->Z);        /* Z^2 */
    p256_fe_add(tmp, p->X, Z2);  /* X + Z^2 */
    p256_fe_sub(M, p->X, Z2);    /* X - Z^2 */
    p256_fe_mul(M, tmp, M);       /* (X+Z^2)(X-Z^2) = X^2 - Z^4 */
    /* 3 * M */
    p256_fe M3;
    p256_fe_add(M3, M, M);
    p256_fe_add(M3, M3, M);       /* M3 = 3*(X^2 - Z^4) */

    p256_fe_sq(Y2, p->Y);        /* Y^2 */
    p256_fe_mul(S, p->X, Y2);    /* X*Y^2 */
    p256_fe_add(S, S, S);
    p256_fe_add(S, S, S);         /* S = 4*X*Y^2 */

    p256_fe_sq(T, M3);            /* M^2 */
    p256_fe_sub(X3, T, S);
    p256_fe_sub(X3, X3, S);       /* X' = M^2 - 2*S */

    p256_fe_sub(tmp, S, X3);      /* S - X' */
    p256_fe_mul(tmp, M3, tmp);    /* M * (S - X') */
    p256_fe_sq(Y2, Y2);           /* Y^4 */
    p256_fe_add(Y2, Y2, Y2);
    p256_fe_add(Y2, Y2, Y2);
    p256_fe_add(Y2, Y2, Y2);     /* 8*Y^4 */
    p256_fe_sub(Y3, tmp, Y2);    /* Y' = M*(S-X') - 8*Y^4 */

    p256_fe_mul(Z3, p->Y, p->Z);
    p256_fe_add(Z3, Z3, Z3);     /* Z' = 2*Y*Z */

    p256_fe_copy(r->X, X3);
    p256_fe_copy(r->Y, Y3);
    p256_fe_copy(r->Z, Z3);
}

/*
 * Point addition in Jacobian coordinates.
 * Uses the standard formulas for mixed/full Jacobian addition.
 * r may alias p or q.
 */
void p256_point_add(p256_point *r, const p256_point *p, const p256_point *q)
{
    if (p256_point_is_zero(p)) {
        p256_point t = *q;
        *r = t;
        return;
    }
    if (p256_point_is_zero(q)) {
        p256_point t = *p;
        *r = t;
        return;
    }

    p256_fe U1, U2, S1, S2, H, R_val, HH, HHH, V, X3, Y3, Z3;

    p256_fe Z1sq, Z2sq;
    p256_fe_sq(Z1sq, p->Z);
    p256_fe_sq(Z2sq, q->Z);

    p256_fe_mul(U1, p->X, Z2sq);   /* U1 = X1 * Z2^2 */
    p256_fe_mul(U2, q->X, Z1sq);   /* U2 = X2 * Z1^2 */

    p256_fe Z1cu, Z2cu;
    p256_fe_mul(Z1cu, Z1sq, p->Z); /* Z1^3 */
    p256_fe_mul(Z2cu, Z2sq, q->Z); /* Z2^3 */

    p256_fe_mul(S1, p->Y, Z2cu);   /* S1 = Y1 * Z2^3 */
    p256_fe_mul(S2, q->Y, Z1cu);   /* S2 = Y2 * Z1^3 */

    p256_fe_sub(H, U2, U1);         /* H = U2 - U1 */
    p256_fe_sub(R_val, S2, S1);      /* R = S2 - S1 */

    /* Check if points are the same */
    if (p256_fe_is_zero(H)) {
        if (p256_fe_is_zero(R_val)) {
            /* P == Q, do doubling */
            p256_point_double(r, p);
            return;
        } else {
            /* P == -Q, result is infinity */
            p256_point_zero(r);
            return;
        }
    }

    p256_fe_sq(HH, H);              /* H^2 */
    p256_fe_mul(HHH, HH, H);        /* H^3 */
    p256_fe_mul(V, U1, HH);          /* V = U1 * H^2 */

    /* X3 = R^2 - H^3 - 2*V */
    p256_fe_sq(X3, R_val);
    p256_fe_sub(X3, X3, HHH);
    p256_fe tmp;
    p256_fe_add(tmp, V, V);
    p256_fe_sub(X3, X3, tmp);

    /* Y3 = R*(V - X3) - S1*H^3 */
    p256_fe_sub(tmp, V, X3);
    p256_fe_mul(Y3, R_val, tmp);
    p256_fe_mul(tmp, S1, HHH);
    p256_fe_sub(Y3, Y3, tmp);

    /* Z3 = Z1*Z2*H */
    p256_fe_mul(Z3, p->Z, q->Z);
    p256_fe_mul(Z3, Z3, H);

    p256_fe_copy(r->X, X3);
    p256_fe_copy(r->Y, Y3);
    p256_fe_copy(r->Z, Z3);
}

/* ------------------------------------------------------------------ */
/* Scalar multiplication: double-and-add                                */
/* ------------------------------------------------------------------ */

/*
 * NOTE: not constant time. The addition is skipped for zero bits of k,
 * and p256_point_add()/p256_point_double() branch on special cases, so
 * the running time depends on the scalar. k is a secret in ECDH and in
 * ECDSA signing. Hardening this (a fixed-window ladder with complete
 * formulas) is tracked separately; it does not affect the results.
 */
void p256_point_scalar_mult(p256_point *r, const uint8_t k[32],
                             const p256_point *p)
{
    p256_point acc, base = *p;      /* r may alias p */

    p256_point_zero(&acc);

    for (int i = 0; i < 256; i++) {
        p256_point_double(&acc, &acc);

        int bit = (k[i / 8] >> (7 - (i & 7))) & 1;
        if (bit)
            p256_point_add(&acc, &acc, &base);
    }

    *r = acc;
}

void p256_point_scalar_mult_base(p256_point *r, const uint8_t k[32])
{
    p256_point G;
    p256_fe_copy(G.X, P256_GX);
    p256_fe_copy(G.Y, P256_GY);
    p256_fe_one(G.Z);

    p256_point_scalar_mult(r, k, &G);
}

/* ------------------------------------------------------------------ */
/* Point encoding/decoding (uncompressed, 04 || X || Y)                 */
/* ------------------------------------------------------------------ */

/* p must not be the point at infinity (the result would be (0, 0)). */
void p256_point_to_affine(uint8_t x[32], uint8_t y[32], const p256_point *p)
{
    p256_fe z_inv, z_inv2, z_inv3;

    p256_fe_inv(z_inv, p->Z);
    p256_fe_sq(z_inv2, z_inv);
    p256_fe_mul(z_inv3, z_inv2, z_inv);

    p256_fe ax, ay;
    p256_fe_mul(ax, p->X, z_inv2);
    p256_fe_mul(ay, p->Y, z_inv3);

    p256_fe_tobytes(x, ax);
    p256_fe_tobytes(y, ay);
}

int p256_point_encode(uint8_t out[65], const p256_point *p)
{
    out[0] = 0x04;
    p256_point_to_affine(out + 1, out + 33, p);
    return 0;
}

int p256_point_decode(p256_point *p, const uint8_t in[65])
{
    if (in[0] != 0x04)
        return -1;

    p256_fe_frombytes(p->X, in + 1);
    p256_fe_frombytes(p->Y, in + 33);
    p256_fe_one(p->Z);

    /*
     * Coordinates must be field elements. The arithmetic below assumes
     * operands below p, so an out-of-range coordinate has to be rejected
     * here rather than left for the curve equation to catch.
     */
    if (p256_fe_cmp(p->X, P256_P) >= 0 || p256_fe_cmp(p->Y, P256_P) >= 0)
        return -1;

    /* Verify point is on curve: y^2 = x^3 + ax + b */
    /* a = -3, b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B */
    p256_fe y2, x3, ax, rhs;
    static const uint8_t B_BYTES[32] = {
        0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
        0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
        0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
        0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
    };
    p256_fe b;
    p256_fe_frombytes(b, B_BYTES);

    p256_fe_sq(y2, p->Y);           /* y^2 */
    p256_fe_sq(x3, p->X);
    p256_fe_mul(x3, x3, p->X);      /* x^3 */
    p256_fe_add(ax, p->X, p->X);
    p256_fe_add(ax, ax, p->X);      /* 3*x */
    p256_fe_sub(rhs, x3, ax);       /* x^3 - 3*x (since a = -3) */
    p256_fe_add(rhs, rhs, b);       /* x^3 - 3*x + b */

    /* Check y^2 == rhs */
    p256_fe diff;
    p256_fe_sub(diff, y2, rhs);
    if (!p256_fe_is_zero(diff))
        return -1;

    return 0;
}
