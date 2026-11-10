/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Field arithmetic for Curve25519 (p = 2^255 - 19).
 *
 * Representation: 5 limbs of 51 bits each stored in uint64_t[5].
 * Element x is represented as x[0] + x[1]*2^51 + x[2]*2^102 +
 *                              x[3]*2^153 + x[4]*2^204.
 *
 * All operations are constant-time.
 */

#include <stdint.h>
#include <string.h>

#include "field25519.h"

/* ------------------------------------------------------------------ */
/* Load / store                                                         */
/* ------------------------------------------------------------------ */

static uint64_t load48(const uint8_t *b)
{
    return ((uint64_t)b[0])
         | ((uint64_t)b[1] << 8)
         | ((uint64_t)b[2] << 16)
         | ((uint64_t)b[3] << 24)
         | ((uint64_t)b[4] << 32)
         | ((uint64_t)b[5] << 40);
}

static void store64(uint8_t *b, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}

/*
 * Decode 32 little-endian bytes into five 51-bit limbs.
 *
 * Limb i holds bits 51*i .. 51*i+50 of the input, so bit 255 is ignored,
 * which is what RFC 7748 section 5 requires for X25519 u-coordinates.
 * Callers for which bit 255 carries meaning (the sign of x in an encoded
 * Ed25519 point) must read it from the byte string themselves.
 *
 * The value is not reduced: inputs in [p, 2^255) decode to their
 * non-canonical representative, and fe25519_tobytes() reduces them.
 */
void fe25519_frombytes(fe25519 h, const uint8_t s[32])
{
    static const uint64_t MASK51 = (1ULL << 51) - 1;

    h[0] = (load48(s) | ((uint64_t)s[6] << 48)) & MASK51;
    h[1] = ((load48(s + 6) | ((uint64_t)s[12] << 48)) >> 3) & MASK51;
    h[2] = ((load48(s + 12) | ((uint64_t)s[18] << 48)
                            | ((uint64_t)s[19] << 56)) >> 6) & MASK51;
    h[3] = ((load48(s + 19) | ((uint64_t)s[25] << 48)) >> 1) & MASK51;
    h[4] = ((load48(s + 25) | ((uint64_t)s[31] << 48)) >> 4) & MASK51;
}

/*
 * Reduce fully and encode as 32 little-endian bytes.
 *
 * The output is the canonical representative in [0, p). Limbs of the
 * input may be as large as 2^63.
 */
void fe25519_tobytes(uint8_t s[32], const fe25519 h)
{
    static const uint64_t MASK51 = (1ULL << 51) - 1;
    uint64_t t[5];
    uint64_t c;

    memcpy(t, h, sizeof(t));

    /* Propagate carries */
    c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
    c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
    c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
    c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
    c = t[4] >> 51; t[4] &= MASK51; t[0] += c * 19;

    /* Second pass: afterwards every limb is below 2^51, value < 2^255 */
    c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
    c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
    c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
    c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
    c = t[4] >> 51; t[4] &= MASK51; t[0] += c * 19;

    /*
     * Conditional subtraction of p = 2^255 - 19, whose limbs are
     * (2^51 - 19, 2^51 - 1, 2^51 - 1, 2^51 - 1, 2^51 - 1).
     * Compute t - p limb by limb; the final borrow says whether t < p.
     */
    uint64_t m = t[0] - 0x7FFFFFFFFFFEDULL;
    uint64_t borrow = (m >> 63);
    uint64_t s1 = t[1] - MASK51 - borrow;
    borrow = (s1 >> 63);
    uint64_t s2 = t[2] - MASK51 - borrow;
    borrow = (s2 >> 63);
    uint64_t s3 = t[3] - MASK51 - borrow;
    borrow = (s3 >> 63);
    uint64_t s4 = t[4] - MASK51 - borrow;

    /* If s4 bit 63 is set, result < 0 meaning t < p, keep t */
    uint64_t mask = ~(s4 >> 63) + 1; /* 0 if t >= p, all-ones if t < p */

    t[0] ^= (t[0] ^ (m & MASK51)) & ~mask;
    t[1] ^= (t[1] ^ (s1 & MASK51)) & ~mask;
    t[2] ^= (t[2] ^ (s2 & MASK51)) & ~mask;
    t[3] ^= (t[3] ^ (s3 & MASK51)) & ~mask;
    t[4] ^= (t[4] ^ (s4 & MASK51)) & ~mask;

    /* Pack 5 x 51-bit limbs (255 bits, top bit always 0) into 32 bytes */
    store64(s,      t[0]        | (t[1] << 51));  /* bits   0.. 63 */
    store64(s + 8,  (t[1] >> 13) | (t[2] << 38)); /* bits  64..127 */
    store64(s + 16, (t[2] >> 26) | (t[3] << 25)); /* bits 128..191 */
    store64(s + 24, (t[3] >> 39) | (t[4] << 12)); /* bits 192..255 */
}

/* ------------------------------------------------------------------ */
/* Basic arithmetic                                                     */
/* ------------------------------------------------------------------ */

void fe25519_0(fe25519 h)
{
    h[0] = h[1] = h[2] = h[3] = h[4] = 0;
}

void fe25519_1(fe25519 h)
{
    h[0] = 1;
    h[1] = h[2] = h[3] = h[4] = 0;
}

void fe25519_copy(fe25519 h, const fe25519 f)
{
    h[0] = f[0]; h[1] = f[1]; h[2] = f[2]; h[3] = f[3]; h[4] = f[4];
}

void fe25519_add(fe25519 h, const fe25519 f, const fe25519 g)
{
    h[0] = f[0] + g[0];
    h[1] = f[1] + g[1];
    h[2] = f[2] + g[2];
    h[3] = f[3] + g[3];
    h[4] = f[4] + g[4];
}

/*
 * Limb bounds.
 *
 * fe25519_mul() and fe25519_sq() accept limbs below 2^54 and return limbs
 * below 2^51 + 2^13. fe25519_add() does not carry, so a sum of two such
 * values has limbs below 2^52 + 2^14, and a few further additions stay
 * below 2^54. fe25519_sub() accepts limbs below 2^54 - 152 for the
 * subtrahend and carries its result back down to 2^51 + 2^9, so the
 * output of a subtraction can be fed to anything.
 */
void fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g)
{
    /*
     * Add 8*p before subtracting so that no limb can go negative, then
     * carry. 8*p in limbs is (2^54 - 152, 2^54 - 8, ..., 2^54 - 8).
     *
     * Without the carry the result of a subtraction has limbs near 2^52,
     * and subtracting such a value again (as the Edwards point formulas
     * do) underflows.
     */
    static const uint64_t EIGHT_P[5] = {
        0x3FFFFFFFFFFF68ULL,    /* 8*(2^51 - 19) */
        0x3FFFFFFFFFFFF8ULL,    /* 8*(2^51 - 1) */
        0x3FFFFFFFFFFFF8ULL,
        0x3FFFFFFFFFFFF8ULL,
        0x3FFFFFFFFFFFF8ULL,
    };
    fe25519 t;

    t[0] = (f[0] + EIGHT_P[0]) - g[0];
    t[1] = (f[1] + EIGHT_P[1]) - g[1];
    t[2] = (f[2] + EIGHT_P[2]) - g[2];
    t[3] = (f[3] + EIGHT_P[3]) - g[3];
    t[4] = (f[4] + EIGHT_P[4]) - g[4];

    fe25519_reduce(h, t);
}

void fe25519_neg(fe25519 h, const fe25519 f)
{
    fe25519 zero;
    fe25519_0(zero);
    fe25519_sub(h, zero, f);
}

/* ------------------------------------------------------------------ */
/* 128-bit multiply helpers                                             */
/* ------------------------------------------------------------------ */

#ifdef __SIZEOF_INT128__
typedef unsigned __int128 uint128_t;
#else
/* Portable 64x64 -> 128 multiply */
typedef struct { uint64_t lo, hi; } uint128_t;

static inline uint128_t mul64(uint64_t a, uint64_t b)
{
    uint128_t r;
    uint32_t a0 = (uint32_t)a, a1 = (uint32_t)(a >> 32);
    uint32_t b0 = (uint32_t)b, b1 = (uint32_t)(b >> 32);
    uint64_t p0 = (uint64_t)a0 * b0;
    uint64_t p1 = (uint64_t)a0 * b1;
    uint64_t p2 = (uint64_t)a1 * b0;
    uint64_t p3 = (uint64_t)a1 * b1;
    uint64_t mid = p1 + (p0 >> 32);
    mid += p2;
    if (mid < p2) p3 += 1ULL << 32;
    r.lo = (p0 & 0xFFFFFFFFULL) | (mid << 32);
    r.hi = p3 + (mid >> 32);
    return r;
}

static inline uint128_t add128(uint128_t a, uint128_t b)
{
    uint128_t r;
    r.lo = a.lo + b.lo;
    r.hi = a.hi + b.hi + (r.lo < a.lo);
    return r;
}
#endif

/* ------------------------------------------------------------------ */
/* Multiplication                                                       */
/* ------------------------------------------------------------------ */

/*
 * Schoolbook multiplication with reduction modulo 2^255-19.
 * Uses the identity: 2^255 = 19 (mod p), so limb overflows
 * from position 5 wrap around multiplied by 19.
 */
void fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g)
{
    uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    uint64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];

    /* Pre-multiply by 19 for wrap-around terms */
    uint64_t g1_19 = 19 * g1;
    uint64_t g2_19 = 19 * g2;
    uint64_t g3_19 = 19 * g3;
    uint64_t g4_19 = 19 * g4;

    static const uint64_t MASK51 = (1ULL << 51) - 1;

#ifdef __SIZEOF_INT128__
    uint128_t t0 = (uint128_t)f0 * g0 + (uint128_t)f1 * g4_19
                  + (uint128_t)f2 * g3_19 + (uint128_t)f3 * g2_19
                  + (uint128_t)f4 * g1_19;

    uint128_t t1 = (uint128_t)f0 * g1 + (uint128_t)f1 * g0
                  + (uint128_t)f2 * g4_19 + (uint128_t)f3 * g3_19
                  + (uint128_t)f4 * g2_19;

    uint128_t t2 = (uint128_t)f0 * g2 + (uint128_t)f1 * g1
                  + (uint128_t)f2 * g0 + (uint128_t)f3 * g4_19
                  + (uint128_t)f4 * g3_19;

    uint128_t t3 = (uint128_t)f0 * g3 + (uint128_t)f1 * g2
                  + (uint128_t)f2 * g1 + (uint128_t)f3 * g0
                  + (uint128_t)f4 * g4_19;

    uint128_t t4 = (uint128_t)f0 * g4 + (uint128_t)f1 * g3
                  + (uint128_t)f2 * g2 + (uint128_t)f3 * g1
                  + (uint128_t)f4 * g0;

    /* Carry chain */
    uint64_t c;
    c = (uint64_t)(t0 >> 51); h[0] = (uint64_t)t0 & MASK51;
    t1 += c;
    c = (uint64_t)(t1 >> 51); h[1] = (uint64_t)t1 & MASK51;
    t2 += c;
    c = (uint64_t)(t2 >> 51); h[2] = (uint64_t)t2 & MASK51;
    t3 += c;
    c = (uint64_t)(t3 >> 51); h[3] = (uint64_t)t3 & MASK51;
    t4 += c;
    c = (uint64_t)(t4 >> 51); h[4] = (uint64_t)t4 & MASK51;

    h[0] += c * 19;
    c = h[0] >> 51; h[0] &= MASK51;
    h[1] += c;
#else
    /* Portable path using mul64/add128 helpers */
    uint128_t t0 = mul64(f0, g0);
    t0 = add128(t0, mul64(f1, g4_19));
    t0 = add128(t0, mul64(f2, g3_19));
    t0 = add128(t0, mul64(f3, g2_19));
    t0 = add128(t0, mul64(f4, g1_19));

    uint128_t t1 = mul64(f0, g1);
    t1 = add128(t1, mul64(f1, g0));
    t1 = add128(t1, mul64(f2, g4_19));
    t1 = add128(t1, mul64(f3, g3_19));
    t1 = add128(t1, mul64(f4, g2_19));

    uint128_t t2 = mul64(f0, g2);
    t2 = add128(t2, mul64(f1, g1));
    t2 = add128(t2, mul64(f2, g0));
    t2 = add128(t2, mul64(f3, g4_19));
    t2 = add128(t2, mul64(f4, g3_19));

    uint128_t t3 = mul64(f0, g3);
    t3 = add128(t3, mul64(f1, g2));
    t3 = add128(t3, mul64(f2, g1));
    t3 = add128(t3, mul64(f3, g0));
    t3 = add128(t3, mul64(f4, g4_19));

    uint128_t t4 = mul64(f0, g4);
    t4 = add128(t4, mul64(f1, g3));
    t4 = add128(t4, mul64(f2, g2));
    t4 = add128(t4, mul64(f3, g1));
    t4 = add128(t4, mul64(f4, g0));

    /* Carry chain -- extract 51-bit limbs from 128-bit accumulators */
    uint64_t r0, r1, r2, r3, r4, c;

    /* For portable 128-bit: low 51 bits from .lo, shift uses both fields */
    r0 = t0.lo & MASK51;
    c = (t0.lo >> 51) | (t0.hi << 13);
    t1.lo += c; t1.hi += (t1.lo < c);

    r1 = t1.lo & MASK51;
    c = (t1.lo >> 51) | (t1.hi << 13);
    t2.lo += c; t2.hi += (t2.lo < c);

    r2 = t2.lo & MASK51;
    c = (t2.lo >> 51) | (t2.hi << 13);
    t3.lo += c; t3.hi += (t3.lo < c);

    r3 = t3.lo & MASK51;
    c = (t3.lo >> 51) | (t3.hi << 13);
    t4.lo += c; t4.hi += (t4.lo < c);

    r4 = t4.lo & MASK51;
    c = (t4.lo >> 51) | (t4.hi << 13);

    r0 += c * 19;
    c = r0 >> 51; r0 &= MASK51;
    r1 += c;

    h[0] = r0; h[1] = r1; h[2] = r2; h[3] = r3; h[4] = r4;
#endif
}

/* ------------------------------------------------------------------ */
/* Squaring (optimized: symmetric terms doubled)                        */
/* ------------------------------------------------------------------ */

void fe25519_sq(fe25519 h, const fe25519 f)
{
    fe25519_mul(h, f, f);
}

/* Square n times */
static void fe25519_sq_n(fe25519 h, const fe25519 f, int n)
{
    fe25519_sq(h, f);
    for (int i = 1; i < n; i++)
        fe25519_sq(h, h);
}

/* ------------------------------------------------------------------ */
/* Inversion via Fermat's little theorem: a^{p-2} mod p                 */
/* p - 2 = 2^255 - 21                                                  */
/* ------------------------------------------------------------------ */

void fe25519_inv(fe25519 out, const fe25519 z)
{
    fe25519 t0, t1, t2, t3;

    /* z^2 */
    fe25519_sq(t0, z);
    /* z^(2^2) */
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    /* z^9 */
    fe25519_mul(t1, z, t1);
    /* z^11 */
    fe25519_mul(t0, t0, t1);
    /* z^(2^5 - 2^0) = z^31 */
    fe25519_sq(t2, t0);
    fe25519_mul(t1, t1, t2);
    /* z^(2^10 - 1) */
    fe25519_sq_n(t2, t1, 5);
    fe25519_mul(t1, t1, t2);
    /* z^(2^20 - 1) */
    fe25519_sq_n(t2, t1, 10);
    fe25519_mul(t2, t2, t1);
    /* z^(2^40 - 1) */
    fe25519_sq_n(t3, t2, 20);
    fe25519_mul(t2, t2, t3);
    /* z^(2^50 - 1) */
    fe25519_sq_n(t2, t2, 10);
    fe25519_mul(t1, t1, t2);
    /* z^(2^100 - 1) */
    fe25519_sq_n(t2, t1, 50);
    fe25519_mul(t2, t2, t1);
    /* z^(2^200 - 1) */
    fe25519_sq_n(t3, t2, 100);
    fe25519_mul(t2, t2, t3);
    /* z^(2^250 - 1) */
    fe25519_sq_n(t2, t2, 50);
    fe25519_mul(t1, t1, t2);
    /* z^(2^255 - 21) = z^(p-2) */
    fe25519_sq_n(t1, t1, 5);
    fe25519_mul(out, t0, t1);
}

/* ------------------------------------------------------------------ */
/* z^((p-5)/8) = z^(2^252 - 3) -- used for square root computation     */
/* ------------------------------------------------------------------ */

void fe25519_pow2523(fe25519 out, const fe25519 z)
{
    fe25519 t0, t1, t2;

    fe25519_sq(t0, z);
    fe25519_sq(t1, t0);
    fe25519_sq(t1, t1);
    fe25519_mul(t1, z, t1);
    fe25519_mul(t0, t0, t1);
    fe25519_sq(t0, t0);
    fe25519_mul(t0, t1, t0);

    fe25519_sq_n(t1, t0, 5);
    fe25519_mul(t0, t0, t1);

    fe25519_sq_n(t1, t0, 10);
    fe25519_mul(t1, t1, t0);

    fe25519_sq_n(t2, t1, 20);
    fe25519_mul(t1, t1, t2);

    fe25519_sq_n(t1, t1, 10);
    fe25519_mul(t0, t0, t1);

    fe25519_sq_n(t1, t0, 50);
    fe25519_mul(t1, t1, t0);

    fe25519_sq_n(t2, t1, 100);
    fe25519_mul(t1, t1, t2);

    fe25519_sq_n(t1, t1, 50);
    fe25519_mul(t0, t0, t1);

    /* 2^252 - 3 */
    fe25519_sq_n(t0, t0, 2);
    fe25519_mul(out, t0, z);
}

/* ------------------------------------------------------------------ */
/* Constant-time conditional swap                                       */
/* ------------------------------------------------------------------ */

void fe25519_cswap(fe25519 f, fe25519 g, uint64_t b)
{
    uint64_t mask = (uint64_t)(-(int64_t)b);  /* 0 or all-ones */
    uint64_t x;

    x = (f[0] ^ g[0]) & mask; f[0] ^= x; g[0] ^= x;
    x = (f[1] ^ g[1]) & mask; f[1] ^= x; g[1] ^= x;
    x = (f[2] ^ g[2]) & mask; f[2] ^= x; g[2] ^= x;
    x = (f[3] ^ g[3]) & mask; f[3] ^= x; g[3] ^= x;
    x = (f[4] ^ g[4]) & mask; f[4] ^= x; g[4] ^= x;
}

/* ------------------------------------------------------------------ */
/* Constant-time conditional select: h = b ? g : f                      */
/* ------------------------------------------------------------------ */

void fe25519_cmov(fe25519 f, const fe25519 g, uint64_t b)
{
    uint64_t mask = (uint64_t)(-(int64_t)b);
    f[0] ^= (f[0] ^ g[0]) & mask;
    f[1] ^= (f[1] ^ g[1]) & mask;
    f[2] ^= (f[2] ^ g[2]) & mask;
    f[3] ^= (f[3] ^ g[3]) & mask;
    f[4] ^= (f[4] ^ g[4]) & mask;
}

/* ------------------------------------------------------------------ */
/* Scalar multiply: h = f * 121666                                      */
/* Used in the X25519 Montgomery ladder, where (A + 2)/4 = 121666.     */
/* ------------------------------------------------------------------ */

void fe25519_mul121666(fe25519 h, const fe25519 f)
{
    /*
     * Goes through the general multiplication rather than a dedicated
     * single-word one. The product of a 51-bit limb and 121666 needs 68
     * bits, and the previous hand-written path for compilers without a
     * 128-bit integer computed it in 64.
     */
    static const fe25519 k121666 = { 121666, 0, 0, 0, 0 };
    fe25519_mul(h, f, k121666);
}

/* ------------------------------------------------------------------ */
/* Test if f is negative (i.e., the low bit of the canonical encoding)  */
/* ------------------------------------------------------------------ */

int fe25519_isnegative(const fe25519 f)
{
    uint8_t s[32];
    fe25519_tobytes(s, f);
    return s[0] & 1;
}

/* ------------------------------------------------------------------ */
/* Test if f is zero                                                    */
/* ------------------------------------------------------------------ */

int fe25519_iszero(const fe25519 f)
{
    uint8_t s[32];
    fe25519_tobytes(s, f);
    uint8_t r = 0;
    for (int i = 0; i < 32; i++)
        r |= s[i];
    return (1 & ((r - 1) >> 8));
}

/* ------------------------------------------------------------------ */
/* Reduce (carry propagation only)                                      */
/* ------------------------------------------------------------------ */

void fe25519_reduce(fe25519 h, const fe25519 f)
{
    static const uint64_t MASK51 = (1ULL << 51) - 1;
    uint64_t c;

    h[0] = f[0]; h[1] = f[1]; h[2] = f[2]; h[3] = f[3]; h[4] = f[4];

    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
    c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
    c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
    c = h[4] >> 51; h[4] &= MASK51; h[0] += c * 19;
}
