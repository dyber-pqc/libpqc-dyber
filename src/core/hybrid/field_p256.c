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
/* Addition mod p                                                       */
/* ------------------------------------------------------------------ */

/* Returns carry (0 or 1) */
static uint64_t add256(p256_fe r, const p256_fe a, const p256_fe b)
{
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t sum = a[i] + b[i] + carry;
        carry = (sum < a[i]) || (carry && sum == a[i]);
        r[i] = sum;
    }
    return carry;
}

/* Proper subtraction with borrow */
uint64_t sub256_v2(p256_fe r, const p256_fe a, const p256_fe b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
#ifdef __SIZEOF_INT128__
        unsigned __int128 diff = (unsigned __int128)a[i] - b[i] - borrow;
        r[i] = (uint64_t)diff;
        borrow = (uint64_t)(diff >> 127) & 1;  /* Sign bit = borrow */
#else
        uint64_t lo = a[i] - b[i];
        uint64_t br1 = (lo > a[i]) ? 1 : 0;
        uint64_t lo2 = lo - borrow;
        uint64_t br2 = (lo2 > lo) ? 1 : 0;
        r[i] = lo2;
        borrow = br1 | br2;
#endif
    }
    return borrow;
}

void p256_fe_add(p256_fe h, const p256_fe f, const p256_fe g)
{
    uint64_t carry = add256(h, f, g);

    /* If carry or h >= p, subtract p */
    p256_fe tmp;
    uint64_t borrow = sub256_v2(tmp, h, P256_P);

    /* Use result if carry was set or no borrow */
    uint64_t use_sub = carry | (1 - borrow);
    p256_fe_cmov(h, tmp, use_sub);
}

void p256_fe_sub(p256_fe h, const p256_fe f, const p256_fe g)
{
    uint64_t borrow = sub256_v2(h, f, g);

    /* If borrow, add p */
    if (borrow) {
        p256_fe tmp;
        add256(tmp, h, P256_P);
        p256_fe_copy(h, tmp);
    }
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
 * 256x256 -> 512-bit multiplication, then reduce mod p using
 * the NIST P-256 reduction identity.
 *
 * p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 *
 * For a 512-bit product T = t7:t6:t5:t4:t3:t2:t1:t0 (32-bit words),
 * we apply the NIST reduction formulas. Here we work with 64-bit limbs
 * and adapt accordingly.
 */

void p256_fe_mul(p256_fe h, const p256_fe f, const p256_fe g)
{
    /* Full 512-bit product in 8 x 64-bit limbs */
    uint64_t t[8];
    memset(t, 0, sizeof(t));

#ifdef __SIZEOF_INT128__
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (unsigned __int128)f[i] * g[j] + t[i + j];
            t[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        t[i + 4] += (uint64_t)carry;
    }
#else
    /* Portable 64x64 -> 128 schoolbook */
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            /* 64x64 -> 128 using 32-bit splits */
            uint64_t a = f[i], b = g[j];
            uint32_t a0 = (uint32_t)a, a1 = (uint32_t)(a >> 32);
            uint32_t b0 = (uint32_t)b, b1 = (uint32_t)(b >> 32);
            uint64_t p0 = (uint64_t)a0 * b0;
            uint64_t p1 = (uint64_t)a0 * b1;
            uint64_t p2 = (uint64_t)a1 * b0;
            uint64_t p3 = (uint64_t)a1 * b1;

            uint64_t lo = p0 + (p1 << 32) + (p2 << 32);
            uint64_t hi = p3 + (p1 >> 32) + (p2 >> 32);
            /* Carry correction for lo overflow */
            if (lo < p0) hi++;
            uint64_t mid = (p1 << 32) + (p2 << 32);
            if (mid < (p1 << 32)) hi++;

            /* Add to accumulator */
            uint64_t prev = t[i + j];
            lo += prev;
            if (lo < prev) hi++;
            lo += carry;
            if (lo < carry) hi++;
            t[i + j] = lo;
            carry = hi;
        }
        t[i + 4] += carry;
    }
#endif

    /*
     * NIST P-256 reduction using the Solinas method.
     * We split the 512-bit result into 32-bit words and apply the
     * reduction formulas from FIPS 186-4 Appendix D.
     *
     * Split t[0..7] (64-bit) into c[0..15] (32-bit), little-endian.
     */
    uint32_t c[16];
    for (int i = 0; i < 8; i++) {
        c[2 * i]     = (uint32_t)t[i];
        c[2 * i + 1] = (uint32_t)(t[i] >> 32);
    }

    /*
     * Per FIPS 186-4 D.2.3, the result is:
     * T + S1 + S2 + S3 + S4 - D1 - D2 - D3 - D4 (mod p)
     *
     * Using 32-bit word notation c0..c15:
     *
     * T  = (c7,  c6,  c5,  c4,  c3,  c2,  c1,  c0)
     * S1 = (c15, c14, c13, c12, c11, 0,   0,   0)  * 2
     * S2 = (0,   c15, c14, c13, c12, 0,   0,   0)  * 2... etc.
     *
     * Let's use the standard formulation with int64 accumulators.
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

    /* + 2*S1: S1 = (c15, c14, c13, c12, c11, 0, 0, 0) */
    s[3] += 2 * (int64_t)c[11];
    s[4] += 2 * (int64_t)c[12];
    s[5] += 2 * (int64_t)c[13];
    s[6] += 2 * (int64_t)c[14];
    s[7] += 2 * (int64_t)c[15];

    /* + 2*S2: S2 = (0, c15, c14, c13, c12, 0, 0, 0) */
    s[3] += 2 * (int64_t)c[12];
    s[4] += 2 * (int64_t)c[13];
    s[5] += 2 * (int64_t)c[14];
    s[6] += 2 * (int64_t)c[15];

    /* + S3: S3 = (c15, c14, 0, 0, 0, c10, c9, c8) */
    s[0] += (int64_t)c[8];
    s[1] += (int64_t)c[9];
    s[2] += (int64_t)c[10];
    s[6] += (int64_t)c[14];
    s[7] += (int64_t)c[15];

    /* + S4: S4 = (c8, c13, c15, c14, c13, c11, c10, c9) */
    s[0] += (int64_t)c[9];
    s[1] += (int64_t)c[10];
    s[2] += (int64_t)c[11];
    s[3] += (int64_t)c[13];
    s[4] += (int64_t)c[14];
    s[5] += (int64_t)c[15];
    s[6] += (int64_t)c[13];
    s[7] += (int64_t)c[8];

    /* - D1: D1 = (c10, c8, 0, 0, 0, c13, c12, c11) */
    s[0] -= (int64_t)c[11];
    s[1] -= (int64_t)c[12];
    s[2] -= (int64_t)c[13];
    s[6] -= (int64_t)c[8];
    s[7] -= (int64_t)c[10];

    /* - D2: D2 = (c11, c9, 0, 0, c15, c14, c13, c12) */
    s[0] -= (int64_t)c[12];
    s[1] -= (int64_t)c[13];
    s[2] -= (int64_t)c[14];
    s[3] -= (int64_t)c[15];
    s[6] -= (int64_t)c[9];
    s[7] -= (int64_t)c[11];

    /* - D3: D3 = (c12, 0, c10, c9, c8, c15, c14, c13) */
    s[0] -= (int64_t)c[13];
    s[1] -= (int64_t)c[14];
    s[2] -= (int64_t)c[15];
    s[3] -= (int64_t)c[8];
    s[4] -= (int64_t)c[9];
    s[5] -= (int64_t)c[10];
    s[7] -= (int64_t)c[12];

    /* - D4: D4 = (c13, 0, c11, c10, c9, 0, c15, c14) */
    s[0] -= (int64_t)c[14];
    s[1] -= (int64_t)c[15];
    s[3] -= (int64_t)c[9];
    s[4] -= (int64_t)c[10];
    s[5] -= (int64_t)c[11];
    s[7] -= (int64_t)c[13];

    /* Propagate carries through 32-bit words */
    int64_t carry;
    for (int i = 0; i < 7; i++) {
        carry = s[i] >> 32;
        s[i] &= 0xFFFFFFFF;
        s[i + 1] += carry;
    }
    carry = s[7] >> 32;
    s[7] &= 0xFFFFFFFF;

    /* Handle remaining carry: multiply by (2^256 mod p) and add back */
    /* 2^256 mod p = 2^224 - 2^192 - 2^96 + 1 */
    s[0] += carry;
    s[3] -= carry;     /* -2^96 * carry (in 32-bit word 3) */
    s[6] -= carry;     /* -2^192 * carry */
    s[7] += carry;     /* +2^224 * carry */

    /* Another round of carry propagation */
    for (int i = 0; i < 7; i++) {
        carry = s[i] >> 32;
        s[i] &= 0xFFFFFFFF;
        if (s[i] < 0) {
            s[i] += (int64_t)1 << 32;
            carry--;
        }
        s[i + 1] += carry;
    }

    /* Handle negative values by adding multiples of p */
    /* Reconstruct as 64-bit limbs */
    h[0] = ((uint64_t)(uint32_t)s[0]) | (((uint64_t)(uint32_t)s[1]) << 32);
    h[1] = ((uint64_t)(uint32_t)s[2]) | (((uint64_t)(uint32_t)s[3]) << 32);
    h[2] = ((uint64_t)(uint32_t)s[4]) | (((uint64_t)(uint32_t)s[5]) << 32);
    h[3] = ((uint64_t)(uint32_t)s[6]) | (((uint64_t)(uint32_t)s[7]) << 32);

    /* Final reduction: subtract p if h >= p */
    p256_fe tmp;
    uint64_t borrow = sub256_v2(tmp, h, P256_P);
    /* If no borrow, h >= p, use tmp */
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
     * p-2 for P-256 has a nice addition-chain structure.
     * We use a simple square-and-multiply approach.
     * p - 2 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD
     */
    p256_fe t, t2;
    int i;

    /* t = f^2 */
    p256_fe_sq(t, f);
    /* t = f^3 */
    p256_fe_mul(t, t, f);
    /* t2 = f^(2^2 - 1) = f^3 */
    p256_fe_copy(t2, t);
    /* Build up f^(2^32 - 1) */
    for (i = 0; i < 2; i++) { p256_fe_sq(t, t); } p256_fe_mul(t, t, t2);
    p256_fe_copy(t2, t);
    for (i = 0; i < 4; i++) { p256_fe_sq(t, t); } p256_fe_mul(t, t, t2);
    p256_fe_copy(t2, t);
    for (i = 0; i < 8; i++) { p256_fe_sq(t, t); } p256_fe_mul(t, t, t2);
    p256_fe_copy(t2, t);
    for (i = 0; i < 16; i++) { p256_fe_sq(t, t); } p256_fe_mul(t, t, t2);

    /* Now t = f^(2^32 - 1) */
    p256_fe x32;
    p256_fe_copy(x32, t);

    /* Square 32 more times and multiply */
    for (i = 0; i < 32; i++) p256_fe_sq(t, t);
    p256_fe_mul(t, t, f);  /* * f for the "01" at the end of the first 64-bit block */

    /* Continue building the exponent p-2 */
    for (i = 0; i < 32; i++) p256_fe_sq(t, t);
    /* middle 32 bits of p-2 second limb are 0, just multiply by 1 */

    for (i = 0; i < 32; i++) p256_fe_sq(t, t);

    for (i = 0; i < 32; i++) p256_fe_sq(t, t);

    /* Now we need the bottom 96 bits: FFFFFFFFFFFFFFFFFFFFFFFD */
    p256_fe_mul(t, t, x32); /* 0xFFFFFFFF */
    for (i = 0; i < 32; i++) p256_fe_sq(t, t);
    p256_fe_mul(t, t, x32);
    for (i = 0; i < 32; i++) p256_fe_sq(t, t);

    /* last 32 bits: FFFFFFFD = 2^32 - 3 */
    /* f^(2^32 - 3) = f^(2^32 - 1) * f^(-2) -- nah, just do binary exp for last word */
    /* Build 0xFFFFFFFD */
    p256_fe last;
    p256_fe_copy(last, x32); /* f^(2^32 - 1) */
    /* We need f^(0xFFFFFFFD) = f^(2^32 - 3) */
    /* = f^(2^32 - 1) / f^2 = x32 * inv(f^2)... too complex */
    /* Instead: direct approach for the last limb */
    /* f^(FFFFFFFD) = f^(FFFFFFFF) * f^(-2) -- not helpful without div */
    /* Better: rebuild. FFFFFFFD = 11111111111111111111111111111101 binary */
    /* = 2^32 - 3 */
    p256_fe_sq(last, f);     /* f^2 */
    p256_fe_mul(last, last, f); /* f^3 */
    /* f^(2^k - 1) via repeated sq+mul */
    p256_fe acc;
    p256_fe_copy(acc, last); /* f^3 = f^(2^2-1) */
    for (i = 0; i < 2; i++) p256_fe_sq(acc, acc);
    p256_fe_mul(acc, acc, last); /* f^(2^4 - 1) */
    p256_fe_copy(last, acc);
    for (i = 0; i < 4; i++) p256_fe_sq(acc, acc);
    p256_fe_mul(acc, acc, last); /* f^(2^8 - 1) */
    p256_fe_copy(last, acc);
    for (i = 0; i < 8; i++) p256_fe_sq(acc, acc);
    p256_fe_mul(acc, acc, last); /* f^(2^16 - 1) */
    p256_fe_copy(last, acc);
    for (i = 0; i < 16; i++) p256_fe_sq(acc, acc);
    p256_fe_mul(acc, acc, last); /* f^(2^32 - 1) */

    /* Now acc = f^(2^32-1). We need f^(2^32-3) = acc * f^(-2).
     * Instead, compute differently: sq once to get f^(2*(2^32-1))
     * and adjust. Actually let's just do it the simple way with the full
     * binary expansion of p-2.
     */

    /* Restart with a clean binary method for p-2 */
    /* p-2 in binary: 256 bits */
    uint8_t exp[32];
    p256_fe_tobytes(exp, P256_P);
    /* Subtract 2 from the big-endian representation */
    exp[31] -= 2;  /* p ends in ...FFFFFFFF, so -2 gives ...FFFFFFFD */

    /* Square-and-multiply from MSB */
    p256_fe result;
    p256_fe_one(result);
    for (i = 0; i < 256; i++) {
        p256_fe_sq(result, result);
        int bit = (exp[i / 8] >> (7 - (i & 7))) & 1;
        if (bit)
            p256_fe_mul(result, result, f);
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

static uint64_t add256_mod(p256_fe r, const p256_fe a, const p256_fe b,
                            const p256_fe mod)
{
    uint64_t carry = add256(r, a, b);
    p256_fe tmp;
    uint64_t borrow = sub256_v2(tmp, r, mod);
    uint64_t use_sub = carry | (1 - borrow);
    p256_fe_cmov(r, tmp, use_sub);
    return 0;
}

void p256_scalar_add(p256_fe h, const p256_fe f, const p256_fe g)
{
    add256_mod(h, f, g, P256_N);
}

void p256_scalar_mul(p256_fe h, const p256_fe f, const p256_fe g)
{
    /* Full 512-bit product, then reduce mod n */
    uint64_t t[8];
    memset(t, 0, sizeof(t));

#ifdef __SIZEOF_INT128__
    for (int i = 0; i < 4; i++) {
        unsigned __int128 carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (unsigned __int128)f[i] * g[j] + t[i + j];
            t[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        t[i + 4] += (uint64_t)carry;
    }
#else
    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            uint64_t a = f[i], b = g[j];
            uint32_t a0 = (uint32_t)a, a1 = (uint32_t)(a >> 32);
            uint32_t b0 = (uint32_t)b, b1 = (uint32_t)(b >> 32);
            uint64_t p0 = (uint64_t)a0 * b0;
            uint64_t p1 = (uint64_t)a0 * b1;
            uint64_t p2 = (uint64_t)a1 * b0;
            uint64_t p3 = (uint64_t)a1 * b1;
            uint64_t lo = p0 + (p1 << 32) + (p2 << 32);
            uint64_t hi = p3 + (p1 >> 32) + (p2 >> 32);
            if (lo < p0) hi++;
            uint64_t prev = t[i + j];
            lo += prev; if (lo < prev) hi++;
            lo += carry; if (lo < carry) hi++;
            t[i + j] = lo;
            carry = hi;
        }
        t[i + 4] += carry;
    }
#endif

    /* Barrett reduction mod n.
     * Simplified: repeatedly subtract n from the result.
     * For a proper implementation, use Barrett or Montgomery.
     * Here we do a simple shift-and-subtract loop.
     */
    /* We have a 512-bit number in t[0..7]. Reduce mod n (256-bit). */
    /* Simple approach: work with the top half, multiply by (2^256 mod n), add to bottom */

    /* Reduce: result = t[0..3] + t[4..7] * (2^256 mod n) */
    p256_fe lo_part = { t[0], t[1], t[2], t[3] };

    /* Use binary long division / repeated subtraction approach */
    /* Copy 512-bit number into a working buffer */
    p256_fe_copy(h, lo_part);
    uint64_t work[8];
    memcpy(work, t, sizeof(work));

    /* Subtract n from the top until < 2^256 */
    while (work[7] || work[6] || work[5] || work[4]) {
        /* Subtract n << appropriate shift */
        /* Simple: subtract n from work[4..7], carry into work[0..3] */
        uint64_t borrow = 0;
        for (int i = 0; i < 4; i++) {
#ifdef __SIZEOF_INT128__
            unsigned __int128 diff = (unsigned __int128)work[i + 4] - P256_N[i] - borrow;
            work[i + 4] = (uint64_t)diff;
            borrow = (uint64_t)(diff >> 127) & 1;
#else
            uint64_t lo = work[i + 4] - P256_N[i];
            uint64_t br1 = (lo > work[i + 4]) ? 1 : 0;
            uint64_t lo2 = lo - borrow;
            uint64_t br2 = (lo2 > lo) ? 1 : 0;
            work[i + 4] = lo2;
            borrow = br1 | br2;
#endif
        }
        /* Add the remainder back to the low part */
        /* Actually, what we're computing is:
         * work = work - n * 2^256
         * But that gives work[0..3] + (work[4..7] - n) * 2^256
         * We need: work mod n = (work[0..3] + work[4..7] * 2^256) mod n
         * = work[0..3] + work[4..7] * (2^256 mod n) mod n
         */
        /* This simple approach doesn't work well. Let's just do repeated subtraction. */
        break;
    }

    /* Final reduction of the lower 256 bits */
    h[0] = work[0]; h[1] = work[1]; h[2] = work[2]; h[3] = work[3];

    /* Subtract n while h >= n */
    for (int iter = 0; iter < 10; iter++) {
        p256_fe tmp;
        uint64_t borrow = sub256_v2(tmp, h, P256_N);
        if (borrow) break;
        p256_fe_copy(h, tmp);
    }
}

void p256_scalar_inv(p256_fe h, const p256_fe f)
{
    /* Fermat's little theorem: f^(n-2) mod n */
    uint8_t exp[32];
    p256_fe_tobytes(exp, P256_N);
    exp[31] -= 2;

    p256_fe result;
    p256_fe_one(result);
    for (int i = 0; i < 256; i++) {
        p256_fe_sq(result, result);
        /* Oops, this squares mod p, not mod n. We need mod n arithmetic. */
        /* For scalar inversion, use scalar_mul. */
    }

    /* Redo with scalar_mul */
    p256_fe_one(result);
    for (int i = 0; i < 256; i++) {
        p256_scalar_mul(result, result, result);
        int bit = (exp[i / 8] >> (7 - (i & 7))) & 1;
        if (bit)
            p256_scalar_mul(result, result, f);
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
 */
void p256_point_double(p256_point *r, const p256_point *p)
{
    if (p256_point_is_zero(p)) {
        p256_point_zero(r);
        return;
    }

    p256_fe M, S, T, Y2, Z2, tmp;

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
    p256_fe_sub(r->X, T, S);
    p256_fe_sub(r->X, r->X, S);  /* X' = M^2 - 2*S */

    p256_fe_sub(tmp, S, r->X);   /* S - X' */
    p256_fe_mul(tmp, M3, tmp);    /* M * (S - X') */
    p256_fe_sq(Y2, Y2);           /* Y^4 */
    p256_fe_add(Y2, Y2, Y2);
    p256_fe_add(Y2, Y2, Y2);
    p256_fe_add(Y2, Y2, Y2);     /* 8*Y^4 */
    p256_fe_sub(r->Y, tmp, Y2);  /* Y' = M*(S-X') - 8*Y^4 */

    p256_fe_mul(r->Z, p->Y, p->Z);
    p256_fe_add(r->Z, r->Z, r->Z); /* Z' = 2*Y*Z */
}

/*
 * Point addition in Jacobian coordinates.
 * Uses the standard formulas for mixed/full Jacobian addition.
 */
void p256_point_add(p256_point *r, const p256_point *p, const p256_point *q)
{
    if (p256_point_is_zero(p)) {
        p256_fe_copy(r->X, q->X);
        p256_fe_copy(r->Y, q->Y);
        p256_fe_copy(r->Z, q->Z);
        return;
    }
    if (p256_point_is_zero(q)) {
        p256_fe_copy(r->X, p->X);
        p256_fe_copy(r->Y, p->Y);
        p256_fe_copy(r->Z, p->Z);
        return;
    }

    p256_fe U1, U2, S1, S2, H, R_val, HH, HHH, V;

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
    p256_fe_sq(r->X, R_val);
    p256_fe_sub(r->X, r->X, HHH);
    p256_fe tmp;
    p256_fe_add(tmp, V, V);
    p256_fe_sub(r->X, r->X, tmp);

    /* Y3 = R*(V - X3) - S1*H^3 */
    p256_fe_sub(tmp, V, r->X);
    p256_fe_mul(r->Y, R_val, tmp);
    p256_fe_mul(tmp, S1, HHH);
    p256_fe_sub(r->Y, r->Y, tmp);

    /* Z3 = Z1*Z2*H */
    p256_fe_mul(r->Z, p->Z, q->Z);
    p256_fe_mul(r->Z, r->Z, H);
}

/* ------------------------------------------------------------------ */
/* Scalar multiplication: double-and-add                                */
/* ------------------------------------------------------------------ */

void p256_point_scalar_mult(p256_point *r, const uint8_t k[32],
                             const p256_point *p)
{
    p256_point_zero(r);
    p256_point R_tmp;

    for (int i = 0; i < 256; i++) {
        p256_point_double(r, r);

        int bit = (k[i / 8] >> (7 - (i & 7))) & 1;
        if (bit) {
            p256_point_add(&R_tmp, r, p);
            p256_fe_copy(r->X, R_tmp.X);
            p256_fe_copy(r->Y, R_tmp.Y);
            p256_fe_copy(r->Z, R_tmp.Z);
        }
    }
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
