/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE - arithmetic in R = GF(2)[x] / (x^r - 1), constant time.
 *
 * Polynomials are arrays of ceil(r/64) little-endian 64-bit words, bit i
 * of the array being the coefficient of x^i, with bits >= r zero.
 *
 * Every function here runs in time independent of the coefficients of
 * its operands, which are secret in key generation (h0, h1, h0^-1) and
 * encapsulation (e1). Only r, which is public, steers control flow or
 * addresses:
 *
 *   - Multiplication is Karatsuba over 64-bit words, with a carry-less
 *     64x64 product computed by masked shifts (no table lookups).
 *   - Inversion uses Fermat's little theorem with the Itoh-Tsujii
 *     addition chain. Raising to 2^k is a fixed permutation of the bit
 *     positions, determined by r and k alone.
 *
 * Until 0.3.0 multiplication skipped zero bits of one operand and
 * reduced with a branch per bit, and inversion was a variable-time
 * extended Euclid on the secret h0.
 */

#include <string.h>
#include <stdlib.h>

#include "pqc/common.h"
#include "bike.h"
#include "bike_params.h"

/* ------------------------------------------------------------------ */
/* Addition                                                             */
/* ------------------------------------------------------------------ */

void bike_gf2x_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    uint32_t r_words)
{
    for (uint32_t i = 0; i < r_words; i++)
        o[i] = a[i] ^ b[i];
}

/* ------------------------------------------------------------------ */
/* Reduction of a polynomial of degree < 2r held in place: fold bits    */
/* [r, 2r) onto [0, r). Callers that only hold r_words words can use    */
/* bike_gf2x_mod, which folds the bits above r in the top word.         */
/* ------------------------------------------------------------------ */

void bike_gf2x_mod(uint64_t *a, uint32_t r)
{
    uint32_t r_words = (r + 63) / 64;
    uint32_t rem = r % 64;

    if (rem == 0)
        return;
    {
        uint64_t overflow = a[r_words - 1] >> rem;
        a[r_words - 1] &= ((uint64_t)1 << rem) - 1;
        a[0] ^= overflow;
    }
}

/* c (2n words) ^= nothing; c = a * b over GF(2)[x], a and b n words. */

/* Carry-less 64 x 64 -> 128, by masked shifts. */
static void clmul64(uint64_t *lo, uint64_t *hi, uint64_t a, uint64_t b)
{
    uint64_t l = 0, h = 0;
    int i;
    l = a & (0 - (b & 1));
    for (i = 1; i < 64; i++) {
        uint64_t m = 0 - ((b >> i) & 1);
        l ^= (a << i) & m;
        h ^= (a >> (64 - i)) & m;
    }
    *lo = l;
    *hi = h;
}

#define KARATSUBA_CUTOFF 12

/* c[0 .. na+nb) = a[0 .. na) * b[0 .. nb), schoolbook. */
static void mul_school(uint64_t *c, const uint64_t *a, size_t na,
                       const uint64_t *b, size_t nb)
{
    size_t i, j;
    memset(c, 0, (na + nb) * sizeof(uint64_t));
    for (i = 0; i < na; i++)
        for (j = 0; j < nb; j++) {
            uint64_t lo, hi;
            clmul64(&lo, &hi, a[i], b[j]);
            c[i + j] ^= lo;
            c[i + j + 1] ^= hi;
        }
}

/*
 * c[0 .. 2n) = a * b, both n words. Karatsuba with an unbalanced split
 * when n is odd: lo = n/2 words, hi = n - lo words.
 */
static int mul_kara(uint64_t *c, const uint64_t *a, const uint64_t *b,
                    size_t n)
{
    size_t lo, hi, i;
    uint64_t *t, *sa, *sb, *mid;

    if (n <= KARATSUBA_CUTOFF) {
        mul_school(c, a, n, b, n);
        return 0;
    }
    lo = n / 2;
    hi = n - lo;

    /* one allocation: sa, sb (hi words each), mid (2*hi words) */
    t = (uint64_t *)calloc(4 * hi, sizeof(uint64_t));
    if (!t) return -1;
    sa = t; sb = t + hi; mid = t + 2 * hi;

    /* c_low = a0 * b0 (2*lo words), c_high = a1 * b1 (2*hi words) */
    if (mul_kara(c, a, b, lo) || mul_kara(c + 2 * lo, a + lo, b + lo, hi)) {
        free(t);
        return -1;
    }

    /* mid = (a0 + a1)(b0 + b1), with a0, b0 zero-extended to hi words */
    for (i = 0; i < hi; i++) {
        sa[i] = a[lo + i] ^ (i < lo ? a[i] : 0);
        sb[i] = b[lo + i] ^ (i < lo ? b[i] : 0);
    }
    if (mul_kara(mid, sa, sb, hi)) {
        free(t);
        return -1;
    }
    /* mid -= a0b0 + a1b1 */
    for (i = 0; i < 2 * lo; i++)
        mid[i] ^= c[i];
    for (i = 0; i < 2 * hi; i++)
        mid[i] ^= c[2 * lo + i];
    /* c += mid * x^(64*lo) */
    for (i = 0; i < 2 * hi; i++)
        c[lo + i] ^= mid[i];

    free(t);
    return 0;
}

/*
 * o = a * b mod (x^r - 1). Constant time in a and b.
 * On allocation failure o is set to zero.
 */
void bike_gf2x_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    uint32_t r)
{
    uint32_t r_words = (r + 63) / 64;
    uint32_t q = r / 64, sh = r % 64, j;
    uint64_t *prod = (uint64_t *)calloc(2 * r_words + 1, sizeof(uint64_t));

    if (!prod || mul_kara(prod, a, b, r_words)) {
        free(prod);
        memset(o, 0, r_words * sizeof(uint64_t));
        return;
    }

    /* Fold bits [r, 2r) onto [0, r): word shifts by the public r. Writes
     * go to words 0..q, and every read of word q happens at j = 0,
     * before it is written. */
    for (j = 0; j < r_words; j++) {
        uint64_t lo = prod[q + j];
        uint64_t hi = prod[q + j + 1];
        prod[j] ^= sh ? (lo >> sh) | (hi << (64 - sh)) : lo;
    }
    memcpy(o, prod, r_words * sizeof(uint64_t));
    if (sh)
        o[r_words - 1] &= ((uint64_t)1 << sh) - 1;

    pqc_memzero(prod, (2 * r_words + 1) * sizeof(uint64_t));
    free(prod);
}

/* ------------------------------------------------------------------ */
/* Inversion                                                            */
/* ------------------------------------------------------------------ */

/* o = a^(2^k): coefficient i moves to i * 2^k mod r. o must not alias a. */
static void sqr_k(uint64_t *o, const uint64_t *a, uint32_t k, uint32_t r)
{
    uint32_t r_words = (r + 63) / 64, i, j = 0, step = 1;

    for (i = 0; i < k; i++)                     /* step = 2^k mod r */
        step = (uint32_t)(((uint64_t)step * 2) % r);
    memset(o, 0, r_words * sizeof(uint64_t));
    for (i = 0; i < r; i++) {
        uint64_t bit = (a[i / 64] >> (i % 64)) & 1;   /* i, j public */
        o[j / 64] |= bit << (j % 64);
        j += step;
        if (j >= r) j -= r;
    }
}

/*
 * o = a^-1 in R. r is prime and 2 is primitive modulo r, so
 * R = GF(2) x GF(2^(r-1)) and every a of odd weight not divisible by
 * (x^r - 1)/(x - 1) has the inverse a^(2^(r-1) - 2). BIKE's h0 has odd
 * weight w/2 and qualifies.
 *
 * With f(k) = a^(2^k - 1): f(2k) = f(k)^(2^k) * f(k) and
 * f(k + 1) = f(k)^2 * a, so f(r - 2) follows from the bits of r - 2, and
 * a^-1 = f(r - 2)^2. Returns 0, or -1 if memory allocation fails.
 */
int bike_gf2x_inv(uint64_t *o, const uint64_t *a, uint32_t r)
{
    uint32_t r_words = (r + 63) / 64;
    uint32_t n = r - 2, k = 1;
    int bit;
    uint64_t *f = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *t = (uint64_t *)calloc(r_words, sizeof(uint64_t));

    if (!f || !t) {
        free(f); free(t);
        return -1;
    }

    memcpy(f, a, r_words * sizeof(uint64_t));          /* f(1) = a */
    for (bit = 30; bit >= 0 && !((n >> bit) & 1); bit--)
        ;                                               /* n is public */
    for (bit--; bit >= 0; bit--) {
        sqr_k(t, f, k, r);
        bike_gf2x_mul(f, t, f, r);                      /* f(2k) */
        k *= 2;
        if ((n >> bit) & 1) {
            sqr_k(t, f, 1, r);
            bike_gf2x_mul(f, t, a, r);                  /* f(k + 1) */
            k += 1;
        }
    }
    sqr_k(o, f, 1, r);                                  /* f(r-2)^2 */

    pqc_memzero(f, r_words * sizeof(uint64_t));
    pqc_memzero(t, r_words * sizeof(uint64_t));
    free(f); free(t);
    return 0;
}
