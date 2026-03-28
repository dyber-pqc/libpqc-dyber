/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE - GF(2)[x] polynomial arithmetic modulo (x^r - 1).
 *
 * Provides addition (XOR), multiplication (schoolbook with reduction),
 * modular reduction, and inversion via the extended Euclidean algorithm.
 */

#include <string.h>
#include <stdlib.h>
#include "bike.h"
#include "bike_params.h"

/* ------------------------------------------------------------------ */
/* Utility: bit access                                                  */
/* ------------------------------------------------------------------ */

static inline int bit_get(const uint64_t *v, uint32_t i)
{
    return (int)((v[i / 64] >> (i % 64)) & 1);
}

static inline void bit_set(uint64_t *v, uint32_t i)
{
    v[i / 64] |= (uint64_t)1 << (i % 64);
}

static inline void bit_flip(uint64_t *v, uint32_t i)
{
    v[i / 64] ^= (uint64_t)1 << (i % 64);
}

/* ------------------------------------------------------------------ */
/* Addition in GF(2): o = a XOR b                                       */
/* ------------------------------------------------------------------ */

void bike_gf2x_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    uint32_t r_words)
{
    for (uint32_t i = 0; i < r_words; i++) {
        o[i] = a[i] ^ b[i];
    }
}

/* ------------------------------------------------------------------ */
/* Reduction mod (x^r - 1)                                              */
/*                                                                      */
/* Folds bits at positions >= r back to positions 0..r-1.               */
/* ------------------------------------------------------------------ */

void bike_gf2x_mod(uint64_t *a, uint32_t r)
{
    uint32_t r_words = (r + 63) / 64;
    uint32_t rem = r % 64;

    if (rem == 0) {
        /* r is a multiple of 64, nothing to fold within the last word */
        return;
    }

    /* Clear bits above r in the last word by folding them */
    uint64_t overflow = a[r_words - 1] >> rem;
    a[r_words - 1] &= ((uint64_t)1 << rem) - 1;
    a[0] ^= overflow;
}

/* ------------------------------------------------------------------ */
/* Multiplication: o = a * b mod (x^r - 1)                              */
/*                                                                      */
/* Schoolbook multiplication. For each set bit in b, XOR the shifted    */
/* copy of a into result, then reduce mod (x^r - 1).                    */
/* ------------------------------------------------------------------ */

void bike_gf2x_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    uint32_t r)
{
    uint32_t r_words = (r + 63) / 64;
    uint32_t result_words = r_words * 2 + 1;
    uint64_t *result = (uint64_t *)calloc(result_words, sizeof(uint64_t));

    if (!result) {
        memset(o, 0, r_words * sizeof(uint64_t));
        return;
    }

    for (uint32_t i = 0; i < r; i++) {
        if (!bit_get(b, i)) continue;

        uint32_t word_off = i / 64;
        uint32_t bit_off  = i % 64;

        if (bit_off == 0) {
            for (uint32_t j = 0; j < r_words; j++) {
                result[word_off + j] ^= a[j];
            }
        } else {
            for (uint32_t j = 0; j < r_words; j++) {
                result[word_off + j]     ^= a[j] << bit_off;
                result[word_off + j + 1] ^= a[j] >> (64 - bit_off);
            }
        }
    }

    /* Reduce mod (x^r - 1): for bits at position p >= r, XOR into p - r */
    for (uint32_t i = 2 * r - 1; i >= r; i--) {
        if (bit_get(result, i)) {
            uint32_t target = i - r;
            bit_flip(result, target);
            bit_flip(result, i);
        }
    }

    memcpy(o, result, r_words * sizeof(uint64_t));

    /* Clear trailing bits */
    uint32_t rem = r % 64;
    if (rem) {
        o[r_words - 1] &= ((uint64_t)1 << rem) - 1;
    }

    free(result);
}

/* ------------------------------------------------------------------ */
/* Inversion in GF(2)[x] / (x^r - 1) via extended GCD                  */
/*                                                                      */
/* Since r is prime and a(x) is nonzero, gcd(a(x), x^r-1) = 1, so     */
/* the inverse always exists.                                           */
/*                                                                      */
/* Uses a binary GCD variant adapted for polynomials over GF(2).        */
/* ------------------------------------------------------------------ */

/* Find the degree of polynomial v */
static int poly_degree(const uint64_t *v, uint32_t max_words)
{
    for (int w = (int)max_words - 1; w >= 0; w--) {
        if (v[w] != 0) {
            /* Find highest set bit */
            uint64_t val = v[w];
            int bit = 63;
            while (bit >= 0 && !((val >> bit) & 1)) bit--;
            return w * 64 + bit;
        }
    }
    return -1;
}

int bike_gf2x_inv(uint64_t *o, const uint64_t *a, uint32_t r)
{
    /*
     * Extended Euclidean algorithm for GF(2)[x].
     * Computes o such that a * o = 1 mod (x^r - 1).
     */
    uint32_t r_words = (r + 63) / 64;
    /* Bezout coefficients can have degree up to 2r during intermediate steps,
     * so allocate enough space for shifted products g2 * x^shift. */
    uint32_t alloc_words = r_words * 2 + 4;

    uint64_t *u  = (uint64_t *)calloc(alloc_words, sizeof(uint64_t));
    uint64_t *v  = (uint64_t *)calloc(alloc_words, sizeof(uint64_t));
    uint64_t *g1 = (uint64_t *)calloc(alloc_words, sizeof(uint64_t));
    uint64_t *g2 = (uint64_t *)calloc(alloc_words, sizeof(uint64_t));

    if (!u || !v || !g1 || !g2) {
        free(u); free(v); free(g1); free(g2);
        return -1;
    }

    /* u = x^r - 1 = x^r + 1 (same in GF(2)) */
    memset(u, 0, alloc_words * sizeof(uint64_t));
    bit_set(u, r);
    bit_set(u, 0);  /* x^r + 1 */

    /* v = a */
    memcpy(v, a, r_words * sizeof(uint64_t));

    /* g1 = 0, g2 = 1 */
    memset(g1, 0, alloc_words * sizeof(uint64_t));
    memset(g2, 0, alloc_words * sizeof(uint64_t));
    g2[0] = 1;

    int deg_u = poly_degree(u, alloc_words);
    int deg_v = poly_degree(v, alloc_words);

    while (deg_v >= 0) {
        /* While deg(u) >= deg(v) */
        int shift = deg_u - deg_v;
        if (shift < 0) {
            /* Swap u <-> v, g1 <-> g2 */
            uint64_t *tmp;
            int tmp_deg;
            tmp = u; u = v; v = tmp;
            tmp = g1; g1 = g2; g2 = tmp;
            tmp_deg = deg_u; deg_u = deg_v; deg_v = tmp_deg;
            shift = -shift;
        }

        /* u = u + v * x^shift */
        if (shift < (int)(alloc_words * 64)) {
            uint32_t word_off = (uint32_t)shift / 64;
            uint32_t bit_off  = (uint32_t)shift % 64;
            uint32_t max_j = alloc_words - word_off;

            if (bit_off == 0) {
                for (uint32_t j = 0; j < max_j && (word_off + j) < alloc_words; j++) {
                    u[word_off + j] ^= v[j];
                }
                for (uint32_t j = 0; j < max_j && (word_off + j) < alloc_words; j++) {
                    g1[word_off + j] ^= g2[j];
                }
            } else {
                for (uint32_t j = 0; j < max_j && (word_off + j) < alloc_words; j++) {
                    u[word_off + j] ^= v[j] << bit_off;
                    if (word_off + j + 1 < alloc_words) {
                        u[word_off + j + 1] ^= v[j] >> (64 - bit_off);
                    }
                }
                for (uint32_t j = 0; j < max_j && (word_off + j) < alloc_words; j++) {
                    g1[word_off + j] ^= g2[j] << bit_off;
                    if (word_off + j + 1 < alloc_words) {
                        g1[word_off + j + 1] ^= g2[j] >> (64 - bit_off);
                    }
                }
            }
        }

        deg_u = poly_degree(u, alloc_words);

        /* Swap if needed to maintain deg_u >= deg_v */
        if (deg_u < deg_v) {
            uint64_t *tmp;
            int tmp_deg;
            tmp = u; u = v; v = tmp;
            tmp = g1; g1 = g2; g2 = tmp;
            tmp_deg = deg_u; deg_u = deg_v; deg_v = tmp_deg;
        }
        deg_v = poly_degree(v, alloc_words);
    }

    /* u should now be 1 (or a constant), g1 is the inverse */
    /* Reduce g1 mod (x^r - 1) */
    for (uint32_t i = r; i < alloc_words * 64; i++) {
        if (bit_get(g1, i)) {
            uint32_t target = (i - r) % r;
            bit_flip(g1, target);
            bit_flip(g1, i);
        }
    }

    memcpy(o, g1, r_words * sizeof(uint64_t));
    uint32_t rem = r % 64;
    if (rem) {
        o[r_words - 1] &= ((uint64_t)1 << rem) - 1;
    }

    free(u); free(v); free(g1); free(g2);
    return 0;
}
