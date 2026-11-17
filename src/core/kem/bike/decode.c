/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE - Black-Gray-Flip (BGF) decoder, constant time.
 *
 * This is the BGF decoder of the BIKE specification (round 4, v5.1,
 * Algorithm 3), with its parameters: NbIter = 5, tau = 3, the linear
 * threshold function below, and the two masked iterations after the
 * first. It replaces an ad-hoc bit-flipping decoder that ran up to 100
 * iterations with approximate thresholds, cost O(r^2) per iteration,
 * stopped as soon as the syndrome was zero, and indexed memory by the
 * secret key. A malformed ciphertext kept it busy for 20 s (L1) to
 * 150 s (L5) in a release build.
 *
 * Constant time. The secret inputs are h0, h1 (the private key) and
 * everything derived from them -- the syndrome, the error vector, the
 * counters. Nothing below branches on them or uses them as an address:
 *
 *   - The positions of the w/2 set bits of h0 and h1 are extracted with
 *     a scan of every bit for every slot (extract_positions).
 *   - A counter for every bit position j, upc[j] = sum over k in supp(h)
 *     of s[(j + k) mod r], is computed by rotating the whole syndrome by
 *     each secret k with a masked barrel shift (rotr_ct) and adding the
 *     result into bit-sliced counters (add_bits).
 *   - Comparisons of all counters with a threshold are bit-sliced too
 *     (ge_threshold), producing a mask of positions to flip.
 *   - The syndrome weight, the threshold derived from it and the final
 *     "is the residual zero" test use arithmetic only.
 *   - The number of iterations is fixed. There is no early exit when the
 *     residual reaches zero, so a valid and a malformed ciphertext take
 *     the same time.
 *
 * The total cost is a fixed number of rotations of r-bit vectors:
 * 7 counter computations and 8 residual computations, each w rotations.
 */

#include <string.h>
#include <stdlib.h>

#include "pqc/common.h"
#include "bike.h"
#include "bike_params.h"

#define BGF_NB_ITER   5
#define BGF_TAU       3
#define UPC_SLICES    8      /* counters hold up to w/2 <= 137 < 256 */

/* ------------------------------------------------------------------ */
/* Threshold function                                                   */
/*                                                                      */
/* threshold(S) = max(floor(c0 + c1 * S), (d + 1) / 2), from the BIKE   */
/* specification and its reference implementation, in fixed point with */
/* 8 decimal places so that no floating point is involved:             */
/*                                                                      */
/*   L1  d =  71   c0 = 13.530    c1 = 0.0069722    min = 36           */
/*   L3  d = 103   c0 = 15.2588   c1 = 0.005265     min = 52           */
/*   L5  d = 137   c0 = 17.8785   c1 = 0.00402312   min = 69           */
/* ------------------------------------------------------------------ */

static uint32_t threshold(uint32_t S, uint32_t d)
{
    uint64_t c0, c1;
    uint32_t t, tmin = (d + 1) / 2, lt;

    switch (d) {                      /* d is public */
    case 71:  c0 = 1353000000ULL; c1 = 697220ULL; break;
    case 103: c0 = 1525880000ULL; c1 = 526500ULL; break;
    default:  c0 = 1787850000ULL; c1 = 402312ULL; break;   /* 137 */
    }
    /* Division by a constant compiles to a multiply, not a divide. */
    t = (uint32_t)((c0 + c1 * (uint64_t)S) / 100000000ULL);
    lt = (uint32_t)(((uint64_t)t - tmin) >> 63);          /* t < tmin */
    return t ^ ((t ^ tmin) & (0u - lt));
}

/* ------------------------------------------------------------------ */
/* Bit-vector helpers                                                   */
/* ------------------------------------------------------------------ */

static uint64_t popcount64(uint64_t x)
{
    x = x - ((x >> 1) & 0x5555555555555555ULL);
    x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
    x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
    return (x * 0x0101010101010101ULL) >> 56;
}

static uint32_t weight(const uint64_t *v, uint32_t words)
{
    uint64_t w = 0;
    uint32_t i;
    for (i = 0; i < words; i++)
        w += popcount64(v[i]);
    return (uint32_t)w;
}

static void mask_tail(uint64_t *v, uint32_t r)
{
    uint32_t rem = r % 64;
    if (rem)
        v[(r + 63) / 64 - 1] &= ((uint64_t)1 << rem) - 1;
}

/*
 * t = v || v as a bit string of 2r bits (bit i of t is v[i mod r]), in
 * tw = 2 * r_words + 1 words. r is public, so the shifts are too.
 */
static void duplicate(uint64_t *t, const uint64_t *v, uint32_t r,
                      uint32_t r_words, uint32_t tw)
{
    uint32_t q = r / 64, b = r % 64, i;

    memset(t, 0, tw * sizeof(uint64_t));
    memcpy(t, v, r_words * sizeof(uint64_t));
    for (i = 0; i < r_words; i++) {
        t[q + i] |= b ? v[i] << b : v[i];
        if (b)
            t[q + i + 1] |= v[i] >> (64 - b);
    }
}

/*
 * out = the r bits of t starting at bit k, i.e. out[j] = v[(j + k) mod r]
 * when t = duplicate(v) and k <= r. k is secret: the word part of the
 * shift is a barrel shifter whose stages are selected by mask, and the
 * bit part is a variable shift, which runs in constant time.
 * buf is scratch of tw words.
 */
static void rotr_ct(uint64_t *out, uint64_t *buf, const uint64_t *t,
                    uint32_t k, uint32_t r, uint32_t r_words, uint32_t tw)
{
    uint32_t q = k >> 6, b = k & 63, s, j;

    memcpy(buf, t, tw * sizeof(uint64_t));
    for (s = 1; s <= r_words; s <<= 1) {
        uint64_t m = 0 - (uint64_t)((q & s) != 0);
        for (j = 0; j + s < tw; j++)
            buf[j] = (buf[j] & ~m) | (buf[j + s] & m);
    }
    for (j = 0; j < r_words; j++)
        out[j] = (buf[j] >> b) | ((buf[j + 1] << (63 - b)) << 1);
    mask_tail(out, r);
}

/* Bit-sliced counters: ctr += v (one bit per position). */
static void add_bits(uint64_t (*ctr)[BIKE_MAX_R_WORDS], const uint64_t *v,
                     uint32_t r_words)
{
    uint32_t i, b;
    for (i = 0; i < r_words; i++) {
        uint64_t carry = v[i];
        for (b = 0; b < UPC_SLICES; b++) {
            uint64_t c = ctr[b][i] & carry;
            ctr[b][i] ^= carry;
            carry = c;
        }
    }
}

/* out[j] = 1 where ctr[j] >= T. */
static void ge_threshold(uint64_t *out, uint64_t (*ctr)[BIKE_MAX_R_WORDS],
                         uint32_t T, uint32_t r_words)
{
    uint32_t i;
    int b;
    for (i = 0; i < r_words; i++) {
        uint64_t gt = 0, eq = ~(uint64_t)0;
        for (b = UPC_SLICES - 1; b >= 0; b--) {
            uint64_t tb = 0 - (uint64_t)((T >> b) & 1);
            uint64_t u = ctr[b][i];
            gt |= eq & u & ~tb;
            eq &= ~(u ^ tb);
        }
        out[i] = gt | eq;
    }
}

/*
 * pos[0..d-1] = the indices of the set bits of h, which has exactly d.
 * Every bit is visited for every slot, so neither the control flow nor
 * any address depends on where the bits are.
 */
static void extract_positions(uint32_t *pos, const uint64_t *h,
                              uint32_t d, uint32_t r)
{
    uint32_t i, k, count = 0;

    memset(pos, 0, d * sizeof(uint32_t));
    for (i = 0; i < r; i++) {
        uint32_t bit = (uint32_t)(h[i / 64] >> (i % 64)) & 1;
        for (k = 0; k < d; k++) {
            uint32_t diff = count ^ k;
            /* hit = 0xFFFFFFFF if bit == 1 and count == k */
            uint32_t eq = (uint32_t)(((uint64_t)diff - 1) >> 63);
            uint32_t hit = 0u - (bit & eq);
            pos[k] |= i & hit;
        }
        count += bit;
    }
}

/* ------------------------------------------------------------------ */
/* Decoder state                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t r, r_words, tw, d;
    uint32_t pos[2][BIKE_MAX_W / 2];
    uint64_t s[BIKE_MAX_R_WORDS];              /* syndrome c0 * h0      */
    uint64_t res[BIKE_MAX_R_WORDS];            /* s + e H^T             */
    uint64_t e[2][BIKE_MAX_R_WORDS];
    uint64_t black[2][BIKE_MAX_R_WORDS];
    uint64_t gray[2][BIKE_MAX_R_WORDS];
    uint64_t flip[BIKE_MAX_R_WORDS];
    uint64_t rot[BIKE_MAX_R_WORDS];
    uint64_t ctr[UPC_SLICES][BIKE_MAX_R_WORDS];
    uint64_t t[2 * BIKE_MAX_R_WORDS + 1];
    uint64_t buf[2 * BIKE_MAX_R_WORDS + 1];
} bgf_t;

/* acc ^= v * h_b, for sparse secret h_b: (v * h)[i] = sum_k v[i - k]. */
static void sparse_mul_acc(bgf_t *st, uint64_t *acc, const uint64_t *v,
                           int b)
{
    uint32_t k, i;
    duplicate(st->t, v, st->r, st->r_words, st->tw);
    for (k = 0; k < st->d; k++) {
        /* v[i - p] = v[(i + (r - p)) mod r]; r - p is in [1, r]. */
        rotr_ct(st->rot, st->buf, st->t, st->r - st->pos[b][k],
                st->r, st->r_words, st->tw);
        for (i = 0; i < st->r_words; i++)
            acc[i] ^= st->rot[i];
    }
}

/* res = s + e0 * h0 + e1 * h1 */
static void residual(bgf_t *st)
{
    memcpy(st->res, st->s, st->r_words * sizeof(uint64_t));
    sparse_mul_acc(st, st->res, st->e[0], 0);
    sparse_mul_acc(st, st->res, st->e[1], 1);
}

/* ctr = unsatisfied parity checks of every position of block b. */
static void count_upc(bgf_t *st, int b)
{
    uint32_t k;
    memset(st->ctr, 0, sizeof st->ctr);
    duplicate(st->t, st->res, st->r, st->r_words, st->tw);
    for (k = 0; k < st->d; k++) {
        rotr_ct(st->rot, st->buf, st->t, st->pos[b][k],
                st->r, st->r_words, st->tw);
        add_bits(st->ctr, st->rot, st->r_words);
    }
}

/* BFIter: flip where upc >= T; record black (flipped) and gray. */
static void bf_iter(bgf_t *st, uint32_t T)
{
    int b;
    uint32_t i;
    /* Every block's counters come from the same residual. */
    for (b = 0; b < 2; b++) {
        count_upc(st, b);
        ge_threshold(st->black[b], st->ctr, T, st->r_words);
        ge_threshold(st->gray[b], st->ctr, T - BGF_TAU, st->r_words);
        for (i = 0; i < st->r_words; i++)
            st->gray[b][i] &= ~st->black[b][i];
    }
    for (b = 0; b < 2; b++)
        for (i = 0; i < st->r_words; i++)
            st->e[b][i] ^= st->black[b][i];
}

/* BFMaskedIter: flip where upc >= T and the mask is set. */
static void bf_masked_iter(bgf_t *st, uint64_t (*mask)[BIKE_MAX_R_WORDS],
                           uint32_t T)
{
    int b;
    uint32_t i;
    uint64_t f[2][BIKE_MAX_R_WORDS];
    for (b = 0; b < 2; b++) {
        count_upc(st, b);
        ge_threshold(f[b], st->ctr, T, st->r_words);
    }
    for (b = 0; b < 2; b++)
        for (i = 0; i < st->r_words; i++)
            st->e[b][i] ^= f[b][i] & mask[b][i];
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                   */
/* ------------------------------------------------------------------ */

int bike_decode_ct(uint64_t *e0, uint64_t *e1,
                   const uint64_t *c0,
                   const uint64_t *h0, const uint64_t *h1,
                   const bike_params_t *params)
{
    bgf_t *st = (bgf_t *)calloc(1, sizeof(bgf_t));
    uint32_t it, i, T, tmask;
    uint64_t nz = 0;
    int ok;

    if (!st)
        return -1;
    st->r = params->r;
    st->r_words = params->r_words;
    st->tw = 2 * params->r_words + 1;
    st->d = params->half_w;
    tmask = (st->d + 1) / 2 + 1;     /* threshold of the masked iterations */

    extract_positions(st->pos[0], h0, st->d, st->r);
    extract_positions(st->pos[1], h1, st->d, st->r);

    /* Syndrome s = c0 * h0. c0 is public, h0 secret. */
    memset(st->s, 0, sizeof st->s);
    sparse_mul_acc(st, st->s, c0, 0);

    for (it = 0; it < BGF_NB_ITER; it++) {
        residual(st);
        T = threshold(weight(st->res, st->r_words), st->d);
        bf_iter(st, T);
        if (it == 0) {
            residual(st);
            bf_masked_iter(st, st->black, tmask);
            residual(st);
            bf_masked_iter(st, st->gray, tmask);
        }
    }

    /* Success iff e H^T = s, i.e. the residual is zero. */
    residual(st);
    for (i = 0; i < st->r_words; i++)
        nz |= st->res[i];
    ok = (int)(((nz | (0 - nz)) >> 63) ^ 1);     /* 1 if nz == 0 */

    memcpy(e0, st->e[0], st->r_words * sizeof(uint64_t));
    memcpy(e1, st->e[1], st->r_words * sizeof(uint64_t));
    pqc_memzero(st, sizeof(bgf_t));
    free(st);
    return ok;
}
