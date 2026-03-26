/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE - Bit-flipping decoder (Black-Gray-Flip variant).
 *
 * Implements the BGF (Black-Gray-Flip) iterative decoder for QC-MDPC
 * codes. The decoder computes syndromes, calculates thresholds, and
 * iteratively flips error bits based on the number of unsatisfied
 * parity checks.
 */

#include <string.h>
#include <stdlib.h>
#include "bike.h"
#include "bike_params.h"

/* ------------------------------------------------------------------ */
/* Utility functions                                                    */
/* ------------------------------------------------------------------ */

static inline int bit_get(const uint64_t *v, uint32_t i)
{
    return (int)((v[i / 64] >> (i % 64)) & 1);
}

static inline void bit_flip(uint64_t *v, uint32_t i)
{
    v[i / 64] ^= (uint64_t)1 << (i % 64);
}

static uint32_t popcount_vec(const uint64_t *v, uint32_t words)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < words; i++) {
        uint64_t x = v[i];
        while (x) { x &= x - 1; count++; }
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Syndrome computation                                                 */
/*                                                                      */
/* syndrome = c0 * h0_inv + c1 (in the parity check interpretation)    */
/* For BIKE: syndrome = c0 + c1 * h_0 where h = h1 * h0^{-1}          */
/*                                                                      */
/* In the decoding context, we compute:                                 */
/*   s = e0 * h0 + e1 * h1 mod (x^r - 1)                             */
/* which is the same as multiplying the error by the parity check.      */
/* ------------------------------------------------------------------ */

void bike_compute_syndrome(uint64_t *syndrome,
                           const uint64_t *c0, const uint64_t *c1,
                           const uint64_t *h0,
                           const bike_params_t *params)
{
    uint32_t r = params->r;
    uint32_t r_words = params->r_words;
    uint64_t *tmp = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    if (!tmp) {
        memset(syndrome, 0, r_words * sizeof(uint64_t));
        return;
    }

    /* syndrome = c0 + c1 * h0 mod (x^r - 1) */
    bike_gf2x_mul(tmp, c1, h0, r);
    bike_gf2x_add(syndrome, c0, tmp, r_words);

    /* Clear trailing bits */
    uint32_t rem = r % 64;
    if (rem) {
        syndrome[r_words - 1] &= ((uint64_t)1 << rem) - 1;
    }

    free(tmp);
}

/* ------------------------------------------------------------------ */
/* Count unsatisfied parity checks for a given position                 */
/*                                                                      */
/* For position j in block b, count how many syndrome bits are set      */
/* at positions where h_b has a 1-bit (cyclically shifted).             */
/* This counts the number of unsatisfied parity checks involving bit j. */
/* ------------------------------------------------------------------ */

static uint32_t count_unsat(const uint64_t *syndrome,
                            const uint64_t *h,
                            uint32_t pos, uint32_t r)
{
    /*
     * For the quasi-cyclic code, the parity checks involving position pos
     * are determined by the nonzero positions of h, rotated by pos.
     * unsat(pos) = |{ k : h[k]=1 and s[(pos+k) mod r]=1 }|
     */
    uint32_t count = 0;
    for (uint32_t k = 0; k < r; k++) {
        if (bit_get(h, k)) {
            uint32_t idx = (pos + k) % r;
            if (bit_get(syndrome, idx)) {
                count++;
            }
        }
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* BGF threshold computation                                            */
/*                                                                      */
/* threshold = floor(syndrome_weight / (2 * w/2)) + constant            */
/* The constant depends on the iteration and security level.            */
/* ------------------------------------------------------------------ */

static uint32_t compute_threshold(uint32_t syndrome_weight,
                                  uint32_t half_w,
                                  int iteration)
{
    /* Approximate: T = floor(S / w) + delta
     * where delta depends on iteration.
     * Standard BGF uses: T_0 ~ S/(2*d) + (d-1)/2 for first iteration */
    uint32_t T;
    if (half_w == 0) return 1;

    T = syndrome_weight / (2 * half_w);

    /* Adjust based on iteration */
    switch (iteration) {
    case 0:
        T = (T > 0) ? T : 1;
        break;
    case 1:
        /* More aggressive in later iterations */
        T = (T > 1) ? T - 1 : 1;
        break;
    default:
        T = (T > 1) ? T - 1 : 1;
        break;
    }

    /* Minimum threshold */
    if (T < 1) T = 1;

    return T;
}

/* ------------------------------------------------------------------ */
/* Update syndrome after flipping bit j in block b                      */
/*                                                                      */
/* Flipping e_b[j] changes syndrome by XOR h_b rotated by j.           */
/* s' = s + h_b * x^j mod (x^r - 1)                                   */
/* ------------------------------------------------------------------ */

static void update_syndrome(uint64_t *syndrome, const uint64_t *h,
                            uint32_t pos, uint32_t r)
{
    for (uint32_t k = 0; k < r; k++) {
        if (bit_get(h, k)) {
            uint32_t idx = (pos + k) % r;
            bit_flip(syndrome, idx);
        }
    }
}

/* ------------------------------------------------------------------ */
/* BGF decoder main loop                                                */
/* ------------------------------------------------------------------ */

int bike_decode(uint64_t *e0, uint64_t *e1,
                const uint64_t *syndrome_in,
                const uint64_t *h0, const uint64_t *h1,
                const bike_params_t *params)
{
    uint32_t r = params->r;
    uint32_t r_words = params->r_words;
    uint32_t t = params->t;

    /* Working copy of syndrome */
    uint64_t *syndrome = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    /* Black and gray masks */
    uint8_t *black0 = (uint8_t *)calloc(r, 1);
    uint8_t *black1 = (uint8_t *)calloc(r, 1);
    uint8_t *gray0  = (uint8_t *)calloc(r, 1);
    uint8_t *gray1  = (uint8_t *)calloc(r, 1);

    if (!syndrome || !black0 || !black1 || !gray0 || !gray1) {
        free(syndrome); free(black0); free(black1);
        free(gray0); free(gray1);
        return -1;
    }

    memcpy(syndrome, syndrome_in, r_words * sizeof(uint64_t));
    memset(e0, 0, r_words * sizeof(uint64_t));
    memset(e1, 0, r_words * sizeof(uint64_t));

    int max_iters = BIKE_MAX_DECODE_ITERS;

    for (int iter = 0; iter < max_iters; iter++) {
        uint32_t sw = popcount_vec(syndrome, r_words);
        if (sw == 0) {
            /* Decoding succeeded */
            free(syndrome); free(black0); free(black1);
            free(gray0); free(gray1);
            return 0;
        }

        uint32_t threshold = compute_threshold(sw, params->half_w, iter);

        memset(black0, 0, r);
        memset(black1, 0, r);
        memset(gray0, 0, r);
        memset(gray1, 0, r);

        /* Step 1: Identify black and gray bits for block 0 (h0) */
        for (uint32_t j = 0; j < r; j++) {
            uint32_t upc = count_unsat(syndrome, h0, j, r);
            if (upc >= threshold) {
                black0[j] = 1;
            } else if (upc >= threshold - 1 && threshold > 1) {
                gray0[j] = 1;
            }
        }

        /* Step 1b: Identify black and gray bits for block 1 (h1) */
        for (uint32_t j = 0; j < r; j++) {
            uint32_t upc = count_unsat(syndrome, h1, j, r);
            if (upc >= threshold) {
                black1[j] = 1;
            } else if (upc >= threshold - 1 && threshold > 1) {
                gray1[j] = 1;
            }
        }

        /* Step 2: Flip black bits and update syndrome */
        int flipped = 0;
        for (uint32_t j = 0; j < r; j++) {
            if (black0[j]) {
                bit_flip(e0, j);
                update_syndrome(syndrome, h0, j, r);
                flipped = 1;
            }
        }
        for (uint32_t j = 0; j < r; j++) {
            if (black1[j]) {
                bit_flip(e1, j);
                update_syndrome(syndrome, h1, j, r);
                flipped = 1;
            }
        }

        /* Step 3: Flip gray bits that still have high UPC */
        for (uint32_t j = 0; j < r; j++) {
            if (gray0[j]) {
                uint32_t upc = count_unsat(syndrome, h0, j, r);
                if (upc >= threshold) {
                    bit_flip(e0, j);
                    update_syndrome(syndrome, h0, j, r);
                    flipped = 1;
                }
            }
        }
        for (uint32_t j = 0; j < r; j++) {
            if (gray1[j]) {
                uint32_t upc = count_unsat(syndrome, h1, j, r);
                if (upc >= threshold) {
                    bit_flip(e1, j);
                    update_syndrome(syndrome, h1, j, r);
                    flipped = 1;
                }
            }
        }

        if (!flipped) {
            /* No progress, decoding failed */
            break;
        }
    }

    /* Check final syndrome */
    uint32_t final_sw = popcount_vec(syndrome, r_words);
    int result = (final_sw == 0) ? 0 : -1;

    free(syndrome); free(black0); free(black1);
    free(gray0); free(gray1);
    return result;
}
