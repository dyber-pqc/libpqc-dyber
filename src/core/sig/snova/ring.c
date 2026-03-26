/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SNOVA - Non-commutative ring operations.
 *
 * The ring R is the ring of l x l matrices over GF(16).
 * GF(16) = GF(2)[x] / (x^4 + x + 1).
 * Ring elements are stored as l*l arrays of uint8_t (one GF(16) per byte).
 */

#include <string.h>
#include <stdint.h>
#include "snova.h"

/* ------------------------------------------------------------------ */
/* GF(16) multiplication table (same polynomial as MAYO)                */
/* ------------------------------------------------------------------ */

static const uint8_t snova_gf16_mul_tab[16][16] = {
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    { 0, 2, 4, 6, 8,10,12,14, 3, 1, 7, 5,11, 9,15,13},
    { 0, 3, 6, 5,12,15,10, 9,11, 8,13,14, 7, 4, 1, 2},
    { 0, 4, 8,12, 3, 7,11,15, 6, 2,14,10, 5, 1,13, 9},
    { 0, 5,10,15, 7, 2,13, 8,14,11, 4, 1, 9,12, 3, 6},
    { 0, 6,12,10,11,13, 7, 1, 5, 3, 9,15,14, 8, 2, 4},
    { 0, 7,14, 9,15, 8, 1, 6,13,10, 3, 4, 2, 5,12,11},
    { 0, 8, 3,11, 6,14, 5,13,12, 4,15, 7,10, 2, 9, 1},
    { 0, 9, 1, 8, 2,11, 3,10, 4,13, 5,12, 6,15, 7,14},
    { 0,10, 7,13,14, 4, 9, 3,15, 5, 8, 2, 1,11, 6,12},
    { 0,11, 5,14,10, 1,15, 4, 7,12, 2, 9,13, 6, 8, 3},
    { 0,12,11, 7, 5, 9,14, 2,10, 6, 1,13,15, 3, 4, 8},
    { 0,13, 9, 4, 1,12, 8, 5, 2,15,11, 6, 3,14,10, 7},
    { 0,14,15, 1,13, 3, 2,12, 9, 7, 6, 8, 4,10,11, 5},
    { 0,15,13, 2, 9, 6, 4,11, 1,14,12, 3, 8, 7, 5,10},
};

static const uint8_t snova_gf16_inv_tab[16] = {
    0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8
};

uint8_t snova_gf16_add(uint8_t a, uint8_t b)
{
    return (a ^ b) & 0x0F;
}

uint8_t snova_gf16_mul(uint8_t a, uint8_t b)
{
    return snova_gf16_mul_tab[a & 0x0F][b & 0x0F];
}

uint8_t snova_gf16_inv(uint8_t a)
{
    return snova_gf16_inv_tab[a & 0x0F];
}

/* ------------------------------------------------------------------ */
/* Ring element operations (l x l matrices over GF(16))                 */
/* ------------------------------------------------------------------ */

void snova_ring_zero(uint8_t *a, int l)
{
    memset(a, 0, (size_t)l * (size_t)l);
}

void snova_ring_identity(uint8_t *a, int l)
{
    int i;
    memset(a, 0, (size_t)l * (size_t)l);
    for (i = 0; i < l; i++) {
        a[i * l + i] = 1;
    }
}

/* C = A + B in the ring (element-wise XOR) */
void snova_ring_add(uint8_t *c, const uint8_t *a, const uint8_t *b, int l)
{
    int i;
    int sz = l * l;
    for (i = 0; i < sz; i++) {
        c[i] = snova_gf16_add(a[i], b[i]);
    }
}

/* C = A * B in the ring (matrix multiplication over GF(16)) */
void snova_ring_mul(uint8_t *c, const uint8_t *a, const uint8_t *b, int l)
{
    int i, j, k;
    uint8_t tmp[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];

    memset(tmp, 0, (size_t)l * (size_t)l);
    for (i = 0; i < l; i++) {
        for (k = 0; k < l; k++) {
            uint8_t a_ik = a[i * l + k];
            if (a_ik == 0) continue;
            for (j = 0; j < l; j++) {
                tmp[i * l + j] = snova_gf16_add(
                    tmp[i * l + j],
                    snova_gf16_mul(a_ik, b[k * l + j])
                );
            }
        }
    }
    memcpy(c, tmp, (size_t)l * (size_t)l);
}

/*
 * Ring inverse via Gauss-Jordan on the l x l matrix over GF(16).
 * Returns 0 on success, -1 if singular.
 */
int snova_ring_inv(uint8_t *out, const uint8_t *in, int l)
{
    int i, j, k;
    uint8_t aug[PQC_SNOVA_MAX_L * (2 * PQC_SNOVA_MAX_L)];
    int cols = 2 * l;

    /* Build augmented matrix [in | I] */
    memset(aug, 0, (size_t)l * (size_t)cols);
    for (i = 0; i < l; i++) {
        for (j = 0; j < l; j++) {
            aug[i * cols + j] = in[i * l + j];
        }
        aug[i * cols + l + i] = 1;
    }

    /* Gauss-Jordan elimination */
    for (k = 0; k < l; k++) {
        /* Find pivot */
        int pivot = -1;
        for (i = k; i < l; i++) {
            if (aug[i * cols + k] != 0) {
                pivot = i;
                break;
            }
        }
        if (pivot < 0) return -1;

        /* Swap rows */
        if (pivot != k) {
            for (j = 0; j < cols; j++) {
                uint8_t tmp = aug[k * cols + j];
                aug[k * cols + j] = aug[pivot * cols + j];
                aug[pivot * cols + j] = tmp;
            }
        }

        /* Scale pivot row */
        uint8_t inv = snova_gf16_inv(aug[k * cols + k]);
        for (j = k; j < cols; j++) {
            aug[k * cols + j] = snova_gf16_mul(aug[k * cols + j], inv);
        }

        /* Eliminate column */
        for (i = 0; i < l; i++) {
            if (i == k) continue;
            uint8_t factor = aug[i * cols + k];
            if (factor == 0) continue;
            for (j = k; j < cols; j++) {
                aug[i * cols + j] = snova_gf16_add(
                    aug[i * cols + j],
                    snova_gf16_mul(factor, aug[k * cols + j])
                );
            }
        }
    }

    /* Extract inverse from right half */
    for (i = 0; i < l; i++) {
        for (j = 0; j < l; j++) {
            out[i * l + j] = aug[i * cols + l + j];
        }
    }

    return 0;
}
