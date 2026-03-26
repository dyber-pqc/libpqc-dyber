/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SNOVA - Block matrix operations.
 *
 * Operations on matrices whose entries are ring elements (l x l
 * matrices over GF(16)).  Each ring element occupies l*l bytes.
 */

#include <string.h>
#include <stdint.h>
#include "snova.h"
#include "pqc/common.h"

/* Size of a single ring element in bytes */
#define RING_SZ(l) ((size_t)(l) * (size_t)(l))

/* ------------------------------------------------------------------ */
/* Block matrix multiply:                                               */
/* C[rows_a x cols_b] = A[rows_a x cols_a] * B[cols_a x cols_b]       */
/* Each entry is a ring element of size l*l.                            */
/* ------------------------------------------------------------------ */

void snova_block_mat_mul(uint8_t *C, const uint8_t *A, const uint8_t *B,
                         int rows_a, int cols_a, int cols_b, int l)
{
    int i, j, k;
    size_t rsz = RING_SZ(l);
    uint8_t tmp[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
    uint8_t prod[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];

    /* Zero C */
    memset(C, 0, (size_t)rows_a * (size_t)cols_b * rsz);

    for (i = 0; i < rows_a; i++) {
        for (k = 0; k < cols_a; k++) {
            const uint8_t *a_ik = A + ((size_t)i * (size_t)cols_a + (size_t)k) * rsz;
            /* Check if a_ik is zero */
            int all_zero = 1;
            {
                size_t s;
                for (s = 0; s < rsz; s++) {
                    if (a_ik[s] != 0) { all_zero = 0; break; }
                }
            }
            if (all_zero) continue;

            for (j = 0; j < cols_b; j++) {
                const uint8_t *b_kj = B + ((size_t)k * (size_t)cols_b + (size_t)j) * rsz;
                uint8_t *c_ij = C + ((size_t)i * (size_t)cols_b + (size_t)j) * rsz;

                snova_ring_mul(prod, a_ik, b_kj, l);
                snova_ring_add(tmp, c_ij, prod, l);
                memcpy(c_ij, tmp, rsz);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Block Gaussian elimination on augmented block matrix [rows x cols].  */
/* Each entry is a ring element.  Operates in-place.                    */
/* Returns 0 on success, -1 if a ring element is singular.              */
/* ------------------------------------------------------------------ */

int snova_block_gauss_elim(uint8_t *mat, int rows, int cols, int l)
{
    int pivot_row, pivot_col, i, j;
    size_t rsz = RING_SZ(l);
    uint8_t inv_elem[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
    uint8_t prod[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
    uint8_t tmp[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];

    pivot_col = 0;

    for (pivot_row = 0; pivot_row < rows && pivot_col < cols; pivot_row++) {
        /* Find non-zero (invertible) pivot in this column */
        int found = -1;
        for (i = pivot_row; i < rows; i++) {
            const uint8_t *entry = mat + ((size_t)i * (size_t)cols + (size_t)pivot_col) * rsz;
            /* Check if invertible (non-zero determinant) */
            if (snova_ring_inv(inv_elem, entry, l) == 0) {
                found = i;
                break;
            }
        }
        if (found < 0) {
            pivot_col++;
            pivot_row--;
            continue;
        }

        /* Swap rows */
        if (found != pivot_row) {
            for (j = 0; j < cols; j++) {
                size_t off_p = ((size_t)pivot_row * (size_t)cols + (size_t)j) * rsz;
                size_t off_f = ((size_t)found * (size_t)cols + (size_t)j) * rsz;
                memcpy(tmp, mat + off_p, rsz);
                memcpy(mat + off_p, mat + off_f, rsz);
                memcpy(mat + off_f, tmp, rsz);
            }
        }

        /* Compute inverse of the pivot element */
        {
            const uint8_t *piv = mat + ((size_t)pivot_row * (size_t)cols + (size_t)pivot_col) * rsz;
            snova_ring_inv(inv_elem, piv, l);
        }

        /* Scale pivot row: row[j] = inv_elem * row[j] */
        for (j = pivot_col; j < cols; j++) {
            uint8_t *entry = mat + ((size_t)pivot_row * (size_t)cols + (size_t)j) * rsz;
            snova_ring_mul(tmp, inv_elem, entry, l);
            memcpy(entry, tmp, rsz);
        }

        /* Eliminate other rows */
        for (i = 0; i < rows; i++) {
            if (i == pivot_row) continue;
            uint8_t *factor_entry = mat + ((size_t)i * (size_t)cols + (size_t)pivot_col) * rsz;

            /* Check if factor is zero */
            int all_zero = 1;
            {
                size_t s;
                for (s = 0; s < rsz; s++) {
                    if (factor_entry[s] != 0) { all_zero = 0; break; }
                }
            }
            if (all_zero) continue;

            uint8_t factor[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
            memcpy(factor, factor_entry, rsz);

            for (j = pivot_col; j < cols; j++) {
                uint8_t *row_ij = mat + ((size_t)i * (size_t)cols + (size_t)j) * rsz;
                const uint8_t *row_pj = mat + ((size_t)pivot_row * (size_t)cols + (size_t)j) * rsz;
                snova_ring_mul(prod, factor, row_pj, l);
                snova_ring_add(tmp, row_ij, prod, l);
                memcpy(row_ij, tmp, rsz);
            }
        }
        pivot_col++;
    }
    return 0;
}
