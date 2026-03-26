/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * MAYO - Matrix operations over GF(16).
 *
 * All matrices are stored in row-major order with one GF(16) element
 * per uint8_t (unpacked representation) for clarity.
 */

#include <string.h>
#include <stdint.h>
#include "mayo.h"

/* ------------------------------------------------------------------ */
/* Matrix multiply: C[rows_a x cols_b] = A[rows_a x cols_a] * B[cols_a x cols_b] */
/* ------------------------------------------------------------------ */

void mayo_mat_mul(uint8_t *c, const uint8_t *a, const uint8_t *b,
                  int rows_a, int cols_a, int cols_b)
{
    int i, j, l;
    memset(c, 0, (size_t)rows_a * (size_t)cols_b);
    for (i = 0; i < rows_a; i++) {
        for (l = 0; l < cols_a; l++) {
            uint8_t a_il = a[i * cols_a + l];
            if (a_il == 0) continue;
            for (j = 0; j < cols_b; j++) {
                c[i * cols_b + j] = gf16_add(
                    c[i * cols_b + j],
                    gf16_mul(a_il, b[l * cols_b + j])
                );
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Matrix add: C = A + B (element-wise XOR in GF(16))                   */
/* ------------------------------------------------------------------ */

void mayo_mat_add(uint8_t *c, const uint8_t *a, const uint8_t *b,
                  int rows, int cols)
{
    int total = rows * cols;
    int i;
    for (i = 0; i < total; i++) {
        c[i] = gf16_add(a[i], b[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Gaussian elimination on an augmented matrix [rows x cols].           */
/* Operates in-place.  Returns 0 on success, -1 if singular.           */
/* The matrix is in row echelon form on output.                         */
/* ------------------------------------------------------------------ */

int mayo_mat_gauss_elim(uint8_t *mat, int rows, int cols)
{
    int pivot_row, pivot_col, i, j;
    pivot_col = 0;

    for (pivot_row = 0; pivot_row < rows && pivot_col < cols; pivot_row++) {
        /* Find a non-zero entry in this column at or below pivot_row */
        int found = -1;
        for (i = pivot_row; i < rows; i++) {
            if (mat[i * cols + pivot_col] != 0) {
                found = i;
                break;
            }
        }
        if (found < 0) {
            /* No pivot in this column; skip column, retry same row */
            pivot_col++;
            pivot_row--;
            continue;
        }

        /* Swap rows if needed */
        if (found != pivot_row) {
            for (j = 0; j < cols; j++) {
                uint8_t tmp = mat[pivot_row * cols + j];
                mat[pivot_row * cols + j] = mat[found * cols + j];
                mat[found * cols + j] = tmp;
            }
        }

        /* Scale pivot row so that the leading entry is 1 */
        uint8_t inv = gf16_inv(mat[pivot_row * cols + pivot_col]);
        for (j = pivot_col; j < cols; j++) {
            mat[pivot_row * cols + j] = gf16_mul(mat[pivot_row * cols + j], inv);
        }

        /* Eliminate all other rows */
        for (i = 0; i < rows; i++) {
            if (i == pivot_row) continue;
            uint8_t factor = mat[i * cols + pivot_col];
            if (factor == 0) continue;
            for (j = pivot_col; j < cols; j++) {
                mat[i * cols + j] = gf16_add(
                    mat[i * cols + j],
                    gf16_mul(factor, mat[pivot_row * cols + j])
                );
            }
        }
        pivot_col++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Matrix transpose                                                     */
/* ------------------------------------------------------------------ */

void mayo_mat_transpose(uint8_t *out, const uint8_t *in, int rows, int cols)
{
    int i, j;
    for (i = 0; i < rows; i++) {
        for (j = 0; j < cols; j++) {
            out[j * rows + i] = in[i * cols + j];
        }
    }
}
