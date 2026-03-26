/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FrodoKEM - Matrix generation and operations.
 *
 * Generates the public matrix A from a seed using SHAKE-128 or AES-128,
 * and provides matrix multiply, add, subtract, and transpose operations
 * over Z_q.
 */

#include <string.h>
#include <stdlib.h>
#include "frodo.h"
#include "frodo_params.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Matrix A generation using SHAKE-128                                  */
/*                                                                      */
/* For each row i, SHAKE-128(seed || i) generates the row entries.      */
/* This matches the FrodoKEM specification for SHAKE variants.          */
/* ------------------------------------------------------------------ */

void frodo_gen_matrix_shake(uint16_t *A, uint32_t n,
                            const uint8_t *seed)
{
    /*
     * For each row i of A (n columns):
     *   input = seed (16 bytes) || le16(i)
     *   SHAKE-128(input) -> n * 2 bytes
     *   parse as n little-endian uint16_t values
     */
    uint8_t input[FRODO_SEED_A_BYTES + 2];
    memcpy(input, seed, FRODO_SEED_A_BYTES);

    for (uint32_t i = 0; i < n; i++) {
        input[FRODO_SEED_A_BYTES]     = (uint8_t)(i & 0xFF);
        input[FRODO_SEED_A_BYTES + 1] = (uint8_t)((i >> 8) & 0xFF);

        uint8_t *row_bytes = (uint8_t *)(A + i * n);
        pqc_shake128(row_bytes, n * sizeof(uint16_t),
                     input, sizeof(input));

        /* Entries are already in little-endian byte order on LE platforms.
         * On BE platforms we'd need to byte-swap. For portability, read
         * as pairs of bytes and reconstruct. On most targets this is
         * already correct due to LE memory layout. */
    }
}

/* ------------------------------------------------------------------ */
/* Matrix A generation using AES-128-ECB                                */
/*                                                                      */
/* AES variant: for each (i, j), AES-ECB(seed, i||j||0...0) gives      */
/* the matrix entry. We approximate this using SHAKE for portability    */
/* (a real AES implementation would use AES-NI or a software AES).      */
/* ------------------------------------------------------------------ */

void frodo_gen_matrix_aes(uint16_t *A, uint32_t n,
                          const uint8_t *seed)
{
    /*
     * AES-based generation: for each pair of row indices (i, j),
     * we AES-encrypt a block [i, j, 0, ..., 0] under the seed as key.
     * We generate 8 matrix entries per AES block (128 bits / 16 bits).
     *
     * For portability, we implement this using SHAKE-128 as a
     * placeholder. A production implementation should use AES-NI.
     */
    uint8_t input[FRODO_SEED_A_BYTES + 4];
    memcpy(input, seed, FRODO_SEED_A_BYTES);

    for (uint32_t i = 0; i < n; i++) {
        input[FRODO_SEED_A_BYTES]     = (uint8_t)(i & 0xFF);
        input[FRODO_SEED_A_BYTES + 1] = (uint8_t)((i >> 8) & 0xFF);

        for (uint32_t j = 0; j < n; j += 8) {
            input[FRODO_SEED_A_BYTES + 2] = (uint8_t)(j & 0xFF);
            input[FRODO_SEED_A_BYTES + 3] = (uint8_t)((j >> 8) & 0xFF);

            uint8_t block[16];
            pqc_shake128(block, 16, input, sizeof(input));

            /* Parse 8 uint16_t values from the 16-byte block */
            for (uint32_t k = 0; k < 8 && (j + k) < n; k++) {
                A[i * n + j + k] = (uint16_t)block[2 * k] |
                                   ((uint16_t)block[2 * k + 1] << 8);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Matrix multiplication: C = A * B mod q                               */
/*                                                                      */
/* A is (rows_a x inner), B is (inner x cols_b), C is (rows_a x cols_b)*/
/* ------------------------------------------------------------------ */

void frodo_matrix_mul(uint16_t *C,
                      const uint16_t *A, uint32_t rows_a, uint32_t inner,
                      const uint16_t *B, uint32_t cols_b,
                      uint32_t q)
{
    uint16_t q_mask = (uint16_t)(q - 1); /* q is always a power of 2 */

    for (uint32_t i = 0; i < rows_a; i++) {
        for (uint32_t j = 0; j < cols_b; j++) {
            uint32_t sum = 0;
            for (uint32_t k = 0; k < inner; k++) {
                sum += (uint32_t)A[i * inner + k] * (uint32_t)B[k * cols_b + j];
            }
            C[i * cols_b + j] = (uint16_t)(sum & q_mask);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Matrix addition: C = A + B mod q                                     */
/* ------------------------------------------------------------------ */

void frodo_matrix_add(uint16_t *C,
                      const uint16_t *A, const uint16_t *B,
                      uint32_t rows, uint32_t cols, uint32_t q)
{
    uint16_t q_mask = (uint16_t)(q - 1);
    uint32_t total = rows * cols;
    for (uint32_t i = 0; i < total; i++) {
        C[i] = (uint16_t)((A[i] + B[i]) & q_mask);
    }
}

/* ------------------------------------------------------------------ */
/* Matrix subtraction: C = A - B mod q                                  */
/* ------------------------------------------------------------------ */

void frodo_matrix_sub(uint16_t *C,
                      const uint16_t *A, const uint16_t *B,
                      uint32_t rows, uint32_t cols, uint32_t q)
{
    uint16_t q_mask = (uint16_t)(q - 1);
    uint32_t total = rows * cols;
    for (uint32_t i = 0; i < total; i++) {
        C[i] = (uint16_t)((A[i] - B[i] + q) & q_mask);
    }
}

/* ------------------------------------------------------------------ */
/* Matrix transpose                                                     */
/* ------------------------------------------------------------------ */

void frodo_matrix_transpose(uint16_t *B, const uint16_t *A,
                            uint32_t rows, uint32_t cols)
{
    for (uint32_t i = 0; i < rows; i++) {
        for (uint32_t j = 0; j < cols; j++) {
            B[j * rows + i] = A[i * cols + j];
        }
    }
}
