/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece - Encryption.
 *
 * Generates a random error vector of Hamming weight t, then computes
 * the syndrome s = H * e using the public key in systematic form.
 */

#include <stdlib.h>
#include <string.h>

#include "mceliece.h"
#include "pqc/rand.h"
#include "core/common/hash/sha3.h"

/* Portable replacement for __builtin_parity */
static inline int portable_parity(unsigned int x)
{
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return (int)(x & 1);
}

/* ------------------------------------------------------------------ */
/* Generate random weight-t error vector                               */
/* ------------------------------------------------------------------ */

/*
 * Fisher-Yates based generation of a random weight-t subset of {0..n-1}.
 */
static int gen_error_vector(uint8_t *e, int n, int t)
{
    int e_bytes = (n + 7) / 8;
    memset(e, 0, (size_t)e_bytes);

    /* Generate t distinct random positions in [0, n) */
    uint16_t *positions = (uint16_t *)calloc((size_t)n, sizeof(uint16_t));
    if (!positions)
        return -1;

    for (int i = 0; i < n; i++)
        positions[i] = (uint16_t)i;

    uint8_t rbuf[4];
    for (int i = 0; i < t; i++) {
        /* Pick random index in [i, n) */
        if (pqc_randombytes(rbuf, 4) != PQC_OK) {
            free(positions);
            return -1;
        }
        uint32_t r = ((uint32_t)rbuf[0]) |
                     ((uint32_t)rbuf[1] << 8) |
                     ((uint32_t)rbuf[2] << 16) |
                     ((uint32_t)rbuf[3] << 24);
        int j = i + (int)(r % (uint32_t)(n - i));

        /* Swap positions[i] and positions[j] */
        uint16_t tmp = positions[i];
        positions[i] = positions[j];
        positions[j] = tmp;
    }

    /* Set the chosen positions */
    for (int i = 0; i < t; i++) {
        int pos = positions[i];
        e[pos >> 3] |= (uint8_t)(1u << (pos & 7));
    }

    free(positions);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Encryption: compute syndrome                                        */
/* ------------------------------------------------------------------ */

/*
 * The public key T is the systematic part of H, stored as mt rows
 * of ceil(k/8) bytes each. H = [I_mt | T].
 *
 * The syndrome s = H * e^T. Since H = [I | T]:
 *   s = e_left + T * e_right
 * where e_left is the first mt bits and e_right is the last k bits.
 *
 * The ciphertext is s (mt bits packed into ct_bytes).
 */
int mceliece_encrypt(uint8_t *ct, uint8_t *e,
                     const uint8_t *pk, const mceliece_params_t *p)
{
    int mt = p->m * p->t;
    int n = p->n;
    int k = p->k;
    int ct_bytes = (mt + 7) / 8;
    int pk_row_bytes = (k + 7) / 8;

    /* Generate random weight-t error vector */
    if (gen_error_vector(e, n, p->t) != 0)
        return -1;

    /* Compute syndrome: s = H * e */
    memset(ct, 0, (size_t)ct_bytes);

    /* s = e_left (first mt bits of e) */
    for (int i = 0; i < mt; i++) {
        if (e[i >> 3] & (1u << (i & 7))) {
            ct[i >> 3] ^= (uint8_t)(1u << (i & 7));
        }
    }

    /* s += T * e_right */
    for (int row = 0; row < mt; row++) {
        uint8_t bit = 0;
        const uint8_t *pk_row = pk + row * pk_row_bytes;

        /* Dot product of pk_row with e_right (bits mt..n-1 of e) */
        for (int byte = 0; byte < pk_row_bytes; byte++) {
            int e_byte_idx = (mt >> 3) + byte;
            /* Handle the first partial byte carefully */
            uint8_t e_val;
            int shift = mt & 7;
            if (shift == 0) {
                e_val = e[e_byte_idx];
            } else {
                e_val = (uint8_t)(e[e_byte_idx] >> shift);
                if (e_byte_idx + 1 < (n + 7) / 8) {
                    e_val |= (uint8_t)(e[e_byte_idx + 1] << (8 - shift));
                }
            }

            bit ^= (uint8_t)portable_parity((unsigned int)(pk_row[byte] & e_val));
        }

        if (bit & 1) {
            ct[row >> 3] ^= (uint8_t)(1u << (row & 7));
        }
    }

    return 0;
}
