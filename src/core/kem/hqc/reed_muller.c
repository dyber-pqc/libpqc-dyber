/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC - Reed-Muller RM(1, 7) codec.
 *
 * RM(1, 7) encodes 8-bit messages into 128-bit codewords using the
 * first-order Reed-Muller code. Decoding uses the Walsh-Hadamard
 * transform (fast Green machine) to find the closest codeword.
 */

#include <string.h>
#include "hqc.h"
#include "hqc_params.h"

/* RM(1, 7): encodes 8 bits (1 + 7 information bits) into 2^7 = 128 bits */
#define RM_M     7
#define RM_N     128  /* = 2^7 */

/* ------------------------------------------------------------------ */
/* RM(1, 7) Encoding                                                    */
/*                                                                      */
/* The generator matrix G of RM(1, 7) has rows:                         */
/*   Row 0: all-ones vector (1, 1, 1, ..., 1)                         */
/*   Row i (1<=i<=7): indicator of bit i in position index              */
/*                                                                      */
/* codeword[j] = m_0 XOR (m_1 & j_0) XOR ... XOR (m_7 & j_6)         */
/* where j = (j_6, ..., j_0) is the binary expansion of position j.    */
/* ------------------------------------------------------------------ */

void hqc_rm_encode(uint8_t *codeword, uint8_t message_byte)
{
    /* 128-bit codeword stored as 16 bytes */
    memset(codeword, 0, RM_N / 8);

    for (uint32_t j = 0; j < RM_N; j++) {
        /* Compute inner product <message, (1, j_0, j_1, ..., j_6)> over GF(2) */
        uint8_t bit = (message_byte >> 7) & 1;  /* m_0: constant term */
        for (uint32_t i = 0; i < RM_M; i++) {
            bit ^= ((message_byte >> (RM_M - 1 - i)) & 1) & ((j >> i) & 1);
        }
        /* Set bit j of codeword */
        if (bit) {
            codeword[j / 8] |= (1u << (j % 8));
        }
    }
}

/* ------------------------------------------------------------------ */
/* Walsh-Hadamard Transform (in-place)                                  */
/*                                                                      */
/* Transforms a vector of length 2^m using the butterfly operation.     */
/* After transform, the position with maximum absolute value indicates  */
/* the closest RM(1,m) codeword.                                        */
/* ------------------------------------------------------------------ */

static void walsh_hadamard_transform(int32_t *v, uint32_t n)
{
    for (uint32_t h = 1; h < n; h <<= 1) {
        for (uint32_t i = 0; i < n; i += (h << 1)) {
            for (uint32_t j = i; j < i + h; j++) {
                int32_t x = v[j];
                int32_t y = v[j + h];
                v[j]     = x + y;
                v[j + h] = x - y;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* RM(1, 7) Decoding                                                    */
/*                                                                      */
/* Convert received 128-bit word to +/-1 representation, apply WHT,     */
/* find the index of maximum absolute value. This gives us the          */
/* affine function (and thus the original 8-bit message).               */
/* ------------------------------------------------------------------ */

uint8_t hqc_rm_decode(const uint8_t *codeword)
{
    int32_t transform[RM_N];

    /* Convert bits to +/-1 representation: 0 -> +1, 1 -> -1 */
    for (uint32_t j = 0; j < RM_N; j++) {
        int bit = (codeword[j / 8] >> (j % 8)) & 1;
        transform[j] = 1 - 2 * bit;
    }

    /* Apply Walsh-Hadamard transform */
    walsh_hadamard_transform(transform, RM_N);

    /* Find the position with the maximum absolute value */
    int32_t max_val = 0;
    uint32_t max_pos = 0;
    int max_sign = 1;

    for (uint32_t j = 0; j < RM_N; j++) {
        int32_t abs_val = transform[j] < 0 ? -transform[j] : transform[j];
        if (abs_val > max_val) {
            max_val = abs_val;
            max_pos = j;
            max_sign = (transform[j] > 0) ? 0 : 1;
        }
    }

    /*
     * Reconstruct the message byte.
     * max_pos gives bits m_1..m_7 (the linear part).
     * max_sign gives m_0 (the constant/affine bit).
     *
     * Message format: m_0 is the MSB (bit 7), m_1..m_7 follow.
     * max_pos bits are in order (j_0, j_1, ..., j_6) corresponding
     * to m_7, m_6, ..., m_1 in our message byte.
     */
    uint8_t message = 0;
    message |= (uint8_t)(max_sign << 7);  /* m_0 */
    for (uint32_t i = 0; i < RM_M; i++) {
        uint8_t bit = (max_pos >> i) & 1;
        message |= (uint8_t)(bit << (RM_M - 1 - i));
    }

    return message;
}
