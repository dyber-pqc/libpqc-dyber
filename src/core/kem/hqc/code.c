/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC - Concatenated code (Reed-Solomon tensor Reed-Muller).
 *
 * The tensor product code C = RS(n1, k) tensor RM(1, 7) encodes
 * k bytes of message into n1 * 128 bits. Each RS symbol (byte)
 * is further encoded by RM(1,7) into a 128-bit codeword.
 */

#include <string.h>
#include "hqc.h"
#include "hqc_params.h"

/* ------------------------------------------------------------------ */
/* Encode: message -> RS encode -> RM encode each symbol                */
/* ------------------------------------------------------------------ */

void hqc_code_encode(uint8_t *encoded, const uint8_t *message,
                     const hqc_params_t *params)
{
    uint32_t n1 = params->n1;
    uint32_t n2 = params->n2;
    uint32_t n2_bytes = n2 / 8;             /* total bytes per RS symbol block */
    uint32_t rm_bytes = HQC_RM_CODEWORD_BITS / 8; /* 16 bytes per RM codeword */
    uint32_t repeat = n2 / HQC_RM_CODEWORD_BITS;  /* repetition factor */
    uint8_t rs_codeword[HQC_MAX_N1];

    /* Step 1: Reed-Solomon encode (k bytes -> n1 bytes) */
    hqc_rs_encode(rs_codeword, message, params);

    /* Step 2: RM(1,7) encode each RS symbol, then repeat */
    memset(encoded, 0, n1 * n2_bytes);
    for (uint32_t i = 0; i < n1; i++) {
        uint8_t rm_codeword[16]; /* 128 bits = 16 bytes */
        hqc_rm_encode(rm_codeword, rs_codeword[i]);
        /* Repeat the RM codeword 'repeat' times within the n2-bit block */
        for (uint32_t r = 0; r < repeat; r++) {
            memcpy(encoded + i * n2_bytes + r * rm_bytes, rm_codeword, rm_bytes);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Decode: RM decode each block -> RS decode -> message                 */
/* ------------------------------------------------------------------ */

int hqc_code_decode(uint8_t *message, const uint8_t *encoded,
                    const hqc_params_t *params)
{
    uint32_t n1 = params->n1;
    uint32_t n2 = params->n2;
    uint32_t n2_bytes = n2 / 8;
    uint32_t rm_bytes = HQC_RM_CODEWORD_BITS / 8;
    uint32_t repeat = n2 / HQC_RM_CODEWORD_BITS;
    uint8_t rs_received[HQC_MAX_N1];

    /* Step 1: For each RS symbol block, sum the repeated RM codewords
     * (majority vote via soft decoding), then RM decode.
     * We accumulate in +/-1 representation across repetitions, then
     * convert back to hard bits for RM decode. */
    for (uint32_t i = 0; i < n1; i++) {
        if (repeat == 1) {
            /* No repetition, decode directly */
            rs_received[i] = hqc_rm_decode(encoded + i * n2_bytes);
        } else {
            /* Accumulate soft values across repetitions */
            int32_t soft[128];
            memset(soft, 0, sizeof(soft));
            for (uint32_t r = 0; r < repeat; r++) {
                const uint8_t *block = encoded + i * n2_bytes + r * rm_bytes;
                for (uint32_t b = 0; b < 128; b++) {
                    int bit = (block[b / 8] >> (b % 8)) & 1;
                    soft[b] += (1 - 2 * bit); /* 0->+1, 1->-1 */
                }
            }
            /* Convert back to hard bits for RM decoder */
            uint8_t combined[16];
            memset(combined, 0, 16);
            for (uint32_t b = 0; b < 128; b++) {
                /* majority: if soft <= 0, the bit is 1; otherwise 0 */
                if (soft[b] <= 0) {
                    combined[b / 8] |= (1u << (b % 8));
                }
            }
            rs_received[i] = hqc_rm_decode(combined);
        }
    }

    /* Step 2: Reed-Solomon decode (n1 bytes -> k bytes) */
    int rc = hqc_rs_decode(message, rs_received, params);

    return rc;
}
