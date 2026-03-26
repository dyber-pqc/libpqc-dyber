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
    uint32_t n2_bytes = HQC_RM_CODEWORD_BITS / 8; /* 16 bytes per RM codeword */
    uint8_t rs_codeword[HQC_MAX_N1];

    /* Step 1: Reed-Solomon encode (k bytes -> n1 bytes) */
    hqc_rs_encode(rs_codeword, message, params);

    /* Step 2: RM(1,7) encode each RS symbol */
    memset(encoded, 0, n1 * n2_bytes);
    for (uint32_t i = 0; i < n1; i++) {
        hqc_rm_encode(encoded + i * n2_bytes, rs_codeword[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Decode: RM decode each block -> RS decode -> message                 */
/* ------------------------------------------------------------------ */

int hqc_code_decode(uint8_t *message, const uint8_t *encoded,
                    const hqc_params_t *params)
{
    uint32_t n1 = params->n1;
    uint32_t k  = params->k;
    uint32_t n2_bytes = HQC_RM_CODEWORD_BITS / 8;
    uint8_t rs_received[HQC_MAX_N1];

    /* Step 1: RM(1,7) decode each block to recover RS symbols */
    for (uint32_t i = 0; i < n1; i++) {
        rs_received[i] = hqc_rm_decode(encoded + i * n2_bytes);
    }

    /* Step 2: Reed-Solomon decode (n1 bytes -> k bytes) */
    int rc = hqc_rs_decode(message, rs_received, params);

    return rc;
}
