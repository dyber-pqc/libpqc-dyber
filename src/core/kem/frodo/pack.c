/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FrodoKEM - Matrix packing/unpacking.
 *
 * Packs arrays of log_q-bit coefficients into contiguous byte arrays
 * and unpacks them back. Used for serializing public keys and
 * ciphertexts.
 */

#include <string.h>
#include "frodo.h"
#include "frodo_params.h"

/* ------------------------------------------------------------------ */
/* Pack: n_elems values of log_q bits each into a byte array            */
/*                                                                      */
/* Values are packed MSB-first into a bit stream, then stored in bytes. */
/* ------------------------------------------------------------------ */

void frodo_pack(uint8_t *out, const uint16_t *in,
                uint32_t n_elems, uint32_t log_q)
{
    uint32_t out_bytes = (n_elems * log_q + 7) / 8;
    memset(out, 0, out_bytes);

    uint32_t bit_pos = 0;
    uint16_t mask = (uint16_t)((1u << log_q) - 1);

    for (uint32_t i = 0; i < n_elems; i++) {
        uint16_t val = in[i] & mask;

        /* Pack log_q bits of val starting at bit_pos */
        for (int b = (int)log_q - 1; b >= 0; b--) {
            uint32_t byte_idx = bit_pos / 8;
            uint32_t bit_idx  = 7 - (bit_pos % 8); /* MSB first within byte */
            if ((val >> b) & 1) {
                out[byte_idx] |= (uint8_t)(1u << bit_idx);
            }
            bit_pos++;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Unpack: byte array -> n_elems values of log_q bits each              */
/* ------------------------------------------------------------------ */

void frodo_unpack(uint16_t *out, const uint8_t *in,
                  uint32_t n_elems, uint32_t log_q)
{
    uint32_t bit_pos = 0;

    for (uint32_t i = 0; i < n_elems; i++) {
        uint16_t val = 0;
        for (uint32_t b = 0; b < log_q; b++) {
            uint32_t byte_idx = bit_pos / 8;
            uint32_t bit_idx  = 7 - (bit_pos % 8);
            val <<= 1;
            val |= (uint16_t)((in[byte_idx] >> bit_idx) & 1);
            bit_pos++;
        }
        out[i] = val;
    }
}

/* ------------------------------------------------------------------ */
/* Message encoding                                                     */
/*                                                                      */
/* Encode len_mu_bits of message into an n_bar x n_bar matrix.         */
/* Each B bits of the message map to one matrix entry, scaled by q/2^B. */
/* ------------------------------------------------------------------ */

void frodo_encode(uint16_t *out, const uint8_t *msg,
                  uint32_t len_mu_bits, uint32_t b, uint32_t q)
{
    uint32_t n_bar = FRODO_N_BAR;
    uint32_t n_elems = n_bar * n_bar;
    uint32_t shift = (q == 0) ? 0 : 0;

    /* q is a power of 2: log_q = log2(q). scale = q / 2^b */
    uint32_t log_q = 0;
    {
        uint32_t qq = q;
        while (qq > 1) { qq >>= 1; log_q++; }
    }
    uint32_t scale_shift = log_q - b;

    memset(out, 0, n_elems * sizeof(uint16_t));
    (void)shift;

    /* Extract B bits at a time from the message */
    uint32_t bit_idx = 0;
    for (uint32_t i = 0; i < n_elems && bit_idx < len_mu_bits; i++) {
        uint16_t val = 0;
        for (uint32_t j = 0; j < b && bit_idx < len_mu_bits; j++) {
            uint32_t byte_pos = bit_idx / 8;
            uint32_t bit_pos  = bit_idx % 8;
            val |= (uint16_t)(((msg[byte_pos] >> bit_pos) & 1) << j);
            bit_idx++;
        }
        out[i] = (uint16_t)(val << scale_shift);
    }
}

/* ------------------------------------------------------------------ */
/* Message decoding                                                     */
/*                                                                      */
/* Decode n_bar x n_bar matrix back to message bits by rounding.        */
/* ------------------------------------------------------------------ */

void frodo_decode(uint8_t *msg, const uint16_t *in,
                  uint32_t len_mu_bits, uint32_t b, uint32_t q)
{
    uint32_t n_bar = FRODO_N_BAR;
    uint32_t n_elems = n_bar * n_bar;
    uint32_t msg_bytes = (len_mu_bits + 7) / 8;

    /* scale = q / 2^b, half = scale / 2 */
    uint32_t log_q = 0;
    {
        uint32_t qq = q;
        while (qq > 1) { qq >>= 1; log_q++; }
    }
    uint32_t scale_shift = log_q - b;
    uint16_t q_mask = (uint16_t)(q - 1);

    memset(msg, 0, msg_bytes);

    uint32_t bit_idx = 0;
    for (uint32_t i = 0; i < n_elems && bit_idx < len_mu_bits; i++) {
        /* Round: add half a scale unit, then shift right */
        uint16_t val = in[i] & q_mask;
        val = (uint16_t)((val + (1u << (scale_shift - 1))) >> scale_shift);
        val &= (uint16_t)((1u << b) - 1);

        /* Extract B bits and place into message */
        for (uint32_t j = 0; j < b && bit_idx < len_mu_bits; j++) {
            if ((val >> j) & 1) {
                msg[bit_idx / 8] |= (uint8_t)(1u << (bit_idx % 8));
            }
            bit_idx++;
        }
    }
}
