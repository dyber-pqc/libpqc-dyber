/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU - Polynomial packing/unpacking.
 *
 * Pack coefficients in Z_q as ceil(log2(q))-bit values.
 * Pack ternary coefficients (trits) five per byte.
 */

#include <string.h>
#include "ntru.h"

/* ------------------------------------------------------------------ */
/* Pack/unpack mod-q polynomial                                        */
/* ------------------------------------------------------------------ */

/*
 * Pack n coefficients of log_q bits each into a byte array.
 * Coefficients are stored as unsigned in [0, q).
 */
void ntru_pack_poly_q(uint8_t *out, const ntru_poly_t *a,
                      const ntru_params_t *p)
{
    int n = p->n;
    int log_q = p->log_q;
    int q = p->q;
    int mask = q - 1;
    int bit_pos = 0;

    /* Compute output size: ceil(n * log_q / 8) */
    int total_bits = n * log_q;
    int total_bytes = (total_bits + 7) / 8;
    memset(out, 0, (size_t)total_bytes);

    for (int i = 0; i < n; i++) {
        uint16_t val = (uint16_t)(a->coeffs[i] & mask);

        for (int b = 0; b < log_q; b++) {
            if ((val >> b) & 1) {
                out[bit_pos >> 3] |= (uint8_t)(1u << (bit_pos & 7));
            }
            bit_pos++;
        }
    }
}

void ntru_unpack_poly_q(ntru_poly_t *r, const uint8_t *in,
                        const ntru_params_t *p)
{
    int n = p->n;
    int log_q = p->log_q;
    int bit_pos = 0;

    ntru_poly_zero(r);

    for (int i = 0; i < n; i++) {
        uint16_t val = 0;
        for (int b = 0; b < log_q; b++) {
            if (in[bit_pos >> 3] & (1u << (bit_pos & 7))) {
                val |= (uint16_t)(1u << b);
            }
            bit_pos++;
        }
        r->coeffs[i] = (int16_t)val;
    }
}

/* ------------------------------------------------------------------ */
/* Pack/unpack ternary (mod 3) polynomials                             */
/* ------------------------------------------------------------------ */

/*
 * Pack ternary coefficients: 5 trits per byte.
 * Encoding: trit in {0, 1, 2} where -1 is stored as 2.
 * 5 trits fit in one byte since 3^5 = 243 < 256.
 */
void ntru_pack_trits(uint8_t *out, const ntru_poly_t *a, int n)
{
    int full_blocks = n / 5;
    int remaining = n % 5;
    int out_idx = 0;

    for (int i = 0; i < full_blocks; i++) {
        int base = i * 5;
        uint8_t val = 0;
        uint8_t mul = 1;
        for (int j = 0; j < 5; j++) {
            int c = a->coeffs[base + j];
            /* Map {-1, 0, 1} to {2, 0, 1} */
            if (c < 0) c += 3;
            val += (uint8_t)(c * mul);
            mul *= 3;
        }
        out[out_idx++] = val;
    }

    /* Handle remaining trits */
    if (remaining > 0) {
        uint8_t val = 0;
        uint8_t mul = 1;
        for (int j = 0; j < remaining; j++) {
            int c = a->coeffs[full_blocks * 5 + j];
            if (c < 0) c += 3;
            val += (uint8_t)(c * mul);
            mul *= 3;
        }
        out[out_idx++] = val;
    }
}

void ntru_unpack_trits(ntru_poly_t *r, const uint8_t *in, int n)
{
    int full_blocks = n / 5;
    int remaining = n % 5;
    int in_idx = 0;

    ntru_poly_zero(r);

    for (int i = 0; i < full_blocks; i++) {
        int base = i * 5;
        uint8_t val = in[in_idx++];
        for (int j = 0; j < 5; j++) {
            int c = val % 3;
            val /= 3;
            if (c == 2) c = -1;
            r->coeffs[base + j] = (int16_t)c;
        }
    }

    if (remaining > 0) {
        uint8_t val = in[in_idx];
        for (int j = 0; j < remaining; j++) {
            int c = val % 3;
            val /= 3;
            if (c == 2) c = -1;
            r->coeffs[full_blocks * 5 + j] = (int16_t)c;
        }
    }
}
