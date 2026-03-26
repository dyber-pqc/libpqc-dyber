/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU Prime - Encoding/decoding.
 *
 * Rq encoding: variable-length encoding of coefficients mod q.
 *   Each coefficient is in [-(q-1)/2, (q-1)/2], stored as unsigned in [0, q-1].
 *   Uses rounded arithmetic encoding for compact representation.
 *
 * Small encoding: coefficients in {-1, 0, 1} packed as trits (5 per byte).
 */

#include <string.h>
#include "ntruprime.h"

/* ------------------------------------------------------------------ */
/* Rq encoding: simple byte-level encoding                             */
/* ------------------------------------------------------------------ */

/*
 * Encode Rq polynomial. Coefficients are in [-(q-1)/2, (q-1)/2].
 * Map to unsigned: u = c + (q-1)/2, so u is in [0, q-1].
 *
 * For rounded coefficients (multiples of 3), we can encode more
 * compactly. Each rounded coefficient is in the set
 * {-(q-1)/2, -(q-1)/2+3, ..., (q-1)/2}.
 * Number of distinct values: ceil(q/3).
 *
 * We use a simplified encoding: pack each value as ceil(log2(q)) bits.
 */
void sntrup_encode_rq(uint8_t *out, const rq_poly_t *a,
                      const sntrup_params_t *p)
{
    int pp = p->p;
    int q = p->q;
    int half = (q - 1) / 2;

    /* Two bytes per coefficient (simple encoding) */
    for (int i = 0; i < pp; i++) {
        uint16_t u = (uint16_t)(a->coeffs[i] + half);
        out[2 * i] = (uint8_t)(u & 0xFF);
        out[2 * i + 1] = (uint8_t)(u >> 8);
    }
}

void sntrup_decode_rq(rq_poly_t *r, const uint8_t *in,
                      const sntrup_params_t *p)
{
    int pp = p->p;
    int q = p->q;
    int half = (q - 1) / 2;

    rq_zero(r);

    for (int i = 0; i < pp; i++) {
        uint16_t u = (uint16_t)((uint16_t)in[2 * i] | ((uint16_t)in[2 * i + 1] << 8));
        if (u >= (uint16_t)q)
            u = (uint16_t)(q - 1);
        r->coeffs[i] = (int16_t)((int)u - half);
    }
}

/* ------------------------------------------------------------------ */
/* Small encoding: trits packed 5 per byte                             */
/* ------------------------------------------------------------------ */

/*
 * Encode small polynomial with coefficients in {-1, 0, 1}.
 * Map: -1 -> 2, 0 -> 0, 1 -> 1.
 * Pack 5 trits per byte: t0 + 3*t1 + 9*t2 + 27*t3 + 81*t4.
 * 3^5 = 243 < 256, so this fits in a byte.
 */
void sntrup_encode_small(uint8_t *out, const r3_poly_t *a, int pp)
{
    int full_blocks = pp / 5;
    int remaining = pp % 5;
    int out_idx = 0;

    for (int i = 0; i < full_blocks; i++) {
        int base = i * 5;
        uint8_t val = 0;
        uint8_t mul = 1;
        for (int j = 0; j < 5; j++) {
            int c = a->coeffs[base + j];
            if (c < 0) c += 3; /* -1 -> 2 */
            val += (uint8_t)(c * mul);
            mul *= 3;
        }
        out[out_idx++] = val;
    }

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

void sntrup_decode_small(r3_poly_t *r, const uint8_t *in, int pp)
{
    int full_blocks = pp / 5;
    int remaining = pp % 5;
    int in_idx = 0;

    r3_zero(r);

    for (int i = 0; i < full_blocks; i++) {
        int base = i * 5;
        uint8_t val = in[in_idx++];
        for (int j = 0; j < 5; j++) {
            int c = val % 3;
            val /= 3;
            if (c == 2) c = -1;
            r->coeffs[base + j] = (int8_t)c;
        }
    }

    if (remaining > 0) {
        uint8_t val = in[in_idx];
        for (int j = 0; j < remaining; j++) {
            int c = val % 3;
            val /= 3;
            if (c == 2) c = -1;
            r->coeffs[full_blocks * 5 + j] = (int8_t)c;
        }
    }
}
