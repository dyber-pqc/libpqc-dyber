/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece - Benes network for applying permutations.
 *
 * A Benes network of size 2^lgs has (2*lgs - 1) layers, each with
 * 2^(lgs-1) conditional swaps. The control bits determine which pairs
 * are swapped at each layer.
 */

#include <string.h>
#include "mceliece.h"

/* ------------------------------------------------------------------ */
/* Single layer of the Benes network                                   */
/* ------------------------------------------------------------------ */

/*
 * Apply one layer of conditional swaps.
 * bits:  control bits for this layer, packed as bytes.
 * r:     data array of 1 << lgs elements (each element is one byte slot,
 *        but we operate on uint64_t for efficiency).
 * lgs:   log2 of the number of elements.
 * layer: which layer (0 to 2*lgs - 2).
 */
static void benes_layer(const uint8_t *bits, uint8_t *r, int lgs, int layer)
{
    int n = 1 << lgs;
    int half = n >> 1;
    int stride;
    int bit_idx = 0;

    /*
     * Layer determines the stride:
     * - Layers 0..lgs-1 use stride 2^(lgs-1-layer)  (first half, outside-in)
     * - Layers lgs..2*lgs-2 use stride 2^(layer-lgs) (second half, inside-out)
     */
    if (layer < lgs) {
        stride = 1 << (lgs - 1 - layer);
    } else {
        stride = 1 << (layer - lgs + 1);
    }

    /* Note: for the middle layer (layer == lgs-1), stride == 1 */

    for (int i = 0; i < n; i++) {
        int partner;
        int blk = i / (2 * stride);
        int pos = i % (2 * stride);

        if (pos < stride) {
            partner = i + stride;
        } else {
            continue; /* only process the lower element */
        }

        if (partner >= n)
            continue;

        /* Get control bit */
        int cb_byte = bit_idx >> 3;
        int cb_bit = bit_idx & 7;
        int swap = (bits[cb_byte] >> cb_bit) & 1;
        bit_idx++;

        (void)blk;

        if (swap) {
            uint8_t tmp = r[i];
            r[i] = r[partner];
            r[partner] = tmp;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void benes_apply(const uint8_t *bits, uint8_t *r, int lgs, int rev)
{
    int layers = 2 * lgs - 1;
    int half = 1 << (lgs - 1);
    /* Each layer has half conditional swaps = half control bits = ceil(half/8) bytes */
    int bits_per_layer = (half + 7) / 8;

    if (rev) {
        /* Reverse: apply layers in reverse order */
        for (int layer = layers - 1; layer >= 0; layer--) {
            benes_layer(bits + layer * bits_per_layer, r, lgs, layer);
        }
    } else {
        for (int layer = 0; layer < layers; layer++) {
            benes_layer(bits + layer * bits_per_layer, r, lgs, layer);
        }
    }
}
