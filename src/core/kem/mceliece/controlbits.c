/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece - Control bits for Benes network.
 *
 * Given a permutation pi of {0, ..., 2^lgs - 1}, compute the control bits
 * for a Benes network that realizes pi. Uses the standard recursive
 * decomposition: split the permutation into two sub-permutations of half
 * the size, each feeding into the top/bottom sub-network, with outer and
 * inner switching layers.
 */

#include <stdlib.h>
#include <string.h>
#include "mceliece.h"

/* ------------------------------------------------------------------ */
/* Helper: set a single bit in the control-bit array                   */
/* ------------------------------------------------------------------ */

static void set_cbit(uint8_t *bits, int pos, int val)
{
    int byte_idx = pos >> 3;
    int bit_idx = pos & 7;
    if (val)
        bits[byte_idx] |= (uint8_t)(1u << bit_idx);
    else
        bits[byte_idx] &= (uint8_t)~(1u << bit_idx);
}

/* ------------------------------------------------------------------ */
/* Recursive control-bit computation                                   */
/* ------------------------------------------------------------------ */

/*
 * Compute control bits for a Benes network that realizes permutation pi.
 *
 * The Benes network for n = 2^lgs elements has 2*lgs - 1 layers.
 * We decompose into:
 *   - An outer input layer (stride n/2)
 *   - A recursive top sub-network on elements {0..n/2-1}
 *   - A recursive bottom sub-network on elements {n/2..n-1}
 *   - An outer output layer (stride n/2)
 *
 * For lgs == 1, a single swap layer suffices.
 */
static void cbits_rec(uint8_t *out, const uint16_t *pi, int lgs,
                       int offset, int stride_bits)
{
    int n = 1 << lgs;
    int half = n >> 1;

    if (lgs == 1) {
        /* Base case: single conditional swap */
        set_cbit(out, offset, pi[0] != 0);
        return;
    }

    /* Allocate workspace */
    uint16_t *pi_top = (uint16_t *)calloc((size_t)half, sizeof(uint16_t));
    uint16_t *pi_bot = (uint16_t *)calloc((size_t)half, sizeof(uint16_t));
    int *assigned_in = (int *)calloc((size_t)n, sizeof(int));
    int *assigned_out = (int *)calloc((size_t)n, sizeof(int));
    int *route_in = (int *)calloc((size_t)n, sizeof(int));   /* 0=top, 1=bottom */
    int *route_out = (int *)calloc((size_t)n, sizeof(int));

    if (!pi_top || !pi_bot || !assigned_in || !assigned_out ||
        !route_in || !route_out) {
        goto cleanup;
    }

    memset(assigned_in, 0, (size_t)n * sizeof(int));
    memset(assigned_out, 0, (size_t)n * sizeof(int));
    memset(route_in, -1, (size_t)n * sizeof(int));
    memset(route_out, -1, (size_t)n * sizeof(int));

    /*
     * Route elements through the network using the standard approach:
     * For each pair (i, i+half) in the input, decide which goes to the
     * top sub-network and which to the bottom.
     *
     * We use a greedy chain-following algorithm:
     * 1. Start with an unassigned input i, route it to top (route_in[i] = 0).
     * 2. Its output pi[i] goes to top. The partner of pi[i] in the output
     *    must go to bottom.
     * 3. Follow the chain back to the input side and continue.
     */
    for (int start = 0; start < n; start++) {
        if (assigned_in[start])
            continue;

        int cur = start;
        int side = 0; /* start with top */

        while (!assigned_in[cur]) {
            /* Assign input cur to 'side' */
            assigned_in[cur] = 1;
            route_in[cur] = side;

            /* Its output pi[cur] goes to the same side */
            int out_pos = pi[cur];
            assigned_out[out_pos] = 1;
            route_out[out_pos] = side;

            /* The partner of out_pos on the output side */
            int partner_out = out_pos ^ half;

            if (assigned_out[partner_out]) {
                break;
            }

            /* Partner goes to opposite side */
            assigned_out[partner_out] = 1;
            route_out[partner_out] = 1 - side;

            /* Find which input maps to partner_out */
            int next_in = -1;
            for (int j = 0; j < n; j++) {
                if (pi[j] == (uint16_t)partner_out) {
                    next_in = j;
                    break;
                }
            }

            if (next_in < 0 || assigned_in[next_in]) {
                break;
            }

            cur = next_in;
            side = 1 - side;
        }
    }

    /*
     * Now build the sub-permutations for top and bottom.
     * Also set the control bits for the input and output layers.
     */
    int top_idx = 0, bot_idx = 0;

    /* Input layer control bits: for pair (i, i+half), swap if
     * route_in[i] == 1 (i.e., i goes to bottom) */
    int bits_per_layer = half;
    int input_layer_offset = offset;
    int output_layer_offset = offset + (2 * lgs - 2) * stride_bits;

    for (int i = 0; i < half; i++) {
        int lo = i;
        int hi = i + half;
        int swap_in = (route_in[lo] == 1) ? 1 : 0;
        set_cbit(out, input_layer_offset + i, swap_in);

        /* After the input switch:
         * element going to top sub-network, element going to bottom */
        int to_top_in, to_bot_in;
        if (swap_in) {
            to_top_in = hi;
            to_bot_in = lo;
        } else {
            to_top_in = lo;
            to_bot_in = hi;
        }

        (void)to_top_in;
        (void)to_bot_in;
    }

    /* Build sub-permutations */
    /* For each output position j, if route_out[j] == 0, it goes through
     * the top sub-network at position j % half */
    int *in_top_pos = (int *)calloc((size_t)n, sizeof(int));
    int *in_bot_pos = (int *)calloc((size_t)n, sizeof(int));

    if (!in_top_pos || !in_bot_pos) {
        free(in_top_pos);
        free(in_bot_pos);
        goto cleanup;
    }

    top_idx = 0;
    bot_idx = 0;

    /* Map inputs to their sub-network positions */
    for (int i = 0; i < n; i++) {
        if (route_in[i] == 0) {
            in_top_pos[i] = top_idx++;
        } else {
            in_bot_pos[i] = bot_idx++;
        }
    }

    /* Map outputs to their sub-network positions and build sub-perms */
    int out_top_idx = 0, out_bot_idx = 0;
    int *out_top_map = (int *)calloc((size_t)n, sizeof(int));
    int *out_bot_map = (int *)calloc((size_t)n, sizeof(int));

    if (!out_top_map || !out_bot_map) {
        free(in_top_pos);
        free(in_bot_pos);
        free(out_top_map);
        free(out_bot_map);
        goto cleanup;
    }

    for (int j = 0; j < n; j++) {
        if (route_out[j] == 0) {
            out_top_map[j] = out_top_idx++;
        } else {
            out_bot_map[j] = out_bot_idx++;
        }
    }

    /* Build pi_top and pi_bot:
     * pi_top maps input top position to output top position
     * pi_bot maps input bottom position to output bottom position */
    for (int i = 0; i < n; i++) {
        int j = pi[i];
        if (route_in[i] == 0) {
            pi_top[in_top_pos[i]] = (uint16_t)out_top_map[j];
        } else {
            pi_bot[in_bot_pos[i]] = (uint16_t)out_bot_map[j];
        }
    }

    /* Output layer control bits */
    for (int i = 0; i < half; i++) {
        int lo = i;
        int hi = i + half;
        /* After the sub-networks, lo comes from top, hi from bottom.
         * We need to swap if route_out[lo] == 1. */
        int swap_out = (route_out[lo] == 1) ? 1 : 0;
        set_cbit(out, output_layer_offset + i, swap_out);
    }

    /* Recurse on sub-networks */
    cbits_rec(out, pi_top, lgs - 1, offset + stride_bits, stride_bits);
    cbits_rec(out, pi_bot, lgs - 1, offset + stride_bits + (half >> 1), stride_bits);

    free(in_top_pos);
    free(in_bot_pos);
    free(out_top_map);
    free(out_bot_map);

cleanup:
    free(pi_top);
    free(pi_bot);
    free(assigned_in);
    free(assigned_out);
    free(route_in);
    free(route_out);
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

void controlbits_from_permutation(uint8_t *out, const uint16_t *pi, int lgs)
{
    int n = 1 << lgs;
    int layers = 2 * lgs - 1;
    int half = n >> 1;
    int total_bits = layers * half;
    int total_bytes = (total_bits + 7) / 8;

    memset(out, 0, (size_t)total_bytes);

    cbits_rec(out, pi, lgs, 0, half);
}
