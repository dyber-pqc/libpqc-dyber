/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE - fixed-weight sampling (specification v5.1, Algorithm 3,
 * WSHAKE256-PRF), constant time.
 *
 * Algorithm 3 draws wt 32-bit words from SHAKE256(seed) and, for
 * i = wt-1 down to 0, takes pos = i + floor((len - i) * s / 2^32), or i
 * itself if pos is already in the list. It never rejects, so the work
 * done does not depend on the seed. As the official KATs fix it:
 *
 *   - the 32-bit words are little-endian and consumed in stream order:
 *     the first word is used for i = wt-1, the second for i = wt-2, ...
 *   - key generation draws h0 from the first 4*(w/2) bytes of
 *     SHAKE256(seed) and h1 from the next 4*(w/2), one stream;
 *   - H(m) draws t positions in [0, 2r) from SHAKE256(m); positions
 *     below r go to e0, the rest (minus r) to e1.
 *
 * Constant time: the duplicate test compares each candidate with every
 * earlier entry using masks, and the list is written into the dense
 * vector by visiting every word for every position. No address or branch
 * depends on a position.
 */

#include <string.h>
#include "bike.h"
#include "pqc/common.h"
#include "bike_params.h"
#include "core/common/hash/sha3.h"

/* 0xFFFFFFFF if a == b, else 0. */
static uint32_t ct_eq32(uint32_t a, uint32_t b)
{
    uint64_t d = (uint64_t)(a ^ b);
    return 0u - (uint32_t)((d - 1) >> 63);
}

/* Algorithm 3 on a stream of 4*wt bytes. */
static void wlist(uint32_t *list, const uint8_t *stream, uint32_t len,
                  uint32_t wt)
{
    uint32_t k, j;
    for (k = 0; k < wt; k++) {
        uint32_t i = wt - 1 - k;
        uint32_t s = (uint32_t)stream[4 * k] |
                     ((uint32_t)stream[4 * k + 1] << 8) |
                     ((uint32_t)stream[4 * k + 2] << 16) |
                     ((uint32_t)stream[4 * k + 3] << 24);
        uint32_t pos = i + (uint32_t)(((uint64_t)(len - i) * s) >> 32);
        uint32_t dup = 0;
        for (j = 0; j < k; j++)
            dup |= ct_eq32(list[j], pos);
        list[k] = (pos & ~dup) | (i & dup);
    }
}

/* v |= the set bits listed, all < r. v has r_words words, pre-zeroed. */
static void scatter(uint64_t *v, const uint32_t *list, uint32_t n,
                    uint32_t r_words)
{
    uint32_t k, j;
    for (k = 0; k < n; k++) {
        uint32_t p = list[k];
        uint64_t bit = (uint64_t)1 << (p & 63);
        for (j = 0; j < r_words; j++)
            v[j] |= bit & (uint64_t)(int64_t)(int32_t)ct_eq32(p >> 6, j);
    }
}

void bike_sample_keys(uint64_t *h0, uint64_t *h1, const uint8_t seed[32],
                      const bike_params_t *p)
{
    uint32_t d = p->half_w;
    uint8_t stream[8 * (BIKE_MAX_W / 2)];
    uint32_t list[BIKE_MAX_W / 2];

    pqc_shake256(stream, 8 * d, seed, 32);
    memset(h0, 0, p->r_words * sizeof(uint64_t));
    memset(h1, 0, p->r_words * sizeof(uint64_t));
    wlist(list, stream, p->r, d);
    scatter(h0, list, d, p->r_words);
    wlist(list, stream + 4 * d, p->r, d);
    scatter(h1, list, d, p->r_words);

    pqc_memzero(stream, sizeof stream);
    pqc_memzero(list, sizeof list);
}

void bike_sample_error(uint64_t *e0, uint64_t *e1, const uint8_t m[32],
                       const bike_params_t *p)
{
    uint32_t t = p->t, r = p->r, k;
    uint8_t stream[4 * BIKE_MAX_T];
    uint32_t list[BIKE_MAX_T], lo[BIKE_MAX_T], hi[BIKE_MAX_T];

    pqc_shake256(stream, 4 * t, m, 32);
    wlist(list, stream, 2 * r, t);

    /*
     * Split [0, 2r) into the two blocks without branching: a position
     * below r goes to e0 and the other block gets an entry that sets
     * nothing (r_words * 64 is past the last word). Both scatters then
     * visit every entry.
     */
    for (k = 0; k < t; k++) {
        uint32_t pos = list[k];
        uint32_t is_lo = 0u - ((uint32_t)((uint64_t)pos - r) >> 31 & 1);
        uint32_t none = p->r_words * 64;
        lo[k] = (pos & is_lo) | (none & ~is_lo);
        hi[k] = ((pos - r) & ~is_lo) | (none & is_lo);
    }
    memset(e0, 0, p->r_words * sizeof(uint64_t));
    memset(e1, 0, p->r_words * sizeof(uint64_t));
    scatter(e0, lo, t, p->r_words);
    scatter(e1, hi, t, p->r_words);

    pqc_memzero(stream, sizeof stream);
    pqc_memzero(list, sizeof list);
    pqc_memzero(lo, sizeof lo);
    pqc_memzero(hi, sizeof hi);
}
