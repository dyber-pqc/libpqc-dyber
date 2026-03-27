/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Keccak-f[1600] permutation -- portable C11 implementation.
 *
 * Copyright (c) 2024-2026 Dyber, Inc.
 * Licensed under the Apache License, Version 2.0 or the MIT license,
 * at your option.
 */

#include "core/common/hash/keccak.h"
#include <string.h>

/* Round constants for Keccak-f[1600]. */
static const uint64_t keccak_rc[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008),
};

static inline uint64_t rotl64(uint64_t x, unsigned int n) {
    return (n == 0) ? x : ((x << n) | (x >> (64u - n)));
}

static inline uint64_t load64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8u * i);
    return v;
}

static inline void store64_le(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8u * i));
}

/*
 * Keccak-f[1600] permutation.
 * State is 25 uint64_t lanes indexed as state[x + 5*y].
 */
void pqc_keccak_f1600(uint64_t state[25])
{
    for (int round = 0; round < 24; round++) {
        uint64_t C[5], D[5], B[25];

        /* Theta */
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        for (int x = 0; x < 5; x++)
            D[x] = C[(x+4) % 5] ^ rotl64(C[(x+1) % 5], 1);
        for (int i = 0; i < 25; i++)
            state[i] ^= D[i % 5];

        /* Rho and Pi (combined) */
        /* Pi: (x,y) -> (y, 2x+3y mod 5) */
        /* We compute B[y + 5*(2x+3y mod 5)] = rotl64(state[x+5*y], rho[x+5*y]) */
        {
            /* Rho offsets indexed by [x + 5*y] */
            static const unsigned rho[25] = {
                 0,  1, 62, 28, 27,    /* y=0: x=0..4 */
                36, 44,  6, 55, 20,    /* y=1 */
                 3, 10, 43, 25, 39,    /* y=2 */
                41, 45, 15, 21,  8,    /* y=3 */
                18,  2, 61, 56, 14,    /* y=4 */
            };
            /* Pi destination index for source [x + 5*y] is [y + 5*((2*x+3*y) % 5)] */
            static const unsigned pi_dest[25] = {
                 0, 10, 20,  5, 15,    /* source (0,0)->(0,0), (1,0)->(0,2), etc */
                16,  1, 11, 21,  6,
                 7, 17,  2, 12, 22,
                23,  8, 18,  3, 13,
                14, 24,  9, 19,  4,
            };
            for (int i = 0; i < 25; i++)
                B[pi_dest[i]] = rotl64(state[i], rho[i]);
        }

        /* Chi */
        for (int y = 0; y < 25; y += 5) {
            for (int x = 0; x < 5; x++)
                state[y+x] = B[y+x] ^ (~B[y + (x+1)%5] & B[y + (x+2)%5]);
        }

        /* Iota */
        state[0] ^= keccak_rc[round];
    }
}

void pqc_keccak_init(uint64_t state[25]) {
    memset(state, 0, 25 * sizeof(uint64_t));
}

void pqc_keccak_absorb(uint64_t state[25], size_t rate_bytes,
                        const uint8_t *data, size_t datalen)
{
    size_t rate_lanes = rate_bytes / 8;

    while (datalen >= rate_bytes) {
        for (size_t i = 0; i < rate_lanes; i++)
            state[i] ^= load64_le(data + 8 * i);
        pqc_keccak_f1600(state);
        data += rate_bytes;
        datalen -= rate_bytes;
    }

    /* Absorb remaining partial block */
    if (datalen > 0) {
        size_t full_lanes = datalen / 8;
        for (size_t i = 0; i < full_lanes; i++)
            state[i] ^= load64_le(data + 8 * i);

        size_t remaining = datalen - full_lanes * 8;
        if (remaining > 0) {
            uint64_t lane = 0;
            for (size_t i = 0; i < remaining; i++)
                lane |= (uint64_t)data[full_lanes * 8 + i] << (8u * i);
            state[full_lanes] ^= lane;
        }
    }
}

void pqc_keccak_squeeze(uint64_t state[25], size_t rate_bytes,
                         uint8_t *out, size_t outlen)
{
    size_t rate_lanes = rate_bytes / 8;

    while (outlen > 0) {
        size_t block = (outlen < rate_bytes) ? outlen : rate_bytes;
        size_t full_lanes = block / 8;

        for (size_t i = 0; i < full_lanes; i++)
            store64_le(out + 8 * i, state[i]);

        size_t remaining = block - full_lanes * 8;
        if (remaining > 0) {
            uint8_t tmp[8];
            store64_le(tmp, state[full_lanes]);
            memcpy(out + full_lanes * 8, tmp, remaining);
        }

        out += block;
        outlen -= block;

        if (outlen > 0)
            pqc_keccak_f1600(state);
    }
}
