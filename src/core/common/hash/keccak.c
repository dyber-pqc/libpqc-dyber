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

/* ------------------------------------------------------------------ */
/* Round constants for Keccak-f[1600] (LFSR-derived).                  */
/* ------------------------------------------------------------------ */
static const uint64_t keccak_rc[PQC_KECCAK_ROUNDS] = {
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

/* ------------------------------------------------------------------ */
/* Rotation offsets rho[x][y] linearised as rho[5*y + x].              */
/* ------------------------------------------------------------------ */
static const unsigned int keccak_rho[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

/* ------------------------------------------------------------------ */
/* Pi step index: pi_index[i] gives the source lane for destination i. */
/* pi: A'[y][2x+3y] = A[x][y], linearised.                            */
/* ------------------------------------------------------------------ */
static const unsigned int keccak_pi[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static inline uint64_t rotl64(uint64_t x, unsigned int n)
{
    return (x << n) | (x >> (64u - n));
}

/* Load a 64-bit little-endian word from a byte pointer. */
static inline uint64_t load64_le(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8u * i);
    }
    return v;
}

/* Store a 64-bit word in little-endian byte order. */
static inline void store64_le(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8u * i));
    }
}

/* ------------------------------------------------------------------ */
/* Keccak-f[1600] permutation                                          */
/* ------------------------------------------------------------------ */
void pqc_keccak_f1600(uint64_t state[PQC_KECCAK_STATE_LANES])
{
    uint64_t C[5], D[5], B[25], t;

    for (int round = 0; round < PQC_KECCAK_ROUNDS; round++) {
        /* --- Theta ------------------------------------------------ */
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10]
                             ^ state[x + 15] ^ state[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        /* --- Rho + Pi -------------------------------------------- */
        for (int i = 0; i < 25; i++) {
            B[i] = rotl64(state[keccak_pi[i]], keccak_rho[keccak_pi[i]]);
        }

        /* --- Chi ------------------------------------------------- */
        for (int y = 0; y < 25; y += 5) {
            for (int x = 0; x < 5; x++) {
                state[y + x] = B[y + x]
                              ^ (~B[y + (x + 1) % 5] & B[y + (x + 2) % 5]);
            }
        }

        /* --- Iota ------------------------------------------------ */
        state[0] ^= keccak_rc[round];
    }
}

/* ------------------------------------------------------------------ */
/* State initialisation                                                */
/* ------------------------------------------------------------------ */
void pqc_keccak_init(uint64_t state[PQC_KECCAK_STATE_LANES])
{
    memset(state, 0, PQC_KECCAK_STATE_LANES * sizeof(uint64_t));
}

/* ------------------------------------------------------------------ */
/* XOR a block of bytes (up to rate bytes) into the state.             */
/* ------------------------------------------------------------------ */
static void keccak_xor_block(uint64_t state[PQC_KECCAK_STATE_LANES],
                              const uint8_t *block,
                              size_t len)
{
    size_t full_lanes = len / 8;
    size_t i;

    for (i = 0; i < full_lanes; i++) {
        state[i] ^= load64_le(block + 8 * i);
    }

    /* Handle a possible partial trailing lane. */
    if (len % 8) {
        uint8_t tmp[8] = {0};
        memcpy(tmp, block + 8 * full_lanes, len % 8);
        state[full_lanes] ^= load64_le(tmp);
    }
}

/* ------------------------------------------------------------------ */
/* Absorb                                                              */
/* ------------------------------------------------------------------ */
void pqc_keccak_absorb(uint64_t state[PQC_KECCAK_STATE_LANES],
                        size_t rate,
                        const uint8_t *data,
                        size_t datalen)
{
    while (datalen >= rate) {
        keccak_xor_block(state, data, rate);
        pqc_keccak_f1600(state);
        data    += rate;
        datalen -= rate;
    }

    /* XOR remaining partial block (no permutation yet). */
    if (datalen > 0) {
        keccak_xor_block(state, data, datalen);
    }
}

/* ------------------------------------------------------------------ */
/* Squeeze                                                             */
/* ------------------------------------------------------------------ */
void pqc_keccak_squeeze(uint64_t state[PQC_KECCAK_STATE_LANES],
                         size_t rate,
                         uint8_t *out,
                         size_t outlen)
{
    uint8_t block[PQC_KECCAK_STATE_BYTES];
    size_t i;

    while (outlen > 0) {
        /* Serialise the rate portion of the state. */
        for (i = 0; i < rate / 8; i++) {
            store64_le(block + 8 * i, state[i]);
        }

        if (outlen <= rate) {
            memcpy(out, block, outlen);
            outlen = 0;
        } else {
            memcpy(out, block, rate);
            out    += rate;
            outlen -= rate;
            pqc_keccak_f1600(state);
        }
    }
}
