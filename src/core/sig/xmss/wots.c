/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * XMSS - WOTS+ one-time signature.
 * RFC 8391 Section 3.
 *
 * WOTS+ with w=16 uses chains of length 15.  Each 4-bit nibble of the
 * message hash indexes a chain position.  The public key is the
 * concatenation of all chain endpoints, compressed via L-tree.
 *
 * Hash function: H(KEY || ADRS || M) using SHA-256 with:
 *   KEY = toByte(0, n) || PUB_SEED  (for PRF)
 *   or PUB_SEED for chain hashing
 */

#include <string.h>
#include <stdint.h>
#include "xmss.h"
#include "pqc/common.h"
#include "core/common/hash/sha2.h"

#define N PQC_XMSS_SHA2_N
#define W PQC_XMSS_WOTS_W
#define LEN PQC_XMSS_WOTS_LEN
#define LEN1 PQC_XMSS_WOTS_LEN1
#define LEN2 PQC_XMSS_WOTS_LEN2

/* ------------------------------------------------------------------ */
/* PRF: output = SHA-256(SEED || ADRS)                                  */
/* Used to derive chain keys from the seed.                             */
/* ------------------------------------------------------------------ */

static void xmss_prf(uint8_t *out, const uint8_t *seed,
                      const uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    pqc_sha256_ctx ctx;
    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, seed, N);
    pqc_sha256_update(&ctx, addr, PQC_XMSS_ADDR_BYTES);
    pqc_sha256_final(&ctx, out);
}

/* ------------------------------------------------------------------ */
/* Randomized hash: H(PUB_SEED || ADRS || M)                           */
/* For WOTS+ chain function F.                                          */
/* ------------------------------------------------------------------ */

static void xmss_hash_f(uint8_t *out, const uint8_t *in,
                          const uint8_t *pub_seed,
                          uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    uint8_t key[N];
    uint8_t bitmask[N];

    /* Generate key and bitmask from pub_seed and ADRS */
    xmss_addr_set_hash(addr, 0);
    xmss_prf(key, pub_seed, addr);
    xmss_addr_set_hash(addr, 1);
    xmss_prf(bitmask, pub_seed, addr);

    /* H(key || (in XOR bitmask)) */
    {
        pqc_sha256_ctx ctx;
        uint8_t tmp[N];
        int i;
        for (i = 0; i < N; i++) {
            tmp[i] = in[i] ^ bitmask[i];
        }
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, key, N);
        pqc_sha256_update(&ctx, tmp, N);
        pqc_sha256_final(&ctx, out);
    }
}

/* ------------------------------------------------------------------ */
/* Chain function: apply F iteratively from start to start+steps.       */
/* ------------------------------------------------------------------ */

static void xmss_chain(uint8_t *out, const uint8_t *in,
                         int start, int steps,
                         const uint8_t *pub_seed,
                         uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    int i;
    memcpy(out, in, N);
    for (i = start; i < start + steps && i < W - 1; i++) {
        xmss_addr_set_hash(addr, (uint32_t)i);
        xmss_hash_f(out, out, pub_seed, addr);
    }
}

/* ------------------------------------------------------------------ */
/* Compute base-w representation of message (4-bit nibbles for w=16).   */
/* Also appends checksum.                                               */
/* ------------------------------------------------------------------ */

static void wots_base_w(int *basew, const uint8_t *msg_hash)
{
    int i;
    uint32_t csum = 0;

    /* Message nibbles (len1 = 64 for n=32, w=16) */
    for (i = 0; i < LEN1; i++) {
        if (i % 2 == 0) {
            basew[i] = (msg_hash[i / 2] >> 4) & 0x0F;
        } else {
            basew[i] = msg_hash[i / 2] & 0x0F;
        }
        csum += (uint32_t)(W - 1 - basew[i]);
    }

    /* Checksum in base w (len2 = 3) */
    csum <<= 4; /* left-shift for alignment */
    for (i = 0; i < LEN2; i++) {
        basew[LEN1 + i] = (int)((csum >> (4 * (LEN2 - 1 - i))) & 0x0F);
    }
}

/* ------------------------------------------------------------------ */
/* WOTS+ Key generation                                                 */
/* ------------------------------------------------------------------ */

void xmss_wots_keygen(uint8_t *pk, const uint8_t *seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    int i;
    uint8_t sk_chain[N];

    xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);

    for (i = 0; i < LEN; i++) {
        xmss_addr_set_chain(addr, (uint32_t)i);
        xmss_addr_set_hash(addr, 0);

        /* Derive chain secret key: sk[i] = PRF(seed, addr) */
        xmss_prf(sk_chain, seed, addr);

        /* pk[i] = chain(sk[i], 0, w-1) */
        xmss_chain(pk + (size_t)i * N, sk_chain, 0, W - 1, pub_seed, addr);
    }

    pqc_memzero(sk_chain, N);
}

/* ------------------------------------------------------------------ */
/* WOTS+ Sign                                                           */
/* ------------------------------------------------------------------ */

void xmss_wots_sign(uint8_t *sig, const uint8_t *msg,
                     const uint8_t *seed, const uint8_t *pub_seed,
                     uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    int basew[LEN];
    uint8_t sk_chain[N];
    int i;

    wots_base_w(basew, msg);

    xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);

    for (i = 0; i < LEN; i++) {
        xmss_addr_set_chain(addr, (uint32_t)i);
        xmss_addr_set_hash(addr, 0);

        xmss_prf(sk_chain, seed, addr);
        xmss_chain(sig + (size_t)i * N, sk_chain, 0, basew[i], pub_seed, addr);
    }

    pqc_memzero(sk_chain, N);
}

/* ------------------------------------------------------------------ */
/* WOTS+ Verify (compute pk from sig)                                   */
/* ------------------------------------------------------------------ */

void xmss_wots_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                             const uint8_t *msg, const uint8_t *pub_seed,
                             uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    int basew[LEN];
    int i;

    wots_base_w(basew, msg);

    xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);

    for (i = 0; i < LEN; i++) {
        xmss_addr_set_chain(addr, (uint32_t)i);
        xmss_chain(pk + (size_t)i * N, sig + (size_t)i * N,
                    basew[i], W - 1 - basew[i], pub_seed, addr);
    }
}
