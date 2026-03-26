/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * LMS - LM-OTS (Leighton-Micali One-Time Signature).
 * RFC 8554 Section 4.
 *
 * LM-OTS uses Winternitz hash chains.  With w=8, each byte of the
 * message digest directly indexes a chain position.  Signing reveals
 * intermediate chain values; verification completes the chains and
 * hashes to the public key.
 */

#include <string.h>
#include <stdint.h>
#include "lms.h"
#include "pqc/common.h"
#include "core/common/hash/sha2.h"

#define N PQC_LMS_SHA256_N
#define P PQC_LMOTS_P
#define W PQC_LMOTS_W

/* ------------------------------------------------------------------ */
/* Hash chain function: compute H(I || u32(q) || u16(i) || u8(j) || x) */
/* ------------------------------------------------------------------ */

static void lmots_chain_hash(uint8_t *out, const uint8_t *I, uint32_t q,
                              uint16_t chain_idx, uint8_t step,
                              const uint8_t *x)
{
    pqc_sha256_ctx ctx;
    uint8_t buf[4];

    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
    lms_store_u32(buf, q);
    pqc_sha256_update(&ctx, buf, 4);
    buf[0] = (uint8_t)(chain_idx >> 8);
    buf[1] = (uint8_t)(chain_idx & 0xFF);
    pqc_sha256_update(&ctx, buf, 2);
    buf[0] = step;
    pqc_sha256_update(&ctx, buf, 1);
    pqc_sha256_update(&ctx, x, N);
    pqc_sha256_final(&ctx, out);
}

/* Iterate chain from start_val for (end - start) steps */
static void lmots_chain(uint8_t *out, const uint8_t *start_val,
                         int start, int end,
                         const uint8_t *I, uint32_t q, uint16_t chain_idx)
{
    uint8_t tmp[N];
    int j;

    memcpy(tmp, start_val, N);
    for (j = start; j < end; j++) {
        lmots_chain_hash(out, I, q, chain_idx, (uint8_t)j, tmp);
        memcpy(tmp, out, N);
    }
    if (start >= end) {
        memcpy(out, start_val, N);
    }
}

/* ------------------------------------------------------------------ */
/* Generate the i-th OTS private key chain value from seed.             */
/* x[i] = H(I || u32(q) || u16(i) || 0xFF || SEED)                     */
/* ------------------------------------------------------------------ */

static void lmots_derive_chain_key(uint8_t *out, const uint8_t *I,
                                    uint32_t q, uint16_t i,
                                    const uint8_t *seed)
{
    pqc_sha256_ctx ctx;
    uint8_t buf[4];

    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
    lms_store_u32(buf, q);
    pqc_sha256_update(&ctx, buf, 4);
    buf[0] = (uint8_t)(i >> 8);
    buf[1] = (uint8_t)(i & 0xFF);
    pqc_sha256_update(&ctx, buf, 2);
    buf[0] = 0xFF;
    pqc_sha256_update(&ctx, buf, 1);
    pqc_sha256_update(&ctx, seed, N);
    pqc_sha256_final(&ctx, out);
}

/* ------------------------------------------------------------------ */
/* Compute the message hash and checksum (Winternitz encoding).         */
/*                                                                      */
/* Q = H(I || u32(q) || u16(D_MESG) || C || message)                   */
/* Then coef: first n bytes from Q, then checksum bytes.                */
/* ------------------------------------------------------------------ */

#define D_MESG 0x8181

static void lmots_compute_digest(uint8_t *coef, const uint8_t *I,
                                  uint32_t q, const uint8_t *C,
                                  const uint8_t *msg, size_t msglen)
{
    uint8_t Q[N];
    pqc_sha256_ctx ctx;
    uint8_t buf[4];
    uint16_t sum = 0;
    int i;

    /* Q = H(I || q || D_MESG || C || msg) */
    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
    lms_store_u32(buf, q);
    pqc_sha256_update(&ctx, buf, 4);
    buf[0] = (uint8_t)(D_MESG >> 8);
    buf[1] = (uint8_t)(D_MESG & 0xFF);
    pqc_sha256_update(&ctx, buf, 2);
    pqc_sha256_update(&ctx, C, N);
    pqc_sha256_update(&ctx, msg, msglen);
    pqc_sha256_final(&ctx, Q);

    /* With w=8, each byte of Q is one coefficient (0..255) */
    for (i = 0; i < N; i++) {
        coef[i] = Q[i];
        sum += (uint16_t)(255 - Q[i]);
    }

    /* Checksum: 2 bytes big-endian */
    coef[N] = (uint8_t)(sum >> 8);
    coef[N + 1] = (uint8_t)(sum & 0xFF);
}

/* ------------------------------------------------------------------ */
/* LM-OTS Key generation: compute public key from seed.                 */
/*                                                                      */
/* pk = H(I || u32(q) || u16(D_PBLC) || y[0] || ... || y[p-1])        */
/* where y[i] = chain(x[i], 0, 2^w - 1)                               */
/* ------------------------------------------------------------------ */

#define D_PBLC 0x8080

void lmots_keygen(uint8_t *pk, const uint8_t *I, uint32_t q,
                  const uint8_t *seed)
{
    pqc_sha256_ctx ctx;
    uint8_t chain_key[N];
    uint8_t chain_end[N];
    uint8_t buf[4];
    int i;

    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
    lms_store_u32(buf, q);
    pqc_sha256_update(&ctx, buf, 4);
    buf[0] = (uint8_t)(D_PBLC >> 8);
    buf[1] = (uint8_t)(D_PBLC & 0xFF);
    pqc_sha256_update(&ctx, buf, 2);

    for (i = 0; i < P; i++) {
        lmots_derive_chain_key(chain_key, I, q, (uint16_t)i, seed);
        lmots_chain(chain_end, chain_key, 0, 255, I, q, (uint16_t)i);
        pqc_sha256_update(&ctx, chain_end, N);
    }

    pqc_sha256_final(&ctx, pk);
    pqc_memzero(chain_key, N);
}

/* ------------------------------------------------------------------ */
/* LM-OTS Sign                                                          */
/*                                                                      */
/* sig = u32(LMOTS_type) || C || y[0] || ... || y[p-1]                 */
/* y[i] = chain(x[i], 0, coef[i])                                      */
/* ------------------------------------------------------------------ */

void lmots_sign(uint8_t *sig, const uint8_t *msg, size_t msglen,
                const uint8_t *I, uint32_t q, const uint8_t *seed)
{
    uint8_t coef[P];
    uint8_t C[N];
    uint8_t chain_key[N];
    uint8_t chain_val[N];
    int i;
    size_t pos = 0;

    /* Type ID */
    lms_store_u32(sig + pos, PQC_LMOTS_SHA256_N32_W8);
    pos += 4;

    /* Randomizer C: derived from seed and q */
    {
        pqc_sha256_ctx ctx;
        uint8_t buf[4];
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
        lms_store_u32(buf, q);
        pqc_sha256_update(&ctx, buf, 4);
        buf[0] = 0xFE;
        pqc_sha256_update(&ctx, buf, 1);
        pqc_sha256_update(&ctx, seed, N);
        pqc_sha256_final(&ctx, C);
    }
    memcpy(sig + pos, C, N);
    pos += N;

    /* Compute digest/coefficients */
    lmots_compute_digest(coef, I, q, C, msg, msglen);

    /* Chain values */
    for (i = 0; i < P; i++) {
        lmots_derive_chain_key(chain_key, I, q, (uint16_t)i, seed);
        lmots_chain(chain_val, chain_key, 0, (int)coef[i], I, q, (uint16_t)i);
        memcpy(sig + pos, chain_val, N);
        pos += N;
    }

    pqc_memzero(chain_key, N);
    pqc_memzero(coef, sizeof(coef));
}

/* ------------------------------------------------------------------ */
/* LM-OTS Verify: complete chains and compute candidate public key.     */
/*                                                                      */
/* sig = u32(type) || C || y[0..p-1]                                    */
/* Compute z[i] = chain(y[i], coef[i], 2^w-1) for each i.              */
/* computed_pk = H(I || q || D_PBLC || z[0] || ... || z[p-1])          */
/* Returns 0 if the computed_pk is valid (caller compares to stored pk).*/
/* ------------------------------------------------------------------ */

int lmots_verify(const uint8_t *msg, size_t msglen,
                 const uint8_t *sig, const uint8_t *I, uint32_t q,
                 uint8_t *computed_pk)
{
    uint8_t coef[P];
    const uint8_t *C;
    const uint8_t *y;
    uint8_t z[N];
    pqc_sha256_ctx ctx;
    uint8_t buf[4];
    int i;

    /* Skip type ID (4 bytes) */
    C = sig + 4;
    y = sig + 4 + N;

    lmots_compute_digest(coef, I, q, C, msg, msglen);

    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
    lms_store_u32(buf, q);
    pqc_sha256_update(&ctx, buf, 4);
    buf[0] = (uint8_t)(D_PBLC >> 8);
    buf[1] = (uint8_t)(D_PBLC & 0xFF);
    pqc_sha256_update(&ctx, buf, 2);

    for (i = 0; i < P; i++) {
        lmots_chain(z, y + i * N, (int)coef[i], 255, I, q, (uint16_t)i);
        pqc_sha256_update(&ctx, z, N);
    }

    pqc_sha256_final(&ctx, computed_pk);
    return 0;
}
