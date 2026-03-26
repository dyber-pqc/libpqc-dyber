/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SHA-3 and SHAKE -- portable C11 implementation built on the
 * Keccak-f[1600] sponge provided by keccak.c.
 *
 * Copyright (c) 2024-2026 Dyber, Inc.
 * Licensed under the Apache License, Version 2.0 or the MIT license,
 * at your option.
 */

#include "core/common/hash/sha3.h"
#include "core/common/hash/keccak.h"
#include <string.h>

/* Domain-separation suffix bytes (before multi-rate padding). */
#define SHA3_DOMAIN  0x06   /* SHA-3:  M || 01 || 10*1 */
#define SHAKE_DOMAIN 0x1F   /* SHAKE:  M || 1111 || 10*1 */

/* ------------------------------------------------------------------ */
/* Internal helper: pad, permute, and optionally squeeze.               */
/*                                                                      */
/* On entry the partial (< rate) tail of the message has already been   */
/* XOR'd into the state by pqc_keccak_absorb; @p absorbed is the       */
/* number of bytes in that partial block.                               */
/* ------------------------------------------------------------------ */
static void keccak_finalize_and_squeeze(uint64_t state[25],
                                         size_t rate,
                                         size_t absorbed,
                                         uint8_t domain,
                                         uint8_t *out,
                                         size_t outlen)
{
    /*
     * Padding: XOR the domain-separation byte at position `absorbed`
     * and set the high bit of the last rate byte (multi-rate padding).
     * If absorbed == rate-1 they coincide in the same byte.
     */
    uint8_t pad_block[200];
    memset(pad_block, 0, sizeof(pad_block));
    pad_block[absorbed] = domain;
    pad_block[rate - 1] |= 0x80;

    /* XOR the padding into the state lane-by-lane. */
    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t v = 0;
        for (unsigned j = 0; j < 8; j++) {
            v |= (uint64_t)pad_block[8 * i + j] << (8u * j);
        }
        state[i] ^= v;
    }

    pqc_keccak_f1600(state);
    pqc_keccak_squeeze(state, rate, out, outlen);
}

/* ================================================================= */
/*  One-shot SHA-3                                                     */
/* ================================================================= */

void pqc_sha3_256(uint8_t out[PQC_SHA3_256_BYTES],
                   const uint8_t *in, size_t inlen)
{
    uint64_t state[25];
    pqc_keccak_init(state);

    size_t absorbed = inlen % PQC_SHA3_256_RATE;
    pqc_keccak_absorb(state, PQC_SHA3_256_RATE, in, inlen);
    keccak_finalize_and_squeeze(state, PQC_SHA3_256_RATE, absorbed,
                                 SHA3_DOMAIN, out, PQC_SHA3_256_BYTES);
}

void pqc_sha3_512(uint8_t out[PQC_SHA3_512_BYTES],
                   const uint8_t *in, size_t inlen)
{
    uint64_t state[25];
    pqc_keccak_init(state);

    size_t absorbed = inlen % PQC_SHA3_512_RATE;
    pqc_keccak_absorb(state, PQC_SHA3_512_RATE, in, inlen);
    keccak_finalize_and_squeeze(state, PQC_SHA3_512_RATE, absorbed,
                                 SHA3_DOMAIN, out, PQC_SHA3_512_BYTES);
}

/* ================================================================= */
/*  One-shot SHAKE                                                     */
/* ================================================================= */

void pqc_shake128(uint8_t *out, size_t outlen,
                   const uint8_t *in, size_t inlen)
{
    uint64_t state[25];
    pqc_keccak_init(state);

    size_t absorbed = inlen % PQC_SHAKE128_RATE;
    pqc_keccak_absorb(state, PQC_SHAKE128_RATE, in, inlen);
    keccak_finalize_and_squeeze(state, PQC_SHAKE128_RATE, absorbed,
                                 SHAKE_DOMAIN, out, outlen);
}

void pqc_shake256(uint8_t *out, size_t outlen,
                   const uint8_t *in, size_t inlen)
{
    uint64_t state[25];
    pqc_keccak_init(state);

    size_t absorbed = inlen % PQC_SHAKE256_RATE;
    pqc_keccak_absorb(state, PQC_SHAKE256_RATE, in, inlen);
    keccak_finalize_and_squeeze(state, PQC_SHAKE256_RATE, absorbed,
                                 SHAKE_DOMAIN, out, outlen);
}

/* ================================================================= */
/*  Incremental SHAKE-128                                              */
/* ================================================================= */

void pqc_shake128_init(pqc_shake128_ctx *ctx)
{
    pqc_keccak_init(ctx->state);
    ctx->bufpos    = 0;
    ctx->finalized = 0;
}

void pqc_shake128_absorb(pqc_shake128_ctx *ctx,
                          const uint8_t *data, size_t len)
{
    const size_t rate = PQC_SHAKE128_RATE;

    /* Fill the internal buffer first. */
    if (ctx->bufpos > 0) {
        size_t room = rate - ctx->bufpos;
        size_t take = len < room ? len : room;
        memcpy(ctx->buf + ctx->bufpos, data, take);
        ctx->bufpos += take;
        data += take;
        len  -= take;

        if (ctx->bufpos == rate) {
            /* Full block -- absorb it. */
            pqc_keccak_absorb(ctx->state, rate, ctx->buf, rate);
            ctx->bufpos = 0;
        }
    }

    /* Absorb full blocks directly. */
    if (len >= rate) {
        size_t full = (len / rate) * rate;
        pqc_keccak_absorb(ctx->state, rate, data, full);
        data += full;
        len  -= full;
    }

    /* Buffer the tail. */
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->bufpos = len;
    }
}

void pqc_shake128_finalize(pqc_shake128_ctx *ctx)
{
    const size_t rate = PQC_SHAKE128_RATE;

    /* XOR buffered partial block into state. */
    if (ctx->bufpos > 0) {
        /* Use keccak_absorb with a length < rate -- it will XOR but not
         * permute. */
        pqc_keccak_absorb(ctx->state, rate, ctx->buf, ctx->bufpos);
    }

    /* Apply SHAKE padding. */
    uint8_t pad[200];
    memset(pad, 0, sizeof(pad));
    pad[ctx->bufpos] = SHAKE_DOMAIN;
    pad[rate - 1]   |= 0x80;

    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t v = 0;
        for (unsigned j = 0; j < 8; j++) {
            v |= (uint64_t)pad[8 * i + j] << (8u * j);
        }
        ctx->state[i] ^= v;
    }

    pqc_keccak_f1600(ctx->state);
    ctx->bufpos    = rate; /* mark: next squeeze starts fresh */
    ctx->finalized = 1;
}

void pqc_shake128_squeeze(pqc_shake128_ctx *ctx,
                           uint8_t *out, size_t len)
{
    const size_t rate = PQC_SHAKE128_RATE;
    uint8_t block[PQC_SHAKE128_RATE];
    int need_serialize = 1;

    while (len > 0) {
        /* If we have consumed the current block, squeeze a new one. */
        if (ctx->bufpos >= rate) {
            /* After finalize, bufpos == rate and the state already holds
             * the first squeezed block.  On every subsequent exhaustion
             * we must permute to get a fresh block. */
            if (ctx->finalized == 1) {
                /* First entry after finalize -- block is ready. */
                ctx->finalized = 2; /* mark: first block consumed */
            } else {
                pqc_keccak_f1600(ctx->state);
            }
            ctx->bufpos = 0;
            need_serialize = 1;
        }

        /* Serialise the rate portion of the state when needed. */
        if (need_serialize) {
            for (size_t i = 0; i < rate / 8; i++) {
                for (unsigned j = 0; j < 8; j++) {
                    block[8 * i + j] = (uint8_t)(ctx->state[i] >> (8u * j));
                }
            }
            need_serialize = 0;
        }

        size_t avail = rate - ctx->bufpos;
        size_t take = len < avail ? len : avail;
        memcpy(out, block + ctx->bufpos, take);
        ctx->bufpos += take;
        out += take;
        len -= take;
    }
}

/* ================================================================= */
/*  Incremental SHAKE-256                                              */
/* ================================================================= */

void pqc_shake256_init(pqc_shake256_ctx *ctx)
{
    pqc_keccak_init(ctx->state);
    ctx->bufpos    = 0;
    ctx->finalized = 0;
}

void pqc_shake256_absorb(pqc_shake256_ctx *ctx,
                          const uint8_t *data, size_t len)
{
    const size_t rate = PQC_SHAKE256_RATE;

    if (ctx->bufpos > 0) {
        size_t room = rate - ctx->bufpos;
        size_t take = len < room ? len : room;
        memcpy(ctx->buf + ctx->bufpos, data, take);
        ctx->bufpos += take;
        data += take;
        len  -= take;

        if (ctx->bufpos == rate) {
            pqc_keccak_absorb(ctx->state, rate, ctx->buf, rate);
            ctx->bufpos = 0;
        }
    }

    if (len >= rate) {
        size_t full = (len / rate) * rate;
        pqc_keccak_absorb(ctx->state, rate, data, full);
        data += full;
        len  -= full;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->bufpos = len;
    }
}

void pqc_shake256_finalize(pqc_shake256_ctx *ctx)
{
    const size_t rate = PQC_SHAKE256_RATE;

    if (ctx->bufpos > 0) {
        pqc_keccak_absorb(ctx->state, rate, ctx->buf, ctx->bufpos);
    }

    uint8_t pad[200];
    memset(pad, 0, sizeof(pad));
    pad[ctx->bufpos] = SHAKE_DOMAIN;
    pad[rate - 1]   |= 0x80;

    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t v = 0;
        for (unsigned j = 0; j < 8; j++) {
            v |= (uint64_t)pad[8 * i + j] << (8u * j);
        }
        ctx->state[i] ^= v;
    }

    pqc_keccak_f1600(ctx->state);
    ctx->bufpos    = rate;
    ctx->finalized = 1;
}

void pqc_shake256_squeeze(pqc_shake256_ctx *ctx,
                           uint8_t *out, size_t len)
{
    const size_t rate = PQC_SHAKE256_RATE;
    uint8_t block[PQC_SHAKE256_RATE];
    int need_serialize = 1;

    while (len > 0) {
        if (ctx->bufpos >= rate) {
            if (ctx->finalized == 1) {
                ctx->finalized = 2;
            } else {
                pqc_keccak_f1600(ctx->state);
            }
            ctx->bufpos = 0;
            need_serialize = 1;
        }

        if (need_serialize) {
            for (size_t i = 0; i < rate / 8; i++) {
                for (unsigned j = 0; j < 8; j++) {
                    block[8 * i + j] = (uint8_t)(ctx->state[i] >> (8u * j));
                }
            }
            need_serialize = 0;
        }

        size_t avail = rate - ctx->bufpos;
        size_t take = len < avail ? len : avail;
        memcpy(out, block + ctx->bufpos, take);
        ctx->bufpos += take;
        out += take;
        len -= take;
    }
}
