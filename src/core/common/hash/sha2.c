/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SHA-2 family (SHA-256, SHA-512) and HMAC -- portable C11 implementation.
 *
 * Copyright (c) 2024-2026 Dyber, Inc.
 * Licensed under the Apache License, Version 2.0 or the MIT license,
 * at your option.
 */

#include "core/common/hash/sha2.h"
#include <string.h>

/* ================================================================= */
/*  Helpers                                                            */
/* ================================================================= */

static inline uint32_t rotr32(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32u - n));
}

static inline uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64u - n));
}

/* Big-endian load / store ----------------------------------------- */

static inline uint32_t load32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) | ((uint32_t)p[3]);
}

static inline void store32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

static inline uint64_t load64_be(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
         | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
         | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
         | ((uint64_t)p[6] <<  8) | ((uint64_t)p[7]);
}

static inline void store64_be(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >>  8);
    p[7] = (uint8_t)(v);
}

/* ================================================================= */
/*  SHA-256                                                            */
/* ================================================================= */

/* SHA-256 round constants (first 32 bits of the fractional parts of
 * the cube roots of the first 64 primes). */
static const uint32_t sha256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/* SHA-256 logical functions */
#define SHA256_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_BSIG0(x) (rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22))
#define SHA256_BSIG1(x) (rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25))
#define SHA256_SSIG0(x) (rotr32(x, 7) ^ rotr32(x, 18) ^ ((x) >> 3))
#define SHA256_SSIG1(x) (rotr32(x, 17) ^ rotr32(x, 19) ^ ((x) >> 10))

/* Process a single 64-byte block. */
static void sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    int t;

    /* Prepare the message schedule. */
    for (t = 0; t < 16; t++) {
        W[t] = load32_be(block + 4 * t);
    }
    for (t = 16; t < 64; t++) {
        W[t] = SHA256_SSIG1(W[t - 2]) + W[t - 7]
             + SHA256_SSIG0(W[t - 15]) + W[t - 16];
    }

    /* Initialise working variables. */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 64 rounds. */
    for (t = 0; t < 64; t++) {
        T1 = h + SHA256_BSIG1(e) + SHA256_CH(e, f, g) + sha256_K[t] + W[t];
        T2 = SHA256_BSIG0(a) + SHA256_MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    /* Add the compressed chunk to the current hash value. */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void pqc_sha256_init(pqc_sha256_ctx *ctx)
{
    /* Initial hash values (first 32 bits of the fractional parts of
     * the square roots of the first 8 primes). */
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void pqc_sha256_update(pqc_sha256_ctx *ctx,
                        const uint8_t *data, size_t len)
{
    size_t buffered = (size_t)(ctx->count % PQC_SHA256_BLOCK_BYTES);

    ctx->count += len;

    /* Fill partial buffer. */
    if (buffered > 0) {
        size_t room = PQC_SHA256_BLOCK_BYTES - buffered;
        size_t take = len < room ? len : room;
        memcpy(ctx->buf + buffered, data, take);
        data += take;
        len  -= take;
        buffered += take;

        if (buffered == PQC_SHA256_BLOCK_BYTES) {
            sha256_compress(ctx->state, ctx->buf);
            buffered = 0;
        }
    }

    /* Process full blocks. */
    while (len >= PQC_SHA256_BLOCK_BYTES) {
        sha256_compress(ctx->state, data);
        data += PQC_SHA256_BLOCK_BYTES;
        len  -= PQC_SHA256_BLOCK_BYTES;
    }

    /* Buffer remaining data. */
    if (len > 0) {
        memcpy(ctx->buf, data, len);
    }
}

void pqc_sha256_final(pqc_sha256_ctx *ctx, uint8_t out[PQC_SHA256_BYTES])
{
    uint64_t bits = ctx->count * 8;
    size_t buffered = (size_t)(ctx->count % PQC_SHA256_BLOCK_BYTES);

    /* Append the 0x80 byte. */
    ctx->buf[buffered++] = 0x80;

    /* If there is not enough room for the 8-byte length, pad and compress. */
    if (buffered > 56) {
        memset(ctx->buf + buffered, 0, PQC_SHA256_BLOCK_BYTES - buffered);
        sha256_compress(ctx->state, ctx->buf);
        buffered = 0;
    }

    /* Pad with zeros up to the length field. */
    memset(ctx->buf + buffered, 0, 56 - buffered);

    /* Append big-endian bit count. */
    store64_be(ctx->buf + 56, bits);
    sha256_compress(ctx->state, ctx->buf);

    /* Write output in big-endian. */
    for (int i = 0; i < 8; i++) {
        store32_be(out + 4 * i, ctx->state[i]);
    }

    /* Wipe context. */
    memset(ctx, 0, sizeof(*ctx));
}

void pqc_sha256(uint8_t out[PQC_SHA256_BYTES],
                 const uint8_t *in, size_t inlen)
{
    pqc_sha256_ctx ctx;
    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, in, inlen);
    pqc_sha256_final(&ctx, out);
}

/* ================================================================= */
/*  SHA-512                                                            */
/* ================================================================= */

static const uint64_t sha512_K[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

#define SHA512_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA512_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA512_BSIG0(x) (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39))
#define SHA512_BSIG1(x) (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41))
#define SHA512_SSIG0(x) (rotr64(x,  1) ^ rotr64(x,  8) ^ ((x) >> 7))
#define SHA512_SSIG1(x) (rotr64(x, 19) ^ rotr64(x, 61) ^ ((x) >> 6))

static void sha512_compress(uint64_t state[8], const uint8_t block[128])
{
    uint64_t W[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t T1, T2;
    int t;

    for (t = 0; t < 16; t++) {
        W[t] = load64_be(block + 8 * t);
    }
    for (t = 16; t < 80; t++) {
        W[t] = SHA512_SSIG1(W[t - 2]) + W[t - 7]
             + SHA512_SSIG0(W[t - 15]) + W[t - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (t = 0; t < 80; t++) {
        T1 = h + SHA512_BSIG1(e) + SHA512_CH(e, f, g) + sha512_K[t] + W[t];
        T2 = SHA512_BSIG0(a) + SHA512_MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void pqc_sha512_init(pqc_sha512_ctx *ctx)
{
    ctx->state[0] = UINT64_C(0x6a09e667f3bcc908);
    ctx->state[1] = UINT64_C(0xbb67ae8584caa73b);
    ctx->state[2] = UINT64_C(0x3c6ef372fe94f82b);
    ctx->state[3] = UINT64_C(0xa54ff53a5f1d36f1);
    ctx->state[4] = UINT64_C(0x510e527fade682d1);
    ctx->state[5] = UINT64_C(0x9b05688c2b3e6c1f);
    ctx->state[6] = UINT64_C(0x1f83d9abfb41bd6b);
    ctx->state[7] = UINT64_C(0x5be0cd19137e2179);
    ctx->count = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void pqc_sha512_update(pqc_sha512_ctx *ctx,
                        const uint8_t *data, size_t len)
{
    size_t buffered = (size_t)(ctx->count % PQC_SHA512_BLOCK_BYTES);

    ctx->count += len;

    if (buffered > 0) {
        size_t room = PQC_SHA512_BLOCK_BYTES - buffered;
        size_t take = len < room ? len : room;
        memcpy(ctx->buf + buffered, data, take);
        data += take;
        len  -= take;
        buffered += take;

        if (buffered == PQC_SHA512_BLOCK_BYTES) {
            sha512_compress(ctx->state, ctx->buf);
            buffered = 0;
        }
    }

    while (len >= PQC_SHA512_BLOCK_BYTES) {
        sha512_compress(ctx->state, data);
        data += PQC_SHA512_BLOCK_BYTES;
        len  -= PQC_SHA512_BLOCK_BYTES;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
    }
}

void pqc_sha512_final(pqc_sha512_ctx *ctx, uint8_t out[PQC_SHA512_BYTES])
{
    uint64_t bits = ctx->count * 8;
    size_t buffered = (size_t)(ctx->count % PQC_SHA512_BLOCK_BYTES);

    ctx->buf[buffered++] = 0x80;

    /* Need 16 bytes for the 128-bit length (we only use the low 64 bits,
     * so the high 8 bytes are zero). */
    if (buffered > 112) {
        memset(ctx->buf + buffered, 0, PQC_SHA512_BLOCK_BYTES - buffered);
        sha512_compress(ctx->state, ctx->buf);
        buffered = 0;
    }

    memset(ctx->buf + buffered, 0, 120 - buffered);

    /* High 64 bits of length (always zero for < 2^64 bytes). */
    store64_be(ctx->buf + 112, 0);
    /* Low 64 bits of length. */
    store64_be(ctx->buf + 120, bits);

    sha512_compress(ctx->state, ctx->buf);

    for (int i = 0; i < 8; i++) {
        store64_be(out + 8 * i, ctx->state[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void pqc_sha512(uint8_t out[PQC_SHA512_BYTES],
                 const uint8_t *in, size_t inlen)
{
    pqc_sha512_ctx ctx;
    pqc_sha512_init(&ctx);
    pqc_sha512_update(&ctx, in, inlen);
    pqc_sha512_final(&ctx, out);
}

/* ================================================================= */
/*  HMAC                                                               */
/* ================================================================= */

void pqc_hmac_sha256(uint8_t out[PQC_SHA256_BYTES],
                      const uint8_t *key, size_t keylen,
                      const uint8_t *data, size_t datalen)
{
    pqc_sha256_ctx inner, outer;
    uint8_t k_padded[PQC_SHA256_BLOCK_BYTES];
    uint8_t inner_hash[PQC_SHA256_BYTES];
    size_t i;

    memset(k_padded, 0, sizeof(k_padded));

    /* If the key is longer than the block size, hash it first. */
    if (keylen > PQC_SHA256_BLOCK_BYTES) {
        pqc_sha256(k_padded, key, keylen);
    } else {
        memcpy(k_padded, key, keylen);
    }

    /* Inner hash: SHA-256( (K ^ ipad) || data ) */
    pqc_sha256_init(&inner);
    {
        uint8_t ipad_block[PQC_SHA256_BLOCK_BYTES];
        for (i = 0; i < PQC_SHA256_BLOCK_BYTES; i++) {
            ipad_block[i] = k_padded[i] ^ 0x36;
        }
        pqc_sha256_update(&inner, ipad_block, PQC_SHA256_BLOCK_BYTES);
    }
    pqc_sha256_update(&inner, data, datalen);
    pqc_sha256_final(&inner, inner_hash);

    /* Outer hash: SHA-256( (K ^ opad) || inner_hash ) */
    pqc_sha256_init(&outer);
    {
        uint8_t opad_block[PQC_SHA256_BLOCK_BYTES];
        for (i = 0; i < PQC_SHA256_BLOCK_BYTES; i++) {
            opad_block[i] = k_padded[i] ^ 0x5c;
        }
        pqc_sha256_update(&outer, opad_block, PQC_SHA256_BLOCK_BYTES);
    }
    pqc_sha256_update(&outer, inner_hash, PQC_SHA256_BYTES);
    pqc_sha256_final(&outer, out);

    /* Wipe sensitive material. */
    memset(k_padded, 0, sizeof(k_padded));
    memset(inner_hash, 0, sizeof(inner_hash));
}

void pqc_hmac_sha512(uint8_t out[PQC_SHA512_BYTES],
                      const uint8_t *key, size_t keylen,
                      const uint8_t *data, size_t datalen)
{
    pqc_sha512_ctx inner, outer;
    uint8_t k_padded[PQC_SHA512_BLOCK_BYTES];
    uint8_t inner_hash[PQC_SHA512_BYTES];
    size_t i;

    memset(k_padded, 0, sizeof(k_padded));

    if (keylen > PQC_SHA512_BLOCK_BYTES) {
        pqc_sha512(k_padded, key, keylen);
    } else {
        memcpy(k_padded, key, keylen);
    }

    /* Inner hash */
    pqc_sha512_init(&inner);
    {
        uint8_t ipad_block[PQC_SHA512_BLOCK_BYTES];
        for (i = 0; i < PQC_SHA512_BLOCK_BYTES; i++) {
            ipad_block[i] = k_padded[i] ^ 0x36;
        }
        pqc_sha512_update(&inner, ipad_block, PQC_SHA512_BLOCK_BYTES);
    }
    pqc_sha512_update(&inner, data, datalen);
    pqc_sha512_final(&inner, inner_hash);

    /* Outer hash */
    pqc_sha512_init(&outer);
    {
        uint8_t opad_block[PQC_SHA512_BLOCK_BYTES];
        for (i = 0; i < PQC_SHA512_BLOCK_BYTES; i++) {
            opad_block[i] = k_padded[i] ^ 0x5c;
        }
        pqc_sha512_update(&outer, opad_block, PQC_SHA512_BLOCK_BYTES);
    }
    pqc_sha512_update(&outer, inner_hash, PQC_SHA512_BYTES);
    pqc_sha512_final(&outer, out);

    memset(k_padded, 0, sizeof(k_padded));
    memset(inner_hash, 0, sizeof(inner_hash));
}
