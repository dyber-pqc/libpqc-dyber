/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SHA-3 (SHA3-256, SHA3-512) and SHAKE (SHAKE-128, SHAKE-256) for
 * libpqc-dyber, built on the Keccak-f[1600] sponge.
 *
 * Copyright (c) 2024-2026 Dyber, Inc.
 * Licensed under the Apache License, Version 2.0 or the MIT license,
 * at your option.
 */

#ifndef PQC_SHA3_H
#define PQC_SHA3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Output lengths (bytes) ------------------------------------ */
#define PQC_SHA3_256_BYTES  32
#define PQC_SHA3_512_BYTES  64

/* ----- Sponge rates (bytes) -------------------------------------- */
#define PQC_SHA3_256_RATE   136   /* (1600 - 2*256) / 8 = 136 */
#define PQC_SHA3_512_RATE    72   /* (1600 - 2*512) / 8 =  72 */
#define PQC_SHAKE128_RATE   168   /* (1600 - 2*128) / 8 = 168 */
#define PQC_SHAKE256_RATE   136   /* (1600 - 2*256) / 8 = 136 */

/* ================================================================= */
/*  One-shot SHA-3                                                     */
/* ================================================================= */

/**
 * Compute a SHA3-256 digest.
 *
 * @param out    32-byte output buffer.
 * @param in     Input data.
 * @param inlen  Length of input data in bytes.
 */
void pqc_sha3_256(uint8_t out[PQC_SHA3_256_BYTES],
                   const uint8_t *in, size_t inlen);

/**
 * Compute a SHA3-512 digest.
 *
 * @param out    64-byte output buffer.
 * @param in     Input data.
 * @param inlen  Length of input data in bytes.
 */
void pqc_sha3_512(uint8_t out[PQC_SHA3_512_BYTES],
                   const uint8_t *in, size_t inlen);

/* ================================================================= */
/*  One-shot SHAKE                                                     */
/* ================================================================= */

/**
 * SHAKE-128 extendable-output function.
 *
 * @param out     Output buffer.
 * @param outlen  Desired output length in bytes.
 * @param in      Input data.
 * @param inlen   Length of input data in bytes.
 */
void pqc_shake128(uint8_t *out, size_t outlen,
                   const uint8_t *in, size_t inlen);

/**
 * SHAKE-256 extendable-output function.
 *
 * @param out     Output buffer.
 * @param outlen  Desired output length in bytes.
 * @param in      Input data.
 * @param inlen   Length of input data in bytes.
 */
void pqc_shake256(uint8_t *out, size_t outlen,
                   const uint8_t *in, size_t inlen);

/* ================================================================= */
/*  Incremental SHAKE-128                                              */
/* ================================================================= */

/**
 * Incremental SHAKE-128 context.
 */
typedef struct {
    uint64_t state[25];
    uint8_t  buf[PQC_SHAKE128_RATE];
    size_t   bufpos;
    int      finalized;
} pqc_shake128_ctx;

void pqc_shake128_init(pqc_shake128_ctx *ctx);
void pqc_shake128_absorb(pqc_shake128_ctx *ctx,
                          const uint8_t *data, size_t len);
void pqc_shake128_finalize(pqc_shake128_ctx *ctx);
void pqc_shake128_squeeze(pqc_shake128_ctx *ctx,
                           uint8_t *out, size_t len);

/* ================================================================= */
/*  Incremental SHAKE-256                                              */
/* ================================================================= */

/**
 * Incremental SHAKE-256 context.
 */
typedef struct {
    uint64_t state[25];
    uint8_t  buf[PQC_SHAKE256_RATE];
    size_t   bufpos;
    int      finalized;
} pqc_shake256_ctx;

void pqc_shake256_init(pqc_shake256_ctx *ctx);
void pqc_shake256_absorb(pqc_shake256_ctx *ctx,
                          const uint8_t *data, size_t len);
void pqc_shake256_finalize(pqc_shake256_ctx *ctx);
void pqc_shake256_squeeze(pqc_shake256_ctx *ctx,
                           uint8_t *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_SHA3_H */
