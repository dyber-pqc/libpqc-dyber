/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SHA-2 family (SHA-256, SHA-512) and HMAC for libpqc-dyber.
 *
 * Copyright (c) 2024-2026 Dyber, Inc.
 * Licensed under the Apache License, Version 2.0 or the MIT license,
 * at your option.
 */

#ifndef PQC_SHA2_H
#define PQC_SHA2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Output / block sizes (bytes) ------------------------------ */
#define PQC_SHA256_BYTES       32
#define PQC_SHA256_BLOCK_BYTES 64

#define PQC_SHA512_BYTES       64
#define PQC_SHA512_BLOCK_BYTES 128

/* ================================================================= */
/*  SHA-256 incremental API                                            */
/* ================================================================= */

typedef struct {
    uint32_t state[8];
    uint8_t  buf[PQC_SHA256_BLOCK_BYTES];
    uint64_t count;  /* total bytes hashed so far */
} pqc_sha256_ctx;

void pqc_sha256_init(pqc_sha256_ctx *ctx);
void pqc_sha256_update(pqc_sha256_ctx *ctx,
                        const uint8_t *data, size_t len);
void pqc_sha256_final(pqc_sha256_ctx *ctx,
                       uint8_t out[PQC_SHA256_BYTES]);

/** One-shot SHA-256. */
void pqc_sha256(uint8_t out[PQC_SHA256_BYTES],
                 const uint8_t *in, size_t inlen);

/* ================================================================= */
/*  SHA-512 incremental API                                            */
/* ================================================================= */

typedef struct {
    uint64_t state[8];
    uint8_t  buf[PQC_SHA512_BLOCK_BYTES];
    uint64_t count;  /* total bytes hashed so far */
} pqc_sha512_ctx;

void pqc_sha512_init(pqc_sha512_ctx *ctx);
void pqc_sha512_update(pqc_sha512_ctx *ctx,
                        const uint8_t *data, size_t len);
void pqc_sha512_final(pqc_sha512_ctx *ctx,
                       uint8_t out[PQC_SHA512_BYTES]);

/** One-shot SHA-512. */
void pqc_sha512(uint8_t out[PQC_SHA512_BYTES],
                 const uint8_t *in, size_t inlen);

/* ================================================================= */
/*  HMAC                                                               */
/* ================================================================= */

/**
 * HMAC-SHA-256.
 *
 * @param out      32-byte MAC output.
 * @param key      HMAC key.
 * @param keylen   Length of key in bytes.
 * @param data     Message data.
 * @param datalen  Length of data in bytes.
 */
void pqc_hmac_sha256(uint8_t out[PQC_SHA256_BYTES],
                      const uint8_t *key, size_t keylen,
                      const uint8_t *data, size_t datalen);

/**
 * HMAC-SHA-512.
 *
 * @param out      64-byte MAC output.
 * @param key      HMAC key.
 * @param keylen   Length of key in bytes.
 * @param data     Message data.
 * @param datalen  Length of data in bytes.
 */
void pqc_hmac_sha512(uint8_t out[PQC_SHA512_BYTES],
                      const uint8_t *key, size_t keylen,
                      const uint8_t *data, size_t datalen);

#ifdef __cplusplus
}
#endif

#endif /* PQC_SHA2_H */
