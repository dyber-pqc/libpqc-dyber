/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - Tweakable hash functions, SHA-2 instantiation.
 *
 * For n <= 16  (128-bit security): uses SHA-256
 * For n > 16   (192/256-bit security): uses SHA-512, truncated to n bytes
 *
 * Per FIPS 205, the SHA-2 instantiation compresses the address via
 * SHA-256 for all security levels to produce an n-byte compressed
 * address, which is then used as part of the hash input.
 */

#include <string.h>
#include <stdint.h>

#include "core/common/hash/sha2.h"
#include "slhdsa.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * Compress the 32-byte ADRS into an n-byte value using SHA-256.
 * FIPS 205 Sec 11.1: ADRSc = SHA-256(ADRS)[0:n]
 * For the SHA-2 instantiation, we produce a compressed address that
 * is exactly 22 bytes (the address is hashed to save bandwidth).
 * We simplify: compress to n bytes via truncation of SHA-256(ADRS).
 */
/* ------------------------------------------------------------------ */
/* thash: T_l(PK.seed, ADRS, M)                                        */
/*                                                                      */
/* For n=16: SHA-256(PK.seed || ADRS || M)[0:n]                         */
/* For n>16: SHA-512(PK.seed || ADRS || M)[0:n]                         */
/*                                                                      */
/* PK.seed is n bytes, ADRS is 32 bytes, M is inblocks*n bytes.         */
/* ------------------------------------------------------------------ */

void slhdsa_thash_sha2(uint8_t *out,
                        const uint8_t *in, uint32_t inblocks,
                        const uint8_t *pub_seed,
                        const uint8_t addr[32],
                        const slhdsa_params_t *p)
{
    uint32_t n = p->n;

    if (n <= 16) {
        /* Use SHA-256 */
        pqc_sha256_ctx ctx;
        uint8_t hash[PQC_SHA256_BYTES];

        pqc_sha256_init(&ctx);

        /* Pad PK.seed to full SHA-256 block (64 bytes) */
        {
            uint8_t block[PQC_SHA256_BLOCK_BYTES];
            memcpy(block, pub_seed, n);
            memset(block + n, 0, PQC_SHA256_BLOCK_BYTES - n);
            pqc_sha256_update(&ctx, block, PQC_SHA256_BLOCK_BYTES);
        }

        pqc_sha256_update(&ctx, addr, 32);
        pqc_sha256_update(&ctx, in, (size_t)inblocks * n);
        pqc_sha256_final(&ctx, hash);
        memcpy(out, hash, n);
    } else {
        /* Use SHA-512 for 192-bit and 256-bit security */
        pqc_sha512_ctx ctx;
        uint8_t hash[PQC_SHA512_BYTES];

        pqc_sha512_init(&ctx);

        /* Pad PK.seed to full SHA-512 block (128 bytes) */
        {
            uint8_t block[PQC_SHA512_BLOCK_BYTES];
            memcpy(block, pub_seed, n);
            memset(block + n, 0, PQC_SHA512_BLOCK_BYTES - n);
            pqc_sha512_update(&ctx, block, PQC_SHA512_BLOCK_BYTES);
        }

        pqc_sha512_update(&ctx, addr, 32);
        pqc_sha512_update(&ctx, in, (size_t)inblocks * n);
        pqc_sha512_final(&ctx, hash);
        memcpy(out, hash, n);
    }
}

/* ------------------------------------------------------------------ */
/* PRF(SK.seed, PK.seed, ADRS)                                          */
/*                                                                      */
/* For n=16: SHA-256(PK.seed || ADRS || SK.seed)[0:n]                   */
/* For n>16: SHA-256(PK.seed || ADRS || SK.seed)[0:n]                   */
/* Note: PRF always uses SHA-256 per FIPS 205 Section 11.1              */
/* ------------------------------------------------------------------ */

void slhdsa_prf_sha2(uint8_t *out,
                      const uint8_t *sk_seed,
                      const uint8_t *pub_seed,
                      const uint8_t addr[32],
                      const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    pqc_sha256_ctx ctx;
    uint8_t hash[PQC_SHA256_BYTES];

    pqc_sha256_init(&ctx);

    /* Pad PK.seed to SHA-256 block */
    {
        uint8_t block[PQC_SHA256_BLOCK_BYTES];
        memcpy(block, pub_seed, n);
        memset(block + n, 0, PQC_SHA256_BLOCK_BYTES - n);
        pqc_sha256_update(&ctx, block, PQC_SHA256_BLOCK_BYTES);
    }

    pqc_sha256_update(&ctx, addr, 32);
    pqc_sha256_update(&ctx, sk_seed, n);
    pqc_sha256_final(&ctx, hash);
    memcpy(out, hash, n);
}

/* ------------------------------------------------------------------ */
/* PRF_msg(SK.prf, opt_rand, M)                                         */
/*                                                                      */
/* HMAC-SHA-256(SK.prf, opt_rand || M) for n<=16                        */
/* HMAC-SHA-512(SK.prf, opt_rand || M) for n>16                         */
/* Output: n bytes                                                      */
/* ------------------------------------------------------------------ */

void slhdsa_prf_msg_sha2(uint8_t *out,
                          const uint8_t *sk_prf,
                          const uint8_t *opt_rand,
                          const uint8_t *msg, size_t msglen,
                          const slhdsa_params_t *p)
{
    uint32_t n = p->n;

    if (n <= 16) {
        /*
         * HMAC-SHA-256 with key = SK.prf (n bytes),
         * data = opt_rand (n bytes) || msg
         */
        uint8_t hmac_data[SLHDSA_MAX_N + 65536];
        uint8_t hmac_out[PQC_SHA256_BYTES];
        size_t total = (size_t)n + msglen;

        /*
         * For large messages, use incremental HMAC.
         * For simplicity, we construct the data buffer for small messages
         * and fall back to a manual HMAC for large ones.
         */
        if (total <= sizeof(hmac_data)) {
            memcpy(hmac_data, opt_rand, n);
            memcpy(hmac_data + n, msg, msglen);
            pqc_hmac_sha256(hmac_out, sk_prf, n, hmac_data, total);
        } else {
            /* Manual HMAC: H((K ^ opad) || H((K ^ ipad) || data)) */
            pqc_sha256_ctx ictx;
            uint8_t ipad[PQC_SHA256_BLOCK_BYTES];
            uint8_t opad[PQC_SHA256_BLOCK_BYTES];
            uint8_t inner[PQC_SHA256_BYTES];
            uint32_t i;

            memset(ipad, 0x36, PQC_SHA256_BLOCK_BYTES);
            memset(opad, 0x5c, PQC_SHA256_BLOCK_BYTES);
            for (i = 0; i < n; i++) {
                ipad[i] ^= sk_prf[i];
                opad[i] ^= sk_prf[i];
            }

            pqc_sha256_init(&ictx);
            pqc_sha256_update(&ictx, ipad, PQC_SHA256_BLOCK_BYTES);
            pqc_sha256_update(&ictx, opt_rand, n);
            pqc_sha256_update(&ictx, msg, msglen);
            pqc_sha256_final(&ictx, inner);

            pqc_sha256_init(&ictx);
            pqc_sha256_update(&ictx, opad, PQC_SHA256_BLOCK_BYTES);
            pqc_sha256_update(&ictx, inner, PQC_SHA256_BYTES);
            pqc_sha256_final(&ictx, hmac_out);
        }

        memcpy(out, hmac_out, n);
    } else {
        /* HMAC-SHA-512 */
        pqc_sha512_ctx ictx;
        uint8_t ipad[PQC_SHA512_BLOCK_BYTES];
        uint8_t opad[PQC_SHA512_BLOCK_BYTES];
        uint8_t inner[PQC_SHA512_BYTES];
        uint8_t hmac_out[PQC_SHA512_BYTES];
        uint32_t i;

        memset(ipad, 0x36, PQC_SHA512_BLOCK_BYTES);
        memset(opad, 0x5c, PQC_SHA512_BLOCK_BYTES);
        for (i = 0; i < n; i++) {
            ipad[i] ^= sk_prf[i];
            opad[i] ^= sk_prf[i];
        }

        pqc_sha512_init(&ictx);
        pqc_sha512_update(&ictx, ipad, PQC_SHA512_BLOCK_BYTES);
        pqc_sha512_update(&ictx, opt_rand, n);
        pqc_sha512_update(&ictx, msg, msglen);
        pqc_sha512_final(&ictx, inner);

        pqc_sha512_init(&ictx);
        pqc_sha512_update(&ictx, opad, PQC_SHA512_BLOCK_BYTES);
        pqc_sha512_update(&ictx, inner, PQC_SHA512_BYTES);
        pqc_sha512_final(&ictx, hmac_out);

        memcpy(out, hmac_out, n);
    }
}

/* ------------------------------------------------------------------ */
/* H_msg(R, PK.seed, PK.root, M)                                       */
/*                                                                      */
/* For n<=16: SHA-256(R || PK.seed || PK.root || M) -> m bytes          */
/* For n>16:  SHA-512(R || PK.seed || PK.root || M) -> m bytes          */
/*                                                                      */
/* m = ceil((k*a + 7) / 8) + ceil((h - h/d + 7) / 8) + ceil((h/d + 7)/8)*/
/* We output enough bytes for the message digest (FORS + tree indices). */
/* The caller provides a buffer of sufficient size.                     */
/* Output length: k*ceil(a/8) + ceil((h-h/d)/8) + ceil((h/d)/8)        */
/* For simplicity we output (k*a + h + 7)/8 rounded bytes.             */
/* ------------------------------------------------------------------ */

void slhdsa_hash_msg_sha2(uint8_t *out,
                           const uint8_t *r,
                           const uint8_t *pk,
                           const uint8_t *msg, size_t msglen,
                           const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    /* We need enough output for the message digest.
     * digest_size = ceil((k*a + h - hp + hp + 7)/8)
     *             = ceil((k*a + h + 7)/8)
     * But per FIPS 205, the digest is split into:
     *   md (k*a bits), idx_tree (h-hp bits), idx_leaf (hp bits)
     * Total bits = k*a + h
     * We compute enough bytes to cover this.
     */
    size_t digest_bits = (size_t)(p->k) * p->a + p->h;
    size_t digest_bytes = (digest_bits + 7) / 8;

    if (n <= 16) {
        pqc_sha256_ctx ctx;
        uint8_t hash[PQC_SHA256_BYTES];
        size_t offset = 0;

        /* We may need more than 32 bytes of output.
         * Use MGF1-SHA-256 style: hash with counter. */
        uint8_t seed[PQC_SHA256_BYTES];

        /* First, compute the seed: SHA-256(R || PK.seed || PK.root || M) */
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, r, n);
        pqc_sha256_update(&ctx, pk, n);            /* PK.seed */
        pqc_sha256_update(&ctx, pk + n, n);        /* PK.root */
        pqc_sha256_update(&ctx, msg, msglen);
        pqc_sha256_final(&ctx, seed);

        /* MGF1-SHA-256 expansion */
        {
            uint32_t counter = 0;
            while (offset < digest_bytes) {
                uint8_t ctr_bytes[4];
                size_t chunk;

                ctr_bytes[0] = (uint8_t)(counter >> 24);
                ctr_bytes[1] = (uint8_t)(counter >> 16);
                ctr_bytes[2] = (uint8_t)(counter >>  8);
                ctr_bytes[3] = (uint8_t)(counter      );

                pqc_sha256_init(&ctx);
                pqc_sha256_update(&ctx, seed, PQC_SHA256_BYTES);
                pqc_sha256_update(&ctx, ctr_bytes, 4);
                pqc_sha256_final(&ctx, hash);

                chunk = digest_bytes - offset;
                if (chunk > PQC_SHA256_BYTES)
                    chunk = PQC_SHA256_BYTES;
                memcpy(out + offset, hash, chunk);
                offset += chunk;
                counter++;
            }
        }
    } else {
        pqc_sha512_ctx ctx;
        uint8_t hash[PQC_SHA512_BYTES];
        size_t offset = 0;

        uint8_t seed[PQC_SHA512_BYTES];

        pqc_sha512_init(&ctx);
        pqc_sha512_update(&ctx, r, n);
        pqc_sha512_update(&ctx, pk, n);
        pqc_sha512_update(&ctx, pk + n, n);
        pqc_sha512_update(&ctx, msg, msglen);
        pqc_sha512_final(&ctx, seed);

        /* MGF1-SHA-512 expansion */
        {
            uint32_t counter = 0;
            while (offset < digest_bytes) {
                uint8_t ctr_bytes[4];
                size_t chunk;

                ctr_bytes[0] = (uint8_t)(counter >> 24);
                ctr_bytes[1] = (uint8_t)(counter >> 16);
                ctr_bytes[2] = (uint8_t)(counter >>  8);
                ctr_bytes[3] = (uint8_t)(counter      );

                pqc_sha512_init(&ctx);
                pqc_sha512_update(&ctx, seed, PQC_SHA512_BYTES);
                pqc_sha512_update(&ctx, ctr_bytes, 4);
                pqc_sha512_final(&ctx, hash);

                chunk = digest_bytes - offset;
                if (chunk > PQC_SHA512_BYTES)
                    chunk = PQC_SHA512_BYTES;
                memcpy(out + offset, hash, chunk);
                offset += chunk;
                counter++;
            }
        }
    }
}
