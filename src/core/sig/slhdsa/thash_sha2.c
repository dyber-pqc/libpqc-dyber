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

/* ------------------------------------------------------------------ */
/* FIPS 205 section 11.2. With ADRSc the 22-byte compressed address:    */
/*                                                                      */
/*   PRF, F        SHA-256(PK.seed || 0^(64-n)  || ADRSc || M)[0:n]     */
/*   H, T_l, n=16  SHA-256(PK.seed || 0^(64-n)  || ADRSc || M)[0:n]     */
/*   H, T_l, n>16  SHA-512(PK.seed || 0^(128-n) || ADRSc || M)[0:n]     */
/*                                                                      */
/* F and PRF stay on SHA-256 at every security category (11.2.2).       */
/*                                                                      */
/* Until 0.3.0 this hashed the uncompressed 32-byte ADRS, and used      */
/* SHA-512 for F as well at n > 16.                                     */
/* ------------------------------------------------------------------ */

static void sha256_tweak(uint8_t *out,
                         const uint8_t *pub_seed, const uint8_t addr[32],
                         const uint8_t *in, size_t inlen, uint32_t n)
{
    pqc_sha256_ctx ctx;
    uint8_t block[PQC_SHA256_BLOCK_BYTES];
    uint8_t adrsc[SLHDSA_ADRSC_BYTES];
    uint8_t hash[PQC_SHA256_BYTES];

    memcpy(block, pub_seed, n);
    memset(block + n, 0, PQC_SHA256_BLOCK_BYTES - n);
    slhdsa_compress_addr(adrsc, addr);

    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, block, PQC_SHA256_BLOCK_BYTES);
    pqc_sha256_update(&ctx, adrsc, SLHDSA_ADRSC_BYTES);
    pqc_sha256_update(&ctx, in, inlen);
    pqc_sha256_final(&ctx, hash);
    memcpy(out, hash, n);
}

static void sha512_tweak(uint8_t *out,
                         const uint8_t *pub_seed, const uint8_t addr[32],
                         const uint8_t *in, size_t inlen, uint32_t n)
{
    pqc_sha512_ctx ctx;
    uint8_t block[PQC_SHA512_BLOCK_BYTES];
    uint8_t adrsc[SLHDSA_ADRSC_BYTES];
    uint8_t hash[PQC_SHA512_BYTES];

    memcpy(block, pub_seed, n);
    memset(block + n, 0, PQC_SHA512_BLOCK_BYTES - n);
    slhdsa_compress_addr(adrsc, addr);

    pqc_sha512_init(&ctx);
    pqc_sha512_update(&ctx, block, PQC_SHA512_BLOCK_BYTES);
    pqc_sha512_update(&ctx, adrsc, SLHDSA_ADRSC_BYTES);
    pqc_sha512_update(&ctx, in, inlen);
    pqc_sha512_final(&ctx, hash);
    memcpy(out, hash, n);
}

/* T_l / H / F: inblocks == 1 is F. */
void slhdsa_thash_sha2(uint8_t *out,
                        const uint8_t *in, uint32_t inblocks,
                        const uint8_t *pub_seed,
                        const uint8_t addr[32],
                        const slhdsa_params_t *p)
{
    uint32_t n = p->n;

    if (n <= 16 || inblocks == 1)
        sha256_tweak(out, pub_seed, addr, in, (size_t)inblocks * n, n);
    else
        sha512_tweak(out, pub_seed, addr, in, (size_t)inblocks * n, n);
}

void slhdsa_prf_sha2(uint8_t *out,
                      const uint8_t *sk_seed,
                      const uint8_t *pub_seed,
                      const uint8_t addr[32],
                      const slhdsa_params_t *p)
{
    sha256_tweak(out, pub_seed, addr, sk_seed, p->n, p->n);
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
                          const uint8_t *pfx, size_t pfxlen,
                          const uint8_t *msg, size_t msglen,
                          const slhdsa_params_t *p)
{
    uint32_t n = p->n;

    if (n <= 16) {
        /*
         * HMAC-SHA-256(SK.prf, opt_rand || pfx || M), streamed so the
         * message length is unbounded. (An earlier version copied short
         * messages into a 64 KiB stack buffer first.)
         */
        pqc_sha256_ctx ictx;
        uint8_t ipad[PQC_SHA256_BLOCK_BYTES];
        uint8_t opad[PQC_SHA256_BLOCK_BYTES];
        uint8_t inner[PQC_SHA256_BYTES];
        uint8_t hmac_out[PQC_SHA256_BYTES];
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
        if (pfxlen)
            pqc_sha256_update(&ictx, pfx, pfxlen);
        pqc_sha256_update(&ictx, msg, msglen);
        pqc_sha256_final(&ictx, inner);

        pqc_sha256_init(&ictx);
        pqc_sha256_update(&ictx, opad, PQC_SHA256_BLOCK_BYTES);
        pqc_sha256_update(&ictx, inner, PQC_SHA256_BYTES);
        pqc_sha256_final(&ictx, hmac_out);

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
        if (pfxlen)
            pqc_sha512_update(&ictx, pfx, pfxlen);
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
/* H_msg(R, PK.seed, PK.root, M')                                      */
/*                                                                      */
/*   n = 16: MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed ||       */
/*                         PK.root || M'), m)                           */
/*   n > 16: the same with SHA-512                                      */
/*                                                                      */
/* m is slhdsa_hmsg_bytes(): ceil(k*a/8) + ceil((h-h/d)/8) + ceil(h/d/8) */
/* ------------------------------------------------------------------ */

void slhdsa_hash_msg_sha2(uint8_t *out,
                           const uint8_t *r,
                           const uint8_t *pk,
                           const uint8_t *pfx, size_t pfxlen,
                           const uint8_t *msg, size_t msglen,
                           const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    size_t digest_bytes = slhdsa_hmsg_bytes(p);  /* FIPS 205 m; see slhdsa_params.h */

    if (n <= 16) {
        pqc_sha256_ctx ctx;
        uint8_t hash[PQC_SHA256_BYTES];
        size_t offset = 0;

        /* We may need more than 32 bytes of output.
         * Use MGF1-SHA-256 style: hash with counter. */
        uint8_t seed[PQC_SHA256_BYTES];

        /* FIPS 205 section 11.2.1:
         *   H_msg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed ||
         *                        PK.root || M), m)
         * Until 0.3.0 the MGF1 seed omitted the leading R || PK.seed. */
        uint8_t mgf_seed[2 * 16 + PQC_SHA256_BYTES];

        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, r, n);
        pqc_sha256_update(&ctx, pk, n);            /* PK.seed */
        pqc_sha256_update(&ctx, pk + n, n);        /* PK.root */
        if (pfxlen)
            pqc_sha256_update(&ctx, pfx, pfxlen);
        pqc_sha256_update(&ctx, msg, msglen);
        pqc_sha256_final(&ctx, seed);
        memcpy(mgf_seed, r, n);
        memcpy(mgf_seed + n, pk, n);
        memcpy(mgf_seed + 2 * n, seed, PQC_SHA256_BYTES);

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
                pqc_sha256_update(&ctx, mgf_seed, 2 * n + PQC_SHA256_BYTES);
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
        /* FIPS 205 section 11.2.2: MGF1-SHA-512(R || PK.seed || SHA-512(...), m) */
        uint8_t mgf_seed[2 * SLHDSA_MAX_N + PQC_SHA512_BYTES];

        pqc_sha512_init(&ctx);
        pqc_sha512_update(&ctx, r, n);
        pqc_sha512_update(&ctx, pk, n);
        pqc_sha512_update(&ctx, pk + n, n);
        if (pfxlen)
            pqc_sha512_update(&ctx, pfx, pfxlen);
        pqc_sha512_update(&ctx, msg, msglen);
        pqc_sha512_final(&ctx, seed);
        memcpy(mgf_seed, r, n);
        memcpy(mgf_seed + n, pk, n);
        memcpy(mgf_seed + 2 * n, seed, PQC_SHA512_BYTES);

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
                pqc_sha512_update(&ctx, mgf_seed, 2 * n + PQC_SHA512_BYTES);
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
