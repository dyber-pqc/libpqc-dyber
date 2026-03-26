/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - Tweakable hash functions, SHAKE instantiation.
 *
 * All security levels use SHAKE-256 per FIPS 205 Section 11.2.
 */

#include <string.h>
#include <stdint.h>

#include "core/common/hash/sha3.h"
#include "slhdsa.h"

/* ------------------------------------------------------------------ */
/* thash: T_l(PK.seed, ADRS, M)                                        */
/*                                                                      */
/* SHAKE-256(PK.seed || ADRS || M, 8n)                                  */
/* ------------------------------------------------------------------ */

void slhdsa_thash_shake(uint8_t *out,
                         const uint8_t *in, uint32_t inblocks,
                         const uint8_t *pub_seed,
                         const uint8_t addr[32],
                         const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    pqc_shake256_ctx ctx;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, pub_seed, n);
    pqc_shake256_absorb(&ctx, addr, 32);
    pqc_shake256_absorb(&ctx, in, (size_t)inblocks * n);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, out, n);
}

/* ------------------------------------------------------------------ */
/* PRF(SK.seed, PK.seed, ADRS)                                          */
/*                                                                      */
/* SHAKE-256(PK.seed || ADRS || SK.seed, 8n)                            */
/* ------------------------------------------------------------------ */

void slhdsa_prf_shake(uint8_t *out,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       const uint8_t addr[32],
                       const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    pqc_shake256_ctx ctx;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, pub_seed, n);
    pqc_shake256_absorb(&ctx, addr, 32);
    pqc_shake256_absorb(&ctx, sk_seed, n);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, out, n);
}

/* ------------------------------------------------------------------ */
/* PRF_msg(SK.prf, opt_rand, M)                                         */
/*                                                                      */
/* SHAKE-256(SK.prf || opt_rand || M, 8n)                               */
/* ------------------------------------------------------------------ */

void slhdsa_prf_msg_shake(uint8_t *out,
                           const uint8_t *sk_prf,
                           const uint8_t *opt_rand,
                           const uint8_t *msg, size_t msglen,
                           const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    pqc_shake256_ctx ctx;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, sk_prf, n);
    pqc_shake256_absorb(&ctx, opt_rand, n);
    pqc_shake256_absorb(&ctx, msg, msglen);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, out, n);
}

/* ------------------------------------------------------------------ */
/* H_msg(R, PK.seed, PK.root, M)                                       */
/*                                                                      */
/* SHAKE-256(R || PK.seed || PK.root || M, 8*digest_bytes)              */
/* ------------------------------------------------------------------ */

void slhdsa_hash_msg_shake(uint8_t *out,
                            const uint8_t *r,
                            const uint8_t *pk,
                            const uint8_t *msg, size_t msglen,
                            const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    size_t digest_bits = (size_t)(p->k) * p->a + p->h;
    size_t digest_bytes = (digest_bits + 7) / 8;
    pqc_shake256_ctx ctx;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, r, n);
    pqc_shake256_absorb(&ctx, pk, n);          /* PK.seed */
    pqc_shake256_absorb(&ctx, pk + n, n);      /* PK.root */
    pqc_shake256_absorb(&ctx, msg, msglen);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, out, digest_bytes);
}
