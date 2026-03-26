/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA (FIPS 206) -- Signature verification.
 *
 * Verification algorithm:
 *   1. Decode public key h from pk.
 *   2. Parse signature: header || nonce || comp(s2).
 *   3. Decompress s2 from the signature.
 *   4. Recompute c = HashToPoint(nonce || msg).
 *   5. Compute s1 = c - s2*h mod q.
 *   6. Check ||(s1, s2)||^2 < bound.
 */

#include <string.h>

#include "fndsa.h"
#include "fndsa_params.h"
#include "pqc/common.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Hash-to-point (same as in sign.c)                                    */
/* ------------------------------------------------------------------ */

static void
hash_to_point(uint16_t *c, unsigned logn,
              const uint8_t *nonce, size_t nonce_len,
              const uint8_t *msg, size_t msglen)
{
    size_t n = (size_t)1 << logn;
    pqc_shake256_ctx ctx;
    size_t i;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, nonce, nonce_len);
    pqc_shake256_absorb(&ctx, msg, msglen);
    pqc_shake256_finalize(&ctx);

    i = 0;
    while (i < n) {
        uint8_t buf[2];
        uint16_t v;

        pqc_shake256_squeeze(&ctx, buf, 2);
        v = (uint16_t)((uint16_t)buf[0] | ((uint16_t)buf[1] << 8));

        if (v < 5 * FNDSA_Q) {
            c[i] = v % FNDSA_Q;
            i++;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Polynomial multiplication mod q mod (x^n + 1)                        */
/* ------------------------------------------------------------------ */

static void
poly_mul_modq(uint16_t *out, const int16_t *a, const uint16_t *b, size_t n)
{
    size_t i, j;
    uint32_t tmp[FNDSA_MAX_N];

    memset(tmp, 0, n * sizeof(uint32_t));

    for (i = 0; i < n; i++) {
        int32_t ai;
        uint32_t ai_mod;

        ai = (int32_t)a[i];
        if (ai == 0) continue;
        /* Normalize ai to [0, q). */
        ai_mod = (uint32_t)((ai % (int32_t)FNDSA_Q + FNDSA_Q) % FNDSA_Q);

        for (j = 0; j < n; j++) {
            size_t idx = i + j;
            uint32_t prod = ai_mod * (uint32_t)b[j] % FNDSA_Q;
            if (idx >= n) {
                idx -= n;
                tmp[idx] = (tmp[idx] + FNDSA_Q - prod) % FNDSA_Q;
            } else {
                tmp[idx] = (tmp[idx] + prod) % FNDSA_Q;
            }
        }
    }

    for (i = 0; i < n; i++)
        out[i] = (uint16_t)tmp[i];
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

int
fndsa_verify(const uint8_t *msg, size_t msglen,
             const uint8_t *sig, size_t siglen,
             const uint8_t *pk, size_t pklen,
             unsigned logn)
{
    size_t n = (size_t)1 << logn;
    uint16_t h[FNDSA_MAX_N];
    int16_t s2[FNDSA_MAX_N];
    uint16_t c[FNDSA_MAX_N];
    uint16_t s2h[FNDSA_MAX_N];
    int16_t s1[FNDSA_MAX_N];
    const uint8_t *nonce;
    const uint8_t *comp_data;
    size_t comp_len;
    uint32_t sig_bound;
    int64_t norm_sq;
    size_t i;

    if (logn == FNDSA_512_LOGN) {
        sig_bound = FNDSA_512_SIG_BOUND;
    } else {
        sig_bound = FNDSA_1024_SIG_BOUND;
    }

    /* Decode public key. */
    if (fndsa_pk_decode(h, pk, pklen, logn) != 0)
        return -1;

    /* Parse signature. */
    if (siglen < 1 + FNDSA_NONCE_LEN + 1)
        return -1;
    if (sig[0] != (uint8_t)FNDSA_SIG_HEADER(logn))
        return -1;

    nonce = sig + 1;
    comp_data = sig + 1 + FNDSA_NONCE_LEN;
    comp_len  = siglen - 1 - FNDSA_NONCE_LEN;

    /* Decompress s2. */
    if (fndsa_comp_decode(s2, comp_data, comp_len, logn) != 0)
        return -1;

    /* Recompute c = HashToPoint(nonce || msg). */
    hash_to_point(c, logn, nonce, FNDSA_NONCE_LEN, msg, msglen);

    /* Compute s1 = c - s2*h mod q. */
    poly_mul_modq(s2h, s2, h, n);

    for (i = 0; i < n; i++) {
        uint32_t v = (uint32_t)c[i] + FNDSA_Q - (uint32_t)s2h[i];
        v %= FNDSA_Q;
        /* Convert to centered representation [-q/2, q/2). */
        if (v > FNDSA_Q / 2)
            s1[i] = (int16_t)((int32_t)v - (int32_t)FNDSA_Q);
        else
            s1[i] = (int16_t)v;
    }

    /* Check norm bound: ||(s1, s2)||^2 < sig_bound. */
    norm_sq = 0;
    for (i = 0; i < n; i++) {
        norm_sq += (int64_t)s1[i] * (int64_t)s1[i];
        norm_sq += (int64_t)s2[i] * (int64_t)s2[i];
    }

    if (norm_sq >= (int64_t)sig_bound)
        return -1;

    return 0;
}
