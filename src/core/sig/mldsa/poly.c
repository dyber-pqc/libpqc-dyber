/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial operations for ML-DSA (FIPS 204).
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
 */

#include <string.h>

#include "core/sig/mldsa/poly.h"
#include "core/sig/mldsa/ntt.h"
#include "core/sig/mldsa/rounding.h"
#include "core/sig/mldsa/mldsa_params.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Basic arithmetic                                                     */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_add(pqc_mldsa_poly *c,
                         const pqc_mldsa_poly *a,
                         const pqc_mldsa_poly *b)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N; ++i)
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void pqc_mldsa_poly_sub(pqc_mldsa_poly *c,
                         const pqc_mldsa_poly *a,
                         const pqc_mldsa_poly *b)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N; ++i)
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

void pqc_mldsa_poly_shiftl(pqc_mldsa_poly *a)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N; ++i)
        a->coeffs[i] <<= PQC_MLDSA_D;
}

/* ------------------------------------------------------------------ */
/* NTT domain                                                           */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_ntt(pqc_mldsa_poly *a)
{
    pqc_mldsa_ntt(a->coeffs);
}

void pqc_mldsa_poly_invntt(pqc_mldsa_poly *a)
{
    pqc_mldsa_invntt(a->coeffs);
}

void pqc_mldsa_poly_pointwise(pqc_mldsa_poly *c,
                               const pqc_mldsa_poly *a,
                               const pqc_mldsa_poly *b)
{
    pqc_mldsa_poly_pointwise_montgomery(c->coeffs, a->coeffs, b->coeffs);
}

/* ------------------------------------------------------------------ */
/* Reduction                                                            */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_reduce(pqc_mldsa_poly *a)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N; ++i)
        a->coeffs[i] = pqc_mldsa_reduce32(a->coeffs[i]);
}

void pqc_mldsa_poly_caddq(pqc_mldsa_poly *a)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N; ++i)
        a->coeffs[i] = pqc_mldsa_caddq(a->coeffs[i]);
}

/* ------------------------------------------------------------------ */
/* Decomposition wrappers                                               */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_power2round(pqc_mldsa_poly *a1,
                                 pqc_mldsa_poly *a0,
                                 const pqc_mldsa_poly *a)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N; ++i)
        a1->coeffs[i] = pqc_mldsa_power2round(&a0->coeffs[i], a->coeffs[i]);
}

void pqc_mldsa_poly_decompose(pqc_mldsa_poly *a1,
                               pqc_mldsa_poly *a0,
                               const pqc_mldsa_poly *a,
                               int32_t gamma2)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N; ++i)
        a1->coeffs[i] = pqc_mldsa_decompose(&a0->coeffs[i],
                                              a->coeffs[i], gamma2);
}

unsigned pqc_mldsa_poly_make_hint(pqc_mldsa_poly *h,
                                   const pqc_mldsa_poly *a0,
                                   const pqc_mldsa_poly *a1,
                                   int32_t gamma2)
{
    unsigned int i, s = 0;
    for (i = 0; i < PQC_MLDSA_N; ++i) {
        h->coeffs[i] = (int32_t)pqc_mldsa_make_hint(
            a0->coeffs[i], a1->coeffs[i], gamma2);
        s += (unsigned)h->coeffs[i];
    }
    return s;
}

void pqc_mldsa_poly_use_hint(pqc_mldsa_poly *b,
                              const pqc_mldsa_poly *a,
                              const pqc_mldsa_poly *hint,
                              int32_t gamma2)
{
    unsigned int i;
    for (i = 0; i < PQC_MLDSA_N; ++i)
        b->coeffs[i] = pqc_mldsa_use_hint(a->coeffs[i],
                                            (unsigned)hint->coeffs[i],
                                            gamma2);
}

/* ------------------------------------------------------------------ */
/* Norm check                                                           */
/* ------------------------------------------------------------------ */

int pqc_mldsa_poly_chknorm(const pqc_mldsa_poly *a, int32_t bound)
{
    unsigned int i;
    int32_t t;

    if (bound > (PQC_MLDSA_Q - 1) / 8)
        return 1;

    /* It is ok to leak which coefficient violates the bound since
       the probability for each coefficient is independent of secret
       data but we must not leak the sign of the centralized representative. */
    for (i = 0; i < PQC_MLDSA_N; ++i) {
        /* Absolute value */
        t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

        if (t >= bound)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Rejection sampling: uniform coefficients in [0, q-1] from raw bytes  */
/* ------------------------------------------------------------------ */

static unsigned int rej_uniform(int32_t *a,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
    unsigned int ctr, pos;
    uint32_t t;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        t  = (uint32_t)buf[pos++];
        t |= (uint32_t)buf[pos++] << 8;
        t |= (uint32_t)buf[pos++] << 16;
        t &= 0x7FFFFF; /* 23 bits */

        if (t < (uint32_t)PQC_MLDSA_Q)
            a[ctr++] = (int32_t)t;
    }
    return ctr;
}

/* ------------------------------------------------------------------ */
/* Rejection sampling from SHAKE-128 (uniform in [0, q-1])              */
/* Algorithm 30 in FIPS 204                                             */
/* ------------------------------------------------------------------ */

#define POLY_UNIFORM_NBLOCKS ((768 + PQC_SHAKE128_RATE - 1) / PQC_SHAKE128_RATE)

void pqc_mldsa_poly_uniform(pqc_mldsa_poly *a,
                             const uint8_t seed[PQC_MLDSA_SEEDBYTES],
                             uint16_t nonce)
{
    unsigned int i, ctr, off;
    unsigned int buflen = POLY_UNIFORM_NBLOCKS * PQC_SHAKE128_RATE;
    uint8_t buf[POLY_UNIFORM_NBLOCKS * PQC_SHAKE128_RATE + 2];
    uint8_t inbuf[PQC_MLDSA_SEEDBYTES + 2];
    pqc_shake128_ctx state;

    memcpy(inbuf, seed, PQC_MLDSA_SEEDBYTES);
    inbuf[PQC_MLDSA_SEEDBYTES + 0] = (uint8_t)(nonce & 0xFF);
    inbuf[PQC_MLDSA_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    pqc_shake128_init(&state);
    pqc_shake128_absorb(&state, inbuf, sizeof(inbuf));
    pqc_shake128_finalize(&state);
    pqc_shake128_squeeze(&state, buf, buflen);

    ctr = rej_uniform(a->coeffs, PQC_MLDSA_N, buf, buflen);

    while (ctr < PQC_MLDSA_N) {
        off = buflen % 3;
        for (i = 0; i < off; ++i)
            buf[i] = buf[buflen - off + i];

        pqc_shake128_squeeze(&state, buf + off, PQC_SHAKE128_RATE);
        buflen = PQC_SHAKE128_RATE + off;
        ctr += rej_uniform(a->coeffs + ctr, PQC_MLDSA_N - ctr, buf, buflen);
    }
}

/* ------------------------------------------------------------------ */
/* Rejection sampling: bounded coefficients in [-eta, eta]              */
/* Algorithm 31 in FIPS 204                                             */
/* ------------------------------------------------------------------ */

static unsigned int rej_eta(int32_t *a,
                            unsigned int len,
                            const uint8_t *buf,
                            unsigned int buflen,
                            unsigned eta)
{
    unsigned int ctr, pos;
    uint32_t t0, t1;

    ctr = pos = 0;
    while (ctr < len && pos < buflen) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos++] >> 4;

        if (eta == 2) {
            if (t0 < 15) {
                t0 = t0 - (205 * t0 >> 10) * 5;
                a[ctr++] = 2 - (int32_t)t0;
            }
            if (t1 < 15 && ctr < len) {
                t1 = t1 - (205 * t1 >> 10) * 5;
                a[ctr++] = 2 - (int32_t)t1;
            }
        } else { /* eta == 4 */
            if (t0 < 9)
                a[ctr++] = 4 - (int32_t)t0;
            if (t1 < 9 && ctr < len)
                a[ctr++] = 4 - (int32_t)t1;
        }
    }
    return ctr;
}

/*
 * For eta=2, we need 136 bytes of output (ceil(N / rejection_rate)).
 * For eta=4, we need 227 bytes. Use the larger to avoid VLAs.
 */
#define POLY_UNIFORM_ETA_NBLOCKS ((227 + PQC_SHAKE256_RATE - 1) / PQC_SHAKE256_RATE)

void pqc_mldsa_poly_uniform_eta(pqc_mldsa_poly *a,
                                 const uint8_t seed[PQC_MLDSA_CRHBYTES],
                                 uint16_t nonce,
                                 unsigned eta)
{
    unsigned int ctr;
    unsigned int buflen = POLY_UNIFORM_ETA_NBLOCKS * PQC_SHAKE256_RATE;
    uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS * PQC_SHAKE256_RATE];
    uint8_t inbuf[PQC_MLDSA_CRHBYTES + 2];
    pqc_shake256_ctx state;

    memcpy(inbuf, seed, PQC_MLDSA_CRHBYTES);
    inbuf[PQC_MLDSA_CRHBYTES + 0] = (uint8_t)(nonce & 0xFF);
    inbuf[PQC_MLDSA_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, inbuf, sizeof(inbuf));
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, buf, buflen);

    ctr = rej_eta(a->coeffs, PQC_MLDSA_N, buf, buflen, eta);

    while (ctr < PQC_MLDSA_N) {
        pqc_shake256_squeeze(&state, buf, PQC_SHAKE256_RATE);
        ctr += rej_eta(a->coeffs + ctr, PQC_MLDSA_N - ctr,
                       buf, PQC_SHAKE256_RATE, eta);
    }
}

/* ------------------------------------------------------------------ */
/* Sample mask polynomial with |coefficients| < gamma1                  */
/* Algorithm 32 in FIPS 204                                             */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_uniform_gamma1(pqc_mldsa_poly *a,
                                    const uint8_t seed[PQC_MLDSA_CRHBYTES],
                                    uint16_t nonce,
                                    int32_t gamma1)
{
    uint8_t buf[640 + 2]; /* max size needed (256*20/8 = 640) */
    uint8_t inbuf[PQC_MLDSA_CRHBYTES + 2];
    unsigned int i;
    size_t outlen;

    memcpy(inbuf, seed, PQC_MLDSA_CRHBYTES);
    inbuf[PQC_MLDSA_CRHBYTES + 0] = (uint8_t)(nonce & 0xFF);
    inbuf[PQC_MLDSA_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    if (gamma1 == (1 << 17))
        outlen = 576; /* 256 * 18 / 8 */
    else
        outlen = 640; /* 256 * 20 / 8 */

    pqc_shake256(buf, outlen, inbuf, sizeof(inbuf));

    if (gamma1 == (1 << 17)) {
        /* 18-bit encoding */
        for (i = 0; i < PQC_MLDSA_N / 4; ++i) {
            a->coeffs[4 * i + 0]  = (int32_t)buf[9 * i + 0];
            a->coeffs[4 * i + 0] |= (int32_t)buf[9 * i + 1] << 8;
            a->coeffs[4 * i + 0] |= (int32_t)buf[9 * i + 2] << 16;
            a->coeffs[4 * i + 0] &= 0x3FFFF;
            a->coeffs[4 * i + 0]  = (1 << 17) - a->coeffs[4 * i + 0];

            a->coeffs[4 * i + 1]  = (int32_t)(buf[9 * i + 2] >> 2);
            a->coeffs[4 * i + 1] |= (int32_t)buf[9 * i + 3] << 6;
            a->coeffs[4 * i + 1] |= (int32_t)buf[9 * i + 4] << 14;
            a->coeffs[4 * i + 1] &= 0x3FFFF;
            a->coeffs[4 * i + 1]  = (1 << 17) - a->coeffs[4 * i + 1];

            a->coeffs[4 * i + 2]  = (int32_t)(buf[9 * i + 4] >> 4);
            a->coeffs[4 * i + 2] |= (int32_t)buf[9 * i + 5] << 4;
            a->coeffs[4 * i + 2] |= (int32_t)buf[9 * i + 6] << 12;
            a->coeffs[4 * i + 2] &= 0x3FFFF;
            a->coeffs[4 * i + 2]  = (1 << 17) - a->coeffs[4 * i + 2];

            a->coeffs[4 * i + 3]  = (int32_t)(buf[9 * i + 6] >> 6);
            a->coeffs[4 * i + 3] |= (int32_t)buf[9 * i + 7] << 2;
            a->coeffs[4 * i + 3] |= (int32_t)buf[9 * i + 8] << 10;
            a->coeffs[4 * i + 3] &= 0x3FFFF;
            a->coeffs[4 * i + 3]  = (1 << 17) - a->coeffs[4 * i + 3];
        }
    } else {
        /* 20-bit encoding (gamma1 = 2^19) */
        for (i = 0; i < PQC_MLDSA_N / 2; ++i) {
            a->coeffs[2 * i + 0]  = (int32_t)buf[5 * i + 0];
            a->coeffs[2 * i + 0] |= (int32_t)buf[5 * i + 1] << 8;
            a->coeffs[2 * i + 0] |= (int32_t)buf[5 * i + 2] << 16;
            a->coeffs[2 * i + 0] &= 0xFFFFF;
            a->coeffs[2 * i + 0]  = (1 << 19) - a->coeffs[2 * i + 0];

            a->coeffs[2 * i + 1]  = (int32_t)(buf[5 * i + 2] >> 4);
            a->coeffs[2 * i + 1] |= (int32_t)buf[5 * i + 3] << 4;
            a->coeffs[2 * i + 1] |= (int32_t)buf[5 * i + 4] << 12;
            a->coeffs[2 * i + 1]  = (1 << 19) - a->coeffs[2 * i + 1];
        }
    }
}

/* ------------------------------------------------------------------ */
/* Challenge polynomial (Algorithm 33 in FIPS 204)                      */
/* Sparse polynomial with exactly tau nonzero entries (+/-1).           */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_challenge(pqc_mldsa_poly *c,
                               const uint8_t *seed,
                               unsigned seedlen,
                               unsigned tau)
{
    unsigned int i, b, pos;
    uint64_t signs;
    uint8_t buf[PQC_SHAKE256_RATE];
    pqc_shake256_ctx state;

    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, seed, seedlen);
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, buf, PQC_SHAKE256_RATE);

    signs = 0;
    for (i = 0; i < 8; ++i)
        signs |= (uint64_t)buf[i] << (8 * i);
    pos = 8;

    for (i = 0; i < PQC_MLDSA_N; ++i)
        c->coeffs[i] = 0;

    for (i = PQC_MLDSA_N - tau; i < PQC_MLDSA_N; ++i) {
        do {
            if (pos >= PQC_SHAKE256_RATE) {
                pqc_shake256_squeeze(&state, buf, PQC_SHAKE256_RATE);
                pos = 0;
            }
            b = buf[pos++];
        } while (b > i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (int32_t)(signs & 1);
        signs >>= 1;
    }
}
