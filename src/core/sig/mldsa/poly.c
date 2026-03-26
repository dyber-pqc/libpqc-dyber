/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Polynomial operations for ML-DSA (FIPS 204).
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
    unsigned i;
    for (i = 0; i < PQC_MLDSA_N; i++)
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void pqc_mldsa_poly_sub(pqc_mldsa_poly *c,
                         const pqc_mldsa_poly *a,
                         const pqc_mldsa_poly *b)
{
    unsigned i;
    for (i = 0; i < PQC_MLDSA_N; i++)
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

void pqc_mldsa_poly_shiftl(pqc_mldsa_poly *a)
{
    unsigned i;
    for (i = 0; i < PQC_MLDSA_N; i++)
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
    unsigned i;
    for (i = 0; i < PQC_MLDSA_N; i++)
        a->coeffs[i] = pqc_mldsa_barrett_reduce(a->coeffs[i]);
}

void pqc_mldsa_poly_caddq(pqc_mldsa_poly *a)
{
    unsigned i;
    for (i = 0; i < PQC_MLDSA_N; i++)
        a->coeffs[i] += (a->coeffs[i] >> 31) & PQC_MLDSA_Q;
}

/* ------------------------------------------------------------------ */
/* Decomposition wrappers                                               */
/* ------------------------------------------------------------------ */

void pqc_mldsa_poly_power2round(pqc_mldsa_poly *a1,
                                 pqc_mldsa_poly *a0,
                                 const pqc_mldsa_poly *a)
{
    unsigned i;
    for (i = 0; i < PQC_MLDSA_N; i++)
        a1->coeffs[i] = pqc_mldsa_power2round(&a0->coeffs[i], a->coeffs[i]);
}

void pqc_mldsa_poly_decompose(pqc_mldsa_poly *a1,
                               pqc_mldsa_poly *a0,
                               const pqc_mldsa_poly *a,
                               int32_t gamma2)
{
    unsigned i;
    for (i = 0; i < PQC_MLDSA_N; i++)
        a1->coeffs[i] = pqc_mldsa_decompose(&a0->coeffs[i],
                                              a->coeffs[i], gamma2);
}

unsigned pqc_mldsa_poly_make_hint(pqc_mldsa_poly *h,
                                   const pqc_mldsa_poly *a0,
                                   const pqc_mldsa_poly *a1,
                                   int32_t gamma2)
{
    unsigned i, s = 0;
    for (i = 0; i < PQC_MLDSA_N; i++) {
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
    unsigned i;
    for (i = 0; i < PQC_MLDSA_N; i++)
        b->coeffs[i] = pqc_mldsa_use_hint(a->coeffs[i],
                                            (unsigned)hint->coeffs[i],
                                            gamma2);
}

/* ------------------------------------------------------------------ */
/* Norm check                                                           */
/* ------------------------------------------------------------------ */

int pqc_mldsa_poly_chknorm(const pqc_mldsa_poly *a, int32_t bound)
{
    unsigned i;
    int32_t t;

    if (bound > (PQC_MLDSA_Q - 1) / 8)
        return 1;

    for (i = 0; i < PQC_MLDSA_N; i++) {
        /* Absolute value */
        t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);

        if (t >= bound)
            return 1;
    }
    return 0;
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
    unsigned ctr, pos, buflen;
    uint8_t buf[POLY_UNIFORM_NBLOCKS * PQC_SHAKE128_RATE + 2];
    uint8_t inbuf[PQC_MLDSA_SEEDBYTES + 2];
    uint32_t t;
    pqc_shake128_ctx state;

    memcpy(inbuf, seed, PQC_MLDSA_SEEDBYTES);
    inbuf[PQC_MLDSA_SEEDBYTES + 0] = (uint8_t)(nonce & 0xFF);
    inbuf[PQC_MLDSA_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    pqc_shake128_init(&state);
    pqc_shake128_absorb(&state, inbuf, sizeof(inbuf));
    pqc_shake128_finalize(&state);
    pqc_shake128_squeeze(&state, buf, POLY_UNIFORM_NBLOCKS * PQC_SHAKE128_RATE);

    buflen = POLY_UNIFORM_NBLOCKS * PQC_SHAKE128_RATE;
    ctr = 0;
    pos = 0;

    while (ctr < PQC_MLDSA_N && pos + 3 <= buflen) {
        t  = (uint32_t)buf[pos++];
        t |= (uint32_t)buf[pos++] << 8;
        t |= (uint32_t)buf[pos++] << 16;
        t &= 0x7FFFFF; /* 23 bits */

        if (t < (uint32_t)PQC_MLDSA_Q)
            a->coeffs[ctr++] = (int32_t)t;
    }

    while (ctr < PQC_MLDSA_N) {
        pqc_shake128_squeeze(&state, buf, PQC_SHAKE128_RATE);
        pos = 0;
        buflen = PQC_SHAKE128_RATE;
        while (ctr < PQC_MLDSA_N && pos + 3 <= buflen) {
            t  = (uint32_t)buf[pos++];
            t |= (uint32_t)buf[pos++] << 8;
            t |= (uint32_t)buf[pos++] << 16;
            t &= 0x7FFFFF;

            if (t < (uint32_t)PQC_MLDSA_Q)
                a->coeffs[ctr++] = (int32_t)t;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Sample with bounded coefficients in [-eta, eta]                      */
/* Algorithm 31 in FIPS 204                                             */
/* ------------------------------------------------------------------ */

static unsigned rej_eta2(int32_t *a, unsigned len,
                          const uint8_t *buf, unsigned buflen)
{
    unsigned ctr, pos;
    uint8_t t0, t1;

    ctr = 0;
    pos = 0;
    while (ctr < len && pos < buflen) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos] >> 4;
        pos++;

        if (t0 < 15) {
            t0 = t0 - (3 * (t0 >> 2)); /* t0 mod 5, but fast */
            /* Actually: for eta=2, valid range [0,14], map to [-2,2] */
            a[ctr++] = 2 - (int32_t)t0;
            if (ctr >= len) break;
        }
        if (t1 < 15) {
            t1 = t1 - (3 * (t1 >> 2));
            a[ctr++] = 2 - (int32_t)t1;
        }
    }
    return ctr;
}

static unsigned rej_eta4(int32_t *a, unsigned len,
                          const uint8_t *buf, unsigned buflen)
{
    unsigned ctr, pos;
    uint8_t t0, t1;

    ctr = 0;
    pos = 0;
    while (ctr < len && pos < buflen) {
        t0 = buf[pos] & 0x0F;
        t1 = buf[pos] >> 4;
        pos++;

        if (t0 < 9) {
            a[ctr++] = 4 - (int32_t)t0;
            if (ctr >= len) break;
        }
        if (t1 < 9) {
            a[ctr++] = 4 - (int32_t)t1;
        }
    }
    return ctr;
}

#define POLY_UNIFORM_ETA_NBLOCKS ((227 + PQC_SHAKE256_RATE - 1) / PQC_SHAKE256_RATE)

void pqc_mldsa_poly_uniform_eta(pqc_mldsa_poly *a,
                                 const uint8_t seed[PQC_MLDSA_CRHBYTES],
                                 uint16_t nonce,
                                 unsigned eta)
{
    unsigned ctr;
    uint8_t buf[POLY_UNIFORM_ETA_NBLOCKS * PQC_SHAKE256_RATE];
    uint8_t inbuf[PQC_MLDSA_CRHBYTES + 2];
    pqc_shake256_ctx state;

    memcpy(inbuf, seed, PQC_MLDSA_CRHBYTES);
    inbuf[PQC_MLDSA_CRHBYTES + 0] = (uint8_t)(nonce & 0xFF);
    inbuf[PQC_MLDSA_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, inbuf, sizeof(inbuf));
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, buf, sizeof(buf));

    if (eta == 2)
        ctr = rej_eta2(a->coeffs, PQC_MLDSA_N, buf, sizeof(buf));
    else
        ctr = rej_eta4(a->coeffs, PQC_MLDSA_N, buf, sizeof(buf));

    while (ctr < PQC_MLDSA_N) {
        pqc_shake256_squeeze(&state, buf, PQC_SHAKE256_RATE);
        if (eta == 2)
            ctr += rej_eta2(a->coeffs + ctr, PQC_MLDSA_N - ctr,
                            buf, PQC_SHAKE256_RATE);
        else
            ctr += rej_eta4(a->coeffs + ctr, PQC_MLDSA_N - ctr,
                            buf, PQC_SHAKE256_RATE);
    }
}

/* ------------------------------------------------------------------ */
/* Sample mask polynomial with |coefficients| < gamma1                  */
/* Algorithm 32 in FIPS 204                                             */
/* ------------------------------------------------------------------ */

#define POLY_UNIFORM_GAMMA1_NBLOCKS_17 ((576 + PQC_SHAKE256_RATE - 1) / PQC_SHAKE256_RATE)
#define POLY_UNIFORM_GAMMA1_NBLOCKS_19 ((640 + PQC_SHAKE256_RATE - 1) / PQC_SHAKE256_RATE)

void pqc_mldsa_poly_uniform_gamma1(pqc_mldsa_poly *a,
                                    const uint8_t seed[PQC_MLDSA_CRHBYTES],
                                    uint16_t nonce,
                                    int32_t gamma1)
{
    uint8_t buf[640 + 2]; /* max size needed */
    uint8_t inbuf[PQC_MLDSA_CRHBYTES + 2];
    unsigned i;
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
        for (i = 0; i < PQC_MLDSA_N / 4; i++) {
            a->coeffs[4 * i + 0]  = (int32_t)buf[9 * i + 0];
            a->coeffs[4 * i + 0] |= (int32_t)buf[9 * i + 1] << 8;
            a->coeffs[4 * i + 0] |= (int32_t)(buf[9 * i + 2] & 0x03) << 16;
            a->coeffs[4 * i + 0]  = (1 << 17) - a->coeffs[4 * i + 0];

            a->coeffs[4 * i + 1]  = (int32_t)(buf[9 * i + 2] >> 2);
            a->coeffs[4 * i + 1] |= (int32_t)buf[9 * i + 3] << 6;
            a->coeffs[4 * i + 1] |= (int32_t)(buf[9 * i + 4] & 0x0F) << 14;
            a->coeffs[4 * i + 1]  = (1 << 17) - a->coeffs[4 * i + 1];

            a->coeffs[4 * i + 2]  = (int32_t)(buf[9 * i + 4] >> 4);
            a->coeffs[4 * i + 2] |= (int32_t)buf[9 * i + 5] << 4;
            a->coeffs[4 * i + 2] |= (int32_t)(buf[9 * i + 6] & 0x3F) << 12;
            a->coeffs[4 * i + 2]  = (1 << 17) - a->coeffs[4 * i + 2];

            a->coeffs[4 * i + 3]  = (int32_t)(buf[9 * i + 6] >> 6);
            a->coeffs[4 * i + 3] |= (int32_t)buf[9 * i + 7] << 2;
            a->coeffs[4 * i + 3] |= (int32_t)buf[9 * i + 8] << 10;
            a->coeffs[4 * i + 3]  = (1 << 17) - a->coeffs[4 * i + 3];
        }
    } else {
        /* 20-bit encoding (gamma1 = 2^19) */
        for (i = 0; i < PQC_MLDSA_N / 2; i++) {
            a->coeffs[2 * i + 0]  = (int32_t)buf[5 * i + 0];
            a->coeffs[2 * i + 0] |= (int32_t)buf[5 * i + 1] << 8;
            a->coeffs[2 * i + 0] |= (int32_t)(buf[5 * i + 2] & 0x0F) << 16;
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
    unsigned i, b, pos;
    uint64_t signs;
    uint8_t buf[PQC_SHAKE256_RATE];
    pqc_shake256_ctx state;

    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, seed, seedlen);
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, buf, 8);

    signs = 0;
    for (i = 0; i < 8; i++)
        signs |= (uint64_t)buf[i] << (8 * i);

    pos = 8;

    memset(c->coeffs, 0, sizeof(c->coeffs));

    for (i = PQC_MLDSA_N - tau; i < PQC_MLDSA_N; i++) {
        /* Sample j uniformly from [0, i] */
        uint8_t j_byte;
        unsigned j;
        do {
            if (pos >= PQC_SHAKE256_RATE) {
                pqc_shake256_squeeze(&state, buf, PQC_SHAKE256_RATE);
                pos = 0;
            }
            j_byte = buf[pos++];
            j = (unsigned)j_byte;
        } while (j > i);

        c->coeffs[i] = c->coeffs[j];
        b = (unsigned)(signs & 1);
        c->coeffs[j] = 1 - 2 * (int32_t)b;
        signs >>= 1;
    }
}
