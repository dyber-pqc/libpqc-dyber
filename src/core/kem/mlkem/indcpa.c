/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * IND-CPA-secure public-key encryption (K-PKE) for ML-KEM (FIPS 203).
 *
 * Implements:
 *   - K-PKE.KeyGen  (Algorithm 12)
 *   - K-PKE.Encrypt (Algorithm 13)
 *   - K-PKE.Decrypt (Algorithm 14)
 *
 * The matrix A is generated from a seed rho using SHAKE-128 (XOF)
 * via rejection sampling (Algorithm 6 - SampleNTT).
 */

#include <string.h>

#include "core/kem/mlkem/indcpa.h"
#include "core/kem/mlkem/poly.h"
#include "core/kem/mlkem/polyvec.h"
#include "core/kem/mlkem/cbd.h"
#include "core/kem/mlkem/ntt.h"
#include "core/kem/mlkem/reduce.h"
#include "core/common/hash/sha3.h"

/* ================================================================= */
/*  Helper: pack / unpack public key                                   */
/* ================================================================= */

static void pack_pk(uint8_t *pk,
                    const pqc_mlkem_polyvec *t,
                    const uint8_t rho[PQC_MLKEM_SYMBYTES],
                    unsigned int k)
{
    pqc_mlkem_polyvec_tobytes(pk, t, k);
    memcpy(pk + k * PQC_MLKEM_POLYBYTES, rho, PQC_MLKEM_SYMBYTES);
}

static void unpack_pk(pqc_mlkem_polyvec *t,
                      uint8_t rho[PQC_MLKEM_SYMBYTES],
                      const uint8_t *pk,
                      unsigned int k)
{
    pqc_mlkem_polyvec_frombytes(t, pk, k);
    memcpy(rho, pk + k * PQC_MLKEM_POLYBYTES, PQC_MLKEM_SYMBYTES);
}

static void pack_sk(uint8_t *sk,
                    const pqc_mlkem_polyvec *s,
                    unsigned int k)
{
    pqc_mlkem_polyvec_tobytes(sk, s, k);
}

static void unpack_sk(pqc_mlkem_polyvec *s,
                      const uint8_t *sk,
                      unsigned int k)
{
    pqc_mlkem_polyvec_frombytes(s, sk, k);
}

static void pack_ciphertext(uint8_t *ct,
                            const pqc_mlkem_polyvec *b,
                            const pqc_mlkem_poly *v,
                            const pqc_mlkem_params_t *params)
{
    pqc_mlkem_polyvec_compress(ct, b, params->k, params->du);
    pqc_mlkem_poly_compress(ct + params->polyvec_compressed, v, params->dv);
}

static void unpack_ciphertext(pqc_mlkem_polyvec *b,
                              pqc_mlkem_poly *v,
                              const uint8_t *ct,
                              const pqc_mlkem_params_t *params)
{
    pqc_mlkem_polyvec_decompress(b, ct, params->k, params->du);
    pqc_mlkem_poly_decompress(v, ct + params->polyvec_compressed, params->dv);
}

/* ================================================================= */
/*  SampleNTT: generate a polynomial in NTT domain via SHAKE-128       */
/*  (Algorithm 6 in FIPS 203 - rejection sampling from XOF)            */
/* ================================================================= */

/*
 * Parse a SHAKE-128 stream into an NTT-domain polynomial using
 * rejection sampling: read 3-byte groups, extract two 12-bit
 * candidates, keep those < q.
 */
static void gen_matrix_entry(pqc_mlkem_poly *a,
                             const uint8_t rho[PQC_MLKEM_SYMBYTES],
                             uint8_t x, uint8_t y)
{
    /*
     * XOF input = rho || x || y  (34 bytes).
     * We squeeze in blocks and rejection-sample.
     */
    pqc_shake128_ctx ctx;
    uint8_t buf[PQC_SHAKE128_RATE * 2]; /* two blocks at a time */
    unsigned int ctr, bufpos, buflen;
    uint16_t d1, d2;

    pqc_shake128_init(&ctx);
    pqc_shake128_absorb(&ctx, rho, PQC_MLKEM_SYMBYTES);
    pqc_shake128_absorb(&ctx, &x, 1);
    pqc_shake128_absorb(&ctx, &y, 1);
    pqc_shake128_finalize(&ctx);

    /* Initial squeeze */
    buflen = sizeof(buf);
    pqc_shake128_squeeze(&ctx, buf, buflen);
    bufpos = 0;
    ctr = 0;

    while (ctr < PQC_MLKEM_N) {
        if (bufpos + 3 > buflen) {
            /* Squeeze another block */
            buflen = PQC_SHAKE128_RATE;
            pqc_shake128_squeeze(&ctx, buf, buflen);
            bufpos = 0;
        }

        d1 = (uint16_t)(((uint16_t)buf[bufpos + 0] >> 0) |
                         ((uint16_t)buf[bufpos + 1] << 8)) & 0xFFF;
        d2 = (uint16_t)(((uint16_t)buf[bufpos + 1] >> 4) |
                         ((uint16_t)buf[bufpos + 2] << 4)) & 0xFFF;
        bufpos += 3;

        if (d1 < PQC_MLKEM_Q) {
            a->coeffs[ctr++] = (int16_t)d1;
        }
        if (ctr < PQC_MLKEM_N && d2 < PQC_MLKEM_Q) {
            a->coeffs[ctr++] = (int16_t)d2;
        }
    }
}

/*
 * Generate the full k x k matrix A (or its transpose) in NTT domain.
 * When transposed == 0, A[i][j] is sampled with XOF(rho, i, j).
 * When transposed != 0, A[i][j] is sampled with XOF(rho, j, i).
 */
static void gen_matrix(pqc_mlkem_polyvec *a,
                       const uint8_t rho[PQC_MLKEM_SYMBYTES],
                       unsigned int k,
                       int transposed)
{
    unsigned int i, j;
    for (i = 0; i < k; i++) {
        for (j = 0; j < k; j++) {
            if (transposed) {
                gen_matrix_entry(&a[i].vec[j], rho, (uint8_t)j, (uint8_t)i);
            } else {
                gen_matrix_entry(&a[i].vec[j], rho, (uint8_t)i, (uint8_t)j);
            }
        }
    }
}

/* ================================================================= */
/*  SamplePolyCBD: derive noise polynomial via PRF + CBD               */
/*  (Algorithm 7 in FIPS 203)                                          */
/* ================================================================= */

/*
 * PRF_eta: SHAKE-256(sigma || nonce) -> 64*eta bytes
 * Then sample via CBD_eta.
 */
static void sample_noise(pqc_mlkem_poly *r,
                         const uint8_t sigma[PQC_MLKEM_SYMBYTES],
                         uint8_t nonce,
                         unsigned int eta)
{
    uint8_t buf[PQC_MLKEM_SYMBYTES + 1];
    uint8_t extbuf[3 * 64]; /* max 64*eta = 64*3 = 192 */

    memcpy(buf, sigma, PQC_MLKEM_SYMBYTES);
    buf[PQC_MLKEM_SYMBYTES] = nonce;

    pqc_shake256(extbuf, 64 * eta, buf, PQC_MLKEM_SYMBYTES + 1);
    pqc_mlkem_cbd_eta(r, extbuf, eta);
}

/* ================================================================= */
/*  K-PKE.KeyGen (Algorithm 12)                                        */
/* ================================================================= */

void pqc_mlkem_indcpa_keygen(uint8_t *pk,
                              uint8_t *sk,
                              const pqc_mlkem_params_t *params)
{
    unsigned int i;
    unsigned int k = params->k;
    uint8_t buf[2 * PQC_MLKEM_SYMBYTES]; /* (rho, sigma) = G(d) */
    uint8_t *rho, *sigma;
    pqc_mlkem_polyvec a[PQC_MLKEM_K_MAX]; /* matrix A (row-major, NTT) */
    pqc_mlkem_polyvec s, e, t;            /* secret, error, public     */
    uint8_t d[PQC_MLKEM_SYMBYTES];
    uint8_t g_input[PQC_MLKEM_SYMBYTES + 1];
    uint8_t nonce = 0;

    /* Step 1: d <-$ B^32  (caller has already filled d via randombytes) */
    /* In the FO transform (mlkem.c), d is passed in via sk generation.
     * Here we generate it fresh -- the top-level keygen in mlkem.c
     * does it differently (provides d as input). We generate d ourselves
     * for a standalone K-PKE.KeyGen. */
    pqc_shake256(d, PQC_MLKEM_SYMBYTES, pk, 0); /* placeholder: will be overwritten */

    /* Actually, per FIPS 203 Algorithm 16 (ML-KEM.KeyGen_internal),
     * d and z are provided.  The standalone K-PKE.KeyGen generates d
     * randomly.  For the internal API, we receive the seed via the
     * pk buffer (first 32 bytes) as a convention from mlkem.c. */

    /* Read 32-byte seed from pk (set by mlkem.c keygen) */
    memcpy(d, pk, PQC_MLKEM_SYMBYTES);

    /* Step 2: (rho, sigma) = G(d || k) */
    memcpy(g_input, d, PQC_MLKEM_SYMBYTES);
    g_input[PQC_MLKEM_SYMBYTES] = (uint8_t)k;
    pqc_sha3_512(buf, g_input, PQC_MLKEM_SYMBYTES + 1);
    rho   = buf;
    sigma = buf + PQC_MLKEM_SYMBYTES;

    /* Step 3-4: Generate matrix A in NTT domain */
    gen_matrix(a, rho, k, 0 /* not transposed */);

    /* Step 5-8: Sample secret vector s */
    for (i = 0; i < k; i++) {
        sample_noise(&s.vec[i], sigma, nonce++, params->eta1);
    }

    /* Step 9-12: Sample error vector e */
    for (i = 0; i < k; i++) {
        sample_noise(&e.vec[i], sigma, nonce++, params->eta1);
    }

    /* Step 13: NTT(s) */
    pqc_mlkem_polyvec_ntt(&s, k);

    /* Step 14: NTT(e) */
    pqc_mlkem_polyvec_ntt(&e, k);

    /* Step 15-17: t = A * s + e  (in NTT domain) */
    for (i = 0; i < k; i++) {
        pqc_mlkem_polyvec_basemul_acc_montgomery(&t.vec[i], &a[i], &s, k);
        pqc_mlkem_poly_tomont(&t.vec[i]);
        pqc_mlkem_poly_add(&t.vec[i], &t.vec[i], &e.vec[i]);
        pqc_mlkem_poly_reduce(&t.vec[i]);
    }

    /* Step 18-19: Pack keys */
    pack_pk(pk, &t, rho, k);
    pack_sk(sk, &s, k);
}

/* ================================================================= */
/*  K-PKE.Encrypt (Algorithm 13)                                       */
/* ================================================================= */

void pqc_mlkem_indcpa_enc(uint8_t *ct,
                           const uint8_t msg[PQC_MLKEM_SYMBYTES],
                           const uint8_t *pk,
                           const uint8_t coins[PQC_MLKEM_SYMBYTES],
                           const pqc_mlkem_params_t *params)
{
    unsigned int i;
    unsigned int k = params->k;
    uint8_t rho[PQC_MLKEM_SYMBYTES];
    pqc_mlkem_polyvec a[PQC_MLKEM_K_MAX]; /* matrix A^T */
    pqc_mlkem_polyvec t;                   /* public key vector */
    pqc_mlkem_polyvec r, e1;               /* randomness, error1 */
    pqc_mlkem_poly e2, v, mp;              /* error2, result, message poly */
    pqc_mlkem_polyvec u;
    uint8_t nonce = 0;

    /* Unpack public key */
    unpack_pk(&t, rho, pk, k);

    /* Encode message as polynomial */
    pqc_mlkem_poly_frommsg(&mp, msg);

    /* Generate A^T (transposed) */
    gen_matrix(a, rho, k, 1 /* transposed */);

    /* Sample r (secret randomness vector) */
    for (i = 0; i < k; i++) {
        sample_noise(&r.vec[i], coins, nonce++, params->eta1);
    }

    /* Sample e1 (error vector) */
    for (i = 0; i < k; i++) {
        sample_noise(&e1.vec[i], coins, nonce++, params->eta2);
    }

    /* Sample e2 (error scalar polynomial) */
    sample_noise(&e2, coins, nonce++, params->eta2);

    /* NTT(r) */
    pqc_mlkem_polyvec_ntt(&r, k);

    /* u = NTT^{-1}(A^T * NTT(r)) + e1 */
    for (i = 0; i < k; i++) {
        pqc_mlkem_polyvec_basemul_acc_montgomery(&u.vec[i], &a[i], &r, k);
        pqc_mlkem_poly_invntt(&u.vec[i]);
    }
    pqc_mlkem_polyvec_add(&u, &u, &e1, k);
    pqc_mlkem_polyvec_reduce(&u, k);

    /* v = NTT^{-1}(t^T * NTT(r)) + e2 + Decompress_1(m) */
    pqc_mlkem_polyvec_basemul_acc_montgomery(&v, &t, &r, k);
    pqc_mlkem_poly_invntt(&v);
    pqc_mlkem_poly_add(&v, &v, &e2);
    pqc_mlkem_poly_add(&v, &v, &mp);
    pqc_mlkem_poly_reduce(&v);

    /* Pack ciphertext */
    pack_ciphertext(ct, &u, &v, params);
}

/* ================================================================= */
/*  K-PKE.Decrypt (Algorithm 14)                                       */
/* ================================================================= */

void pqc_mlkem_indcpa_dec(uint8_t msg[PQC_MLKEM_SYMBYTES],
                           const uint8_t *ct,
                           const uint8_t *sk,
                           const pqc_mlkem_params_t *params)
{
    unsigned int k = params->k;
    pqc_mlkem_polyvec u, s;
    pqc_mlkem_poly v, mp;

    /* Unpack */
    unpack_ciphertext(&u, &v, ct, params);
    unpack_sk(&s, sk, k);

    /* NTT(u) */
    pqc_mlkem_polyvec_ntt(&u, k);

    /* mp = v - NTT^{-1}(s^T * NTT(u)) */
    pqc_mlkem_polyvec_basemul_acc_montgomery(&mp, &s, &u, k);
    pqc_mlkem_poly_invntt(&mp);
    pqc_mlkem_poly_sub(&mp, &v, &mp);
    pqc_mlkem_poly_reduce(&mp);

    /* Encode as message */
    pqc_mlkem_poly_tomsg(msg, &mp);
}
