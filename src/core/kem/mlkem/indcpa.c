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
 *
 * Based on the reference implementation from pq-crystals/kyber.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "core/kem/mlkem/mlkem_params.h"
#include "core/kem/mlkem/indcpa.h"
#include "core/kem/mlkem/polyvec.h"
#include "core/kem/mlkem/poly.h"
#include "core/kem/mlkem/ntt.h"
#include "core/common/hash/sha3.h"

/* XOF block size for SHAKE-128 */
#define PQC_MLKEM_XOF_BLOCKBYTES  PQC_SHAKE128_RATE

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk
*              and the public seed used to generate the matrix A.
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              pqc_mlkem_polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
*              unsigned int k: module rank
**************************************************/
static void pack_pk(uint8_t *r,
                    const pqc_mlkem_polyvec *pk,
                    const uint8_t seed[PQC_MLKEM_SYMBYTES],
                    unsigned int k)
{
    pqc_mlkem_polyvec_tobytes(r, pk, k);
    memcpy(r + k * PQC_MLKEM_POLYBYTES, seed, PQC_MLKEM_SYMBYTES);
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - pqc_mlkem_polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
*              - unsigned int k: module rank
**************************************************/
static void unpack_pk(pqc_mlkem_polyvec *pk,
                      uint8_t seed[PQC_MLKEM_SYMBYTES],
                      const uint8_t *packedpk,
                      unsigned int k)
{
    pqc_mlkem_polyvec_frombytes(pk, packedpk, k);
    memcpy(seed, packedpk + k * PQC_MLKEM_POLYBYTES, PQC_MLKEM_SYMBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - pqc_mlkem_polyvec *sk: pointer to input vector of polynomials (secret key)
*              - unsigned int k: module rank
**************************************************/
static void pack_sk(uint8_t *r,
                    const pqc_mlkem_polyvec *sk,
                    unsigned int k)
{
    pqc_mlkem_polyvec_tobytes(r, sk, k);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - pqc_mlkem_polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
*              - unsigned int k: module rank
**************************************************/
static void unpack_sk(pqc_mlkem_polyvec *sk,
                      const uint8_t *packedsk,
                      unsigned int k)
{
    pqc_mlkem_polyvec_frombytes(sk, packedsk, k);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              compressed and serialized vector of polynomials b
*              and the compressed and serialized polynomial v
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              pqc_mlkem_polyvec *b: pointer to the input vector of polynomials b
*              pqc_mlkem_poly *v: pointer to the input polynomial v
*              const pqc_mlkem_params_t *params: parameter set
**************************************************/
static void pack_ciphertext(uint8_t *r,
                            const pqc_mlkem_polyvec *b,
                            const pqc_mlkem_poly *v,
                            const pqc_mlkem_params_t *params)
{
    pqc_mlkem_polyvec_compress(r, b, params->k, params->du);
    pqc_mlkem_poly_compress(r + params->polyvec_compressed, v, params->dv);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize and decompress ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - pqc_mlkem_polyvec *b: pointer to the output vector of polynomials b
*              - pqc_mlkem_poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
*              - const pqc_mlkem_params_t *params: parameter set
**************************************************/
static void unpack_ciphertext(pqc_mlkem_polyvec *b,
                              pqc_mlkem_poly *v,
                              const uint8_t *c,
                              const pqc_mlkem_params_t *params)
{
    pqc_mlkem_polyvec_decompress(b, c, params->k, params->du);
    pqc_mlkem_poly_decompress(v, c + params->polyvec_compressed, params->dv);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;

        if (val0 < PQC_MLKEM_Q)
            r[ctr++] = val0;
        if (ctr < len && val1 < PQC_MLKEM_Q)
            r[ctr++] = val1;
    }

    return ctr;
}

/*
 * Number of initial XOF blocks to squeeze for matrix generation.
 * This ensures we almost always have enough samples in the first squeeze.
 */
#define GEN_MATRIX_NBLOCKS \
    ((12 * PQC_MLKEM_N / 8 * (1 << 12) / PQC_MLKEM_Q + PQC_MLKEM_XOF_BLOCKBYTES) / PQC_MLKEM_XOF_BLOCKBYTES)

/*************************************************
* Name:        pqc_mlkem_gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF (SHAKE-128).
*
* Arguments:   - pqc_mlkem_polyvec *a: pointer to output matrix A
*              - const uint8_t *seed: pointer to input seed
*              - unsigned int k: module rank
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
void pqc_mlkem_gen_matrix(pqc_mlkem_polyvec *a,
                           const uint8_t seed[PQC_MLKEM_SYMBYTES],
                           unsigned int k,
                           int transposed)
{
    unsigned int ctr, i, j;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * PQC_MLKEM_XOF_BLOCKBYTES];
    uint8_t extseed[PQC_MLKEM_SYMBYTES + 2];
    pqc_shake128_ctx state;

    memcpy(extseed, seed, PQC_MLKEM_SYMBYTES);

    for (i = 0; i < k; i++) {
        for (j = 0; j < k; j++) {
            if (transposed) {
                extseed[PQC_MLKEM_SYMBYTES + 0] = (uint8_t)i;
                extseed[PQC_MLKEM_SYMBYTES + 1] = (uint8_t)j;
            } else {
                extseed[PQC_MLKEM_SYMBYTES + 0] = (uint8_t)j;
                extseed[PQC_MLKEM_SYMBYTES + 1] = (uint8_t)i;
            }

            pqc_shake128_init(&state);
            pqc_shake128_absorb(&state, extseed, sizeof(extseed));
            pqc_shake128_finalize(&state);

            pqc_shake128_squeeze(&state, buf, GEN_MATRIX_NBLOCKS * PQC_MLKEM_XOF_BLOCKBYTES);
            buflen = GEN_MATRIX_NBLOCKS * PQC_MLKEM_XOF_BLOCKBYTES;
            ctr = rej_uniform(a[i].vec[j].coeffs, PQC_MLKEM_N, buf, buflen);

            while (ctr < PQC_MLKEM_N) {
                pqc_shake128_squeeze(&state, buf, PQC_MLKEM_XOF_BLOCKBYTES);
                buflen = PQC_MLKEM_XOF_BLOCKBYTES;
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, PQC_MLKEM_N - ctr, buf, buflen);
            }
        }
    }
}

#define gen_a(A, B, K)   pqc_mlkem_gen_matrix(A, B, K, 0)
#define gen_at(A, B, K)  pqc_mlkem_gen_matrix(A, B, K, 1)

/*************************************************
* Name:        pqc_mlkem_indcpa_keypair_derand
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying ML-KEM.
*              Deterministic version using provided coins.
*
* Arguments:   - uint8_t *pk: pointer to output public key
*              - uint8_t *sk: pointer to output private key
*              - const uint8_t *coins: pointer to input randomness (32 bytes)
*              - const pqc_mlkem_params_t *params: parameter set
**************************************************/
void pqc_mlkem_indcpa_keypair_derand(uint8_t *pk,
                                      uint8_t *sk,
                                      const uint8_t coins[PQC_MLKEM_SYMBYTES],
                                      const pqc_mlkem_params_t *params)
{
    unsigned int i;
    unsigned int k = params->k;
    uint8_t buf[2 * PQC_MLKEM_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed = buf + PQC_MLKEM_SYMBYTES;
    uint8_t nonce = 0;
    pqc_mlkem_polyvec a[PQC_MLKEM_K_MAX], e, pkpv, skpv;

    /* (rho, sigma) = G(coins || k) */
    {
        uint8_t g_input[PQC_MLKEM_SYMBYTES + 1];
        memcpy(g_input, coins, PQC_MLKEM_SYMBYTES);
        g_input[PQC_MLKEM_SYMBYTES] = (uint8_t)k;
        pqc_sha3_512(buf, g_input, PQC_MLKEM_SYMBYTES + 1);
    }

    gen_a(a, publicseed, k);

    for (i = 0; i < k; i++)
        pqc_mlkem_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++, params->eta1);
    for (i = 0; i < k; i++)
        pqc_mlkem_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++, params->eta1);

    pqc_mlkem_polyvec_ntt(&skpv, k);
    pqc_mlkem_polyvec_ntt(&e, k);

    /* matrix-vector multiplication */
    for (i = 0; i < k; i++) {
        pqc_mlkem_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv, k);
        pqc_mlkem_poly_tomont(&pkpv.vec[i]);
    }

    pqc_mlkem_polyvec_add(&pkpv, &pkpv, &e, k);
    pqc_mlkem_polyvec_reduce(&pkpv, k);

    pack_sk(sk, &skpv, k);
    pack_pk(pk, &pkpv, publicseed, k);
}

/*************************************************
* Name:        pqc_mlkem_indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying ML-KEM.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*              - const uint8_t *m: pointer to input message
*              - const uint8_t *pk: pointer to input public key
*              - const uint8_t *coins: pointer to input random coins
*              - const pqc_mlkem_params_t *params: parameter set
**************************************************/
void pqc_mlkem_indcpa_enc(uint8_t *c,
                           const uint8_t m[PQC_MLKEM_SYMBYTES],
                           const uint8_t *pk,
                           const uint8_t coins[PQC_MLKEM_SYMBYTES],
                           const pqc_mlkem_params_t *params)
{
    unsigned int i;
    unsigned int k = params->k;
    uint8_t seed[PQC_MLKEM_SYMBYTES];
    uint8_t nonce = 0;
    pqc_mlkem_polyvec sp, pkpv, ep, at[PQC_MLKEM_K_MAX], b;
    pqc_mlkem_poly v, kk, epp;

    unpack_pk(&pkpv, seed, pk, k);
    pqc_mlkem_poly_frommsg(&kk, m);
    gen_at(at, seed, k);

    for (i = 0; i < k; i++)
        pqc_mlkem_poly_getnoise_eta1(sp.vec + i, coins, nonce++, params->eta1);
    for (i = 0; i < k; i++)
        pqc_mlkem_poly_getnoise_eta2(ep.vec + i, coins, nonce++);
    pqc_mlkem_poly_getnoise_eta2(&epp, coins, nonce++);

    pqc_mlkem_polyvec_ntt(&sp, k);

    /* matrix-vector multiplication */
    for (i = 0; i < k; i++)
        pqc_mlkem_polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp, k);

    pqc_mlkem_polyvec_basemul_acc_montgomery(&v, &pkpv, &sp, k);

    pqc_mlkem_polyvec_invntt(&b, k);
    pqc_mlkem_poly_invntt(&v);

    pqc_mlkem_polyvec_add(&b, &b, &ep, k);
    pqc_mlkem_poly_add(&v, &v, &epp);
    pqc_mlkem_poly_add(&v, &v, &kk);
    pqc_mlkem_polyvec_reduce(&b, k);
    pqc_mlkem_poly_reduce(&v);

    pack_ciphertext(c, &b, &v, params);
}

/*************************************************
* Name:        pqc_mlkem_indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying ML-KEM.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*              - const uint8_t *c: pointer to input ciphertext
*              - const uint8_t *sk: pointer to input secret key
*              - const pqc_mlkem_params_t *params: parameter set
**************************************************/
void pqc_mlkem_indcpa_dec(uint8_t m[PQC_MLKEM_SYMBYTES],
                           const uint8_t *c,
                           const uint8_t *sk,
                           const pqc_mlkem_params_t *params)
{
    unsigned int k = params->k;
    pqc_mlkem_polyvec b, skpv;
    pqc_mlkem_poly v, mp;

    unpack_ciphertext(&b, &v, c, params);
    unpack_sk(&skpv, sk, k);

    pqc_mlkem_polyvec_ntt(&b, k);
    pqc_mlkem_polyvec_basemul_acc_montgomery(&mp, &skpv, &b, k);
    pqc_mlkem_poly_invntt(&mp);

    pqc_mlkem_poly_sub(&mp, &v, &mp);
    pqc_mlkem_poly_reduce(&mp);

    pqc_mlkem_poly_tomsg(m, &mp);
}
