/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-DSA (FIPS 204) - Module-Lattice-Based Digital Signature Algorithm.
 * Key generation, signing, and verification.
 *
 * Adapted from the reference pq-crystals/dilithium implementation
 * (Public Domain / CC0).
 */

#include <string.h>

#include "pqc/common.h"
#include "pqc/rand.h"
#include "core/sig/sig_internal.h"
#include "core/sig/mldsa/mldsa.h"
#include "core/sig/mldsa/mldsa_params.h"
#include "core/sig/mldsa/poly.h"
#include "core/sig/mldsa/polyvec.h"
#include "core/sig/mldsa/ntt.h"
#include "core/sig/mldsa/packing.h"
#include "core/sig/mldsa/expand.h"
#include "core/sig/mldsa/rounding.h"
#include "core/sig/mldsa/hint.h"
#include "core/common/hash/sha3.h"

/* ================================================================= */
/*  Parameter set definitions                                          */
/* ================================================================= */

const pqc_mldsa_params_t PQC_MLDSA_44 = {
    .name           = "ML-DSA-44",
    .k              = PQC_MLDSA44_K,
    .l              = PQC_MLDSA44_L,
    .eta            = PQC_MLDSA44_ETA,
    .tau            = PQC_MLDSA44_TAU,
    .beta           = PQC_MLDSA44_BETA,
    .gamma1         = PQC_MLDSA44_GAMMA1,
    .gamma2         = PQC_MLDSA44_GAMMA2,
    .omega          = PQC_MLDSA44_OMEGA,
    .ctilde_bytes   = PQC_MLDSA44_CTILDEBYTES,
    .polyz_packed   = PQC_MLDSA44_POLYZ_PACKEDBYTES,
    .polyw1_packed  = PQC_MLDSA44_POLYW1_PACKEDBYTES,
    .polyeta_packed = PQC_MLDSA44_POLYETA_PACKEDBYTES,
    .pk_bytes       = PQC_MLDSA44_PUBLICKEYBYTES,
    .sk_bytes       = PQC_MLDSA44_SECRETKEYBYTES,
    .sig_bytes      = PQC_MLDSA44_SIGBYTES,
};

const pqc_mldsa_params_t PQC_MLDSA_65 = {
    .name           = "ML-DSA-65",
    .k              = PQC_MLDSA65_K,
    .l              = PQC_MLDSA65_L,
    .eta            = PQC_MLDSA65_ETA,
    .tau            = PQC_MLDSA65_TAU,
    .beta           = PQC_MLDSA65_BETA,
    .gamma1         = PQC_MLDSA65_GAMMA1,
    .gamma2         = PQC_MLDSA65_GAMMA2,
    .omega          = PQC_MLDSA65_OMEGA,
    .ctilde_bytes   = PQC_MLDSA65_CTILDEBYTES,
    .polyz_packed   = PQC_MLDSA65_POLYZ_PACKEDBYTES,
    .polyw1_packed  = PQC_MLDSA65_POLYW1_PACKEDBYTES,
    .polyeta_packed = PQC_MLDSA65_POLYETA_PACKEDBYTES,
    .pk_bytes       = PQC_MLDSA65_PUBLICKEYBYTES,
    .sk_bytes       = PQC_MLDSA65_SECRETKEYBYTES,
    .sig_bytes      = PQC_MLDSA65_SIGBYTES,
};

const pqc_mldsa_params_t PQC_MLDSA_87 = {
    .name           = "ML-DSA-87",
    .k              = PQC_MLDSA87_K,
    .l              = PQC_MLDSA87_L,
    .eta            = PQC_MLDSA87_ETA,
    .tau            = PQC_MLDSA87_TAU,
    .beta           = PQC_MLDSA87_BETA,
    .gamma1         = PQC_MLDSA87_GAMMA1,
    .gamma2         = PQC_MLDSA87_GAMMA2,
    .omega          = PQC_MLDSA87_OMEGA,
    .ctilde_bytes   = PQC_MLDSA87_CTILDEBYTES,
    .polyz_packed   = PQC_MLDSA87_POLYZ_PACKEDBYTES,
    .polyw1_packed  = PQC_MLDSA87_POLYW1_PACKEDBYTES,
    .polyeta_packed = PQC_MLDSA87_POLYETA_PACKEDBYTES,
    .pk_bytes       = PQC_MLDSA87_PUBLICKEYBYTES,
    .sk_bytes       = PQC_MLDSA87_SECRETKEYBYTES,
    .sig_bytes      = PQC_MLDSA87_SIGBYTES,
};

/* ================================================================= */
/*  ML-DSA.KeyGen                                                      */
/*  Reference: crypto_sign_keypair in pq-crystals/dilithium            */
/* ================================================================= */

pqc_status_t pqc_mldsa_keygen(const pqc_mldsa_params_t *params,
                               uint8_t *pk, uint8_t *sk)
{
    uint8_t seedbuf[2 * PQC_MLDSA_SEEDBYTES + PQC_MLDSA_CRHBYTES];
    uint8_t tr[PQC_MLDSA_TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    pqc_mldsa_polyvecl mat[PQC_MLDSA_K_MAX];
    pqc_mldsa_polyvecl s1, s1hat;
    pqc_mldsa_polyveck s2, t1, t0;
    pqc_status_t status;

    if (!params || !pk || !sk)
        return PQC_ERROR_INVALID_ARGUMENT;

    /* Get randomness for rho, rhoprime and key */
    status = pqc_randombytes(seedbuf, PQC_MLDSA_SEEDBYTES);
    if (status != PQC_OK)
        return PQC_ERROR_RNG_FAILED;

    seedbuf[PQC_MLDSA_SEEDBYTES + 0] = (uint8_t)params->k;
    seedbuf[PQC_MLDSA_SEEDBYTES + 1] = (uint8_t)params->l;
    pqc_shake256(seedbuf,
                 2 * PQC_MLDSA_SEEDBYTES + PQC_MLDSA_CRHBYTES,
                 seedbuf, PQC_MLDSA_SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + PQC_MLDSA_SEEDBYTES;
    key = rhoprime + PQC_MLDSA_CRHBYTES;

    /* Expand matrix A from rho */
    pqc_mldsa_polyvec_matrix_expand(mat, rho, params->k, params->l);

    /* Sample short vectors s1 and s2 */
    pqc_mldsa_expand_s(&s1, rhoprime, params->eta, params->l, 0);
    pqc_mldsa_expand_s((pqc_mldsa_polyvecl *)&s2, rhoprime,
                        params->eta, params->k, (uint16_t)params->l);

    /* Matrix-vector multiplication: t = A * NTT(s1) */
    s1hat = s1;
    pqc_mldsa_polyvecl_ntt(&s1hat, params->l);
    pqc_mldsa_polyvec_matrix_pointwise(&t1, mat, &s1hat,
                                        params->k, params->l);
    pqc_mldsa_polyveck_reduce(&t1, params->k);
    pqc_mldsa_polyveck_invntt(&t1, params->k);

    /* Add error vector s2 */
    pqc_mldsa_polyveck_add(&t1, &t1, &s2, params->k);

    /* Extract t1 and write public key */
    pqc_mldsa_polyveck_caddq(&t1, params->k);
    pqc_mldsa_polyveck_power2round(&t1, &t0, &t1, params->k);
    pqc_mldsa_pack_pk(pk, rho, &t1, params->k);

    /* Compute tr = H(pk) and write secret key */
    pqc_shake256(tr, PQC_MLDSA_TRBYTES, pk, params->pk_bytes);
    pqc_mldsa_pack_sk(sk, rho, tr, key, &t0, &s1, &s2, params);

    /* Zeroize sensitive intermediates */
    pqc_memzero(seedbuf, sizeof(seedbuf));
    pqc_memzero(&s1, sizeof(s1));
    pqc_memzero(&s1hat, sizeof(s1hat));
    pqc_memzero(&s2, sizeof(s2));
    pqc_memzero(&t0, sizeof(t0));

    return PQC_OK;
}

/* ================================================================= */
/*  ML-DSA.Sign                                                        */
/*  Reference: crypto_sign_signature_internal in pq-crystals/dilithium */
/* ================================================================= */

pqc_status_t pqc_mldsa_sign(const pqc_mldsa_params_t *params,
                             uint8_t *sig, size_t *siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *sk)
{
    unsigned int n;
    uint8_t seedbuf[2 * PQC_MLDSA_SEEDBYTES + PQC_MLDSA_TRBYTES +
                     2 * PQC_MLDSA_CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime;
    uint8_t rnd[PQC_MLDSA_SEEDBYTES];
    uint16_t nonce = 0;
    pqc_mldsa_polyvecl mat[PQC_MLDSA_K_MAX], s1, y, z;
    pqc_mldsa_polyveck t0, s2, w1, w0, h;
    pqc_mldsa_poly cp;
    pqc_shake256_ctx state;

    if (!params || !sig || !siglen || !msg || !sk)
        return PQC_ERROR_INVALID_ARGUMENT;

    rho = seedbuf;
    tr = rho + PQC_MLDSA_SEEDBYTES;
    key = tr + PQC_MLDSA_TRBYTES;
    mu = key + PQC_MLDSA_SEEDBYTES;
    rhoprime = mu + PQC_MLDSA_CRHBYTES;

    pqc_mldsa_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk, params);

    /* Compute mu = CRH(tr, msg) */
    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, tr, PQC_MLDSA_TRBYTES);
    pqc_shake256_absorb(&state, msg, msglen);
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, mu, PQC_MLDSA_CRHBYTES);

    /* Compute rhoprime = CRH(key, rnd, mu)
     * Use hedged signing: rnd is random */
    pqc_randombytes(rnd, PQC_MLDSA_SEEDBYTES);

    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, key, PQC_MLDSA_SEEDBYTES);
    pqc_shake256_absorb(&state, rnd, PQC_MLDSA_SEEDBYTES);
    pqc_shake256_absorb(&state, mu, PQC_MLDSA_CRHBYTES);
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, rhoprime, PQC_MLDSA_CRHBYTES);

    /* Expand matrix and transform vectors */
    pqc_mldsa_polyvec_matrix_expand(mat, rho, params->k, params->l);
    pqc_mldsa_polyvecl_ntt(&s1, params->l);
    pqc_mldsa_polyveck_ntt((pqc_mldsa_polyveck *)&s2, params->k);
    pqc_mldsa_polyveck_ntt(&t0, params->k);

    /* Rejection sampling loop */
rej:
    /* Sample intermediate vector y */
    pqc_mldsa_expand_mask(&y, rhoprime, nonce++, params->gamma1, params->l);

    /* w = A * NTT(y) */
    z = y;
    pqc_mldsa_polyvecl_ntt(&z, params->l);
    pqc_mldsa_polyvec_matrix_pointwise(&w1, mat, &z,
                                        params->k, params->l);
    pqc_mldsa_polyveck_reduce(&w1, params->k);
    pqc_mldsa_polyveck_invntt(&w1, params->k);

    /* Decompose w and call the random oracle */
    pqc_mldsa_polyveck_caddq(&w1, params->k);
    pqc_mldsa_polyveck_decompose(&w1, &w0, &w1,
                                  params->gamma2, params->k);
    pqc_mldsa_polyveck_pack_w1(sig, &w1, params->k,
                                params->gamma2, params->polyw1_packed);

    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, mu, PQC_MLDSA_CRHBYTES);
    pqc_shake256_absorb(&state, sig, params->k * params->polyw1_packed);
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, sig, params->ctilde_bytes);

    pqc_mldsa_poly_challenge(&cp, sig, params->ctilde_bytes, params->tau);
    pqc_mldsa_poly_ntt(&cp);

    /* Compute z, reject if it reveals secret */
    pqc_mldsa_polyvecl_pointwise_poly(&z, &cp, &s1, params->l);
    pqc_mldsa_polyvecl_invntt(&z, params->l);
    pqc_mldsa_polyvecl_add(&z, &z, &y, params->l);
    pqc_mldsa_polyvecl_reduce(&z, params->l);
    if (pqc_mldsa_polyvecl_chknorm(&z,
            params->gamma1 - (int32_t)params->beta, params->l))
        goto rej;

    /* Check that subtracting cs2 does not change high bits of w and
     * low bits do not reveal secret information */
    pqc_mldsa_polyveck_pointwise_poly(&h, &cp, &s2, params->k);
    pqc_mldsa_polyveck_invntt(&h, params->k);
    pqc_mldsa_polyveck_sub(&w0, &w0, &h, params->k);
    pqc_mldsa_polyveck_reduce(&w0, params->k);
    if (pqc_mldsa_polyveck_chknorm(&w0,
            params->gamma2 - (int32_t)params->beta, params->k))
        goto rej;

    /* Compute hints for w1 */
    pqc_mldsa_polyveck_pointwise_poly(&h, &cp, &t0, params->k);
    pqc_mldsa_polyveck_invntt(&h, params->k);
    pqc_mldsa_polyveck_reduce(&h, params->k);
    if (pqc_mldsa_polyveck_chknorm(&h,
            (int32_t)params->gamma2, params->k))
        goto rej;

    pqc_mldsa_polyveck_add(&w0, &w0, &h, params->k);
    n = pqc_mldsa_polyveck_make_hint(&h, &w0, &w1,
                                      params->gamma2, params->k);
    if (n > params->omega)
        goto rej;

    /* Write signature: sig = (c_tilde || z || h) */
    pqc_mldsa_pack_sig(sig, sig, &z, &h, params);
    *siglen = params->sig_bytes;

    /* Zeroize sensitive state */
    pqc_memzero(seedbuf, sizeof(seedbuf));
    pqc_memzero(rnd, sizeof(rnd));
    pqc_memzero(&s1, sizeof(s1));
    pqc_memzero(&s2, sizeof(s2));
    pqc_memzero(&t0, sizeof(t0));

    return PQC_OK;
}

/* ================================================================= */
/*  ML-DSA.Verify                                                      */
/*  Reference: crypto_sign_verify_internal in pq-crystals/dilithium    */
/* ================================================================= */

pqc_status_t pqc_mldsa_verify(const pqc_mldsa_params_t *params,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *sig, size_t siglen,
                               const uint8_t *pk)
{
    unsigned int i;
    uint8_t buf[PQC_MLDSA_K_MAX * 192]; /* max k * polyw1_packed */
    uint8_t rho[PQC_MLDSA_SEEDBYTES];
    uint8_t mu[PQC_MLDSA_CRHBYTES];
    uint8_t c[PQC_MLDSA87_CTILDEBYTES];  /* max ctilde size */
    uint8_t c2[PQC_MLDSA87_CTILDEBYTES];
    pqc_mldsa_poly cp;
    pqc_mldsa_polyvecl mat[PQC_MLDSA_K_MAX], z;
    pqc_mldsa_polyveck t1, w1, h;
    pqc_shake256_ctx state;

    if (!params || !msg || !sig || !pk)
        return PQC_ERROR_INVALID_ARGUMENT;

    if (siglen != params->sig_bytes)
        return PQC_ERROR_VERIFICATION_FAILED;

    pqc_mldsa_unpack_pk(rho, &t1, pk, params->k);
    if (pqc_mldsa_unpack_sig(c, &z, &h, sig, params))
        return PQC_ERROR_VERIFICATION_FAILED;
    if (pqc_mldsa_polyvecl_chknorm(&z,
            params->gamma1 - (int32_t)params->beta, params->l))
        return PQC_ERROR_VERIFICATION_FAILED;

    /* Compute mu = CRH(H(rho, t1), msg) */
    pqc_shake256(mu, PQC_MLDSA_TRBYTES, pk, params->pk_bytes);
    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, mu, PQC_MLDSA_TRBYTES);
    pqc_shake256_absorb(&state, msg, msglen);
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, mu, PQC_MLDSA_CRHBYTES);

    /* Matrix-vector multiplication; compute Az - c*2^d*t1 */
    pqc_mldsa_poly_challenge(&cp, c, params->ctilde_bytes, params->tau);
    pqc_mldsa_polyvec_matrix_expand(mat, rho, params->k, params->l);

    pqc_mldsa_polyvecl_ntt(&z, params->l);
    pqc_mldsa_polyvec_matrix_pointwise(&w1, mat, &z,
                                        params->k, params->l);

    pqc_mldsa_poly_ntt(&cp);
    pqc_mldsa_polyveck_shiftl(&t1, params->k);
    pqc_mldsa_polyveck_ntt(&t1, params->k);
    pqc_mldsa_polyveck_pointwise_poly(&t1, &cp, &t1, params->k);

    pqc_mldsa_polyveck_sub(&w1, &w1, &t1, params->k);
    pqc_mldsa_polyveck_reduce(&w1, params->k);
    pqc_mldsa_polyveck_invntt(&w1, params->k);

    /* Reconstruct w1 */
    pqc_mldsa_polyveck_caddq(&w1, params->k);
    pqc_mldsa_polyveck_use_hint(&w1, &w1, &h,
                                 params->gamma2, params->k);
    pqc_mldsa_polyveck_pack_w1(buf, &w1, params->k,
                                params->gamma2, params->polyw1_packed);

    /* Call random oracle and verify challenge */
    pqc_shake256_init(&state);
    pqc_shake256_absorb(&state, mu, PQC_MLDSA_CRHBYTES);
    pqc_shake256_absorb(&state, buf, params->k * params->polyw1_packed);
    pqc_shake256_finalize(&state);
    pqc_shake256_squeeze(&state, c2, params->ctilde_bytes);

    for (i = 0; i < params->ctilde_bytes; ++i)
        if (c[i] != c2[i])
            return PQC_ERROR_VERIFICATION_FAILED;

    return PQC_OK;
}

/* ================================================================= */
/*  Vtable wrappers for the unified signature API                      */
/* ================================================================= */

static pqc_status_t mldsa44_keygen(uint8_t *pk, uint8_t *sk)
{
    return pqc_mldsa_keygen(&PQC_MLDSA_44, pk, sk);
}

static pqc_status_t mldsa44_sign(uint8_t *sig, size_t *siglen,
                                  const uint8_t *msg, size_t msglen,
                                  const uint8_t *sk)
{
    return pqc_mldsa_sign(&PQC_MLDSA_44, sig, siglen, msg, msglen, sk);
}

static pqc_status_t mldsa44_verify(const uint8_t *msg, size_t msglen,
                                    const uint8_t *sig, size_t siglen,
                                    const uint8_t *pk)
{
    return pqc_mldsa_verify(&PQC_MLDSA_44, msg, msglen, sig, siglen, pk);
}

static pqc_status_t mldsa65_keygen(uint8_t *pk, uint8_t *sk)
{
    return pqc_mldsa_keygen(&PQC_MLDSA_65, pk, sk);
}

static pqc_status_t mldsa65_sign(uint8_t *sig, size_t *siglen,
                                  const uint8_t *msg, size_t msglen,
                                  const uint8_t *sk)
{
    return pqc_mldsa_sign(&PQC_MLDSA_65, sig, siglen, msg, msglen, sk);
}

static pqc_status_t mldsa65_verify(const uint8_t *msg, size_t msglen,
                                    const uint8_t *sig, size_t siglen,
                                    const uint8_t *pk)
{
    return pqc_mldsa_verify(&PQC_MLDSA_65, msg, msglen, sig, siglen, pk);
}

static pqc_status_t mldsa87_keygen(uint8_t *pk, uint8_t *sk)
{
    return pqc_mldsa_keygen(&PQC_MLDSA_87, pk, sk);
}

static pqc_status_t mldsa87_sign(uint8_t *sig, size_t *siglen,
                                  const uint8_t *msg, size_t msglen,
                                  const uint8_t *sk)
{
    return pqc_mldsa_sign(&PQC_MLDSA_87, sig, siglen, msg, msglen, sk);
}

static pqc_status_t mldsa87_verify(const uint8_t *msg, size_t msglen,
                                    const uint8_t *sig, size_t siglen,
                                    const uint8_t *pk)
{
    return pqc_mldsa_verify(&PQC_MLDSA_87, msg, msglen, sig, siglen, pk);
}

/* ================================================================= */
/*  Registration                                                       */
/* ================================================================= */

static const pqc_sig_vtable_t mldsa_vtables[] = {
    {
        .algorithm_name     = "ML-DSA-44",
        .security_level     = PQC_SECURITY_LEVEL_2,
        .nist_standard      = "FIPS 204",
        .is_stateful        = 0,
        .public_key_size    = PQC_MLDSA44_PUBLICKEYBYTES,
        .secret_key_size    = PQC_MLDSA44_SECRETKEYBYTES,
        .max_signature_size = PQC_MLDSA44_SIGBYTES,
        .keygen             = mldsa44_keygen,
        .sign               = mldsa44_sign,
        .verify             = mldsa44_verify,
        .sign_stateful      = NULL,
    },
    {
        .algorithm_name     = "ML-DSA-65",
        .security_level     = PQC_SECURITY_LEVEL_3,
        .nist_standard      = "FIPS 204",
        .is_stateful        = 0,
        .public_key_size    = PQC_MLDSA65_PUBLICKEYBYTES,
        .secret_key_size    = PQC_MLDSA65_SECRETKEYBYTES,
        .max_signature_size = PQC_MLDSA65_SIGBYTES,
        .keygen             = mldsa65_keygen,
        .sign               = mldsa65_sign,
        .verify             = mldsa65_verify,
        .sign_stateful      = NULL,
    },
    {
        .algorithm_name     = "ML-DSA-87",
        .security_level     = PQC_SECURITY_LEVEL_5,
        .nist_standard      = "FIPS 204",
        .is_stateful        = 0,
        .public_key_size    = PQC_MLDSA87_PUBLICKEYBYTES,
        .secret_key_size    = PQC_MLDSA87_SECRETKEYBYTES,
        .max_signature_size = PQC_MLDSA87_SIGBYTES,
        .keygen             = mldsa87_keygen,
        .sign               = mldsa87_sign,
        .verify             = mldsa87_verify,
        .sign_stateful      = NULL,
    },
};

int pqc_sig_mldsa_register(void)
{
    unsigned int i;
    for (i = 0; i < sizeof(mldsa_vtables) / sizeof(mldsa_vtables[0]); ++i) {
        if (pqc_sig_add_vtable(&mldsa_vtables[i]) != 0)
            return -1;
    }
    return 0;
}
