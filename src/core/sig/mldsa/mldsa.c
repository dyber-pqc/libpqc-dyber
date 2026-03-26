/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-DSA (FIPS 204) - Module-Lattice-Based Digital Signature Algorithm.
 * Key generation, signing, and verification.
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
/*  ML-DSA.KeyGen (Algorithm 1 in FIPS 204)                            */
/* ================================================================= */

pqc_status_t pqc_mldsa_keygen(const pqc_mldsa_params_t *params,
                               uint8_t *pk, uint8_t *sk)
{
    uint8_t seed[32];
    uint8_t expanded[128]; /* rho(32) || rhoprime(64) || K(32) */
    uint8_t rho[PQC_MLDSA_SEEDBYTES];
    uint8_t rhoprime[PQC_MLDSA_CRHBYTES];
    uint8_t K[PQC_MLDSA_SEEDBYTES];
    uint8_t tr[PQC_MLDSA_TRBYTES];

    pqc_mldsa_poly mat[PQC_MLDSA_K_MAX * PQC_MLDSA_L_MAX];
    pqc_mldsa_polyvecl s1, s1hat;
    pqc_mldsa_polyveck s2, t, t1, t0;
    pqc_status_t status;

    if (!params || !pk || !sk)
        return PQC_ERROR_INVALID_ARGUMENT;

    /* Step 1: Generate random seed xi */
    status = pqc_randombytes(seed, 32);
    if (status != PQC_OK)
        return PQC_ERROR_RNG_FAILED;

    /* Step 2: H(xi || k || l) -> rho, rhoprime, K
     * Per FIPS 204, expand seed with SHAKE-256 */
    {
        uint8_t hashbuf[34];
        memcpy(hashbuf, seed, 32);
        hashbuf[32] = (uint8_t)params->k;
        hashbuf[33] = (uint8_t)params->l;
        pqc_shake256(expanded, 128, hashbuf, 34);
    }

    memcpy(rho, expanded, 32);
    memcpy(rhoprime, expanded + 32, 64);
    memcpy(K, expanded + 96, 32);

    /* Step 3: Expand matrix A from rho */
    pqc_mldsa_expand_a(mat, rho, params->k, params->l);

    /* Step 4-5: Sample secret vectors s1, s2 */
    pqc_mldsa_expand_s(&s1, rhoprime, params->eta, params->l, 0);
    pqc_mldsa_expand_s((pqc_mldsa_polyvecl *)&s2, rhoprime,
                        params->eta, params->k, params->l);

    /* Step 6: t = A * NTT(s1) + s2 */
    s1hat = s1;
    pqc_mldsa_polyvecl_ntt(&s1hat, params->l);
    pqc_mldsa_polyvec_matrix_pointwise(&t, mat, &s1hat,
                                        params->k, params->l);
    pqc_mldsa_polyveck_reduce(&t, params->k);
    pqc_mldsa_polyveck_invntt(&t, params->k);
    pqc_mldsa_polyveck_add(&t, &t, &s2, params->k);
    pqc_mldsa_polyveck_caddq(&t, params->k);

    /* Step 7: Power2Round(t) -> (t1, t0) */
    pqc_mldsa_polyveck_power2round(&t1, &t0, &t, params->k);

    /* Step 8: Pack public key */
    pqc_mldsa_pack_pk(pk, rho, &t1, params->k);

    /* Step 9: Compute tr = H(pk) using SHAKE-256 */
    pqc_shake256(tr, PQC_MLDSA_TRBYTES, pk, params->pk_bytes);

    /* Step 10: Pack secret key */
    pqc_mldsa_pack_sk(sk, rho, K, tr, &s1, &s2, &t0, params);

    /* Zeroize sensitive intermediates */
    pqc_memzero(seed, sizeof(seed));
    pqc_memzero(expanded, sizeof(expanded));
    pqc_memzero(rhoprime, sizeof(rhoprime));
    pqc_memzero(K, sizeof(K));
    pqc_memzero(&s1, sizeof(s1));
    pqc_memzero(&s1hat, sizeof(s1hat));
    pqc_memzero(&s2, sizeof(s2));
    pqc_memzero(&t0, sizeof(t0));

    return PQC_OK;
}

/* ================================================================= */
/*  ML-DSA.Sign (Algorithm 2 in FIPS 204)                              */
/* ================================================================= */

pqc_status_t pqc_mldsa_sign(const pqc_mldsa_params_t *params,
                             uint8_t *sig, size_t *siglen,
                             const uint8_t *msg, size_t msglen,
                             const uint8_t *sk)
{
    uint8_t rho[PQC_MLDSA_SEEDBYTES];
    uint8_t K[PQC_MLDSA_SEEDBYTES];
    uint8_t tr[PQC_MLDSA_TRBYTES];
    uint8_t mu[PQC_MLDSA_CRHBYTES];
    uint8_t rhoprime[PQC_MLDSA_CRHBYTES];
    uint8_t ctilde[PQC_MLDSA87_CTILDEBYTES]; /* max size */

    pqc_mldsa_poly mat[PQC_MLDSA_K_MAX * PQC_MLDSA_L_MAX];
    pqc_mldsa_polyvecl s1, s1hat, y, yhat, z;
    pqc_mldsa_polyveck s2, t0, w, w1, w0, h, cs2, ct0;
    pqc_mldsa_poly cp;
    unsigned n_hints;
    uint16_t kappa;
    int reject;

    if (!params || !sig || !siglen || !msg || !sk)
        return PQC_ERROR_INVALID_ARGUMENT;

    /* Step 1: Unpack secret key */
    pqc_mldsa_unpack_sk(rho, K, tr, &s1, &s2, &t0, sk, params);

    /* Step 2: Compute mu = H(tr || msg) using SHAKE-256 */
    {
        pqc_shake256_ctx ctx;
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, tr, PQC_MLDSA_TRBYTES);
        pqc_shake256_absorb(&ctx, msg, msglen);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, mu, PQC_MLDSA_CRHBYTES);
    }

    /* Step 3: Compute rhoprime = H(K || rnd || mu)
     * For deterministic signing (FIPS 204), rnd = 0^32.
     * For hedged signing, rnd is random. We use random. */
    {
        uint8_t rnd[32];
        pqc_shake256_ctx ctx;

        pqc_randombytes(rnd, 32);

        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, K, PQC_MLDSA_SEEDBYTES);
        pqc_shake256_absorb(&ctx, rnd, 32);
        pqc_shake256_absorb(&ctx, mu, PQC_MLDSA_CRHBYTES);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, rhoprime, PQC_MLDSA_CRHBYTES);

        pqc_memzero(rnd, sizeof(rnd));
    }

    /* Step 4: Expand matrix A */
    pqc_mldsa_expand_a(mat, rho, params->k, params->l);

    /* Step 5: NTT(s1), NTT(s2), NTT(t0) for fast multiplication */
    s1hat = s1;
    pqc_mldsa_polyvecl_ntt(&s1hat, params->l);
    pqc_mldsa_polyveck_ntt((pqc_mldsa_polyveck *)&s2, params->k);
    pqc_mldsa_polyveck_ntt(&t0, params->k);

    /* Step 6: Rejection sampling loop */
    kappa = 0;
    for (;;) {
        /* Step 7: y = ExpandMask(rhoprime, kappa) */
        pqc_mldsa_expand_mask(&y, rhoprime, kappa, params->gamma1, params->l);
        kappa += (uint16_t)params->l;

        /* Step 8: w = A * NTT(y) */
        yhat = y;
        pqc_mldsa_polyvecl_ntt(&yhat, params->l);
        pqc_mldsa_polyvec_matrix_pointwise(&w, mat, &yhat,
                                            params->k, params->l);
        pqc_mldsa_polyveck_reduce(&w, params->k);
        pqc_mldsa_polyveck_invntt(&w, params->k);
        pqc_mldsa_polyveck_caddq(&w, params->k);

        /* Step 9: Decompose w into (w1, w0) */
        pqc_mldsa_polyveck_decompose(&w1, &w0, &w,
                                      params->gamma2, params->k);

        /* Step 10: Compute challenge hash c_tilde = H(mu || w1) */
        {
            pqc_shake256_ctx ctx;
            unsigned i;
            uint8_t w1_packed[PQC_MLDSA_K_MAX * 192]; /* max w1 packed */

            for (i = 0; i < params->k; i++) {
                pqc_mldsa_polyw1_pack(
                    w1_packed + i * params->polyw1_packed,
                    &w1.vec[i], params->gamma2);
            }

            pqc_shake256_init(&ctx);
            pqc_shake256_absorb(&ctx, mu, PQC_MLDSA_CRHBYTES);
            pqc_shake256_absorb(&ctx, w1_packed,
                                params->k * params->polyw1_packed);
            pqc_shake256_finalize(&ctx);
            pqc_shake256_squeeze(&ctx, ctilde, params->ctilde_bytes);
        }

        /* Step 11: Challenge polynomial c */
        pqc_mldsa_poly_challenge(&cp, ctilde, params->ctilde_bytes,
                                  params->tau);
        pqc_mldsa_poly_ntt(&cp);

        /* Step 12: z = y + c * s1 */
        {
            unsigned i;
            pqc_mldsa_poly tmp;
            for (i = 0; i < params->l; i++) {
                pqc_mldsa_poly_pointwise(&tmp, &cp, &s1hat.vec[i]);
                pqc_mldsa_poly_invntt(&tmp);
                pqc_mldsa_poly_add(&z.vec[i], &y.vec[i], &tmp);
                pqc_mldsa_poly_reduce(&z.vec[i]);
            }
        }

        /* Step 13: Check ||z||_inf < gamma1 - beta */
        reject = pqc_mldsa_polyvecl_chknorm(
            &z, params->gamma1 - (int32_t)params->beta, params->l);
        if (reject)
            continue;

        /* Step 14: Compute cs2 = c * s2, check ||w0 - cs2||_inf < gamma2 - beta */
        {
            unsigned i;
            pqc_mldsa_poly tmp;
            for (i = 0; i < params->k; i++) {
                pqc_mldsa_poly_pointwise(&tmp, &cp, &s2.vec[i]);
                pqc_mldsa_poly_invntt(&tmp);
                pqc_mldsa_poly_sub(&cs2.vec[i], &w0.vec[i], &tmp);
                pqc_mldsa_poly_reduce(&cs2.vec[i]);
            }
        }

        reject = pqc_mldsa_polyveck_chknorm(
            &cs2, params->gamma2 - (int32_t)params->beta, params->k);
        if (reject)
            continue;

        /* Step 15: Compute ct0 = c * t0, check ||ct0||_inf < gamma2 */
        {
            unsigned i;
            for (i = 0; i < params->k; i++) {
                pqc_mldsa_poly_pointwise(&ct0.vec[i], &cp, &t0.vec[i]);
                pqc_mldsa_poly_invntt(&ct0.vec[i]);
                pqc_mldsa_poly_reduce(&ct0.vec[i]);
            }
        }

        reject = pqc_mldsa_polyveck_chknorm(
            &ct0, (int32_t)params->gamma2, params->k);
        if (reject)
            continue;

        /* Step 16: Compute hint h = MakeHint(-ct0, w - cs2 + ct0, gamma2)
         *
         * Per FIPS 204: cs2 currently holds (w0 - c*s2).
         * We need MakeHint(-ct0, (w0 - c*s2) + ct0, gamma2).
         * The first argument is the "low part" and the second is the
         * "candidate high part" input to MakeHint. */
        {
            unsigned i, j;
            pqc_mldsa_polyveck r0, r1;

            for (i = 0; i < params->k; i++) {
                /* r1 = (w0 - c*s2) + c*t0 */
                pqc_mldsa_poly_add(&r1.vec[i], &cs2.vec[i], &ct0.vec[i]);

                /* r0 = -c*t0 (negate ct0) */
                for (j = 0; j < PQC_MLDSA_N; j++)
                    r0.vec[i].coeffs[j] = -ct0.vec[i].coeffs[j];
            }

            n_hints = pqc_mldsa_polyveck_make_hint(
                &h, &r0, &r1, params->gamma2, params->k);
        }

        if (n_hints > params->omega)
            continue;

        /* Success: pack signature */
        pqc_mldsa_pack_sig(sig, ctilde, &z, &h, params);
        *siglen = params->sig_bytes;

        break;
    }

    /* Zeroize sensitive state */
    pqc_memzero(K, sizeof(K));
    pqc_memzero(rhoprime, sizeof(rhoprime));
    pqc_memzero(&s1, sizeof(s1));
    pqc_memzero(&s1hat, sizeof(s1hat));
    pqc_memzero(&s2, sizeof(s2));
    pqc_memzero(&t0, sizeof(t0));

    return PQC_OK;
}

/* ================================================================= */
/*  ML-DSA.Verify (Algorithm 3 in FIPS 204)                            */
/* ================================================================= */

pqc_status_t pqc_mldsa_verify(const pqc_mldsa_params_t *params,
                               const uint8_t *msg, size_t msglen,
                               const uint8_t *sig, size_t siglen,
                               const uint8_t *pk)
{
    uint8_t rho[PQC_MLDSA_SEEDBYTES];
    uint8_t tr[PQC_MLDSA_TRBYTES];
    uint8_t mu[PQC_MLDSA_CRHBYTES];
    uint8_t ctilde[PQC_MLDSA87_CTILDEBYTES];
    uint8_t ctilde2[PQC_MLDSA87_CTILDEBYTES];

    pqc_mldsa_poly mat[PQC_MLDSA_K_MAX * PQC_MLDSA_L_MAX];
    pqc_mldsa_polyveck t1, w1prime, h;
    pqc_mldsa_polyvecl z;
    pqc_mldsa_poly cp;

    if (!params || !msg || !sig || !pk)
        return PQC_ERROR_INVALID_ARGUMENT;

    if (siglen != params->sig_bytes)
        return PQC_ERROR_VERIFICATION_FAILED;

    /* Step 1: Unpack public key */
    pqc_mldsa_unpack_pk(rho, &t1, pk, params->k);

    /* Step 2: Unpack signature */
    if (pqc_mldsa_unpack_sig(ctilde, &z, &h, sig, params) != 0)
        return PQC_ERROR_VERIFICATION_FAILED;

    /* Step 3: Check ||z||_inf < gamma1 - beta */
    if (pqc_mldsa_polyvecl_chknorm(&z, params->gamma1 - (int32_t)params->beta,
                                     params->l))
        return PQC_ERROR_VERIFICATION_FAILED;

    /* Step 4: Compute tr = H(pk) */
    pqc_shake256(tr, PQC_MLDSA_TRBYTES, pk, params->pk_bytes);

    /* Step 5: Compute mu = H(tr || msg) */
    {
        pqc_shake256_ctx ctx;
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, tr, PQC_MLDSA_TRBYTES);
        pqc_shake256_absorb(&ctx, msg, msglen);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, mu, PQC_MLDSA_CRHBYTES);
    }

    /* Step 6: Expand matrix A */
    pqc_mldsa_expand_a(mat, rho, params->k, params->l);

    /* Step 7: Compute challenge polynomial c from c_tilde */
    pqc_mldsa_poly_challenge(&cp, ctilde, params->ctilde_bytes, params->tau);
    pqc_mldsa_poly_ntt(&cp);

    /* Step 8: Compute w'1 = UseHint(h, A*NTT(z) - c*NTT(t1*2^d), gamma2)
     *
     * First: A * NTT(z) */
    {
        pqc_mldsa_polyvecl zhat;
        pqc_mldsa_polyveck az, ct1;
        unsigned i;

        zhat = z;
        pqc_mldsa_polyvecl_ntt(&zhat, params->l);
        pqc_mldsa_polyvec_matrix_pointwise(&az, mat, &zhat,
                                            params->k, params->l);

        /* c * NTT(t1 * 2^d) */
        pqc_mldsa_polyveck_shiftl(&t1, params->k);
        pqc_mldsa_polyveck_ntt(&t1, params->k);

        for (i = 0; i < params->k; i++) {
            pqc_mldsa_poly_pointwise(&ct1.vec[i], &cp, &t1.vec[i]);
        }

        /* w'_approx = A*z - c*t1*2^d */
        for (i = 0; i < params->k; i++) {
            pqc_mldsa_poly_sub(&az.vec[i], &az.vec[i], &ct1.vec[i]);
        }
        pqc_mldsa_polyveck_reduce(&az, params->k);
        pqc_mldsa_polyveck_invntt(&az, params->k);
        pqc_mldsa_polyveck_caddq(&az, params->k);

        /* UseHint to recover w'1 */
        pqc_mldsa_polyveck_use_hint(&w1prime, &az, &h,
                                     params->gamma2, params->k);
    }

    /* Step 9: Recompute c_tilde' = H(mu || w'1) */
    {
        pqc_shake256_ctx ctx;
        unsigned i;
        uint8_t w1_packed[PQC_MLDSA_K_MAX * 192];

        for (i = 0; i < params->k; i++) {
            pqc_mldsa_polyw1_pack(
                w1_packed + i * params->polyw1_packed,
                &w1prime.vec[i], params->gamma2);
        }

        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, mu, PQC_MLDSA_CRHBYTES);
        pqc_shake256_absorb(&ctx, w1_packed,
                            params->k * params->polyw1_packed);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, ctilde2, params->ctilde_bytes);
    }

    /* Step 10: Check c_tilde == c_tilde' */
    if (pqc_memcmp_ct(ctilde, ctilde2, params->ctilde_bytes) != 0)
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
    unsigned i;
    for (i = 0; i < sizeof(mldsa_vtables) / sizeof(mldsa_vtables[0]); i++) {
        if (pqc_sig_add_vtable(&mldsa_vtables[i]) != 0)
            return -1;
    }
    return 0;
}
