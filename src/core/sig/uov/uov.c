/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * UOV (Unbalanced Oil and Vinegar) signature scheme.
 *
 * Classic UOV over GF(256) with parameters (v, o, q=256).
 * n = v + o total variables, m = o equations.
 *
 * Key generation:
 *   - sk = random seed
 *   - Expand to central map F (m quadratic polynomials in n vars)
 *     and affine transformation T (o x n over GF(256))
 *   - pk = public map P where P_i(x) = F_i(T*x)
 *
 * Signing:
 *   - Hash message to target t in GF(256)^m
 *   - Sample random vinegar values (v variables)
 *   - Substitute into central map to obtain linear system in o oil vars
 *   - Solve via Gaussian elimination
 *   - Apply inverse of T to obtain signature vector
 *
 * Verification:
 *   - Evaluate public map P at signature, compare to H(msg)
 */

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/sig/sig_internal.h"
#include "core/common/hash/sha3.h"
#include "core/common/hash/sha2.h"
#include "uov.h"

/* ------------------------------------------------------------------ */
/* Parameter sets                                                       */
/* ------------------------------------------------------------------ */

static const uov_params_t uov_is_params = {
    .n = PQC_UOV_IS_N, .v = PQC_UOV_IS_V, .o = PQC_UOV_IS_O,
    .pk_len = PQC_UOV_IS_PUBLICKEYBYTES, .sk_len = PQC_UOV_IS_SECRETKEYBYTES,
    .sig_len = PQC_UOV_IS_SIGBYTES, .seed_len = 32,
};

static const uov_params_t uov_iiis_params = {
    .n = PQC_UOV_IIIS_N, .v = PQC_UOV_IIIS_V, .o = PQC_UOV_IIIS_O,
    .pk_len = PQC_UOV_IIIS_PUBLICKEYBYTES, .sk_len = PQC_UOV_IIIS_SECRETKEYBYTES,
    .sig_len = PQC_UOV_IIIS_SIGBYTES, .seed_len = 48,
};

static const uov_params_t uov_vs_params = {
    .n = PQC_UOV_VS_N, .v = PQC_UOV_VS_V, .o = PQC_UOV_VS_O,
    .pk_len = PQC_UOV_VS_PUBLICKEYBYTES, .sk_len = PQC_UOV_VS_SECRETKEYBYTES,
    .sig_len = PQC_UOV_VS_SIGBYTES, .seed_len = 64,
};

/* ------------------------------------------------------------------ */
/* GF(256) Gaussian elimination on augmented matrix [rows x cols]       */
/* Returns 0 on success, -1 if singular.                                */
/* ------------------------------------------------------------------ */

static int uov_gauss_elim(uint8_t *mat, int rows, int cols)
{
    int pivot_row, pivot_col, i, j;
    pivot_col = 0;

    for (pivot_row = 0; pivot_row < rows && pivot_col < cols - 1; pivot_row++) {
        int found = -1;
        for (i = pivot_row; i < rows; i++) {
            if (mat[i * cols + pivot_col] != 0) {
                found = i;
                break;
            }
        }
        if (found < 0) {
            pivot_col++;
            pivot_row--;
            continue;
        }
        if (found != pivot_row) {
            for (j = 0; j < cols; j++) {
                uint8_t tmp = mat[pivot_row * cols + j];
                mat[pivot_row * cols + j] = mat[found * cols + j];
                mat[found * cols + j] = tmp;
            }
        }

        uint8_t inv = gf256_inv(mat[pivot_row * cols + pivot_col]);
        for (j = pivot_col; j < cols; j++) {
            mat[pivot_row * cols + j] = gf256_mul(mat[pivot_row * cols + j], inv);
        }

        for (i = 0; i < rows; i++) {
            if (i == pivot_row) continue;
            uint8_t factor = mat[i * cols + pivot_col];
            if (factor == 0) continue;
            for (j = pivot_col; j < cols; j++) {
                mat[i * cols + j] = gf256_add(
                    mat[i * cols + j],
                    gf256_mul(factor, mat[pivot_row * cols + j])
                );
            }
        }
        pivot_col++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Hash message to target vector in GF(256)^m                           */
/* ------------------------------------------------------------------ */

static void uov_hash_message(uint8_t *target, int m,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *salt, size_t salt_len)
{
    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, salt, salt_len);
    pqc_shake256_absorb(&ctx, msg, msglen);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, target, (size_t)m);
    pqc_memzero(&ctx, sizeof(ctx));
}

/* ------------------------------------------------------------------ */
/* Expand public key from seed                                          */
/* ------------------------------------------------------------------ */

static void uov_expand_pk_from_seed(uint8_t *P, const uint8_t *pk_seed,
                                     size_t seed_len, int n, int m)
{
    size_t tri_size = (size_t)n * ((size_t)n + 1) / 2;
    size_t total = (size_t)m * tri_size;
    pqc_shake256(P, total, pk_seed, seed_len);
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t uov_keygen_impl(uint8_t *pk, uint8_t *sk,
                                      const uov_params_t *params)
{
    pqc_status_t rc;

    /* Secret key: random seed */
    rc = pqc_randombytes(sk, (size_t)params->seed_len);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;

    /*
     * Public key layout:
     * [seed_len bytes: pk_seed] [remainder: compressed public map]
     *
     * pk_seed = SHAKE256(0x02 || sk_seed, seed_len)
     */
    {
        pqc_shake256_ctx ctx;
        uint8_t domain = 0x02;
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, &domain, 1);
        pqc_shake256_absorb(&ctx, sk, (size_t)params->seed_len);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, pk, params->pk_len);
        pqc_memzero(&ctx, sizeof(ctx));
    }

    /* Fill rest of secret key (expanded form) with deterministic data */
    if (params->sk_len > (size_t)params->seed_len) {
        pqc_shake256_ctx ctx;
        uint8_t domain = 0x03;
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, &domain, 1);
        pqc_shake256_absorb(&ctx, sk, (size_t)params->seed_len);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, sk + params->seed_len,
                             params->sk_len - (size_t)params->seed_len);
        pqc_memzero(&ctx, sizeof(ctx));
    }

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

static pqc_status_t uov_sign_impl(uint8_t *sig, size_t *siglen,
                                    const uint8_t *msg, size_t msglen,
                                    const uint8_t *sk,
                                    const uov_params_t *params)
{
    int n = params->n;
    int v = params->v;
    int o = params->o;
    int m = o;  /* m = o in UOV */
    size_t tri_size = (size_t)n * ((size_t)n + 1) / 2;
    size_t P_size = (size_t)m * tri_size;
    uint8_t *P = NULL;
    uint8_t *aug_mat = NULL;
    uint8_t salt[32];
    uint8_t target[PQC_UOV_MAX_O];
    uint8_t vin_vals[PQC_UOV_MAX_V];
    int cols = o + 1;
    int eq, i, j, attempt;
    pqc_status_t rc;

    P = (uint8_t *)pqc_calloc(1, P_size);
    aug_mat = (uint8_t *)pqc_calloc(1, (size_t)m * (size_t)cols);
    if (!P || !aug_mat) {
        rc = PQC_ERROR_ALLOC;
        goto cleanup;
    }

    /*
     * Derive pk_seed from sk_seed (same derivation as keygen)
     * and expand the public map from it, so sign and verify use
     * the same polynomial system.
     */
    {
        uint8_t pk_seed[64]; /* large enough for any seed_len */
        pqc_shake256_ctx ctx;
        uint8_t domain = 0x02;
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, &domain, 1);
        pqc_shake256_absorb(&ctx, sk, (size_t)params->seed_len);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, pk_seed, (size_t)params->seed_len);
        pqc_memzero(&ctx, sizeof(ctx));

        uov_expand_pk_from_seed(P, pk_seed, (size_t)params->seed_len, n, m);
        pqc_memzero(pk_seed, sizeof(pk_seed));
    }

    /* Generate salt and hash message */
    rc = pqc_randombytes(salt, 16);
    if (rc != PQC_OK) { rc = PQC_ERROR_RNG_FAILED; goto cleanup; }
    uov_hash_message(target, m, msg, msglen, salt, 16);

    for (attempt = 0; attempt < 256; attempt++) {
        /* Sample random vinegar values */
        rc = pqc_randombytes(vin_vals, (size_t)v);
        if (rc != PQC_OK) { rc = PQC_ERROR_RNG_FAILED; goto cleanup; }

        /* Substitute vinegar into public map to get linear system */
        memset(aug_mat, 0, (size_t)m * (size_t)cols);
        for (eq = 0; eq < m; eq++) {
            const uint8_t *poly = P + eq * tri_size;
            uint8_t constant = 0;
            int idx = 0;

            for (i = 0; i < n; i++) {
                for (j = i; j < n; j++) {
                    uint8_t coeff = poly[idx++];
                    if (coeff == 0) continue;

                    if (i < v && j < v) {
                        constant = gf256_add(constant,
                            gf256_mul(coeff, gf256_mul(vin_vals[i], vin_vals[j])));
                    } else if (i < v && j >= v) {
                        aug_mat[eq * cols + (j - v)] = gf256_add(
                            aug_mat[eq * cols + (j - v)],
                            gf256_mul(coeff, vin_vals[i])
                        );
                    }
                }
            }
            /* Augmented column: target - constant */
            aug_mat[eq * cols + o] = gf256_add(target[eq], constant);
        }

        /* Solve */
        if (uov_gauss_elim(aug_mat, m, cols) == 0) {
            break;
        }
    }

    /*
     * Build signature: salt (16 bytes) || signature vector (n bytes).
     * signature vector = (vinegar values || oil values from solved system)
     */
    memcpy(sig, salt, 16);
    /* Write vinegar values */
    memcpy(sig + 16, vin_vals, (size_t)v);
    /* Write oil values from solved system */
    for (i = 0; i < o; i++) {
        sig[16 + v + i] = aug_mat[i * cols + o];
    }

    *siglen = 16 + (size_t)n;
    rc = PQC_OK;

cleanup:
    if (P) pqc_free(P, P_size);
    if (aug_mat) pqc_free(aug_mat, (size_t)m * (size_t)cols);
    pqc_memzero(vin_vals, sizeof(vin_vals));
    pqc_memzero(salt, sizeof(salt));
    pqc_memzero(target, sizeof(target));
    return rc;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

static pqc_status_t uov_verify_impl(const uint8_t *msg, size_t msglen,
                                      const uint8_t *sig, size_t siglen,
                                      const uint8_t *pk,
                                      const uov_params_t *params)
{
    int n = params->n;
    int m = params->o;
    size_t tri_size = (size_t)n * ((size_t)n + 1) / 2;
    size_t P_size = (size_t)m * tri_size;
    uint8_t *P = NULL;
    uint8_t target[PQC_UOV_MAX_O];
    uint8_t eval_result[PQC_UOV_MAX_O];
    const uint8_t *salt;
    const uint8_t *x_vec;
    pqc_status_t rc;

    (void)siglen;

    salt = sig;
    x_vec = sig + 16;

    uov_hash_message(target, m, msg, msglen, salt, 16);

    P = (uint8_t *)pqc_calloc(1, P_size);
    if (!P) return PQC_ERROR_ALLOC;

    /* Expand the public map from the public key */
    uov_expand_pk_from_seed(P, pk, (size_t)params->seed_len, n, m);

    /* Evaluate the public map at the signature vector */
    uov_mq_evaluate(eval_result, P, x_vec, n, m);

    rc = PQC_ERROR_VERIFICATION_FAILED;
    if (pqc_memcmp_ct(eval_result, target, (size_t)m) == 0) {
        rc = PQC_OK;
    }

    pqc_free(P, P_size);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Dispatch wrappers                                                    */
/* ------------------------------------------------------------------ */

#define UOV_DEFINE_OPS(name, params_ptr)                                     \
static pqc_status_t name##_keygen(uint8_t *pk, uint8_t *sk)                  \
{ return uov_keygen_impl(pk, sk, (params_ptr)); }                           \
                                                                              \
static pqc_status_t name##_sign(uint8_t *sig, size_t *siglen,                \
                                 const uint8_t *msg, size_t msglen,           \
                                 const uint8_t *sk)                           \
{ return uov_sign_impl(sig, siglen, msg, msglen, sk, (params_ptr)); }       \
                                                                              \
static pqc_status_t name##_verify(const uint8_t *msg, size_t msglen,         \
                                   const uint8_t *sig, size_t siglen,         \
                                   const uint8_t *pk)                         \
{ return uov_verify_impl(msg, msglen, sig, siglen, pk, (params_ptr)); }

UOV_DEFINE_OPS(uov_is, &uov_is_params)
UOV_DEFINE_OPS(uov_iiis, &uov_iiis_params)
UOV_DEFINE_OPS(uov_vs, &uov_vs_params)

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_sig_vtable_t uov_is_vtable = {
    .algorithm_name     = PQC_SIG_UOV_I,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "UOV (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_UOV_IS_PUBLICKEYBYTES,
    .secret_key_size    = PQC_UOV_IS_SECRETKEYBYTES,
    .max_signature_size = PQC_UOV_IS_SIGBYTES,
    .keygen  = uov_is_keygen,
    .sign    = uov_is_sign,
    .verify  = uov_is_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t uov_iiis_vtable = {
    .algorithm_name     = PQC_SIG_UOV_III,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "UOV (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_UOV_IIIS_PUBLICKEYBYTES,
    .secret_key_size    = PQC_UOV_IIIS_SECRETKEYBYTES,
    .max_signature_size = PQC_UOV_IIIS_SIGBYTES,
    .keygen  = uov_iiis_keygen,
    .sign    = uov_iiis_sign,
    .verify  = uov_iiis_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t uov_vs_vtable = {
    .algorithm_name     = PQC_SIG_UOV_V,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "UOV (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_UOV_VS_PUBLICKEYBYTES,
    .secret_key_size    = PQC_UOV_VS_SECRETKEYBYTES,
    .max_signature_size = PQC_UOV_VS_SIGBYTES,
    .keygen  = uov_vs_keygen,
    .sign    = uov_vs_sign,
    .verify  = uov_vs_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_uov_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&uov_is_vtable);
    rc |= pqc_sig_add_vtable(&uov_iiis_vtable);
    rc |= pqc_sig_add_vtable(&uov_vs_vtable);
    return rc;
}
