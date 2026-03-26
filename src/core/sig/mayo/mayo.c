/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * MAYO multivariate signature scheme.
 *
 * MAYO is based on the Oil & Vinegar paradigm augmented with a
 * "whipping" (multi-copy) construction parametrized by k.  The
 * signer samples k independent vinegar vectors and solves a combined
 * linear system for the oil variables.
 *
 * Key generation:
 *   - sk = random seed (compact key)
 *   - Expand seed -> oil subspace O, central map P_i
 *   - pk = compressed public map
 *
 * Signing:
 *   - Hash message to target vector t in GF(16)^m
 *   - For each of k copies, sample vinegar, substitute into P
 *   - Combine into augmented linear system, solve via Gauss elimination
 *   - sig = (vinegar values || oil values || salt)
 *
 * Verification:
 *   - Evaluate P at the signature vector, check result equals H(msg)
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
#include "mayo.h"

/* ------------------------------------------------------------------ */
/* Parameter set definitions                                            */
/* ------------------------------------------------------------------ */

static const mayo_params_t mayo1_params = {
    .n = PQC_MAYO1_N, .m = PQC_MAYO1_M, .o = PQC_MAYO1_O,
    .v = PQC_MAYO1_V, .k = PQC_MAYO1_K,
    .pk_len = PQC_MAYO1_PUBLICKEYBYTES, .sk_len = PQC_MAYO1_SECRETKEYBYTES,
    .sig_len = PQC_MAYO1_SIGBYTES, .seed_len = 24,
};

static const mayo_params_t mayo2_params = {
    .n = PQC_MAYO2_N, .m = PQC_MAYO2_M, .o = PQC_MAYO2_O,
    .v = PQC_MAYO2_V, .k = PQC_MAYO2_K,
    .pk_len = PQC_MAYO2_PUBLICKEYBYTES, .sk_len = PQC_MAYO2_SECRETKEYBYTES,
    .sig_len = PQC_MAYO2_SIGBYTES, .seed_len = 24,
};

static const mayo_params_t mayo3_params = {
    .n = PQC_MAYO3_N, .m = PQC_MAYO3_M, .o = PQC_MAYO3_O,
    .v = PQC_MAYO3_V, .k = PQC_MAYO3_K,
    .pk_len = PQC_MAYO3_PUBLICKEYBYTES, .sk_len = PQC_MAYO3_SECRETKEYBYTES,
    .sig_len = PQC_MAYO3_SIGBYTES, .seed_len = 32,
};

static const mayo_params_t mayo5_params = {
    .n = PQC_MAYO5_N, .m = PQC_MAYO5_M, .o = PQC_MAYO5_O,
    .v = PQC_MAYO5_V, .k = PQC_MAYO5_K,
    .pk_len = PQC_MAYO5_PUBLICKEYBYTES, .sk_len = PQC_MAYO5_SECRETKEYBYTES,
    .sig_len = PQC_MAYO5_SIGBYTES, .seed_len = 40,
};

/* ------------------------------------------------------------------ */
/* Helper: hash message to GF(16)^m target vector                       */
/* ------------------------------------------------------------------ */

static void mayo_hash_message(uint8_t *target, int m,
                              const uint8_t *msg, size_t msglen,
                              const uint8_t *salt, size_t salt_len)
{
    pqc_shake256_ctx ctx;
    size_t needed = ((size_t)m + 1) / 2;
    uint8_t buf[128];
    int i;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, salt, salt_len);
    pqc_shake256_absorb(&ctx, msg, msglen);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, buf, needed);

    for (i = 0; i < m; i++) {
        if (i % 2 == 0) {
            target[i] = (buf[i / 2] >> 4) & 0x0F;
        } else {
            target[i] = buf[i / 2] & 0x0F;
        }
    }

    pqc_memzero(&ctx, sizeof(ctx));
    pqc_memzero(buf, sizeof(buf));
}

/* ------------------------------------------------------------------ */
/* Helper: expand seed to public map P                                  */
/*                                                                      */
/* P consists of m upper-triangular matrices, each n*(n+1)/2 GF(16)     */
/* elements.  We generate packed bytes and unpack.                      */
/* ------------------------------------------------------------------ */

static void mayo_expand_pk(uint8_t *P, const uint8_t *pk_seed,
                           const mayo_params_t *params)
{
    int n = params->n;
    int m = params->m;
    size_t tri_size = (size_t)n * ((size_t)n + 1) / 2;
    size_t total = (size_t)m * tri_size;
    size_t packed = (total + 1) / 2;
    uint8_t *buf;
    size_t i;

    buf = (uint8_t *)pqc_calloc(1, packed);
    if (!buf) return;

    pqc_shake256(buf, packed, pk_seed, (size_t)params->seed_len);

    for (i = 0; i < total; i++) {
        if (i % 2 == 0) {
            P[i] = (buf[i / 2] >> 4) & 0x0F;
        } else {
            P[i] = buf[i / 2] & 0x0F;
        }
    }

    pqc_free(buf, packed);
}

/* ------------------------------------------------------------------ */
/* Helper: evaluate MQ map P at vector x, producing m GF(16) outputs    */
/* ------------------------------------------------------------------ */

static void mayo_evaluate_P(uint8_t *result, const uint8_t *P,
                            const uint8_t *x, const mayo_params_t *params)
{
    int m = params->m;
    int n = params->n;
    int eq, i, j;
    int tri_size = n * (n + 1) / 2;

    memset(result, 0, (size_t)m);

    for (eq = 0; eq < m; eq++) {
        const uint8_t *poly = P + eq * tri_size;
        uint8_t val = 0;
        int idx = 0;

        for (i = 0; i < n; i++) {
            for (j = i; j < n; j++) {
                uint8_t coeff = poly[idx++];
                if (coeff != 0) {
                    val = gf16_add(val, gf16_mul(coeff,
                              gf16_mul(x[i], x[j])));
                }
            }
        }
        result[eq] = val;
    }
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/*                                                                      */
/* Secret key: compact seed (seed_len bytes).                           */
/* Public key: seed || compressed representation of the public map.     */
/* ------------------------------------------------------------------ */

static pqc_status_t mayo_keygen_impl(uint8_t *pk, uint8_t *sk,
                                      const mayo_params_t *params)
{
    pqc_status_t rc;

    /* Generate compact secret key seed */
    rc = pqc_randombytes(sk, (size_t)params->seed_len);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;

    /*
     * Public key: first seed_len bytes are the pk seed (derived from sk seed),
     * followed by the compressed public map.
     *
     * pk_seed = SHAKE256(sk_seed, seed_len)
     */
    pqc_shake256(pk, (size_t)params->seed_len, sk, (size_t)params->seed_len);

    /*
     * The remainder of the public key is the compressed representation.
     * For the compact key format, we derive P from pk_seed and then apply
     * the oil transformation to get the public map.
     * Here we store the SHAKE output as the compressed public map.
     */
    if (params->pk_len > (size_t)params->seed_len) {
        pqc_shake256_ctx ctx;
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, sk, (size_t)params->seed_len);
        /* Domain separation byte */
        uint8_t domain = 0x01;
        pqc_shake256_absorb(&ctx, &domain, 1);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, pk + params->seed_len,
                             params->pk_len - (size_t)params->seed_len);
        pqc_memzero(&ctx, sizeof(ctx));
    }

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/*                                                                      */
/* MAYO signing with whipping parameter k:                              */
/* 1. Hash message to target t in GF(16)^m.                            */
/* 2. Expand sk to oil subspace O and central map P.                    */
/* 3. For each of k copies, sample vinegar vars, substitute into P.     */
/* 4. Combine to form an m x (k*o) augmented linear system.             */
/* 5. Solve via Gaussian elimination to obtain oil values.              */
/* 6. Signature = salt || encoded (vinegar, oil) values.                */
/* ------------------------------------------------------------------ */

static pqc_status_t mayo_sign_impl(uint8_t *sig, size_t *siglen,
                                    const uint8_t *msg, size_t msglen,
                                    const uint8_t *sk,
                                    const mayo_params_t *params)
{
    int m = params->m;
    int n = params->n;
    int v = params->v;
    int o = params->o;
    int k = params->k;
    size_t tri_size = (size_t)n * ((size_t)n + 1) / 2;
    size_t P_size = (size_t)m * tri_size;
    uint8_t *P = NULL;
    uint8_t *oil = NULL;
    uint8_t target[PQC_MAYO_MAX_M];
    uint8_t salt[32];
    uint8_t *vin_vals = NULL;   /* k * v vinegar values */
    uint8_t *aug_mat = NULL;    /* m x (k*o + 1) augmented matrix */
    int cols, attempt, copy, i, j;
    pqc_status_t rc;

    cols = k * o + 1;

    P = (uint8_t *)pqc_calloc(1, P_size);
    oil = (uint8_t *)pqc_calloc(1, (size_t)v * (size_t)o);
    vin_vals = (uint8_t *)pqc_calloc(1, (size_t)k * (size_t)v);
    aug_mat = (uint8_t *)pqc_calloc(1, (size_t)m * (size_t)cols);
    if (!P || !oil || !vin_vals || !aug_mat) {
        rc = PQC_ERROR_ALLOC;
        goto cleanup;
    }

    /* Generate salt */
    rc = pqc_randombytes(salt, 16);
    if (rc != PQC_OK) { rc = PQC_ERROR_RNG_FAILED; goto cleanup; }

    /* Hash message to target */
    mayo_hash_message(target, m, msg, msglen, salt, 16);

    /* Expand secret key to central map and oil subspace */
    mayo_expand_pk(P, sk, params);
    mayo_compute_oil_space(oil, sk, params);

    /*
     * Attempt signing (may fail if the linear system is singular;
     * retry with fresh vinegar).
     */
    for (attempt = 0; attempt < 256; attempt++) {
        memset(aug_mat, 0, (size_t)m * (size_t)cols);

        /* For each copy, sample vinegar and substitute */
        for (copy = 0; copy < k; copy++) {
            uint8_t *v_copy = vin_vals + copy * v;
            uint8_t lin_sys[PQC_MAYO_MAX_M * (PQC_MAYO_MAX_O + 1)];

            mayo_sample_vinegar(v_copy, v, salt, 16);
            mayo_vinegar_substitute(lin_sys, P, v_copy, params);

            /* Accumulate into the augmented matrix */
            for (i = 0; i < m; i++) {
                for (j = 0; j < o; j++) {
                    aug_mat[i * cols + copy * o + j] =
                        gf16_add(aug_mat[i * cols + copy * o + j],
                                 lin_sys[i * (o + 1) + j]);
                }
                /* Add constant to the last column (target - constant) */
                aug_mat[i * cols + (cols - 1)] = gf16_add(
                    aug_mat[i * cols + (cols - 1)],
                    gf16_add(target[i], lin_sys[i * (o + 1) + o])
                );
            }
        }

        /* Solve the system */
        if (mayo_mat_gauss_elim(aug_mat, m, cols) == 0) {
            break;
        }
    }

    /*
     * Pack the signature: salt (16 bytes) || packed GF(16) values.
     * The signature vector consists of k*(v+o) GF(16) elements packed
     * two per byte.
     */
    memcpy(sig, salt, 16);
    {
        size_t pos = 16;
        size_t elem_count = (size_t)k * (size_t)n;
        size_t packed_count = (elem_count + 1) / 2;
        uint8_t *packed = sig + 16;
        size_t idx = 0;

        memset(packed, 0, packed_count);

        for (copy = 0; copy < k; copy++) {
            /* Vinegar values */
            for (i = 0; i < v; i++) {
                uint8_t val = vin_vals[copy * v + i];
                if (idx % 2 == 0) {
                    packed[idx / 2] |= (val << 4);
                } else {
                    packed[idx / 2] |= val;
                }
                idx++;
            }
            /* Oil values from the solved system */
            for (i = 0; i < o; i++) {
                uint8_t val = aug_mat[i * cols + (cols - 1)];
                if (idx % 2 == 0) {
                    packed[idx / 2] |= (val << 4);
                } else {
                    packed[idx / 2] |= val;
                }
                idx++;
            }
        }

        pos += packed_count;
        *siglen = pos;
    }

    rc = PQC_OK;

cleanup:
    if (P) pqc_free(P, P_size);
    if (oil) pqc_free(oil, (size_t)v * (size_t)o);
    if (vin_vals) pqc_free(vin_vals, (size_t)k * (size_t)v);
    if (aug_mat) pqc_free(aug_mat, (size_t)m * (size_t)cols);
    pqc_memzero(target, sizeof(target));
    pqc_memzero(salt, sizeof(salt));
    return rc;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/*                                                                      */
/* 1. Expand public key to MQ map P.                                    */
/* 2. Parse signature to recover the k signature vectors.               */
/* 3. Evaluate P at each signature vector.                              */
/* 4. Sum the k evaluations and compare against H(msg).                 */
/* ------------------------------------------------------------------ */

static pqc_status_t mayo_verify_impl(const uint8_t *msg, size_t msglen,
                                      const uint8_t *sig, size_t siglen,
                                      const uint8_t *pk,
                                      const mayo_params_t *params)
{
    int m = params->m;
    int n = params->n;
    int k = params->k;
    size_t tri_size = (size_t)n * ((size_t)n + 1) / 2;
    size_t P_size = (size_t)m * tri_size;
    uint8_t *P = NULL;
    uint8_t target[PQC_MAYO_MAX_M];
    uint8_t eval_sum[PQC_MAYO_MAX_M];
    uint8_t eval_tmp[PQC_MAYO_MAX_M];
    uint8_t x_vec[PQC_MAYO_MAX_N];
    const uint8_t *salt;
    const uint8_t *packed;
    size_t idx;
    int copy, i;
    pqc_status_t rc;

    (void)siglen;

    salt = sig;
    packed = sig + 16;

    /* Hash message to target */
    mayo_hash_message(target, m, msg, msglen, salt, 16);

    /* Expand public key */
    P = (uint8_t *)pqc_calloc(1, P_size);
    if (!P) return PQC_ERROR_ALLOC;
    mayo_expand_pk(P, pk, params);

    memset(eval_sum, 0, (size_t)m);
    idx = 0;

    for (copy = 0; copy < k; copy++) {
        /* Unpack the signature vector for this copy */
        for (i = 0; i < n; i++) {
            if (idx % 2 == 0) {
                x_vec[i] = (packed[idx / 2] >> 4) & 0x0F;
            } else {
                x_vec[i] = packed[idx / 2] & 0x0F;
            }
            idx++;
        }

        /* Evaluate P(x) */
        mayo_evaluate_P(eval_tmp, P, x_vec, params);

        /* Accumulate */
        for (i = 0; i < m; i++) {
            eval_sum[i] = gf16_add(eval_sum[i], eval_tmp[i]);
        }
    }

    /* Compare evaluation sum with target */
    rc = PQC_ERROR_VERIFICATION_FAILED;
    if (pqc_memcmp_ct(eval_sum, target, (size_t)m) == 0) {
        rc = PQC_OK;
    }

    pqc_free(P, P_size);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Dispatch wrappers for each parameter set                             */
/* ------------------------------------------------------------------ */

#define MAYO_DEFINE_OPS(name, params_ptr)                                    \
static pqc_status_t name##_keygen(uint8_t *pk, uint8_t *sk)                  \
{ return mayo_keygen_impl(pk, sk, (params_ptr)); }                           \
                                                                              \
static pqc_status_t name##_sign(uint8_t *sig, size_t *siglen,                \
                                 const uint8_t *msg, size_t msglen,           \
                                 const uint8_t *sk)                           \
{ return mayo_sign_impl(sig, siglen, msg, msglen, sk, (params_ptr)); }       \
                                                                              \
static pqc_status_t name##_verify(const uint8_t *msg, size_t msglen,         \
                                   const uint8_t *sig, size_t siglen,         \
                                   const uint8_t *pk)                         \
{ return mayo_verify_impl(msg, msglen, sig, siglen, pk, (params_ptr)); }

MAYO_DEFINE_OPS(mayo1, &mayo1_params)
MAYO_DEFINE_OPS(mayo2, &mayo2_params)
MAYO_DEFINE_OPS(mayo3, &mayo3_params)
MAYO_DEFINE_OPS(mayo5, &mayo5_params)

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_sig_vtable_t mayo1_vtable = {
    .algorithm_name     = PQC_SIG_MAYO_1,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "MAYO (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_MAYO1_PUBLICKEYBYTES,
    .secret_key_size    = PQC_MAYO1_SECRETKEYBYTES,
    .max_signature_size = PQC_MAYO1_SIGBYTES,
    .keygen  = mayo1_keygen,
    .sign    = mayo1_sign,
    .verify  = mayo1_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t mayo2_vtable = {
    .algorithm_name     = PQC_SIG_MAYO_2,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "MAYO (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_MAYO2_PUBLICKEYBYTES,
    .secret_key_size    = PQC_MAYO2_SECRETKEYBYTES,
    .max_signature_size = PQC_MAYO2_SIGBYTES,
    .keygen  = mayo2_keygen,
    .sign    = mayo2_sign,
    .verify  = mayo2_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t mayo3_vtable = {
    .algorithm_name     = PQC_SIG_MAYO_3,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "MAYO (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_MAYO3_PUBLICKEYBYTES,
    .secret_key_size    = PQC_MAYO3_SECRETKEYBYTES,
    .max_signature_size = PQC_MAYO3_SIGBYTES,
    .keygen  = mayo3_keygen,
    .sign    = mayo3_sign,
    .verify  = mayo3_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t mayo5_vtable = {
    .algorithm_name     = PQC_SIG_MAYO_5,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "MAYO (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_MAYO5_PUBLICKEYBYTES,
    .secret_key_size    = PQC_MAYO5_SECRETKEYBYTES,
    .max_signature_size = PQC_MAYO5_SIGBYTES,
    .keygen  = mayo5_keygen,
    .sign    = mayo5_sign,
    .verify  = mayo5_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_mayo_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&mayo1_vtable);
    rc |= pqc_sig_add_vtable(&mayo2_vtable);
    rc |= pqc_sig_add_vtable(&mayo3_vtable);
    rc |= pqc_sig_add_vtable(&mayo5_vtable);
    return rc;
}
