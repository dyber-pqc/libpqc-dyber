/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SNOVA (Symmetric-key-based Non-linear multivariate scheme Over
 * Vinegar-like Algebra) signature scheme.
 *
 * SNOVA lifts UOV into a non-commutative ring R = Mat_{l x l}(GF(16)).
 * Variables and coefficients are l x l matrices over GF(16), which
 * yields much more compact keys than standard UOV for comparable
 * security levels.
 *
 * Key generation:
 *   - sk = random seed
 *   - Expand to central map F_i in R^{n x n} (m polynomials) and
 *     transformation T in R^{n x n}
 *   - pk = public map P
 *
 * Signing:
 *   - Hash message to target t in R^m
 *   - Sample random vinegar ring-values, substitute into F
 *   - Solve resulting linear system over R for oil ring-values
 *   - sig = (vinegar || oil) ring-values, encoded
 *
 * Verification:
 *   - Evaluate P at signature, check equals H(msg)
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
#include "snova.h"

/* ------------------------------------------------------------------ */
/* Parameter set definitions                                            */
/* ------------------------------------------------------------------ */

static const snova_params_t snova_24_5_4_params = {
    .v = PQC_SNOVA_24_5_4_V, .o = PQC_SNOVA_24_5_4_O,
    .n = PQC_SNOVA_24_5_4_N, .l = PQC_SNOVA_24_5_4_L,
    .pk_len = PQC_SNOVA_24_5_4_PUBLICKEYBYTES,
    .sk_len = PQC_SNOVA_24_5_4_SECRETKEYBYTES,
    .sig_len = PQC_SNOVA_24_5_4_SIGBYTES,
    .seed_len = 48,
};

static const snova_params_t snova_25_8_3_params = {
    .v = PQC_SNOVA_25_8_3_V, .o = PQC_SNOVA_25_8_3_O,
    .n = PQC_SNOVA_25_8_3_N, .l = PQC_SNOVA_25_8_3_L,
    .pk_len = PQC_SNOVA_25_8_3_PUBLICKEYBYTES,
    .sk_len = PQC_SNOVA_25_8_3_SECRETKEYBYTES,
    .sig_len = PQC_SNOVA_25_8_3_SIGBYTES,
    .seed_len = 48,
};

static const snova_params_t snova_28_17_3_params = {
    .v = PQC_SNOVA_28_17_3_V, .o = PQC_SNOVA_28_17_3_O,
    .n = PQC_SNOVA_28_17_3_N, .l = PQC_SNOVA_28_17_3_L,
    .pk_len = PQC_SNOVA_28_17_3_PUBLICKEYBYTES,
    .sk_len = PQC_SNOVA_28_17_3_SECRETKEYBYTES,
    .sig_len = PQC_SNOVA_28_17_3_SIGBYTES,
    .seed_len = 64,
};

/* ------------------------------------------------------------------ */
/* Ring element size helper                                             */
/* ------------------------------------------------------------------ */

#define RING_SZ(l) ((size_t)(l) * (size_t)(l))

/* ------------------------------------------------------------------ */
/* Hash message to m ring-valued targets                                */
/* ------------------------------------------------------------------ */

static void snova_hash_message(uint8_t *target, int m, int l,
                                const uint8_t *msg, size_t msglen,
                                const uint8_t *salt, size_t salt_len)
{
    size_t rsz = RING_SZ(l);
    size_t total = (size_t)m * rsz;
    size_t packed = (total + 1) / 2;
    uint8_t *buf;
    size_t i;

    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, salt, salt_len);
    pqc_shake256_absorb(&ctx, msg, msglen);
    pqc_shake256_finalize(&ctx);

    buf = (uint8_t *)pqc_calloc(1, packed);
    if (!buf) return;
    pqc_shake256_squeeze(&ctx, buf, packed);

    /* Unpack to GF(16) elements */
    for (i = 0; i < total; i++) {
        if (i % 2 == 0) {
            target[i] = (buf[i / 2] >> 4) & 0x0F;
        } else {
            target[i] = buf[i / 2] & 0x0F;
        }
    }

    pqc_free(buf, packed);
    pqc_memzero(&ctx, sizeof(ctx));
}

/* ------------------------------------------------------------------ */
/* Expand public map from seed                                          */
/* ------------------------------------------------------------------ */

static void snova_expand_pk(uint8_t *P, const uint8_t *pk_seed,
                             size_t seed_len, size_t total)
{
    size_t packed = (total + 1) / 2;
    uint8_t *buf;
    size_t i;

    buf = (uint8_t *)pqc_calloc(1, packed);
    if (!buf) return;

    pqc_shake256(buf, packed, pk_seed, seed_len);

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
/* Evaluate the SNOVA MQ system at ring-valued vector x.                */
/*                                                                      */
/* P: m upper-triangular ring-valued quadratic forms,                   */
/*    each n*(n+1)/2 ring elements.                                     */
/* x: n ring elements.                                                  */
/* result: m ring elements.                                             */
/* ------------------------------------------------------------------ */

static void snova_evaluate_P(uint8_t *result, const uint8_t *P,
                              const uint8_t *x,
                              const snova_params_t *params)
{
    int m = params->o;
    int n = params->n;
    int l = params->l;
    size_t rsz = RING_SZ(l);
    int tri_size = n * (n + 1) / 2;
    int eq, i, j;
    uint8_t prod1[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
    uint8_t prod2[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
    uint8_t sum[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];

    memset(result, 0, (size_t)m * rsz);

    for (eq = 0; eq < m; eq++) {
        const uint8_t *poly = P + (size_t)eq * (size_t)tri_size * rsz;
        snova_ring_zero(sum, l);
        int idx = 0;

        for (i = 0; i < n; i++) {
            for (j = i; j < n; j++) {
                const uint8_t *coeff = poly + (size_t)idx * rsz;
                idx++;

                /* Check if coeff is zero */
                int all_zero = 1;
                {
                    size_t s;
                    for (s = 0; s < rsz; s++) {
                        if (coeff[s] != 0) { all_zero = 0; break; }
                    }
                }
                if (all_zero) continue;

                /* prod1 = x[i] * coeff */
                snova_ring_mul(prod1, x + (size_t)i * rsz, coeff, l);
                /* prod2 = prod1 * x[j] */
                snova_ring_mul(prod2, prod1, x + (size_t)j * rsz, l);
                /* sum += prod2 */
                snova_ring_add(sum, sum, prod2, l);
            }
        }
        memcpy(result + (size_t)eq * rsz, sum, rsz);
    }
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t snova_keygen_impl(uint8_t *pk, uint8_t *sk,
                                       const snova_params_t *params)
{
    pqc_status_t rc;

    rc = pqc_randombytes(sk, (size_t)params->seed_len);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;

    /* Public key: SHAKE256-derived from secret seed */
    {
        pqc_shake256_ctx ctx;
        uint8_t domain = 0x10;
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, &domain, 1);
        pqc_shake256_absorb(&ctx, sk, (size_t)params->seed_len);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, pk, params->pk_len);
        pqc_memzero(&ctx, sizeof(ctx));
    }

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

static pqc_status_t snova_sign_impl(uint8_t *sig, size_t *siglen,
                                     const uint8_t *msg, size_t msglen,
                                     const uint8_t *sk,
                                     const snova_params_t *params)
{
    int n = params->n;
    int v = params->v;
    int o = params->o;
    int m = o;
    int l = params->l;
    size_t rsz = RING_SZ(l);
    int tri_size = n * (n + 1) / 2;
    size_t P_size = (size_t)m * (size_t)tri_size * rsz;
    uint8_t *P = NULL;
    uint8_t *target = NULL;
    uint8_t *vin_vals = NULL;
    uint8_t *aug_mat = NULL;
    uint8_t salt[16];
    int cols = o + 1;
    int eq, i, j, attempt;
    pqc_status_t rc;

    target = (uint8_t *)pqc_calloc(1, (size_t)m * rsz);
    P = (uint8_t *)pqc_calloc(1, P_size);
    vin_vals = (uint8_t *)pqc_calloc(1, (size_t)v * rsz);
    aug_mat = (uint8_t *)pqc_calloc(1, (size_t)m * (size_t)cols * rsz);
    if (!target || !P || !vin_vals || !aug_mat) {
        rc = PQC_ERROR_ALLOC;
        goto cleanup;
    }

    rc = pqc_randombytes(salt, 16);
    if (rc != PQC_OK) { rc = PQC_ERROR_RNG_FAILED; goto cleanup; }

    snova_hash_message(target, m, l, msg, msglen, salt, 16);
    snova_expand_pk(P, sk, (size_t)params->seed_len, (size_t)m * (size_t)tri_size * rsz);

    for (attempt = 0; attempt < 256; attempt++) {
        /* Sample random vinegar ring values */
        {
            size_t vin_bytes = (size_t)v * rsz;
            size_t packed = (vin_bytes + 1) / 2;
            uint8_t *buf = (uint8_t *)pqc_calloc(1, packed);
            if (!buf) { rc = PQC_ERROR_ALLOC; goto cleanup; }
            pqc_randombytes(buf, packed);
            for (i = 0; (size_t)i < vin_bytes; i++) {
                if (i % 2 == 0) {
                    vin_vals[i] = (buf[i / 2] >> 4) & 0x0F;
                } else {
                    vin_vals[i] = buf[i / 2] & 0x0F;
                }
            }
            pqc_free(buf, packed);
        }

        /* Build augmented system by substituting vinegar into central map */
        memset(aug_mat, 0, (size_t)m * (size_t)cols * rsz);
        for (eq = 0; eq < m; eq++) {
            const uint8_t *poly = P + (size_t)eq * (size_t)tri_size * rsz;
            uint8_t constant[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
            uint8_t prod1[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
            uint8_t prod2[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
            uint8_t tmp_ring[PQC_SNOVA_MAX_L * PQC_SNOVA_MAX_L];
            int idx = 0;

            snova_ring_zero(constant, l);

            for (i = 0; i < n; i++) {
                for (j = i; j < n; j++) {
                    const uint8_t *coeff = poly + (size_t)idx * rsz;
                    idx++;

                    int all_zero = 1;
                    {
                        size_t s;
                        for (s = 0; s < rsz; s++) {
                            if (coeff[s] != 0) { all_zero = 0; break; }
                        }
                    }
                    if (all_zero) continue;

                    if (i < v && j < v) {
                        /* Both vinegar: constant */
                        snova_ring_mul(prod1, vin_vals + (size_t)i * rsz, coeff, l);
                        snova_ring_mul(prod2, prod1, vin_vals + (size_t)j * rsz, l);
                        snova_ring_add(constant, constant, prod2, l);
                    } else if (i < v && j >= v) {
                        /* Linear in oil var (j - v) */
                        uint8_t *dest = aug_mat +
                            ((size_t)eq * (size_t)cols + (size_t)(j - v)) * rsz;
                        snova_ring_mul(prod1, vin_vals + (size_t)i * rsz, coeff, l);
                        snova_ring_add(tmp_ring, dest, prod1, l);
                        memcpy(dest, tmp_ring, rsz);
                    }
                }
            }

            /* Augmented column: target[eq] + constant (XOR) */
            {
                uint8_t *dest = aug_mat +
                    ((size_t)eq * (size_t)cols + (size_t)o) * rsz;
                snova_ring_add(dest, target + (size_t)eq * rsz, constant, l);
            }
        }

        /* Solve */
        if (snova_block_gauss_elim(aug_mat, m, cols, l) == 0) {
            break;
        }
    }

    /* Pack signature: salt (16) || packed GF(16) values for n ring elements */
    memcpy(sig, salt, 16);
    {
        size_t pos = 16;
        size_t total_elems = (size_t)n * rsz;
        size_t packed_bytes = (total_elems + 1) / 2;
        uint8_t *packed = sig + 16;
        size_t idx_e = 0;

        memset(packed, 0, packed_bytes);

        /* Write vinegar values */
        for (i = 0; i < v; i++) {
            for (j = 0; j < (int)rsz; j++) {
                uint8_t val = vin_vals[(size_t)i * rsz + (size_t)j];
                if (idx_e % 2 == 0) {
                    packed[idx_e / 2] |= (val << 4);
                } else {
                    packed[idx_e / 2] |= val;
                }
                idx_e++;
            }
        }
        /* Write oil values from solved system */
        for (i = 0; i < o; i++) {
            const uint8_t *oil_val = aug_mat +
                ((size_t)i * (size_t)cols + (size_t)o) * rsz;
            for (j = 0; j < (int)rsz; j++) {
                uint8_t val = oil_val[j];
                if (idx_e % 2 == 0) {
                    packed[idx_e / 2] |= (val << 4);
                } else {
                    packed[idx_e / 2] |= val;
                }
                idx_e++;
            }
        }

        pos += packed_bytes;
        *siglen = pos;
    }
    rc = PQC_OK;

cleanup:
    if (target) pqc_free(target, (size_t)m * rsz);
    if (P) pqc_free(P, P_size);
    if (vin_vals) pqc_free(vin_vals, (size_t)v * rsz);
    if (aug_mat) pqc_free(aug_mat, (size_t)m * (size_t)cols * rsz);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

static pqc_status_t snova_verify_impl(const uint8_t *msg, size_t msglen,
                                       const uint8_t *sig, size_t siglen,
                                       const uint8_t *pk,
                                       const snova_params_t *params)
{
    int n = params->n;
    int m = params->o;
    int l = params->l;
    size_t rsz = RING_SZ(l);
    int tri_size = n * (n + 1) / 2;
    size_t P_size = (size_t)m * (size_t)tri_size * rsz;
    uint8_t *P = NULL;
    uint8_t *target = NULL;
    uint8_t *x_vec = NULL;
    uint8_t *eval_result = NULL;
    const uint8_t *salt;
    const uint8_t *packed;
    pqc_status_t rc;

    (void)siglen;

    salt = sig;
    packed = sig + 16;

    target = (uint8_t *)pqc_calloc(1, (size_t)m * rsz);
    P = (uint8_t *)pqc_calloc(1, P_size);
    x_vec = (uint8_t *)pqc_calloc(1, (size_t)n * rsz);
    eval_result = (uint8_t *)pqc_calloc(1, (size_t)m * rsz);
    if (!target || !P || !x_vec || !eval_result) {
        rc = PQC_ERROR_ALLOC;
        goto cleanup;
    }

    snova_hash_message(target, m, l, msg, msglen, salt, 16);
    snova_expand_pk(P, pk, (size_t)params->seed_len,
                    (size_t)m * (size_t)tri_size * rsz);

    /* Unpack signature vector */
    {
        size_t total_elems = (size_t)n * rsz;
        size_t i;
        for (i = 0; i < total_elems; i++) {
            if (i % 2 == 0) {
                x_vec[i] = (packed[i / 2] >> 4) & 0x0F;
            } else {
                x_vec[i] = packed[i / 2] & 0x0F;
            }
        }
    }

    snova_evaluate_P(eval_result, P, x_vec, params);

    rc = PQC_ERROR_VERIFICATION_FAILED;
    if (pqc_memcmp_ct(eval_result, target, (size_t)m * rsz) == 0) {
        rc = PQC_OK;
    }

cleanup:
    if (target) pqc_free(target, (size_t)m * rsz);
    if (P) pqc_free(P, P_size);
    if (x_vec) pqc_free(x_vec, (size_t)n * rsz);
    if (eval_result) pqc_free(eval_result, (size_t)m * rsz);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                             */
/* ------------------------------------------------------------------ */

#define SNOVA_DEFINE_OPS(name, params_ptr)                                   \
static pqc_status_t name##_keygen(uint8_t *pk, uint8_t *sk)                  \
{ return snova_keygen_impl(pk, sk, (params_ptr)); }                          \
                                                                              \
static pqc_status_t name##_sign(uint8_t *sig, size_t *siglen,                \
                                 const uint8_t *msg, size_t msglen,           \
                                 const uint8_t *sk)                           \
{ return snova_sign_impl(sig, siglen, msg, msglen, sk, (params_ptr)); }      \
                                                                              \
static pqc_status_t name##_verify(const uint8_t *msg, size_t msglen,         \
                                   const uint8_t *sig, size_t siglen,         \
                                   const uint8_t *pk)                         \
{ return snova_verify_impl(msg, msglen, sig, siglen, pk, (params_ptr)); }

SNOVA_DEFINE_OPS(snova_24_5_4, &snova_24_5_4_params)
SNOVA_DEFINE_OPS(snova_25_8_3, &snova_25_8_3_params)
SNOVA_DEFINE_OPS(snova_28_17_3, &snova_28_17_3_params)

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_sig_vtable_t snova_24_5_4_vtable = {
    .algorithm_name     = PQC_SIG_SNOVA_24_5_4,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "SNOVA (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_SNOVA_24_5_4_PUBLICKEYBYTES,
    .secret_key_size    = PQC_SNOVA_24_5_4_SECRETKEYBYTES,
    .max_signature_size = PQC_SNOVA_24_5_4_SIGBYTES,
    .keygen  = snova_24_5_4_keygen,
    .sign    = snova_24_5_4_sign,
    .verify  = snova_24_5_4_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t snova_25_8_3_vtable = {
    .algorithm_name     = PQC_SIG_SNOVA_25_8_3,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "SNOVA (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_SNOVA_25_8_3_PUBLICKEYBYTES,
    .secret_key_size    = PQC_SNOVA_25_8_3_SECRETKEYBYTES,
    .max_signature_size = PQC_SNOVA_25_8_3_SIGBYTES,
    .keygen  = snova_25_8_3_keygen,
    .sign    = snova_25_8_3_sign,
    .verify  = snova_25_8_3_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t snova_28_17_3_vtable = {
    .algorithm_name     = PQC_SIG_SNOVA_28_17_3,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "SNOVA (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_SNOVA_28_17_3_PUBLICKEYBYTES,
    .secret_key_size    = PQC_SNOVA_28_17_3_SECRETKEYBYTES,
    .max_signature_size = PQC_SNOVA_28_17_3_SIGBYTES,
    .keygen  = snova_28_17_3_keygen,
    .sign    = snova_28_17_3_sign,
    .verify  = snova_28_17_3_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_snova_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&snova_24_5_4_vtable);
    rc |= pqc_sig_add_vtable(&snova_25_8_3_vtable);
    rc |= pqc_sig_add_vtable(&snova_28_17_3_vtable);
    return rc;
}
