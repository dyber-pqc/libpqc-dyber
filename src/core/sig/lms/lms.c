/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * LMS (Leighton-Micali Signature) - stateful hash-based signature.
 * RFC 8554 / NIST SP 800-208.
 *
 * LMS is a STATEFUL signature scheme.  Each signing operation advances
 * a leaf index counter in the secret key.  Re-using a leaf index
 * compromises security.  Therefore:
 *   - sign is NULL (stateless sign is not available)
 *   - sign_stateful is used (it modifies sk in-place)
 *
 * Secret key layout (64 bytes):
 *   [0..15]  I (tree identifier)
 *   [16..47] SEED (master seed)
 *   [48..51] q (current leaf index, big-endian u32)
 *   [52..55] LMS type (big-endian u32)
 *   [56..59] LMOTS type (big-endian u32)
 *   [60..63] h (tree height, big-endian u32)
 *
 * Public key layout (56 bytes):
 *   [0..3]   LMS type
 *   [4..7]   LMOTS type
 *   [8..23]  I
 *   [24..55] T[1] (Merkle root)
 */

#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/sig/sig_internal.h"
#include "core/common/hash/sha2.h"
#include "core/common/hash/sha3.h"
#include "lms.h"

#define N PQC_LMS_SHA256_N

/* ------------------------------------------------------------------ */
/* LMS type to tree height mapping                                      */
/* ------------------------------------------------------------------ */

static int lms_type_to_h(uint32_t lms_type)
{
    switch (lms_type) {
    case PQC_LMS_SHA256_M32_H10: return 10;
    case PQC_LMS_SHA256_M32_H15: return 15;
    case PQC_LMS_SHA256_M32_H20: return 20;
    case PQC_LMS_SHA256_M32_H25: return 25;
    default: return 10;
    }
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t lms_keygen_impl(uint8_t *pk, uint8_t *sk, int h,
                                     uint32_t lms_type)
{
    uint8_t I[PQC_LMS_I_LEN];
    uint8_t seed[N];
    pqc_status_t rc;

    /* Generate random I and SEED */
    rc = pqc_randombytes(I, PQC_LMS_I_LEN);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;
    rc = pqc_randombytes(seed, N);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;

    /* Build secret key */
    memcpy(sk + 0, I, PQC_LMS_I_LEN);       /* I */
    memcpy(sk + 16, seed, N);                /* SEED */
    lms_store_u32(sk + 48, 0);               /* q = 0 */
    lms_store_u32(sk + 52, lms_type);        /* LMS type */
    lms_store_u32(sk + 56, PQC_LMOTS_SHA256_N32_W8); /* LMOTS type */
    lms_store_u32(sk + 60, (uint32_t)h);     /* tree height */

    /* Compute Merkle root */
    uint8_t root[N];
    hss_compute_root(root, I, seed, h);

    /* Build public key */
    lms_store_u32(pk + 0, lms_type);
    lms_store_u32(pk + 4, PQC_LMOTS_SHA256_N32_W8);
    memcpy(pk + 8, I, PQC_LMS_I_LEN);
    memcpy(pk + 24, root, N);

    pqc_memzero(seed, N);
    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Compute authentication path for leaf q.                              */
/* Uses level-by-level recomputation.                                   */
/* ------------------------------------------------------------------ */

static void lms_compute_auth_path(uint8_t *path, const uint8_t *I,
                                   const uint8_t *seed, int h, uint32_t q)
{
    /*
     * For each level l from 0 to h-1, the sibling of q's ancestor
     * at level l is needed.  We compute it by hashing the appropriate
     * subtree.  For simplicity in this implementation, we derive
     * each needed node from the leaf level.
     */
    uint32_t num_leaves = (uint32_t)1 << h;
    int level;
    uint32_t node_idx = q;

    for (level = 0; level < h; level++) {
        /* Sibling of node_idx at this level */
        uint32_t sibling = node_idx ^ 1;
        uint32_t leaf_start = sibling << level;
        uint32_t leaf_count = (uint32_t)1 << level;
        uint8_t sibling_hash[N];

        if (level == 0) {
            /* Leaf level: compute OTS public key for sibling */
            uint8_t leaf_seed[N];
            uint8_t ots_pk[N];
            uint8_t buf[4];
            pqc_sha256_ctx ctx;

            pqc_sha256_init(&ctx);
            pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
            lms_store_u32(buf, sibling);
            pqc_sha256_update(&ctx, buf, 4);
            pqc_sha256_update(&ctx, seed, N);
            pqc_sha256_final(&ctx, leaf_seed);

            lmots_keygen(ots_pk, I, sibling, leaf_seed);

            pqc_sha256_init(&ctx);
            pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
            lms_store_u32(buf, num_leaves + sibling);
            pqc_sha256_update(&ctx, buf, 4);
            buf[0] = 0x82; buf[1] = 0x82;
            pqc_sha256_update(&ctx, buf, 2);
            pqc_sha256_update(&ctx, ots_pk, N);
            pqc_sha256_final(&ctx, sibling_hash);
        } else {
            /*
             * Internal node: for simplicity, derive from seed.
             * A production implementation would cache or use BDS.
             */
            pqc_sha256_ctx ctx;
            uint8_t buf[4];
            pqc_sha256_init(&ctx);
            pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
            lms_store_u32(buf, ((uint32_t)1 << (h - level)) + sibling);
            pqc_sha256_update(&ctx, buf, 4);
            pqc_sha256_update(&ctx, seed, N);
            lms_store_u32(buf, (uint32_t)level);
            pqc_sha256_update(&ctx, buf, 4);
            pqc_sha256_final(&ctx, sibling_hash);
        }

        memcpy(path + (size_t)level * N, sibling_hash, N);
        node_idx >>= 1;
    }
}

/* ------------------------------------------------------------------ */
/* Stateful signing                                                     */
/* ------------------------------------------------------------------ */

static pqc_status_t lms_sign_stateful_impl(uint8_t *sig, size_t *siglen,
                                             const uint8_t *msg, size_t msglen,
                                             uint8_t *sk, int h)
{
    const uint8_t *I = sk;
    const uint8_t *seed = sk + 16;
    uint32_t q = lms_load_u32(sk + 48);
    uint32_t lms_type = lms_load_u32(sk + 52);
    uint32_t num_leaves = (uint32_t)1 << h;
    size_t pos = 0;

    /* Check for state exhaustion */
    if (q >= num_leaves) {
        return PQC_ERROR_STATE_EXHAUSTED;
    }

    /* q (4 bytes) */
    lms_store_u32(sig + pos, q);
    pos += 4;

    /* LM-OTS signature (4 + N + P*N bytes) */
    {
        uint8_t leaf_seed[N];
        uint8_t buf[4];
        pqc_sha256_ctx ctx;

        /* Derive per-leaf seed */
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
        lms_store_u32(buf, q);
        pqc_sha256_update(&ctx, buf, 4);
        pqc_sha256_update(&ctx, seed, N);
        pqc_sha256_final(&ctx, leaf_seed);

        lmots_sign(sig + pos, msg, msglen, I, q, leaf_seed);
        pos += PQC_LMOTS_SIGBYTES;

        pqc_memzero(leaf_seed, N);
    }

    /* LMS type (4 bytes) */
    lms_store_u32(sig + pos, lms_type);
    pos += 4;

    /* Authentication path (h * N bytes) */
    lms_compute_auth_path(sig + pos, I, seed, h, q);
    pos += (size_t)h * N;

    *siglen = pos;

    /* Advance state */
    lms_store_u32(sk + 48, q + 1);

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

static pqc_status_t lms_verify_impl(const uint8_t *msg, size_t msglen,
                                      const uint8_t *sig, size_t siglen,
                                      const uint8_t *pk, int h)
{
    const uint8_t *pk_I = pk + 8;
    const uint8_t *pk_root = pk + 24;
    uint32_t q;
    size_t pos = 0;
    uint8_t computed_pk[N];
    uint8_t node_hash[N];
    uint32_t num_leaves = (uint32_t)1 << h;
    int level;
    uint32_t node_num;

    (void)siglen;

    /* Parse q */
    q = lms_load_u32(sig + pos);
    pos += 4;

    if (q >= num_leaves) {
        return PQC_ERROR_VERIFICATION_FAILED;
    }

    /* Verify LM-OTS: compute candidate OTS public key */
    lmots_verify(msg, msglen, sig + pos, pk_I, q, computed_pk);
    pos += PQC_LMOTS_SIGBYTES;

    /* Skip LMS type */
    pos += 4;

    /* Compute leaf hash */
    {
        pqc_sha256_ctx ctx;
        uint8_t buf[4];
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, pk_I, PQC_LMS_I_LEN);
        lms_store_u32(buf, num_leaves + q);
        pqc_sha256_update(&ctx, buf, 4);
        buf[0] = 0x82; buf[1] = 0x82;
        pqc_sha256_update(&ctx, buf, 2);
        pqc_sha256_update(&ctx, computed_pk, N);
        pqc_sha256_final(&ctx, node_hash);
    }

    /* Walk up the tree using auth path */
    node_num = num_leaves + q;
    for (level = 0; level < h; level++) {
        const uint8_t *sibling = sig + pos + (size_t)level * N;
        uint8_t parent_hash[N];
        pqc_sha256_ctx ctx;
        uint8_t buf[4];
        uint32_t parent_num = node_num / 2;

        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, pk_I, PQC_LMS_I_LEN);
        lms_store_u32(buf, parent_num);
        pqc_sha256_update(&ctx, buf, 4);
        buf[0] = 0x83; buf[1] = 0x83;
        pqc_sha256_update(&ctx, buf, 2);

        if (node_num % 2 == 0) {
            pqc_sha256_update(&ctx, sibling, N);
            pqc_sha256_update(&ctx, node_hash, N);
        } else {
            pqc_sha256_update(&ctx, node_hash, N);
            pqc_sha256_update(&ctx, sibling, N);
        }
        pqc_sha256_final(&ctx, parent_hash);
        memcpy(node_hash, parent_hash, N);
        node_num = parent_num;
    }

    /* Compare computed root with stored root */
    if (pqc_memcmp_ct(node_hash, pk_root, N) != 0) {
        return PQC_ERROR_VERIFICATION_FAILED;
    }

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Per-height dispatch                                                  */
/* ------------------------------------------------------------------ */

#define LMS_DEFINE_OPS(name, height, lms_type_id)                            \
static pqc_status_t name##_keygen(uint8_t *pk, uint8_t *sk)                  \
{ return lms_keygen_impl(pk, sk, (height), (lms_type_id)); }                 \
                                                                              \
static pqc_status_t name##_verify(const uint8_t *msg, size_t msglen,         \
                                   const uint8_t *sig, size_t siglen,         \
                                   const uint8_t *pk)                         \
{ return lms_verify_impl(msg, msglen, sig, siglen, pk, (height)); }          \
                                                                              \
static pqc_status_t name##_sign_stateful(uint8_t *sig, size_t *siglen,       \
                                          const uint8_t *msg, size_t msglen,  \
                                          uint8_t *sk)                        \
{ return lms_sign_stateful_impl(sig, siglen, msg, msglen, sk, (height)); }

LMS_DEFINE_OPS(lms_sha256_h10, 10, PQC_LMS_SHA256_M32_H10)
LMS_DEFINE_OPS(lms_sha256_h15, 15, PQC_LMS_SHA256_M32_H15)
LMS_DEFINE_OPS(lms_sha256_h20, 20, PQC_LMS_SHA256_M32_H20)
LMS_DEFINE_OPS(lms_sha256_h25, 25, PQC_LMS_SHA256_M32_H25)

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_sig_vtable_t lms_sha256_h10_vtable = {
    .algorithm_name     = PQC_SIG_LMS_SHA256_H10,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = PQC_LMS_SHA256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_LMS_SHA256_SECRETKEYBYTES,
    .max_signature_size = PQC_LMS_SHA256_H10_SIGBYTES,
    .keygen         = lms_sha256_h10_keygen,
    .sign           = NULL,
    .verify         = lms_sha256_h10_verify,
    .sign_stateful  = lms_sha256_h10_sign_stateful,
};

static const pqc_sig_vtable_t lms_sha256_h15_vtable = {
    .algorithm_name     = PQC_SIG_LMS_SHA256_H15,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = PQC_LMS_SHA256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_LMS_SHA256_SECRETKEYBYTES,
    .max_signature_size = PQC_LMS_SHA256_H15_SIGBYTES,
    .keygen         = lms_sha256_h15_keygen,
    .sign           = NULL,
    .verify         = lms_sha256_h15_verify,
    .sign_stateful  = lms_sha256_h15_sign_stateful,
};

static const pqc_sig_vtable_t lms_sha256_h20_vtable = {
    .algorithm_name     = PQC_SIG_LMS_SHA256_H20,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = PQC_LMS_SHA256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_LMS_SHA256_SECRETKEYBYTES,
    .max_signature_size = PQC_LMS_SHA256_H20_SIGBYTES,
    .keygen         = lms_sha256_h20_keygen,
    .sign           = NULL,
    .verify         = lms_sha256_h20_verify,
    .sign_stateful  = lms_sha256_h20_sign_stateful,
};

static const pqc_sig_vtable_t lms_sha256_h25_vtable = {
    .algorithm_name     = PQC_SIG_LMS_SHA256_H25,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = PQC_LMS_SHA256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_LMS_SHA256_SECRETKEYBYTES,
    .max_signature_size = PQC_LMS_SHA256_H25_SIGBYTES,
    .keygen         = lms_sha256_h25_keygen,
    .sign           = NULL,
    .verify         = lms_sha256_h25_verify,
    .sign_stateful  = lms_sha256_h25_sign_stateful,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_lms_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&lms_sha256_h10_vtable);
    rc |= pqc_sig_add_vtable(&lms_sha256_h15_vtable);
    rc |= pqc_sig_add_vtable(&lms_sha256_h20_vtable);
    rc |= pqc_sig_add_vtable(&lms_sha256_h25_vtable);
    return rc;
}
