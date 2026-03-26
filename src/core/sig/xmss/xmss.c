/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * XMSS (eXtended Merkle Signature Scheme) - stateful hash-based
 * signature. RFC 8391 / NIST SP 800-208.
 *
 * XMSS is STATEFUL: each signing operation consumes a leaf index.
 * Re-using an index compromises security.
 *
 * Secret key layout (2573 bytes):
 *   [0..3]       leaf index (big-endian u32)
 *   [4..35]      SK_SEED (secret seed for WOTS key derivation)
 *   [36..67]     SK_PRF (secret key for randomized hashing)
 *   [68..99]     PUB_SEED (public seed)
 *   [100..131]   root (Merkle root, cached from keygen)
 *   [132..135]   tree height h
 *   [136..2572]  reserved for cached tree state
 *
 * Public key layout (64 bytes):
 *   [0..31]      root
 *   [32..63]     PUB_SEED
 *
 * Signature layout:
 *   [0..3]       leaf index (big-endian u32)
 *   [4..35]      randomizer R (n bytes)
 *   [36..2179]   WOTS+ signature (len * n = 67 * 32 = 2144 bytes)
 *   [2180..]     authentication path (h * n bytes)
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
#include "xmss.h"

#define N PQC_XMSS_SHA2_N
#define LEN PQC_XMSS_WOTS_LEN

/* ------------------------------------------------------------------ */
/* Utility: big-endian u32 read/write                                   */
/* ------------------------------------------------------------------ */

static void xmss_store_u32(uint8_t *dst, uint32_t val)
{
    dst[0] = (uint8_t)(val >> 24);
    dst[1] = (uint8_t)(val >> 16);
    dst[2] = (uint8_t)(val >> 8);
    dst[3] = (uint8_t)(val);
}

static uint32_t xmss_load_u32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}

/* ------------------------------------------------------------------ */
/* Hash functions for tree nodes                                        */
/* ------------------------------------------------------------------ */

/* PRF: out = SHA-256(key || addr) */
static void xmss_prf_keygen(uint8_t *out, const uint8_t *key,
                              const uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    pqc_sha256_ctx ctx;
    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, key, N);
    pqc_sha256_update(&ctx, addr, PQC_XMSS_ADDR_BYTES);
    pqc_sha256_final(&ctx, out);
}

/* Randomized tree hash: H(PUB_SEED || ADDR || left || right) */
static void xmss_hash_h(uint8_t *out, const uint8_t *left,
                          const uint8_t *right, const uint8_t *pub_seed,
                          uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    uint8_t key[N], bm0[N], bm1[N];
    uint8_t tmp[2 * N];
    int i;

    xmss_addr_set_hash(addr, 0);
    xmss_prf_keygen(key, pub_seed, addr);
    xmss_addr_set_hash(addr, 1);
    xmss_prf_keygen(bm0, pub_seed, addr);
    xmss_addr_set_hash(addr, 2);
    xmss_prf_keygen(bm1, pub_seed, addr);

    for (i = 0; i < N; i++) {
        tmp[i] = left[i] ^ bm0[i];
        tmp[N + i] = right[i] ^ bm1[i];
    }

    {
        pqc_sha256_ctx ctx;
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, key, N);
        pqc_sha256_update(&ctx, tmp, 2 * N);
        pqc_sha256_final(&ctx, out);
    }
}

/* ------------------------------------------------------------------ */
/* L-tree: compress len WOTS public key values to one n-byte value.     */
/* RFC 8391 Section 4.1.5.                                              */
/* ------------------------------------------------------------------ */

static void xmss_ltree(uint8_t *out, const uint8_t *wots_pk,
                         const uint8_t *pub_seed,
                         uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    uint8_t buf[LEN * N];
    int num_nodes = LEN;
    int parent;
    uint32_t height = 0;
    int i;

    memcpy(buf, wots_pk, (size_t)LEN * N);
    xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_LTREE);

    while (num_nodes > 1) {
        xmss_addr_set_tree_height(addr, height);
        parent = 0;
        for (i = 0; i + 1 < num_nodes; i += 2) {
            xmss_addr_set_tree_index(addr, (uint32_t)(i / 2));
            xmss_hash_h(buf + (size_t)parent * N,
                         buf + (size_t)i * N,
                         buf + (size_t)(i + 1) * N,
                         pub_seed, addr);
            parent++;
        }
        /* If odd, copy the last node up */
        if (num_nodes % 2 == 1) {
            memcpy(buf + (size_t)parent * N,
                   buf + (size_t)(num_nodes - 1) * N, N);
            parent++;
        }
        num_nodes = parent;
        height++;
    }

    memcpy(out, buf, N);
}

/* ------------------------------------------------------------------ */
/* Compute a leaf node: L-tree(WOTS_PK(seed, pub_seed, addr))           */
/* ------------------------------------------------------------------ */

static void xmss_compute_leaf(uint8_t *leaf, const uint8_t *sk_seed,
                                const uint8_t *pub_seed, uint32_t idx,
                                uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    uint8_t wots_pk[LEN * N];

    xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);
    xmss_addr_set_ots(addr, idx);

    xmss_wots_keygen(wots_pk, sk_seed, pub_seed, addr);
    xmss_ltree(leaf, wots_pk, pub_seed, addr);
}

/* ------------------------------------------------------------------ */
/* Build Merkle tree and compute root + auth path for leaf at idx.      */
/* ------------------------------------------------------------------ */

static void xmss_treehash(uint8_t *root, uint8_t *auth_path,
                            const uint8_t *sk_seed, const uint8_t *pub_seed,
                            int h, uint32_t target_idx)
{
    uint32_t num_leaves = (uint32_t)1 << h;
    uint8_t *nodes = NULL;
    uint8_t addr[PQC_XMSS_ADDR_BYTES];
    uint32_t i;
    int level;
    uint32_t level_size;

    xmss_addr_zero(addr);

    nodes = (uint8_t *)pqc_calloc((size_t)num_leaves, N);
    if (!nodes) {
        memset(root, 0, N);
        return;
    }

    /* Compute all leaves */
    for (i = 0; i < num_leaves; i++) {
        xmss_compute_leaf(nodes + (size_t)i * N, sk_seed, pub_seed, i, addr);
    }

    /* Extract auth path and build tree bottom-up */
    level_size = num_leaves;
    for (level = 0; level < h; level++) {
        uint32_t parent_count = level_size / 2;
        uint8_t *parents;
        uint32_t target_at_level = target_idx >> level;
        uint32_t sibling = target_at_level ^ 1;

        /* Copy sibling to auth path */
        if (auth_path && sibling < level_size) {
            memcpy(auth_path + (size_t)level * N,
                   nodes + (size_t)sibling * N, N);
        }

        parents = (uint8_t *)pqc_calloc((size_t)parent_count, N);
        if (!parents) {
            pqc_free(nodes, (size_t)level_size * N);
            memset(root, 0, N);
            return;
        }

        xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_TREE);
        xmss_addr_set_tree_height(addr, (uint32_t)level);

        for (i = 0; i < parent_count; i++) {
            xmss_addr_set_tree_index(addr, i);
            xmss_hash_h(parents + (size_t)i * N,
                         nodes + (size_t)(2 * i) * N,
                         nodes + (size_t)(2 * i + 1) * N,
                         pub_seed, addr);
        }

        pqc_free(nodes, (size_t)level_size * N);
        nodes = parents;
        level_size = parent_count;
    }

    memcpy(root, nodes, N);
    pqc_free(nodes, N);
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t xmss_keygen_impl(uint8_t *pk, uint8_t *sk, int h)
{
    uint8_t sk_seed[N], sk_prf[N], pub_seed[N], root[N];
    pqc_status_t rc;

    rc = pqc_randombytes(sk_seed, N);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;
    rc = pqc_randombytes(sk_prf, N);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;
    rc = pqc_randombytes(pub_seed, N);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;

    /* Compute tree root */
    xmss_treehash(root, NULL, sk_seed, pub_seed, h, 0);

    /* Build secret key */
    xmss_store_u32(sk + 0, 0);           /* idx = 0 */
    memcpy(sk + 4, sk_seed, N);          /* SK_SEED */
    memcpy(sk + 36, sk_prf, N);          /* SK_PRF */
    memcpy(sk + 68, pub_seed, N);        /* PUB_SEED */
    memcpy(sk + 100, root, N);           /* root */
    xmss_store_u32(sk + 132, (uint32_t)h); /* tree height */
    /* Remainder is zeroed (reserved for cached state) */
    memset(sk + 136, 0, PQC_XMSS_SHA2_256_SECRETKEYBYTES - 136);

    /* Build public key */
    memcpy(pk + 0, root, N);
    memcpy(pk + 32, pub_seed, N);

    pqc_memzero(sk_seed, N);
    pqc_memzero(sk_prf, N);
    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Stateful signing                                                     */
/* ------------------------------------------------------------------ */

static pqc_status_t xmss_sign_stateful_impl(uint8_t *sig, size_t *siglen,
                                              const uint8_t *msg, size_t msglen,
                                              uint8_t *sk, int h)
{
    uint32_t idx = xmss_load_u32(sk);
    const uint8_t *sk_seed = sk + 4;
    const uint8_t *sk_prf = sk + 36;
    const uint8_t *pub_seed = sk + 68;
    uint32_t num_leaves = (uint32_t)1 << h;
    uint8_t R[N];
    uint8_t msg_hash[N];
    uint8_t addr[PQC_XMSS_ADDR_BYTES];
    size_t pos;

    if (idx >= num_leaves) {
        return PQC_ERROR_STATE_EXHAUSTED;
    }

    /* Generate randomizer R = PRF(SK_PRF, idx) */
    {
        pqc_sha256_ctx ctx;
        uint8_t idx_buf[32];
        memset(idx_buf, 0, 32);
        xmss_store_u32(idx_buf + 28, idx);
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, sk_prf, N);
        pqc_sha256_update(&ctx, idx_buf, 32);
        pqc_sha256_final(&ctx, R);
    }

    /* Hash message: H_msg(R || root || idx || msg) */
    {
        pqc_sha256_ctx ctx;
        uint8_t idx_buf[4];
        xmss_store_u32(idx_buf, idx);
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, R, N);
        pqc_sha256_update(&ctx, sk + 100, N); /* root */
        pqc_sha256_update(&ctx, idx_buf, 4);
        pqc_sha256_update(&ctx, msg, msglen);
        pqc_sha256_final(&ctx, msg_hash);
    }

    /* Build signature */
    pos = 0;

    /* Leaf index (4 bytes) */
    xmss_store_u32(sig + pos, idx);
    pos += 4;

    /* Randomizer R (n bytes) */
    memcpy(sig + pos, R, N);
    pos += N;

    /* WOTS+ signature (len * n bytes) */
    xmss_addr_zero(addr);
    xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);
    xmss_addr_set_ots(addr, idx);
    xmss_wots_sign(sig + pos, msg_hash, sk_seed, pub_seed, addr);
    pos += (size_t)LEN * N;

    /* Authentication path (h * n bytes) */
    {
        uint8_t root_check[N];
        xmss_treehash(root_check, sig + pos, sk_seed, pub_seed, h, idx);
        pos += (size_t)h * N;
    }

    *siglen = pos;

    /* Advance state */
    xmss_store_u32(sk, idx + 1);

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

static pqc_status_t xmss_verify_impl(const uint8_t *msg, size_t msglen,
                                       const uint8_t *sig, size_t siglen,
                                       const uint8_t *pk, int h)
{
    const uint8_t *pk_root = pk;
    const uint8_t *pub_seed = pk + 32;
    uint32_t idx;
    const uint8_t *R;
    const uint8_t *wots_sig;
    const uint8_t *auth_path;
    uint8_t msg_hash[N];
    uint8_t wots_pk[LEN * N];
    uint8_t leaf[N];
    uint8_t node[N];
    uint8_t addr[PQC_XMSS_ADDR_BYTES];
    int level;

    (void)siglen;

    /* Parse signature */
    idx = xmss_load_u32(sig);
    R = sig + 4;
    wots_sig = sig + 4 + N;
    auth_path = sig + 4 + N + (size_t)LEN * N;

    /* Check leaf index range */
    if (idx >= ((uint32_t)1 << h)) {
        return PQC_ERROR_VERIFICATION_FAILED;
    }

    /* Compute message hash */
    {
        pqc_sha256_ctx ctx;
        uint8_t idx_buf[4];
        xmss_store_u32(idx_buf, idx);
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, R, N);
        pqc_sha256_update(&ctx, pk_root, N);
        pqc_sha256_update(&ctx, idx_buf, 4);
        pqc_sha256_update(&ctx, msg, msglen);
        pqc_sha256_final(&ctx, msg_hash);
    }

    /* Compute WOTS+ public key from signature */
    xmss_addr_zero(addr);
    xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);
    xmss_addr_set_ots(addr, idx);
    xmss_wots_pk_from_sig(wots_pk, wots_sig, msg_hash, pub_seed, addr);

    /* L-tree to compress WOTS pk to leaf */
    xmss_ltree(leaf, wots_pk, pub_seed, addr);

    /* Walk up the tree using authentication path */
    memcpy(node, leaf, N);
    xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_TREE);

    for (level = 0; level < h; level++) {
        xmss_addr_set_tree_height(addr, (uint32_t)level);
        xmss_addr_set_tree_index(addr, idx >> 1);

        if (idx % 2 == 0) {
            xmss_hash_h(node, node, auth_path + (size_t)level * N,
                         pub_seed, addr);
        } else {
            xmss_hash_h(node, auth_path + (size_t)level * N, node,
                         pub_seed, addr);
        }
        idx >>= 1;
    }

    /* Compare computed root with public key root */
    if (pqc_memcmp_ct(node, pk_root, N) != 0) {
        return PQC_ERROR_VERIFICATION_FAILED;
    }

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Per-height dispatch                                                  */
/* ------------------------------------------------------------------ */

#define XMSS_DEFINE_OPS(name, height)                                        \
static pqc_status_t name##_keygen(uint8_t *pk, uint8_t *sk)                  \
{ return xmss_keygen_impl(pk, sk, (height)); }                              \
                                                                              \
static pqc_status_t name##_verify(const uint8_t *msg, size_t msglen,         \
                                   const uint8_t *sig, size_t siglen,         \
                                   const uint8_t *pk)                         \
{ return xmss_verify_impl(msg, msglen, sig, siglen, pk, (height)); }        \
                                                                              \
static pqc_status_t name##_sign_stateful(uint8_t *sig, size_t *siglen,       \
                                          const uint8_t *msg, size_t msglen,  \
                                          uint8_t *sk)                        \
{ return xmss_sign_stateful_impl(sig, siglen, msg, msglen, sk, (height)); }

XMSS_DEFINE_OPS(xmss_sha2_10_256, 10)
XMSS_DEFINE_OPS(xmss_sha2_16_256, 16)
XMSS_DEFINE_OPS(xmss_sha2_20_256, 20)

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_sig_vtable_t xmss_sha2_10_256_vtable = {
    .algorithm_name     = PQC_SIG_XMSS_SHA2_10_256,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = PQC_XMSS_SHA2_256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_XMSS_SHA2_256_SECRETKEYBYTES,
    .max_signature_size = PQC_XMSS_SHA2_10_256_SIGBYTES,
    .keygen         = xmss_sha2_10_256_keygen,
    .sign           = NULL,
    .verify         = xmss_sha2_10_256_verify,
    .sign_stateful  = xmss_sha2_10_256_sign_stateful,
};

static const pqc_sig_vtable_t xmss_sha2_16_256_vtable = {
    .algorithm_name     = PQC_SIG_XMSS_SHA2_16_256,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = PQC_XMSS_SHA2_256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_XMSS_SHA2_256_SECRETKEYBYTES,
    .max_signature_size = PQC_XMSS_SHA2_16_256_SIGBYTES,
    .keygen         = xmss_sha2_16_256_keygen,
    .sign           = NULL,
    .verify         = xmss_sha2_16_256_verify,
    .sign_stateful  = xmss_sha2_16_256_sign_stateful,
};

static const pqc_sig_vtable_t xmss_sha2_20_256_vtable = {
    .algorithm_name     = PQC_SIG_XMSS_SHA2_20_256,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "NIST SP 800-208",
    .is_stateful        = 1,
    .public_key_size    = PQC_XMSS_SHA2_256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_XMSS_SHA2_256_SECRETKEYBYTES,
    .max_signature_size = PQC_XMSS_SHA2_20_256_SIGBYTES,
    .keygen         = xmss_sha2_20_256_keygen,
    .sign           = NULL,
    .verify         = xmss_sha2_20_256_verify,
    .sign_stateful  = xmss_sha2_20_256_sign_stateful,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_xmss_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&xmss_sha2_10_256_vtable);
    rc |= pqc_sig_add_vtable(&xmss_sha2_16_256_vtable);
    rc |= pqc_sig_add_vtable(&xmss_sha2_20_256_vtable);
    return rc;
}
