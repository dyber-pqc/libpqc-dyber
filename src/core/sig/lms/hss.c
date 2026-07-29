/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * LMS - HSS (Hierarchical Signature System) multi-tree.
 *
 * For single-tree LMS, HSS degenerates to computing the Merkle tree
 * root from the LM-OTS public keys of all 2^h leaves.
 *
 * The Merkle tree is computed bottom-up:
 *   - Leaf[i] = H(I || u32(r) || u16(D_LEAF) || OTS_PK[i])
 *   - Node[r] = H(I || u32(r) || u16(D_INTR) || Node[2r] || Node[2r+1])
 *   where r is the node number in the full binary tree: the leaf for
 *   index i is node 2^h + i, and the root is node 1.
 *
 * The same traversal yields the authentication path for a chosen leaf,
 * so signing and key generation share one implementation.  The path
 * MUST come from this tree -- deriving it from the secret seed would
 * both fail to verify and publish a PRF of secret key material.
 */

#include <string.h>
#include <stdint.h>
#include "lms.h"
#include "pqc/common.h"
#include "core/common/hash/sha2.h"

#define N  PQC_LMS_SHA256_N
#define D_LEAF 0x8282
#define D_INTR 0x8383

/*
 * Largest tree height this implementation will build.
 *
 * Building the tree costs 2^h LM-OTS key generations, each of which is
 * PQC_LMOTS_P chains of 2^PQC_LMOTS_W - 1 hash steps.  Beyond h = 15
 * that is not a computation a caller can wait for, and there is no
 * cached-state format in the 64-byte secret key to amortise it across
 * signatures.  Refusing is the honest answer; silently substituting a
 * hash of the seed for the root (as an earlier version did) produces a
 * public key that commits to nothing.
 */
#define HSS_MAX_COMPUTABLE_H  15

/* ------------------------------------------------------------------ */
/* Derive the per-leaf LM-OTS seed.                                     */
/* Must match the derivation used by lms_sign_stateful_impl.            */
/* ------------------------------------------------------------------ */

static void hss_leaf_seed(uint8_t *out, const uint8_t *I,
                          const uint8_t *seed, uint32_t leaf)
{
    pqc_sha256_ctx ctx;
    uint8_t buf[4];

    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
    lms_store_u32(buf, leaf);
    pqc_sha256_update(&ctx, buf, 4);
    pqc_sha256_update(&ctx, seed, N);
    pqc_sha256_final(&ctx, out);
}

/* ------------------------------------------------------------------ */
/* Compute the LMS Merkle tree root and, optionally, the               */
/* authentication path for one leaf.                                    */
/*                                                                      */
/* root:      32-byte output (may be NULL if only the path is wanted).  */
/* auth_path: h * 32-byte output, or NULL.  Entry l is the sibling of   */
/*            the target's ancestor at height l.                        */
/* I:         16-byte tree identifier.                                  */
/* seed:      32-byte master seed for deriving OTS keys.                */
/* h:         tree height.                                              */
/* target:    leaf index the auth path is for (ignored if auth_path is  */
/*            NULL).                                                    */
/*                                                                      */
/* Returns 0 on success, -1 if the height is not computable or on       */
/* allocation failure.                                                  */
/* ------------------------------------------------------------------ */

int hss_compute_root_and_path(uint8_t *root, uint8_t *auth_path,
                              const uint8_t *I, const uint8_t *seed,
                              int h, uint32_t target)
{
    uint32_t num_leaves;
    uint32_t level_size;
    uint8_t *current = NULL;
    uint8_t *next = NULL;
    uint32_t i;
    int hh;

    if (h < 1 || h > HSS_MAX_COMPUTABLE_H) {
        if (root) memset(root, 0, N);
        return -1;
    }

    num_leaves = (uint32_t)1 << h;

    current = (uint8_t *)pqc_calloc((size_t)num_leaves, N);
    if (!current) {
        if (root) memset(root, 0, N);
        return -1;
    }

    /* Leaf[i] = H(I || u32(2^h + i) || D_LEAF || OTS_PK[i]) */
    for (i = 0; i < num_leaves; i++) {
        uint8_t leaf_seed[N];
        uint8_t ots_pk[N];
        pqc_sha256_ctx ctx;
        uint8_t buf[4];

        hss_leaf_seed(leaf_seed, I, seed, i);
        lmots_keygen(ots_pk, I, i, leaf_seed);

        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
        lms_store_u32(buf, num_leaves + i);
        pqc_sha256_update(&ctx, buf, 4);
        buf[0] = (uint8_t)(D_LEAF >> 8);
        buf[1] = (uint8_t)(D_LEAF & 0xFF);
        pqc_sha256_update(&ctx, buf, 2);
        pqc_sha256_update(&ctx, ots_pk, N);
        pqc_sha256_final(&ctx, current + (size_t)i * N);

        pqc_memzero(leaf_seed, N);
    }

    /*
     * Merge upward.  Before collapsing height hh into hh+1, the
     * sibling of the target's ancestor at height hh is still present,
     * so capture it for the authentication path.
     */
    level_size = num_leaves;
    for (hh = 0; hh < h; hh++) {
        uint32_t parent_count = level_size / 2;

        if (auth_path) {
            uint32_t sibling = (target >> hh) ^ 1u;
            if (sibling < level_size) {
                memcpy(auth_path + (size_t)hh * N,
                       current + (size_t)sibling * N, N);
            } else {
                memset(auth_path + (size_t)hh * N, 0, N);
            }
        }

        next = (uint8_t *)pqc_calloc((size_t)parent_count, N);
        if (!next) {
            pqc_free(current, (size_t)level_size * N);
            if (root) memset(root, 0, N);
            return -1;
        }

        for (i = 0; i < parent_count; i++) {
            pqc_sha256_ctx ctx;
            uint8_t buf[4];
            /* Parent node number at height hh+1. */
            uint32_t r = (num_leaves >> (hh + 1)) + i;

            pqc_sha256_init(&ctx);
            pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
            lms_store_u32(buf, r);
            pqc_sha256_update(&ctx, buf, 4);
            buf[0] = (uint8_t)(D_INTR >> 8);
            buf[1] = (uint8_t)(D_INTR & 0xFF);
            pqc_sha256_update(&ctx, buf, 2);
            pqc_sha256_update(&ctx, current + (size_t)(2 * i) * N, N);
            pqc_sha256_update(&ctx, current + (size_t)(2 * i + 1) * N, N);
            pqc_sha256_final(&ctx, next + (size_t)i * N);
        }

        pqc_free(current, (size_t)level_size * N);
        current = next;
        next = NULL;
        level_size = parent_count;
    }

    if (root) memcpy(root, current, N);
    pqc_free(current, N);
    return 0;
}

int hss_compute_root(uint8_t *root, const uint8_t *I,
                     const uint8_t *seed, int h)
{
    return hss_compute_root_and_path(root, NULL, I, seed, h, 0);
}
