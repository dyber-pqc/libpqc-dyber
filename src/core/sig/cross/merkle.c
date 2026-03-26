/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * CROSS - Merkle tree construction and verification.
 *
 * Binary Merkle tree for the cut-and-choose proof.
 * Leaves are hashed commitments; internal nodes are H(left || right).
 * Tree is stored in array form: node i has children 2i+1, 2i+2.
 * The root is at index 0.
 */

#include <string.h>
#include <stdint.h>
#include "cross.h"
#include "pqc/common.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Helper: hash two child nodes into parent                             */
/* ------------------------------------------------------------------ */

static void merkle_hash_pair(uint8_t *parent,
                              const uint8_t *left, const uint8_t *right,
                              int hash_len)
{
    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, left, (size_t)hash_len);
    pqc_shake256_absorb(&ctx, right, (size_t)hash_len);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, parent, (size_t)hash_len);
}

/* ------------------------------------------------------------------ */
/* Build Merkle tree from leaf hashes.                                  */
/*                                                                      */
/* tree: output array of (2*num_leaves - 1) hash values.                */
/*       Leaves are at indices [num_leaves-1 .. 2*num_leaves-2].        */
/* leaves: num_leaves hash values, each hash_len bytes.                 */
/* num_leaves: must be a power of 2.                                    */
/* ------------------------------------------------------------------ */

void cross_merkle_build(uint8_t *tree, const uint8_t *leaves,
                        int num_leaves, int hash_len)
{
    int total = 2 * num_leaves - 1;
    int offset = num_leaves - 1;
    int i;

    /* Copy leaves into the tree */
    memcpy(tree + (size_t)offset * (size_t)hash_len,
           leaves, (size_t)num_leaves * (size_t)hash_len);

    /* Build bottom-up */
    for (i = offset - 1; i >= 0; i--) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        merkle_hash_pair(
            tree + (size_t)i * (size_t)hash_len,
            tree + (size_t)left * (size_t)hash_len,
            tree + (size_t)right * (size_t)hash_len,
            hash_len
        );
    }

    (void)total;
}

/* ------------------------------------------------------------------ */
/* Compute authentication path for a given leaf.                        */
/*                                                                      */
/* path: output buffer for sibling hashes along the path.               */
/* path_len: output, number of hash values in path (= log2(num_leaves))*/
/* tree: complete Merkle tree array.                                    */
/* leaf_idx: index of the leaf (0-based among leaves).                  */
/* ------------------------------------------------------------------ */

void cross_merkle_path(uint8_t *path, int *path_len,
                       const uint8_t *tree, int leaf_idx,
                       int num_leaves, int hash_len)
{
    int node = num_leaves - 1 + leaf_idx;
    int depth = 0;

    while (node > 0) {
        int sibling;
        if (node % 2 == 1) {
            sibling = node + 1;  /* node is left child */
        } else {
            sibling = node - 1;  /* node is right child */
        }
        memcpy(path + (size_t)depth * (size_t)hash_len,
               tree + (size_t)sibling * (size_t)hash_len,
               (size_t)hash_len);
        depth++;
        node = (node - 1) / 2;  /* parent */
    }

    *path_len = depth;
}

/* ------------------------------------------------------------------ */
/* Verify a leaf against the root using an authentication path.         */
/* Returns 0 if valid, -1 otherwise.                                    */
/* ------------------------------------------------------------------ */

int cross_merkle_verify(const uint8_t *root, const uint8_t *leaf,
                        int leaf_idx, const uint8_t *path, int path_len,
                        int num_leaves, int hash_len)
{
    uint8_t current[64]; /* max hash_len = 64 */
    int node = num_leaves - 1 + leaf_idx;
    int i;

    memcpy(current, leaf, (size_t)hash_len);

    for (i = 0; i < path_len; i++) {
        const uint8_t *sibling = path + (size_t)i * (size_t)hash_len;
        uint8_t parent[64];

        if (node % 2 == 1) {
            /* current is left child */
            merkle_hash_pair(parent, current, sibling, hash_len);
        } else {
            /* current is right child */
            merkle_hash_pair(parent, sibling, current, hash_len);
        }
        memcpy(current, parent, (size_t)hash_len);
        node = (node - 1) / 2;
    }

    return pqc_memcmp_ct(current, root, (size_t)hash_len) == 0 ? 0 : -1;
}
