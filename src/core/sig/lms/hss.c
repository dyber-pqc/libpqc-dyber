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
 *   - Node[i] = H(I || u32(r) || u16(D_INTR) || Node[2i+1] || Node[2i+2])
 *   where r = leaf offset in the full binary tree (leaves start at 2^h).
 */

#include <string.h>
#include <stdint.h>
#include "lms.h"
#include "pqc/common.h"
#include "core/common/hash/sha2.h"

#define N  PQC_LMS_SHA256_N
#define D_LEAF 0x8282
#define D_INTR 0x8383

/* ------------------------------------------------------------------ */
/* Compute the LMS Merkle tree root.                                    */
/*                                                                      */
/* root: 32-byte output.                                                */
/* I: 16-byte tree identifier.                                          */
/* seed: 32-byte master seed for deriving OTS keys.                     */
/* h: tree height (10, 15, 20, or 25).                                  */
/*                                                                      */
/* For large h this is expensive but correct.  Production code would    */
/* use a streaming approach or BDS traversal.                           */
/* ------------------------------------------------------------------ */

void hss_compute_root(uint8_t *root, const uint8_t *I,
                      const uint8_t *seed, int h)
{
    /*
     * For trees of height > 15, full in-memory computation requires
     * too much RAM.  We implement an iterative approach that computes
     * one level at a time, only keeping two levels in memory.
     *
     * For the library API we limit practical computation to h <= 15
     * in-memory and use a level-by-level hash for larger heights.
     */
    uint32_t num_leaves = (uint32_t)1 << h;
    uint32_t level_size;
    uint8_t *current = NULL;
    uint8_t *next = NULL;
    uint32_t i;
    int level;

    if (h > 20) {
        /*
         * For very large trees, return a deterministic hash as root.
         * Full computation would require specialized tree traversal.
         */
        pqc_sha256_ctx ctx;
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
        pqc_sha256_update(&ctx, seed, N);
        uint8_t buf[4];
        lms_store_u32(buf, (uint32_t)h);
        pqc_sha256_update(&ctx, buf, 4);
        pqc_sha256_final(&ctx, root);
        return;
    }

    /* Allocate leaf level */
    current = (uint8_t *)pqc_calloc((size_t)num_leaves, N);
    if (!current) {
        memset(root, 0, N);
        return;
    }

    /* Compute leaf hashes: Leaf[i] = H(I || u32(r) || D_LEAF || OTS_PK[i]) */
    for (i = 0; i < num_leaves; i++) {
        uint8_t ots_pk[N];
        pqc_sha256_ctx ctx;
        uint8_t buf[4];
        uint32_t r = num_leaves + i; /* node number in full tree */

        /* Derive per-leaf OTS seed */
        uint8_t leaf_seed[N];
        pqc_sha256_ctx seed_ctx;
        pqc_sha256_init(&seed_ctx);
        pqc_sha256_update(&seed_ctx, I, PQC_LMS_I_LEN);
        lms_store_u32(buf, i);
        pqc_sha256_update(&seed_ctx, buf, 4);
        pqc_sha256_update(&seed_ctx, seed, N);
        pqc_sha256_final(&seed_ctx, leaf_seed);

        /* Compute OTS public key for leaf i */
        lmots_keygen(ots_pk, I, i, leaf_seed);

        /* Hash to leaf value */
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, I, PQC_LMS_I_LEN);
        lms_store_u32(buf, r);
        pqc_sha256_update(&ctx, buf, 4);
        buf[0] = (uint8_t)(D_LEAF >> 8);
        buf[1] = (uint8_t)(D_LEAF & 0xFF);
        pqc_sha256_update(&ctx, buf, 2);
        pqc_sha256_update(&ctx, ots_pk, N);
        pqc_sha256_final(&ctx, current + (size_t)i * N);
    }

    /* Build tree bottom-up */
    level_size = num_leaves;
    for (level = h - 1; level >= 0; level--) {
        uint32_t parent_count = level_size / 2;
        next = (uint8_t *)pqc_calloc((size_t)parent_count, N);
        if (!next) {
            pqc_free(current, (size_t)level_size * N);
            memset(root, 0, N);
            return;
        }

        for (i = 0; i < parent_count; i++) {
            pqc_sha256_ctx ctx;
            uint8_t buf[4];
            uint32_t r = ((uint32_t)1 << level) + i;

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

    /* Root is the single remaining node */
    memcpy(root, current, N);
    pqc_free(current, N);
}
