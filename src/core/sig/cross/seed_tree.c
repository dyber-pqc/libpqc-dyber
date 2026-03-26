/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * CROSS - Seed tree expansion.
 *
 * GGM-like binary tree for deriving per-round seeds from a single
 * master seed.  Each internal node is expanded into two children via
 * SHAKE-256.  Leaves provide the per-round random seeds.
 *
 * During signing, the prover reveals seeds for the non-challenged
 * rounds.  The seed tree allows compact representation: instead of
 * revealing individual leaf seeds, we reveal the minimal set of
 * internal nodes that covers the revealed leaves.
 */

#include <string.h>
#include <stdint.h>
#include "cross.h"
#include "pqc/common.h"
#include "core/common/hash/sha3.h"

/* ------------------------------------------------------------------ */
/* Expand root seed into a full binary tree of seeds.                   */
/*                                                                      */
/* seeds: output array of (2*num_leaves - 1) seeds, each seed_len bytes.*/
/*        Node i has children 2i+1 and 2i+2.                           */
/*        Leaves are at indices [num_leaves-1 .. 2*num_leaves-2].       */
/* root_seed: the master seed.                                          */
/* ------------------------------------------------------------------ */

void cross_seed_tree_expand(uint8_t *seeds, int num_leaves,
                            const uint8_t *root_seed, int seed_len)
{
    int total = 2 * num_leaves - 1;
    int i;
    uint8_t buf[128]; /* max 2 * 64 bytes */

    /* Place root seed */
    memcpy(seeds, root_seed, (size_t)seed_len);

    /* Expand top-down */
    for (i = 0; i < num_leaves - 1; i++) {
        /* Expand node i into children 2i+1 and 2i+2 */
        pqc_shake256(buf, (size_t)seed_len * 2,
                     seeds + (size_t)i * (size_t)seed_len,
                     (size_t)seed_len);
        memcpy(seeds + (size_t)(2 * i + 1) * (size_t)seed_len,
               buf, (size_t)seed_len);
        memcpy(seeds + (size_t)(2 * i + 2) * (size_t)seed_len,
               buf + seed_len, (size_t)seed_len);
    }

    pqc_memzero(buf, sizeof(buf));
    (void)total;
}

/* ------------------------------------------------------------------ */
/* Get the minimal set of tree nodes that covers all revealed leaves.   */
/*                                                                      */
/* path: output buffer for the node seeds that form the cover.          */
/* path_len: output, number of seeds in path.                           */
/* seeds: the full seed tree (expanded).                                */
/* reveal_set: indices of leaves to reveal (0-based among leaves).      */
/* reveal_count: number of leaves to reveal.                            */
/* ------------------------------------------------------------------ */

void cross_seed_tree_get_path(uint8_t *path, int *path_len,
                              const uint8_t *seeds, int num_leaves,
                              const int *reveal_set, int reveal_count,
                              int seed_len)
{
    int total = 2 * num_leaves - 1;
    /*
     * Mark which nodes need to be revealed.
     * A leaf node is "needed" if it's in the reveal set.
     * An internal node is "needed" if both children are needed.
     * We emit a node if it is needed but its parent is not fully needed.
     */
    uint8_t *needed = (uint8_t *)pqc_calloc(1, (size_t)total);
    int offset = num_leaves - 1;
    int i, count;

    if (!needed) { *path_len = 0; return; }

    /* Mark leaf nodes */
    for (i = 0; i < reveal_count; i++) {
        needed[offset + reveal_set[i]] = 1;
    }

    /* Propagate upward: a parent is "fully covered" if both children are */
    for (i = offset - 1; i >= 0; i--) {
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        if (needed[left] && needed[right]) {
            needed[i] = 1;
        }
    }

    /*
     * Emit: traverse top-down.  If a node is needed and its parent
     * is NOT needed (or it's the root), emit it.
     */
    count = 0;
    for (i = 0; i < total; i++) {
        if (!needed[i]) continue;
        int parent = (i - 1) / 2;
        if (i == 0 || !needed[parent]) {
            memcpy(path + (size_t)count * (size_t)seed_len,
                   seeds + (size_t)i * (size_t)seed_len,
                   (size_t)seed_len);
            count++;
        }
    }

    *path_len = count;
    pqc_free(needed, (size_t)total);
}

/* ------------------------------------------------------------------ */
/* Reconstruct leaf seeds from a path and the known reveal set.         */
/*                                                                      */
/* On output, seeds[offset + reveal_set[i]] are populated for each      */
/* revealed leaf.  Non-revealed leaf positions are zeroed.               */
/* ------------------------------------------------------------------ */

void cross_seed_tree_reconstruct(uint8_t *seeds, int num_leaves,
                                  const uint8_t *path, int path_len,
                                  const int *reveal_set, int reveal_count,
                                  int seed_len)
{
    int total = 2 * num_leaves - 1;
    int offset = num_leaves - 1;
    uint8_t *needed = (uint8_t *)pqc_calloc(1, (size_t)total);
    uint8_t *known = (uint8_t *)pqc_calloc(1, (size_t)total);
    int i, pidx;
    uint8_t buf[128];

    if (!needed || !known) {
        if (needed) pqc_free(needed, (size_t)total);
        if (known) pqc_free(known, (size_t)total);
        return;
    }

    memset(seeds, 0, (size_t)total * (size_t)seed_len);

    /* Mark needed leaves */
    for (i = 0; i < reveal_count; i++) {
        needed[offset + reveal_set[i]] = 1;
    }
    for (i = offset - 1; i >= 0; i--) {
        if (needed[2 * i + 1] && needed[2 * i + 2]) {
            needed[i] = 1;
        }
    }

    /* Place path seeds at the appropriate nodes */
    pidx = 0;
    for (i = 0; i < total && pidx < path_len; i++) {
        if (!needed[i]) continue;
        int parent = (i - 1) / 2;
        if (i == 0 || !needed[parent]) {
            memcpy(seeds + (size_t)i * (size_t)seed_len,
                   path + (size_t)pidx * (size_t)seed_len,
                   (size_t)seed_len);
            known[i] = 1;
            pidx++;
        }
    }

    /* Expand known internal nodes top-down */
    for (i = 0; i < offset; i++) {
        if (!known[i]) continue;
        int left = 2 * i + 1;
        int right = 2 * i + 2;
        pqc_shake256(buf, (size_t)seed_len * 2,
                     seeds + (size_t)i * (size_t)seed_len,
                     (size_t)seed_len);
        if (needed[left]) {
            memcpy(seeds + (size_t)left * (size_t)seed_len,
                   buf, (size_t)seed_len);
            known[left] = 1;
        }
        if (needed[right]) {
            memcpy(seeds + (size_t)right * (size_t)seed_len,
                   buf + seed_len, (size_t)seed_len);
            known[right] = 1;
        }
    }

    pqc_free(needed, (size_t)total);
    pqc_free(known, (size_t)total);
    pqc_memzero(buf, sizeof(buf));
}
