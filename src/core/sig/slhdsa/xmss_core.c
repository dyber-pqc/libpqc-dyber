/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - XMSS subtree operations.
 *
 * These are the XMSS operations internal to SLH-DSA (not the standalone
 * RFC 8391 XMSS).  Each XMSS tree has height hp = h/d and uses WOTS+
 * at the leaves.  The Merkle tree is built using the tweakable hash
 * with HASHTREE address type.
 */

#include <string.h>
#include <stdint.h>

#include "slhdsa.h"

/* ------------------------------------------------------------------ */
/* Compute an internal node of the XMSS Merkle tree.                    */
/*                                                                      */
/* xmss_node(index, height) computes the node at position 'index' at    */
/* tree level 'height'.  At height 0, this is the WOTS+ leaf (the       */
/* compressed WOTS+ public key).  Higher nodes are computed by hashing   */
/* pairs of children.                                                   */
/* ------------------------------------------------------------------ */

void slhdsa_xmss_node(uint8_t *out,
                       uint32_t index, uint32_t height,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p)
{
    uint32_t n = p->n;

    if (height == 0) {
        /* Leaf node: compute WOTS+ public key */
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);
        slhdsa_set_keypair_addr(addr, index);
        slhdsa_wots_gen_pk(out, sk_seed, pub_seed, addr, p);
    } else {
        /* Internal node: hash left || right children */
        uint8_t left[SLHDSA_MAX_N];
        uint8_t right[SLHDSA_MAX_N];
        uint8_t pair[2 * SLHDSA_MAX_N];

        slhdsa_xmss_node(left, 2 * index, height - 1,
                          sk_seed, pub_seed, addr, p);
        slhdsa_xmss_node(right, 2 * index + 1, height - 1,
                          sk_seed, pub_seed, addr, p);

        memcpy(pair, left, n);
        memcpy(pair + n, right, n);

        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_HASHTREE);
        slhdsa_set_tree_height(addr, height);
        slhdsa_set_tree_index(addr, index);
        slhdsa_thash(out, pair, 2, pub_seed, addr, p);
    }
}

/* ------------------------------------------------------------------ */
/* Compute the root of an XMSS tree.                                    */
/* ------------------------------------------------------------------ */

void slhdsa_xmss_root(uint8_t *root,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p)
{
    slhdsa_xmss_node(root, 0, p->hp, sk_seed, pub_seed, addr, p);
}

/* ------------------------------------------------------------------ */
/* XMSS sign: produce a WOTS+ signature and authentication path.        */
/*                                                                      */
/* The signature consists of:                                           */
/*   - WOTS+ signature (wots_sig_bytes)                                 */
/*   - Authentication path: hp nodes of n bytes each                    */
/*                                                                      */
/* Also computes and returns the tree root.                              */
/* ------------------------------------------------------------------ */

void slhdsa_xmss_sign(uint8_t *sig, uint8_t *root,
                       uint32_t idx,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t hp = p->hp;
    uint8_t *auth = sig + p->wots_sig_bytes;
    uint32_t i;

    /* Build the tree using a treehash-like approach.
     * For each level, compute the authentication path sibling. */

    /* Sign the message with WOTS+ at this leaf position */
    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);
    slhdsa_set_keypair_addr(addr, idx);

    /*
     * The WOTS+ message to sign is provided externally (it's the message
     * being authenticated by the hypertree, or the FORS root at layer 0).
     * The caller will use the root returned to chain upward.
     *
     * For the treehash computation, we need all nodes.  We use the
     * recursive xmss_node function for the authentication path nodes.
     */

    /* Compute auth path: for each level j, the sibling of the
     * node on the path from leaf idx to the root. */
    for (i = 0; i < hp; i++) {
        /* The sibling at level i is the node with index
         * (idx >> i) ^ 1 at height i. */
        uint32_t sibling = (idx >> i) ^ 1;
        slhdsa_xmss_node(auth + i * n, sibling, i,
                          sk_seed, pub_seed, addr, p);
    }

    /* Compute the root */
    slhdsa_xmss_root(root, sk_seed, pub_seed, addr, p);
}

/* ------------------------------------------------------------------ */
/* XMSS root recovery from signature.                                   */
/*                                                                      */
/* Given a WOTS+ signature, authentication path, and leaf index,         */
/* recompute the XMSS root.                                             */
/* ------------------------------------------------------------------ */

void slhdsa_xmss_root_from_sig(uint8_t *root,
                                uint32_t idx,
                                const uint8_t *auth_path,
                                const uint8_t *wots_pk,
                                const uint8_t *pub_seed,
                                uint8_t addr[32],
                                const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t hp = p->hp;
    uint8_t node[SLHDSA_MAX_N];
    uint8_t pair[2 * SLHDSA_MAX_N];
    uint32_t i;

    memcpy(node, wots_pk, n);

    for (i = 0; i < hp; i++) {
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_HASHTREE);
        slhdsa_set_tree_height(addr, i + 1);
        slhdsa_set_tree_index(addr, idx >> (i + 1));

        if ((idx >> i) & 1) {
            /* node is right child */
            memcpy(pair, auth_path + i * n, n);
            memcpy(pair + n, node, n);
        } else {
            /* node is left child */
            memcpy(pair, node, n);
            memcpy(pair + n, auth_path + i * n, n);
        }

        slhdsa_thash(node, pair, 2, pub_seed, addr, p);
    }

    memcpy(root, node, n);
}
