/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - FORS (Forest of Random Subsets) signature.
 *
 * FORS is a few-time signature scheme that signs a message digest by
 * revealing one leaf from each of k binary trees of height a.  The
 * signature includes the revealed secret values and their authentication
 * paths, plus the compressed public key can be recovered from the
 * k tree roots.
 */

#include <string.h>
#include <stdint.h>

#include "slhdsa.h"

/* ------------------------------------------------------------------ */
/* Extract FORS indices from the message digest.                        */
/*                                                                      */
/* The message digest md has k*a bits.  Split it into k values, each    */
/* 'a' bits, representing leaf indices in the k FORS trees.             */
/* ------------------------------------------------------------------ */

static void message_to_indices(uint32_t *indices,
                                const uint8_t *md,
                                uint32_t k, uint32_t a)
{
    uint32_t i;
    uint32_t offset = 0; /* bit offset into md */

    for (i = 0; i < k; i++) {
        uint32_t idx = 0;
        uint32_t j;

        for (j = 0; j < a; j++) {
            uint32_t byte_pos = offset / 8;
            uint32_t bit_pos = offset % 8;
            /* Extract bit (MSB first within each byte) */
            idx <<= 1;
            idx |= (md[byte_pos] >> (7 - bit_pos)) & 1;
            offset++;
        }

        indices[i] = idx;
    }
}

/* ------------------------------------------------------------------ */
/* Compute a single FORS leaf value.                                    */
/*                                                                      */
/* leaf = PRF(SK.seed, PK.seed, ADRS) where ADRS has type FORSTREE.     */
/* ------------------------------------------------------------------ */

static void fors_gen_leaf(uint8_t *leaf,
                           const uint8_t *sk_seed,
                           const uint8_t *pub_seed,
                           uint32_t addr_idx,
                           uint8_t addr[32],
                           const slhdsa_params_t *p)
{
    uint8_t prf_addr[32];

    memset(prf_addr, 0, 32);
    slhdsa_copy_keypair_addr(prf_addr, addr);
    slhdsa_set_type(prf_addr, SLHDSA_ADDR_TYPE_FORSPRF);
    slhdsa_set_tree_index(prf_addr, addr_idx);
    slhdsa_set_tree_height(prf_addr, 0);

    slhdsa_prf(leaf, sk_seed, pub_seed, prf_addr, p);
}

/* ------------------------------------------------------------------ */
/* Compute a FORS tree node at a given height and index.                */
/* ------------------------------------------------------------------ */

static void fors_tree_node(uint8_t *out,
                            uint32_t tree_idx, uint32_t node_idx,
                            uint32_t height,
                            const uint8_t *sk_seed,
                            const uint8_t *pub_seed,
                            uint8_t addr[32],
                            const slhdsa_params_t *p)
{
    uint32_t n = p->n;

    if (height == 0) {
        /* Leaf: generate secret value then hash it */
        uint32_t leaf_abs = tree_idx * (1u << p->a) + node_idx;
        uint8_t sk[SLHDSA_MAX_N];

        fors_gen_leaf(sk, sk_seed, pub_seed, leaf_abs, addr, p);

        /* Hash the leaf: F(PK.seed, ADRS, SK) */
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_FORSTREE);
        slhdsa_set_tree_height(addr, 0);
        slhdsa_set_tree_index(addr, leaf_abs);
        slhdsa_thash(out, sk, 1, pub_seed, addr, p);
    } else {
        /* Internal node: hash children */
        uint8_t left[SLHDSA_MAX_N];
        uint8_t right[SLHDSA_MAX_N];
        uint8_t pair[2 * SLHDSA_MAX_N];

        fors_tree_node(left, tree_idx, 2 * node_idx, height - 1,
                        sk_seed, pub_seed, addr, p);
        fors_tree_node(right, tree_idx, 2 * node_idx + 1, height - 1,
                        sk_seed, pub_seed, addr, p);

        memcpy(pair, left, n);
        memcpy(pair + n, right, n);

        uint32_t abs_idx = tree_idx * (1u << (p->a - height)) + node_idx;
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_FORSTREE);
        slhdsa_set_tree_height(addr, height);
        slhdsa_set_tree_index(addr, abs_idx);
        slhdsa_thash(out, pair, 2, pub_seed, addr, p);
    }
}

/* ------------------------------------------------------------------ */
/* FORS sign                                                            */
/*                                                                      */
/* For each of the k trees:                                             */
/*   1. Output the secret leaf value at the index from the digest.      */
/*   2. Output the authentication path (a sibling nodes).               */
/*                                                                      */
/* Signature layout per tree: [secret_value (n)] [auth_path (a*n)]      */
/* Total: k * (1 + a) * n bytes                                         */
/* ------------------------------------------------------------------ */

void slhdsa_fors_sign(uint8_t *sig,
                       const uint8_t *md,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t k = p->k;
    uint32_t a = p->a;
    uint32_t indices[SLHDSA_MAX_FORS_TREES];
    uint32_t i, j;
    uint8_t *sig_ptr = sig;

    message_to_indices(indices, md, k, a);

    for (i = 0; i < k; i++) {
        uint32_t idx = indices[i];
        uint32_t leaf_abs = i * (1u << a) + idx;

        /* Output the secret leaf value */
        fors_gen_leaf(sig_ptr, sk_seed, pub_seed, leaf_abs, addr, p);
        sig_ptr += n;

        /* Output authentication path */
        for (j = 0; j < a; j++) {
            uint32_t sibling = (idx >> j) ^ 1;
            fors_tree_node(sig_ptr, i, sibling, j,
                           sk_seed, pub_seed, addr, p);
            sig_ptr += n;
        }
    }
}

/* ------------------------------------------------------------------ */
/* FORS public key recovery from signature.                             */
/*                                                                      */
/* For each tree, hash the revealed secret to get the leaf, then walk    */
/* up the authentication path to get the tree root.  Compress all k     */
/* roots into the FORS public key.                                      */
/* ------------------------------------------------------------------ */

void slhdsa_fors_pk_from_sig(uint8_t *pk,
                              const uint8_t *sig,
                              const uint8_t *md,
                              const uint8_t *pub_seed,
                              uint8_t addr[32],
                              const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t k = p->k;
    uint32_t a = p->a;
    uint32_t indices[SLHDSA_MAX_FORS_TREES];
    uint8_t roots[SLHDSA_MAX_FORS_TREES * SLHDSA_MAX_N];
    const uint8_t *sig_ptr = sig;
    uint32_t i, j;

    message_to_indices(indices, md, k, a);

    for (i = 0; i < k; i++) {
        uint32_t idx = indices[i];
        uint8_t node[SLHDSA_MAX_N];
        uint8_t pair[2 * SLHDSA_MAX_N];
        uint32_t leaf_abs = i * (1u << a) + idx;

        /* Hash the secret value to get the leaf */
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_FORSTREE);
        slhdsa_set_tree_height(addr, 0);
        slhdsa_set_tree_index(addr, leaf_abs);
        slhdsa_thash(node, sig_ptr, 1, pub_seed, addr, p);
        sig_ptr += n;

        /* Walk up the authentication path */
        for (j = 0; j < a; j++) {
            uint32_t parent_idx;

            slhdsa_set_tree_height(addr, j + 1);
            parent_idx = i * (1u << (a - j - 1)) + (idx >> (j + 1));
            slhdsa_set_tree_index(addr, parent_idx);

            if ((idx >> j) & 1) {
                /* node is right child */
                memcpy(pair, sig_ptr, n);
                memcpy(pair + n, node, n);
            } else {
                /* node is left child */
                memcpy(pair, node, n);
                memcpy(pair + n, sig_ptr, n);
            }

            slhdsa_thash(node, pair, 2, pub_seed, addr, p);
            sig_ptr += n;
        }

        memcpy(roots + i * n, node, n);
    }

    /* Compress all k roots into the FORS public key */
    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_FORSPK);
    slhdsa_thash(pk, roots, k, pub_seed, addr, p);
}
