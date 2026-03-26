/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - Hypertree signature.
 *
 * The hypertree is a certification chain of d XMSS trees stacked
 * vertically.  Layer 0 is at the bottom (signs the FORS public key),
 * and layer d-1 is at the top (the root is PK.root).
 *
 * Each layer i has trees of height hp = h/d, addressed by a tree
 * index.  The leaf index within each tree is derived from the
 * overall idx_tree and idx_leaf values.
 */

#include <string.h>
#include <stdint.h>

#include "slhdsa.h"

/* ------------------------------------------------------------------ */
/* Hypertree sign                                                       */
/*                                                                      */
/* Sign 'msg' (n bytes, typically a FORS public key) using the          */
/* hypertree.  The signature is d XMSS signatures chained together.     */
/*                                                                      */
/* idx_tree: identifies which tree at layer 0                           */
/* idx_leaf: identifies which leaf within the layer-0 tree              */
/* ------------------------------------------------------------------ */

void slhdsa_ht_sign(uint8_t *sig,
                     const uint8_t *msg,
                     const uint8_t *sk_seed,
                     const uint8_t *pub_seed,
                     uint64_t idx_tree, uint32_t idx_leaf,
                     const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t d = p->d;
    uint32_t hp = p->hp;
    uint32_t xmss_sig_bytes = p->wots_sig_bytes + hp * n;
    uint8_t addr[32];
    uint8_t root[SLHDSA_MAX_N];
    uint32_t layer;
    uint8_t *sig_ptr = sig;

    memset(addr, 0, 32);

    /* Layer 0: sign the message (FORS pk) */
    slhdsa_set_layer_addr(addr, 0);
    slhdsa_set_tree_addr(addr, idx_tree);

    /* WOTS+ sign at leaf idx_leaf */
    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);
    slhdsa_set_keypair_addr(addr, idx_leaf);
    slhdsa_wots_sign(sig_ptr, msg, sk_seed, pub_seed, addr, p);

    /* Compute auth path and root for layer 0 */
    {
        uint8_t *auth_path = sig_ptr + p->wots_sig_bytes;
        uint32_t i;

        /* Compute authentication path */
        for (i = 0; i < hp; i++) {
            uint32_t sibling = (idx_leaf >> i) ^ 1;
            slhdsa_xmss_node(auth_path + i * n, sibling, i,
                              sk_seed, pub_seed, addr, p);
        }

        /* Recover the root by walking up from the WOTS+ pk */
        {
            uint8_t wots_pk[SLHDSA_MAX_N];
            slhdsa_wots_pk_from_sig(wots_pk, sig_ptr, msg,
                                     pub_seed, addr, p);
            slhdsa_xmss_root_from_sig(root, idx_leaf, auth_path,
                                       wots_pk, pub_seed, addr, p);
        }
    }

    sig_ptr += xmss_sig_bytes;

    /* Layers 1 through d-1 */
    for (layer = 1; layer < d; layer++) {
        /* The leaf index in this layer comes from the previous tree index */
        uint32_t leaf = (uint32_t)(idx_tree & ((1u << hp) - 1));
        idx_tree >>= hp;

        slhdsa_set_layer_addr(addr, layer);
        slhdsa_set_tree_addr(addr, idx_tree);

        /* WOTS+ sign the root from the layer below */
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);
        slhdsa_set_keypair_addr(addr, leaf);
        slhdsa_wots_sign(sig_ptr, root, sk_seed, pub_seed, addr, p);

        /* Compute auth path */
        {
            uint8_t *auth_path = sig_ptr + p->wots_sig_bytes;
            uint32_t i;

            for (i = 0; i < hp; i++) {
                uint32_t sibling = (leaf >> i) ^ 1;
                slhdsa_xmss_node(auth_path + i * n, sibling, i,
                                  sk_seed, pub_seed, addr, p);
            }

            /* Recover the new root */
            if (layer < d - 1) {
                uint8_t wots_pk[SLHDSA_MAX_N];
                slhdsa_wots_pk_from_sig(wots_pk, sig_ptr, root,
                                         pub_seed, addr, p);
                slhdsa_xmss_root_from_sig(root, leaf, auth_path,
                                           wots_pk, pub_seed, addr, p);
            }
        }

        sig_ptr += xmss_sig_bytes;
    }
}

/* ------------------------------------------------------------------ */
/* Hypertree verify                                                     */
/*                                                                      */
/* Verify a hypertree signature by recovering the XMSS root at each     */
/* layer and checking that the top-level root matches PK.root.          */
/*                                                                      */
/* Returns 0 on success, -1 on failure.                                 */
/* ------------------------------------------------------------------ */

int slhdsa_ht_verify(const uint8_t *msg,
                      const uint8_t *sig,
                      const uint8_t *pub_seed,
                      uint64_t idx_tree, uint32_t idx_leaf,
                      const uint8_t *pk_root,
                      const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint32_t d = p->d;
    uint32_t hp = p->hp;
    uint32_t xmss_sig_bytes = p->wots_sig_bytes + hp * n;
    uint8_t addr[32];
    uint8_t node[SLHDSA_MAX_N];
    uint8_t wots_pk[SLHDSA_MAX_N];
    const uint8_t *sig_ptr = sig;
    uint32_t layer;

    memset(addr, 0, 32);

    /* Layer 0: recover WOTS+ pk, then XMSS root */
    slhdsa_set_layer_addr(addr, 0);
    slhdsa_set_tree_addr(addr, idx_tree);
    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);
    slhdsa_set_keypair_addr(addr, idx_leaf);

    slhdsa_wots_pk_from_sig(wots_pk, sig_ptr, msg, pub_seed, addr, p);

    slhdsa_xmss_root_from_sig(node, idx_leaf,
                                sig_ptr + p->wots_sig_bytes,
                                wots_pk, pub_seed, addr, p);

    sig_ptr += xmss_sig_bytes;

    /* Layers 1 through d-1 */
    for (layer = 1; layer < d; layer++) {
        uint32_t leaf = (uint32_t)(idx_tree & ((1u << hp) - 1));
        idx_tree >>= hp;

        slhdsa_set_layer_addr(addr, layer);
        slhdsa_set_tree_addr(addr, idx_tree);
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);
        slhdsa_set_keypair_addr(addr, leaf);

        slhdsa_wots_pk_from_sig(wots_pk, sig_ptr, node,
                                 pub_seed, addr, p);

        slhdsa_xmss_root_from_sig(node, leaf,
                                    sig_ptr + p->wots_sig_bytes,
                                    wots_pk, pub_seed, addr, p);

        sig_ptr += xmss_sig_bytes;
    }

    /* Compare recovered root with PK.root */
    return pqc_memcmp_ct(node, pk_root, n) == 0 ? 0 : -1;
}
