/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - ADRS (address) structure handling.
 *
 * The ADRS is a 32-byte structure used to domain-separate all hash
 * calls in SLH-DSA.  Layout (byte offsets, big-endian):
 *
 *   [0..3]   layer address
 *   [4..11]  tree address (8 bytes)
 *   [12..15] type
 *   [16..19] keypair address   (or padding, depends on type)
 *   [20..23] chain address     (or tree height)
 *   [24..27] hash address      (or tree index)
 *   [28..31] padding / zero
 */

#include <string.h>
#include <stdint.h>

#include "slhdsa.h"

/* ------------------------------------------------------------------ */
/* Helpers: store big-endian uint32/uint64 into byte array              */
/* ------------------------------------------------------------------ */

static inline void u32_to_bytes(uint8_t *out, uint32_t val)
{
    out[0] = (uint8_t)(val >> 24);
    out[1] = (uint8_t)(val >> 16);
    out[2] = (uint8_t)(val >>  8);
    out[3] = (uint8_t)(val      );
}

static inline void u64_to_bytes(uint8_t *out, uint64_t val)
{
    out[0] = (uint8_t)(val >> 56);
    out[1] = (uint8_t)(val >> 48);
    out[2] = (uint8_t)(val >> 40);
    out[3] = (uint8_t)(val >> 32);
    out[4] = (uint8_t)(val >> 24);
    out[5] = (uint8_t)(val >> 16);
    out[6] = (uint8_t)(val >>  8);
    out[7] = (uint8_t)(val      );
}

/* ------------------------------------------------------------------ */
/* Address field setters                                                 */
/* ------------------------------------------------------------------ */

void slhdsa_set_layer_addr(uint8_t addr[32], uint32_t layer)
{
    u32_to_bytes(addr + 0, layer);
}

void slhdsa_set_tree_addr(uint8_t addr[32], uint64_t tree)
{
    u64_to_bytes(addr + 4, tree);
}

void slhdsa_set_type(uint8_t addr[32], uint32_t type)
{
    u32_to_bytes(addr + 12, type);
    /* Per FIPS 205: when type changes, zero bytes 16..31 */
    memset(addr + 16, 0, 16);
}

void slhdsa_set_keypair_addr(uint8_t addr[32], uint32_t keypair)
{
    u32_to_bytes(addr + 16, keypair);
}

void slhdsa_set_chain_addr(uint8_t addr[32], uint32_t chain)
{
    u32_to_bytes(addr + 20, chain);
}

void slhdsa_set_hash_addr(uint8_t addr[32], uint32_t hash)
{
    u32_to_bytes(addr + 24, hash);
}

void slhdsa_set_tree_height(uint8_t addr[32], uint32_t height)
{
    u32_to_bytes(addr + 20, height);
}

void slhdsa_set_tree_index(uint8_t addr[32], uint32_t index)
{
    u32_to_bytes(addr + 24, index);
}

/*
 * Copy the layer and tree part of an address (bytes 0..15).
 * This is used when deriving a new address in the same subtree.
 */
void slhdsa_copy_subtree_addr(uint8_t out[32], const uint8_t in[32])
{
    memcpy(out, in, 16);
}

/*
 * Copy layer, tree, and keypair fields (bytes 0..19).
 * Used for WOTS+ PRF address derivation.
 */
void slhdsa_copy_keypair_addr(uint8_t out[32], const uint8_t in[32])
{
    memcpy(out, in, 20);
}
