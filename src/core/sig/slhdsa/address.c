/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - ADRS (address) structure handling.
 *
 * The ADRS is a 32-byte structure used to domain-separate all hash
 * calls in SLH-DSA. FIPS 205 section 4.2, Figure 2 (big-endian words):
 *
 *   [0..3]   layer address
 *   [4..15]  tree address (12 bytes; this library's 64-bit value fills
 *            bytes 8..15 and bytes 4..7 stay zero)
 *   [16..19] type
 *   [20..23] key pair address  (zero for TREE / FORS_ROOTS)
 *   [24..27] chain address     or tree height
 *   [28..31] hash address      or tree index
 *
 * Before 0.3.0 the tree address was 8 bytes at [4..11], which shifted every
 * later field 4 bytes early and left [28..31] permanently zero. All of the
 * algorithm logic was unaffected and sign/verify agreed, but every
 * tweakable-hash input differed from FIPS 205, so no signature or public
 * key interoperated with a conformant implementation.
 */

#define ADRS_LAYER    0
#define ADRS_TREE     8    /* low 8 bytes of the 12-byte tree address */
#define ADRS_TYPE     16
#define ADRS_KEYPAIR  20
#define ADRS_WORD2    24   /* chain address / tree height */
#define ADRS_WORD3    28   /* hash address  / tree index  */

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
    u32_to_bytes(addr + ADRS_LAYER, layer);
}

void slhdsa_set_tree_addr(uint8_t addr[32], uint64_t tree)
{
    memset(addr + 4, 0, 4);
    u64_to_bytes(addr + ADRS_TREE, tree);
}

void slhdsa_set_type(uint8_t addr[32], uint32_t type)
{
    u32_to_bytes(addr + ADRS_TYPE, type);
    /* setTypeAndClear: the three words after the type are zeroed. */
    memset(addr + ADRS_KEYPAIR, 0, 12);
}

void slhdsa_set_keypair_addr(uint8_t addr[32], uint32_t keypair)
{
    u32_to_bytes(addr + ADRS_KEYPAIR, keypair);
}

uint32_t slhdsa_get_keypair_addr(const uint8_t addr[32])
{
    const uint8_t *b = addr + ADRS_KEYPAIR;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}

/*
 * ADRS.setTypeAndClear(type) followed by
 * ADRS.setKeyPairAddress(<the keypair address it had before>).
 *
 * slhdsa_set_type() is a faithful setTypeAndClear: it zeroes bytes 16..31,
 * which includes the keypair address. FIPS 205 relies on that, but
 * wherever it changes the type of an address that identifies a WOTS+ or
 * FORS key pair -- Algorithms 6, 7 and 8 (WOTS_PRF, WOTS_PK) and 14, 15
 * and 17 (FORS_PRF, FORS_TREE, FORS_ROOTS) -- it immediately restores the
 * keypair address from the original.
 *
 * Calling slhdsa_set_type() alone at those points silently discards the
 * keypair address. That made every FORS instance, and every WOTS+ public
 * key compression, independent of which key pair it belonged to: FORS
 * collapsed from 2^h distinct few-time instances to 2^(h - h'), and the
 * scheme stopped interoperating with conformant implementations. Signing
 * and verification shared the defect, so it round-tripped perfectly.
 * This is the same shape as the XMSS leaf-index defect fixed in 0.2.0.
 */
void slhdsa_set_type_keep_keypair(uint8_t addr[32], uint32_t type)
{
    uint32_t keypair = slhdsa_get_keypair_addr(addr);
    slhdsa_set_type(addr, type);
    slhdsa_set_keypair_addr(addr, keypair);
}

void slhdsa_set_chain_addr(uint8_t addr[32], uint32_t chain)
{
    u32_to_bytes(addr + ADRS_WORD2, chain);
}

void slhdsa_set_hash_addr(uint8_t addr[32], uint32_t hash)
{
    u32_to_bytes(addr + ADRS_WORD3, hash);
}

void slhdsa_set_tree_height(uint8_t addr[32], uint32_t height)
{
    u32_to_bytes(addr + ADRS_WORD2, height);
}

void slhdsa_set_tree_index(uint8_t addr[32], uint32_t index)
{
    u32_to_bytes(addr + ADRS_WORD3, index);
}

/*
 * Copy the layer and tree address (bytes 0..15).
 * This is used when deriving a new address in the same subtree.
 */
void slhdsa_copy_subtree_addr(uint8_t out[32], const uint8_t in[32])
{
    memcpy(out, in, 16);
}

/*
 * Copy the layer, tree and key pair address, but not the type: bytes
 * 0..15 and 20..23. Callers set the type themselves.
 */
void slhdsa_copy_keypair_addr(uint8_t out[32], const uint8_t in[32])
{
    memcpy(out, in, 16);
    memcpy(out + ADRS_KEYPAIR, in + ADRS_KEYPAIR, 4);
}

/*
 * ADRSc, the 22-byte compressed address of the SHA-2 instantiation
 * (FIPS 205 section 11.2): ADRS[3] || ADRS[8..15] || ADRS[19] || ADRS[20..31].
 */
void slhdsa_compress_addr(uint8_t out[SLHDSA_ADRSC_BYTES], const uint8_t addr[32])
{
    out[0] = addr[3];
    memcpy(out + 1, addr + 8, 8);
    out[9] = addr[19];
    memcpy(out + 10, addr + 20, 12);
}
