/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * XMSS - Hash address structure handling.
 * RFC 8391 Section 2.5.
 *
 * The ADRS (address) is a 32-byte structure used for domain separation
 * in all XMSS hash calls.  It encodes the position within the tree
 * hierarchy (layer, tree address, type, and type-specific fields).
 *
 * Layout (all big-endian):
 *   [0..3]   layer address
 *   [4..11]  tree address (64-bit)
 *   [12..15] type (0=OTS, 1=L-tree, 2=hash tree)
 *   [16..19] OTS address / L-tree address / padding
 *   [20..23] chain address / tree height / padding
 *   [24..27] hash address / tree index / padding
 *   [28..31] key and mask selector / padding
 */

#include <string.h>
#include <stdint.h>
#include "xmss.h"

/* ------------------------------------------------------------------ */
/* Utility: store 32-bit big-endian at offset                           */
/* ------------------------------------------------------------------ */

static void addr_store_u32(uint8_t *dst, int offset, uint32_t val)
{
    dst[offset]     = (uint8_t)(val >> 24);
    dst[offset + 1] = (uint8_t)(val >> 16);
    dst[offset + 2] = (uint8_t)(val >> 8);
    dst[offset + 3] = (uint8_t)(val);
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

void xmss_addr_zero(uint8_t addr[PQC_XMSS_ADDR_BYTES])
{
    memset(addr, 0, PQC_XMSS_ADDR_BYTES);
}

void xmss_addr_set_layer(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t layer)
{
    addr_store_u32(addr, 0, layer);
}

void xmss_addr_set_tree(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint64_t tree)
{
    addr[4]  = (uint8_t)(tree >> 56);
    addr[5]  = (uint8_t)(tree >> 48);
    addr[6]  = (uint8_t)(tree >> 40);
    addr[7]  = (uint8_t)(tree >> 32);
    addr[8]  = (uint8_t)(tree >> 24);
    addr[9]  = (uint8_t)(tree >> 16);
    addr[10] = (uint8_t)(tree >> 8);
    addr[11] = (uint8_t)(tree);
}

void xmss_addr_set_type(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t type)
{
    addr_store_u32(addr, 12, type);
    /* Zero the type-specific fields when changing type */
    memset(addr + 16, 0, 16);
}

void xmss_addr_set_ots(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t ots)
{
    addr_store_u32(addr, 16, ots);
}

void xmss_addr_set_chain(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t chain)
{
    addr_store_u32(addr, 20, chain);
}

void xmss_addr_set_hash(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t hash)
{
    addr_store_u32(addr, 24, hash);
}

void xmss_addr_set_ltree(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t ltree)
{
    addr_store_u32(addr, 16, ltree);
}

void xmss_addr_set_tree_height(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t h)
{
    addr_store_u32(addr, 20, h);
}

void xmss_addr_set_tree_index(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t idx)
{
    addr_store_u32(addr, 24, idx);
}
