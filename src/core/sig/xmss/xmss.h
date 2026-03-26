/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * XMSS internal interface.
 */

#ifndef PQC_XMSS_H
#define PQC_XMSS_H

#include <stddef.h>
#include <stdint.h>

#include "xmss_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Hash address manipulation (hash_address.c)                           */
/* ------------------------------------------------------------------ */

void xmss_addr_zero(uint8_t addr[PQC_XMSS_ADDR_BYTES]);
void xmss_addr_set_layer(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t layer);
void xmss_addr_set_tree(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint64_t tree);
void xmss_addr_set_type(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t type);
void xmss_addr_set_ots(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t ots);
void xmss_addr_set_chain(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t chain);
void xmss_addr_set_hash(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t hash);
void xmss_addr_set_ltree(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t ltree);
void xmss_addr_set_tree_height(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t h);
void xmss_addr_set_tree_index(uint8_t addr[PQC_XMSS_ADDR_BYTES], uint32_t idx);

/* ------------------------------------------------------------------ */
/* WOTS+ operations (wots.c)                                            */
/* ------------------------------------------------------------------ */

void xmss_wots_keygen(uint8_t *pk, const uint8_t *seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[PQC_XMSS_ADDR_BYTES]);
void xmss_wots_sign(uint8_t *sig, const uint8_t *msg,
                     const uint8_t *seed, const uint8_t *pub_seed,
                     uint8_t addr[PQC_XMSS_ADDR_BYTES]);
void xmss_wots_pk_from_sig(uint8_t *pk, const uint8_t *sig,
                             const uint8_t *msg, const uint8_t *pub_seed,
                             uint8_t addr[PQC_XMSS_ADDR_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* PQC_XMSS_H */
