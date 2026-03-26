/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) internal interface.
 */

#ifndef PQC_SLHDSA_H
#define PQC_SLHDSA_H

#include <stddef.h>
#include <stdint.h>

#include "slhdsa_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* ADRS (address) manipulation                                          */
/* ------------------------------------------------------------------ */

void slhdsa_set_layer_addr(uint8_t addr[32], uint32_t layer);
void slhdsa_set_tree_addr(uint8_t addr[32], uint64_t tree);
void slhdsa_set_type(uint8_t addr[32], uint32_t type);
void slhdsa_set_keypair_addr(uint8_t addr[32], uint32_t keypair);
void slhdsa_set_chain_addr(uint8_t addr[32], uint32_t chain);
void slhdsa_set_hash_addr(uint8_t addr[32], uint32_t hash);
void slhdsa_set_tree_height(uint8_t addr[32], uint32_t height);
void slhdsa_set_tree_index(uint8_t addr[32], uint32_t index);
void slhdsa_copy_subtree_addr(uint8_t out[32], const uint8_t in[32]);
void slhdsa_copy_keypair_addr(uint8_t out[32], const uint8_t in[32]);

/* ------------------------------------------------------------------ */
/* Tweakable hash — SHA-2 instantiation                                 */
/* ------------------------------------------------------------------ */

void slhdsa_thash_sha2(uint8_t *out,
                        const uint8_t *in, uint32_t inblocks,
                        const uint8_t *pub_seed,
                        const uint8_t addr[32],
                        const slhdsa_params_t *p);

void slhdsa_prf_sha2(uint8_t *out,
                      const uint8_t *sk_seed,
                      const uint8_t *pub_seed,
                      const uint8_t addr[32],
                      const slhdsa_params_t *p);

void slhdsa_prf_msg_sha2(uint8_t *out,
                          const uint8_t *sk_prf,
                          const uint8_t *opt_rand,
                          const uint8_t *msg, size_t msglen,
                          const slhdsa_params_t *p);

void slhdsa_hash_msg_sha2(uint8_t *out,
                           const uint8_t *r,
                           const uint8_t *pk,
                           const uint8_t *msg, size_t msglen,
                           const slhdsa_params_t *p);

/* ------------------------------------------------------------------ */
/* Tweakable hash — SHAKE instantiation                                 */
/* ------------------------------------------------------------------ */

void slhdsa_thash_shake(uint8_t *out,
                         const uint8_t *in, uint32_t inblocks,
                         const uint8_t *pub_seed,
                         const uint8_t addr[32],
                         const slhdsa_params_t *p);

void slhdsa_prf_shake(uint8_t *out,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       const uint8_t addr[32],
                       const slhdsa_params_t *p);

void slhdsa_prf_msg_shake(uint8_t *out,
                           const uint8_t *sk_prf,
                           const uint8_t *opt_rand,
                           const uint8_t *msg, size_t msglen,
                           const slhdsa_params_t *p);

void slhdsa_hash_msg_shake(uint8_t *out,
                            const uint8_t *r,
                            const uint8_t *pk,
                            const uint8_t *msg, size_t msglen,
                            const slhdsa_params_t *p);

/* ------------------------------------------------------------------ */
/* Dispatched tweakable hash (selects SHA2 or SHAKE based on params)     */
/* ------------------------------------------------------------------ */

void slhdsa_thash(uint8_t *out,
                   const uint8_t *in, uint32_t inblocks,
                   const uint8_t *pub_seed,
                   const uint8_t addr[32],
                   const slhdsa_params_t *p);

void slhdsa_prf(uint8_t *out,
                 const uint8_t *sk_seed,
                 const uint8_t *pub_seed,
                 const uint8_t addr[32],
                 const slhdsa_params_t *p);

void slhdsa_prf_msg(uint8_t *out,
                     const uint8_t *sk_prf,
                     const uint8_t *opt_rand,
                     const uint8_t *msg, size_t msglen,
                     const slhdsa_params_t *p);

void slhdsa_hash_msg(uint8_t *out,
                      const uint8_t *r,
                      const uint8_t *pk,
                      const uint8_t *msg, size_t msglen,
                      const slhdsa_params_t *p);

/* ------------------------------------------------------------------ */
/* WOTS+ one-time signature                                             */
/* ------------------------------------------------------------------ */

void slhdsa_wots_gen_pk(uint8_t *pk,
                         const uint8_t *sk_seed,
                         const uint8_t *pub_seed,
                         uint8_t addr[32],
                         const slhdsa_params_t *p);

void slhdsa_wots_sign(uint8_t *sig,
                       const uint8_t *msg,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p);

void slhdsa_wots_pk_from_sig(uint8_t *pk,
                              const uint8_t *sig,
                              const uint8_t *msg,
                              const uint8_t *pub_seed,
                              uint8_t addr[32],
                              const slhdsa_params_t *p);

/* ------------------------------------------------------------------ */
/* XMSS tree operations (internal to SLH-DSA)                           */
/* ------------------------------------------------------------------ */

void slhdsa_xmss_node(uint8_t *out,
                       uint32_t index, uint32_t height,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p);

void slhdsa_xmss_sign(uint8_t *sig, uint8_t *root,
                       uint32_t idx,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p);

void slhdsa_xmss_root(uint8_t *root,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p);

void slhdsa_xmss_root_from_sig(uint8_t *root,
                                uint32_t idx,
                                const uint8_t *sig,
                                const uint8_t *wots_sig,
                                const uint8_t *pub_seed,
                                uint8_t addr[32],
                                const slhdsa_params_t *p);

/* ------------------------------------------------------------------ */
/* FORS (Forest of Random Subsets)                                      */
/* ------------------------------------------------------------------ */

void slhdsa_fors_sign(uint8_t *sig,
                       const uint8_t *md,
                       const uint8_t *sk_seed,
                       const uint8_t *pub_seed,
                       uint8_t addr[32],
                       const slhdsa_params_t *p);

void slhdsa_fors_pk_from_sig(uint8_t *pk,
                              const uint8_t *sig,
                              const uint8_t *md,
                              const uint8_t *pub_seed,
                              uint8_t addr[32],
                              const slhdsa_params_t *p);

/* ------------------------------------------------------------------ */
/* Hypertree                                                            */
/* ------------------------------------------------------------------ */

void slhdsa_ht_sign(uint8_t *sig,
                     const uint8_t *msg,
                     const uint8_t *sk_seed,
                     const uint8_t *pub_seed,
                     uint64_t idx_tree, uint32_t idx_leaf,
                     const slhdsa_params_t *p);

int slhdsa_ht_verify(const uint8_t *msg,
                      const uint8_t *sig,
                      const uint8_t *pub_seed,
                      uint64_t idx_tree, uint32_t idx_leaf,
                      const uint8_t *pk_root,
                      const slhdsa_params_t *p);

/* ------------------------------------------------------------------ */
/* Top-level SLH-DSA API (called from vtable)                           */
/* ------------------------------------------------------------------ */

int pqc_slhdsa_keygen(uint8_t *pk, uint8_t *sk,
                       const slhdsa_params_t *p);

int pqc_slhdsa_sign(uint8_t *sig, size_t *siglen,
                     const uint8_t *msg, size_t msglen,
                     const uint8_t *sk,
                     const slhdsa_params_t *p);

int pqc_slhdsa_verify(const uint8_t *msg, size_t msglen,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *pk,
                       const slhdsa_params_t *p);

#ifdef __cplusplus
}
#endif

#endif /* PQC_SLHDSA_H */
