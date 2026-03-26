/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * CROSS internal interface.
 */

#ifndef PQC_CROSS_H
#define PQC_CROSS_H

#include <stddef.h>
#include <stdint.h>

#include "cross_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Runtime parameter structure                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    int n;          /* code length               */
    int k;          /* code dimension             */
    int w;          /* weight of secret           */
    int z;          /* field prime                */
    int t;          /* number of rounds           */
    int hash_len;   /* hash output bytes          */
    size_t pk_len;
    size_t sk_len;
    size_t sig_len;
    int seed_len;
} cross_params_t;

/* ------------------------------------------------------------------ */
/* RSDP operations (rsdp.c)                                             */
/* ------------------------------------------------------------------ */

void cross_rsdp_compute_syndrome(uint8_t *syndrome, const uint8_t *H,
                                  const uint8_t *e, int n, int k, int z);
void cross_rsdp_sample_error(uint8_t *e, int n, int w, int z,
                              const uint8_t *seed, size_t seed_len);
void cross_rsdp_expand_H(uint8_t *H, int n, int k, int z,
                          const uint8_t *seed, size_t seed_len);

/* ------------------------------------------------------------------ */
/* Merkle tree (merkle.c)                                               */
/* ------------------------------------------------------------------ */

void cross_merkle_build(uint8_t *tree, const uint8_t *leaves,
                        int num_leaves, int hash_len);
void cross_merkle_path(uint8_t *path, int *path_len,
                       const uint8_t *tree, int leaf_idx,
                       int num_leaves, int hash_len);
int  cross_merkle_verify(const uint8_t *root, const uint8_t *leaf,
                         int leaf_idx, const uint8_t *path, int path_len,
                         int num_leaves, int hash_len);

/* ------------------------------------------------------------------ */
/* Seed tree (seed_tree.c)                                              */
/* ------------------------------------------------------------------ */

void cross_seed_tree_expand(uint8_t *seeds, int num_leaves,
                            const uint8_t *root_seed, int seed_len);
void cross_seed_tree_get_path(uint8_t *path, int *path_len,
                              const uint8_t *seeds, int num_leaves,
                              const int *reveal_set, int reveal_count,
                              int seed_len);
void cross_seed_tree_reconstruct(uint8_t *seeds, int num_leaves,
                                  const uint8_t *path, int path_len,
                                  const int *reveal_set, int reveal_count,
                                  int seed_len);

#ifdef __cplusplus
}
#endif

#endif /* PQC_CROSS_H */
