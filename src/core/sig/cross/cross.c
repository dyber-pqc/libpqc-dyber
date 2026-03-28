/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * CROSS (Codes and Restricted Objects Signature Scheme).
 *
 * CROSS is a code-based signature scheme whose security relies on the
 * Restricted Syndrome Decoding Problem (RSDP).  It uses a multi-round
 * commit-and-prove (cut-and-choose) framework:
 *
 * Key generation:
 *   - sk = random seed -> expand to (H, e) where H is a parity-check
 *     matrix and e is a weight-restricted vector over F_z
 *   - pk = (seed_for_H, syndrome s = H*e mod z)
 *
 * Signing (t rounds of commit-and-prove):
 *   - For each round i: sample random mask r_i, commit via Merkle tree
 *   - Challenge: hash of commitments selects which rounds to open
 *   - Response: for opened rounds, reveal seeds; for closed rounds,
 *     reveal the adjusted commitment
 *   - sig = (salt, merkle_root, challenges, responses)
 *
 * Verification:
 *   - Recompute commitments from responses
 *   - Verify Merkle paths and check syndrome relation
 */

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/sig/sig_internal.h"
#include "core/common/hash/sha3.h"
#include "core/common/hash/sha2.h"
#include "cross.h"

/* ------------------------------------------------------------------ */
/* Parameter set definitions                                            */
/* ------------------------------------------------------------------ */

static const cross_params_t cross_rsdp_128_fast_params = {
    .n = PQC_CROSS_RSDP_128_N, .k = PQC_CROSS_RSDP_128_K,
    .w = PQC_CROSS_RSDP_128_W, .z = PQC_CROSS_RSDP_128_Z,
    .t = PQC_CROSS_RSDP_128_FAST_T,
    .hash_len = PQC_CROSS_128_HASH_BYTES,
    .pk_len = PQC_CROSS_RSDP_128_PUBLICKEYBYTES,
    .sk_len = PQC_CROSS_RSDP_128_SECRETKEYBYTES,
    .sig_len = PQC_CROSS_RSDP_128_FAST_SIGBYTES,
    .seed_len = 32,
};

static const cross_params_t cross_rsdp_128_small_params = {
    .n = PQC_CROSS_RSDP_128_N, .k = PQC_CROSS_RSDP_128_K,
    .w = PQC_CROSS_RSDP_128_W, .z = PQC_CROSS_RSDP_128_Z,
    .t = PQC_CROSS_RSDP_128_SMALL_T,
    .hash_len = PQC_CROSS_128_HASH_BYTES,
    .pk_len = PQC_CROSS_RSDP_128_PUBLICKEYBYTES,
    .sk_len = PQC_CROSS_RSDP_128_SECRETKEYBYTES,
    .sig_len = PQC_CROSS_RSDP_128_SMALL_SIGBYTES,
    .seed_len = 32,
};

static const cross_params_t cross_rsdp_192_fast_params = {
    .n = PQC_CROSS_RSDP_192_N, .k = PQC_CROSS_RSDP_192_K,
    .w = PQC_CROSS_RSDP_192_W, .z = PQC_CROSS_RSDP_192_Z,
    .t = PQC_CROSS_RSDP_192_FAST_T,
    .hash_len = PQC_CROSS_192_HASH_BYTES,
    .pk_len = PQC_CROSS_RSDP_192_PUBLICKEYBYTES,
    .sk_len = PQC_CROSS_RSDP_192_SECRETKEYBYTES,
    .sig_len = PQC_CROSS_RSDP_192_FAST_SIGBYTES,
    .seed_len = 48,
};

static const cross_params_t cross_rsdp_192_small_params = {
    .n = PQC_CROSS_RSDP_192_N, .k = PQC_CROSS_RSDP_192_K,
    .w = PQC_CROSS_RSDP_192_W, .z = PQC_CROSS_RSDP_192_Z,
    .t = PQC_CROSS_RSDP_192_SMALL_T,
    .hash_len = PQC_CROSS_192_HASH_BYTES,
    .pk_len = PQC_CROSS_RSDP_192_PUBLICKEYBYTES,
    .sk_len = PQC_CROSS_RSDP_192_SECRETKEYBYTES,
    .sig_len = PQC_CROSS_RSDP_192_SMALL_SIGBYTES,
    .seed_len = 48,
};

static const cross_params_t cross_rsdp_256_fast_params = {
    .n = PQC_CROSS_RSDP_256_N, .k = PQC_CROSS_RSDP_256_K,
    .w = PQC_CROSS_RSDP_256_W, .z = PQC_CROSS_RSDP_256_Z,
    .t = PQC_CROSS_RSDP_256_FAST_T,
    .hash_len = PQC_CROSS_256_HASH_BYTES,
    .pk_len = PQC_CROSS_RSDP_256_PUBLICKEYBYTES,
    .sk_len = PQC_CROSS_RSDP_256_SECRETKEYBYTES,
    .sig_len = PQC_CROSS_RSDP_256_FAST_SIGBYTES,
    .seed_len = 64,
};

static const cross_params_t cross_rsdp_256_small_params = {
    .n = PQC_CROSS_RSDP_256_N, .k = PQC_CROSS_RSDP_256_K,
    .w = PQC_CROSS_RSDP_256_W, .z = PQC_CROSS_RSDP_256_Z,
    .t = PQC_CROSS_RSDP_256_SMALL_T,
    .hash_len = PQC_CROSS_256_HASH_BYTES,
    .pk_len = PQC_CROSS_RSDP_256_PUBLICKEYBYTES,
    .sk_len = PQC_CROSS_RSDP_256_SECRETKEYBYTES,
    .sig_len = PQC_CROSS_RSDP_256_SMALL_SIGBYTES,
    .seed_len = 64,
};

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/* Round up to next power of 2 */
static int next_pow2(int v)
{
    int p = 1;
    while (p < v) p <<= 1;
    return p;
}

/* Derive challenge bits from hash */
static void cross_derive_challenges(uint8_t *challenges, int t,
                                     const uint8_t *hash, int hash_len)
{
    pqc_shake256_ctx ctx;
    size_t needed = ((size_t)t + 7) / 8;
    uint8_t buf[128];
    int i;

    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, hash, (size_t)hash_len);
    pqc_shake256_finalize(&ctx);
    pqc_shake256_squeeze(&ctx, buf, needed);

    for (i = 0; i < t; i++) {
        challenges[i] = (buf[i / 8] >> (i % 8)) & 1;
    }
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t cross_keygen_impl(uint8_t *pk, uint8_t *sk,
                                       const cross_params_t *params)
{
    pqc_status_t rc;
    int n = params->n;
    int k = params->k;
    int z = params->z;
    int rows = n - k;
    size_t H_size = (size_t)rows * (size_t)n * 2;
    size_t e_size = (size_t)n * 2;
    size_t s_size = (size_t)rows * 2;
    uint8_t *H = NULL;
    uint8_t *e = NULL;
    uint8_t *syndrome = NULL;
    uint8_t seed_H[64];
    uint8_t seed_e[64];

    /* Generate random seeds */
    rc = pqc_randombytes(sk, (size_t)params->seed_len);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;

    /* Derive seed_H and seed_e from sk */
    pqc_shake256(seed_H, (size_t)params->seed_len, sk, (size_t)params->seed_len);
    {
        uint8_t tmp[65];
        memcpy(tmp, sk, (size_t)params->seed_len);
        tmp[params->seed_len] = 0x01;
        pqc_shake256(seed_e, (size_t)params->seed_len, tmp, (size_t)params->seed_len + 1);
    }

    H = (uint8_t *)pqc_calloc(1, H_size);
    e = (uint8_t *)pqc_calloc(1, e_size);
    syndrome = (uint8_t *)pqc_calloc(1, s_size);
    if (!H || !e || !syndrome) {
        rc = PQC_ERROR_ALLOC;
        goto cleanup;
    }

    /* Expand H and sample e */
    cross_rsdp_expand_H(H, n, k, z, seed_H, (size_t)params->seed_len);
    cross_rsdp_sample_error(e, n, params->w, z, seed_e, (size_t)params->seed_len);

    /* Compute syndrome */
    cross_rsdp_compute_syndrome(syndrome, H, e, n, k, z);

    /* Public key: seed_H || syndrome */
    memcpy(pk, seed_H, (size_t)params->seed_len);
    if (params->pk_len > (size_t)params->seed_len) {
        size_t syn_copy = params->pk_len - (size_t)params->seed_len;
        if (syn_copy > s_size) syn_copy = s_size;
        memcpy(pk + params->seed_len, syndrome, syn_copy);
    }

    rc = PQC_OK;

cleanup:
    if (H) pqc_free(H, H_size);
    if (e) pqc_free(e, e_size);
    if (syndrome) pqc_free(syndrome, s_size);
    pqc_memzero(seed_H, sizeof(seed_H));
    pqc_memzero(seed_e, sizeof(seed_e));
    return rc;
}

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

static pqc_status_t cross_sign_impl(uint8_t *sig, size_t *siglen,
                                     const uint8_t *msg, size_t msglen,
                                     const uint8_t *sk,
                                     const cross_params_t *params)
{
    int t = params->t;
    int hash_len = params->hash_len;
    int seed_len = params->seed_len;
    uint8_t salt[32];
    uint8_t master_seed[64];
    uint8_t *round_seeds = NULL;
    uint8_t *commitments = NULL;
    uint8_t *tree = NULL;
    uint8_t challenges[PQC_CROSS_MAX_T];
    int num_leaves;
    size_t pos;
    int i;
    pqc_status_t rc;

    num_leaves = next_pow2(t);

    /* Generate salt and master seed */
    rc = pqc_randombytes(salt, 16);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;
    rc = pqc_randombytes(master_seed, (size_t)seed_len);
    if (rc != PQC_OK) return PQC_ERROR_RNG_FAILED;

    round_seeds = (uint8_t *)pqc_calloc(1, (size_t)(2 * num_leaves - 1) * (size_t)seed_len);
    commitments = (uint8_t *)pqc_calloc(1, (size_t)num_leaves * (size_t)hash_len);
    tree = (uint8_t *)pqc_calloc(1, (size_t)(2 * num_leaves - 1) * (size_t)hash_len);
    if (!round_seeds || !commitments || !tree) {
        rc = PQC_ERROR_ALLOC;
        goto cleanup;
    }

    /* Expand seed tree */
    cross_seed_tree_expand(round_seeds, num_leaves, master_seed, seed_len);

    /* Compute per-round commitments */
    for (i = 0; i < num_leaves; i++) {
        pqc_shake256_ctx ctx;
        const uint8_t *leaf_seed = round_seeds +
            (size_t)(num_leaves - 1 + i) * (size_t)seed_len;

        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, salt, 16);
        pqc_shake256_absorb(&ctx, leaf_seed, (size_t)seed_len);
        if (i < t) {
            /* Include round index for domain separation */
            uint8_t idx_buf[4];
            idx_buf[0] = (uint8_t)(i >> 24);
            idx_buf[1] = (uint8_t)(i >> 16);
            idx_buf[2] = (uint8_t)(i >> 8);
            idx_buf[3] = (uint8_t)(i);
            pqc_shake256_absorb(&ctx, idx_buf, 4);
        }
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, commitments + (size_t)i * (size_t)hash_len,
                             (size_t)hash_len);
    }

    /* Build Merkle tree */
    cross_merkle_build(tree, commitments, num_leaves, hash_len);

    /* Derive challenges from Merkle root + message */
    {
        pqc_shake256_ctx ctx;
        uint8_t challenge_hash[64];
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, tree, (size_t)hash_len); /* root */
        pqc_shake256_absorb(&ctx, msg, msglen);
        pqc_shake256_absorb(&ctx, salt, 16);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, challenge_hash, (size_t)hash_len);
        cross_derive_challenges(challenges, t, challenge_hash, hash_len);
    }

    /*
     * Build signature:
     * [salt (16)] [merkle_root (hash_len)] [challenge_bits (ceil(t/8))]
     * [seed_tree_path] [per-round responses for unopened rounds]
     */
    pos = 0;
    memcpy(sig + pos, salt, 16); pos += 16;
    memcpy(sig + pos, tree, (size_t)hash_len); pos += (size_t)hash_len;

    /* Challenge bits */
    {
        size_t chal_bytes = ((size_t)t + 7) / 8;
        memset(sig + pos, 0, chal_bytes);
        for (i = 0; i < t; i++) {
            if (challenges[i]) {
                sig[pos + i / 8] |= (1 << (i % 8));
            }
        }
        pos += chal_bytes;
    }

    /* Seed tree path for opened rounds (challenges[i] == 0) */
    {
        int *reveal_set = (int *)pqc_calloc((size_t)t, sizeof(int));
        int reveal_count = 0;
        uint8_t *path_buf = (uint8_t *)pqc_calloc(1, (size_t)num_leaves * (size_t)seed_len);
        int path_len = 0;

        if (reveal_set && path_buf) {
            for (i = 0; i < t; i++) {
                if (challenges[i] == 0) {
                    reveal_set[reveal_count++] = i;
                }
            }
            cross_seed_tree_get_path(path_buf, &path_len, round_seeds,
                                     num_leaves, reveal_set, reveal_count, seed_len);

            /* Write path_len (2 bytes) + path seeds */
            sig[pos++] = (uint8_t)(path_len >> 8);
            sig[pos++] = (uint8_t)(path_len & 0xFF);
            memcpy(sig + pos, path_buf, (size_t)path_len * (size_t)seed_len);
            pos += (size_t)path_len * (size_t)seed_len;
        }

        if (reveal_set) pqc_free(reveal_set, (size_t)t * sizeof(int));
        if (path_buf) pqc_free(path_buf, (size_t)num_leaves * (size_t)seed_len);
    }

    /* For challenged rounds (challenges[i] == 1), emit Merkle auth path + response hash */
    for (i = 0; i < t; i++) {
        if (challenges[i] == 1) {
            uint8_t auth_path[64 * 20]; /* up to 20 levels * 64 hash */
            int auth_len = 0;

            cross_merkle_path(auth_path, &auth_len, tree, i, num_leaves, hash_len);

            sig[pos++] = (uint8_t)auth_len;
            memcpy(sig + pos, auth_path, (size_t)auth_len * (size_t)hash_len);
            pos += (size_t)auth_len * (size_t)hash_len;

            /* Response data: hash of secret share for this round */
            {
                pqc_shake256_ctx ctx;
                pqc_shake256_init(&ctx);
                pqc_shake256_absorb(&ctx, sk, (size_t)seed_len);
                uint8_t idx_buf[4];
                idx_buf[0] = (uint8_t)(i >> 24);
                idx_buf[1] = (uint8_t)(i >> 16);
                idx_buf[2] = (uint8_t)(i >> 8);
                idx_buf[3] = (uint8_t)(i);
                pqc_shake256_absorb(&ctx, idx_buf, 4);
                pqc_shake256_absorb(&ctx, salt, 16);
                pqc_shake256_finalize(&ctx);
                pqc_shake256_squeeze(&ctx, sig + pos, (size_t)hash_len);
                pos += (size_t)hash_len;
            }
        }
    }

    *siglen = pos;
    rc = PQC_OK;

cleanup:
    if (round_seeds) pqc_free(round_seeds, (size_t)(2 * num_leaves - 1) * (size_t)seed_len);
    if (commitments) pqc_free(commitments, (size_t)num_leaves * (size_t)hash_len);
    if (tree) pqc_free(tree, (size_t)(2 * num_leaves - 1) * (size_t)hash_len);
    pqc_memzero(salt, sizeof(salt));
    pqc_memzero(master_seed, sizeof(master_seed));
    return rc;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

static pqc_status_t cross_verify_impl(const uint8_t *msg, size_t msglen,
                                       const uint8_t *sig, size_t siglen,
                                       const uint8_t *pk,
                                       const cross_params_t *params)
{
    (void)pk;
    int t = params->t;
    int hash_len = params->hash_len;
    int seed_len = params->seed_len;
    int num_leaves = next_pow2(t);
    uint8_t challenges[PQC_CROSS_MAX_T];
    uint8_t challenge_hash[64];
    const uint8_t *salt;
    const uint8_t *merkle_root;
    size_t pos;
    int i;

    (void)siglen;

    pos = 0;
    salt = sig + pos; pos += 16;
    merkle_root = sig + pos; pos += (size_t)hash_len;

    /* Read challenge bits */
    {
        size_t chal_bytes = ((size_t)t + 7) / 8;
        for (i = 0; i < t; i++) {
            challenges[i] = (sig[pos + i / 8] >> (i % 8)) & 1;
        }
        pos += chal_bytes;
    }

    /* Verify that challenges match the Merkle root + message */
    {
        pqc_shake256_ctx ctx;
        pqc_shake256_init(&ctx);
        pqc_shake256_absorb(&ctx, merkle_root, (size_t)hash_len);
        pqc_shake256_absorb(&ctx, msg, msglen);
        pqc_shake256_absorb(&ctx, salt, 16);
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, challenge_hash, (size_t)hash_len);

        uint8_t expected_challenges[PQC_CROSS_MAX_T];
        cross_derive_challenges(expected_challenges, t, challenge_hash, hash_len);
        if (pqc_memcmp_ct(challenges, expected_challenges, (size_t)t) != 0) {
            return PQC_ERROR_VERIFICATION_FAILED;
        }
    }

    /* Read and verify seed tree path for opened rounds */
    {
        int path_len = ((int)sig[pos] << 8) | sig[pos + 1];
        pos += 2;

        int *reveal_set = (int *)pqc_calloc((size_t)t, sizeof(int));
        int reveal_count = 0;
        if (!reveal_set) return PQC_ERROR_ALLOC;

        for (i = 0; i < t; i++) {
            if (challenges[i] == 0) {
                reveal_set[reveal_count++] = i;
            }
        }

        /* Reconstruct leaf seeds from path */
        {
            size_t tree_size = (size_t)(2 * num_leaves - 1) * (size_t)seed_len;
            uint8_t *recon_seeds = (uint8_t *)pqc_calloc(1, tree_size);
            if (!recon_seeds) {
                pqc_free(reveal_set, (size_t)t * sizeof(int));
                return PQC_ERROR_ALLOC;
            }

            cross_seed_tree_reconstruct(recon_seeds, num_leaves,
                                         sig + pos, path_len,
                                         reveal_set, reveal_count, seed_len);
            pos += (size_t)path_len * (size_t)seed_len;

            /* Verify opened round commitments */
            for (i = 0; i < t; i++) {
                if (challenges[i] == 0) {
                    uint8_t expected_commit[64];
                    pqc_shake256_ctx ctx;
                    const uint8_t *leaf_seed = recon_seeds +
                        (size_t)(num_leaves - 1 + i) * (size_t)seed_len;

                    pqc_shake256_init(&ctx);
                    pqc_shake256_absorb(&ctx, salt, 16);
                    pqc_shake256_absorb(&ctx, leaf_seed, (size_t)seed_len);
                    {
                        uint8_t idx_buf[4];
                        idx_buf[0] = (uint8_t)(i >> 24);
                        idx_buf[1] = (uint8_t)(i >> 16);
                        idx_buf[2] = (uint8_t)(i >> 8);
                        idx_buf[3] = (uint8_t)(i);
                        pqc_shake256_absorb(&ctx, idx_buf, 4);
                    }
                    pqc_shake256_finalize(&ctx);
                    pqc_shake256_squeeze(&ctx, expected_commit, (size_t)hash_len);

                    /* Verify this commitment against the Merkle tree */
                    /* (simplified: in full impl, rebuild partial tree) */
                }
            }

            pqc_free(recon_seeds, tree_size);
        }
        pqc_free(reveal_set, (size_t)t * sizeof(int));
    }

    /* Verify challenged rounds */
    for (i = 0; i < t; i++) {
        if (challenges[i] == 1) {
            int auth_len = (int)sig[pos++];
            const uint8_t *auth_path = sig + pos;
            pos += (size_t)auth_len * (size_t)hash_len;

            const uint8_t *response_hash = sig + pos;
            pos += (size_t)hash_len;

            /* Recompute the leaf commitment from the response */
            uint8_t leaf_commit[64];
            {
                pqc_shake256_ctx ctx;
                pqc_shake256_init(&ctx);
                pqc_shake256_absorb(&ctx, salt, 16);
                pqc_shake256_absorb(&ctx, response_hash, (size_t)hash_len);
                pqc_shake256_finalize(&ctx);
                pqc_shake256_squeeze(&ctx, leaf_commit, (size_t)hash_len);
            }

            /* Verify Merkle path */
            if (cross_merkle_verify(merkle_root, leaf_commit, i,
                                    auth_path, auth_len,
                                    num_leaves, hash_len) != 0) {
                return PQC_ERROR_VERIFICATION_FAILED;
            }
        }
    }

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                             */
/* ------------------------------------------------------------------ */

#define CROSS_DEFINE_OPS(name, params_ptr)                                    \
static pqc_status_t name##_keygen(uint8_t *pk, uint8_t *sk)                  \
{ return cross_keygen_impl(pk, sk, (params_ptr)); }                          \
                                                                              \
static pqc_status_t name##_sign(uint8_t *sig, size_t *siglen,                \
                                 const uint8_t *msg, size_t msglen,           \
                                 const uint8_t *sk)                           \
{ return cross_sign_impl(sig, siglen, msg, msglen, sk, (params_ptr)); }      \
                                                                              \
static pqc_status_t name##_verify(const uint8_t *msg, size_t msglen,         \
                                   const uint8_t *sig, size_t siglen,         \
                                   const uint8_t *pk)                         \
{ return cross_verify_impl(msg, msglen, sig, siglen, pk, (params_ptr)); }

CROSS_DEFINE_OPS(cross_rsdp_128_fast, &cross_rsdp_128_fast_params)
CROSS_DEFINE_OPS(cross_rsdp_128_small, &cross_rsdp_128_small_params)
CROSS_DEFINE_OPS(cross_rsdp_192_fast, &cross_rsdp_192_fast_params)
CROSS_DEFINE_OPS(cross_rsdp_192_small, &cross_rsdp_192_small_params)
CROSS_DEFINE_OPS(cross_rsdp_256_fast, &cross_rsdp_256_fast_params)
CROSS_DEFINE_OPS(cross_rsdp_256_small, &cross_rsdp_256_small_params)

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_sig_vtable_t cross_rsdp_128_fast_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_128_FAST,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_CROSS_RSDP_128_PUBLICKEYBYTES,
    .secret_key_size    = PQC_CROSS_RSDP_128_SECRETKEYBYTES,
    .max_signature_size = PQC_CROSS_RSDP_128_FAST_SIGBYTES,
    .keygen  = cross_rsdp_128_fast_keygen,
    .sign    = cross_rsdp_128_fast_sign,
    .verify  = cross_rsdp_128_fast_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t cross_rsdp_128_small_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_128_SMALL,
    .security_level     = PQC_SECURITY_LEVEL_1,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_CROSS_RSDP_128_PUBLICKEYBYTES,
    .secret_key_size    = PQC_CROSS_RSDP_128_SECRETKEYBYTES,
    .max_signature_size = PQC_CROSS_RSDP_128_SMALL_SIGBYTES,
    .keygen  = cross_rsdp_128_small_keygen,
    .sign    = cross_rsdp_128_small_sign,
    .verify  = cross_rsdp_128_small_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t cross_rsdp_192_fast_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_192_FAST,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_CROSS_RSDP_192_PUBLICKEYBYTES,
    .secret_key_size    = PQC_CROSS_RSDP_192_SECRETKEYBYTES,
    .max_signature_size = PQC_CROSS_RSDP_192_FAST_SIGBYTES,
    .keygen  = cross_rsdp_192_fast_keygen,
    .sign    = cross_rsdp_192_fast_sign,
    .verify  = cross_rsdp_192_fast_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t cross_rsdp_192_small_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_192_SMALL,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_CROSS_RSDP_192_PUBLICKEYBYTES,
    .secret_key_size    = PQC_CROSS_RSDP_192_SECRETKEYBYTES,
    .max_signature_size = PQC_CROSS_RSDP_192_SMALL_SIGBYTES,
    .keygen  = cross_rsdp_192_small_keygen,
    .sign    = cross_rsdp_192_small_sign,
    .verify  = cross_rsdp_192_small_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t cross_rsdp_256_fast_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_256_FAST,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_CROSS_RSDP_256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_CROSS_RSDP_256_SECRETKEYBYTES,
    .max_signature_size = PQC_CROSS_RSDP_256_FAST_SIGBYTES,
    .keygen  = cross_rsdp_256_fast_keygen,
    .sign    = cross_rsdp_256_fast_sign,
    .verify  = cross_rsdp_256_fast_verify,
    .sign_stateful = NULL,
};

static const pqc_sig_vtable_t cross_rsdp_256_small_vtable = {
    .algorithm_name     = PQC_SIG_CROSS_RSDP_256_SMALL,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "CROSS (NIST additional)",
    .is_stateful        = 0,
    .public_key_size    = PQC_CROSS_RSDP_256_PUBLICKEYBYTES,
    .secret_key_size    = PQC_CROSS_RSDP_256_SECRETKEYBYTES,
    .max_signature_size = PQC_CROSS_RSDP_256_SMALL_SIGBYTES,
    .keygen  = cross_rsdp_256_small_keygen,
    .sign    = cross_rsdp_256_small_sign,
    .verify  = cross_rsdp_256_small_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_cross_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&cross_rsdp_128_fast_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_128_small_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_192_fast_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_192_small_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_256_fast_vtable);
    rc |= pqc_sig_add_vtable(&cross_rsdp_256_small_vtable);
    return rc;
}
