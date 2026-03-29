/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SLH-DSA (FIPS 205) - Main implementation.
 *
 * Stateless hash-based digital signature scheme.  Implements all 12
 * FIPS 205 parameter sets (SHA2 and SHAKE, at 128/192/256-bit security,
 * small and fast variants).
 */

#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/sig/sig_internal.h"
#include "slhdsa.h"

/* ------------------------------------------------------------------ */
/* Hash dispatch functions                                              */
/*                                                                      */
/* Select SHA-2 or SHAKE based on the params hash_id field.             */
/* ------------------------------------------------------------------ */

void slhdsa_thash(uint8_t *out,
                   const uint8_t *in, uint32_t inblocks,
                   const uint8_t *pub_seed,
                   const uint8_t addr[32],
                   const slhdsa_params_t *p)
{
    if (p->hash_id == SLHDSA_HASH_SHA2)
        slhdsa_thash_sha2(out, in, inblocks, pub_seed, addr, p);
    else
        slhdsa_thash_shake(out, in, inblocks, pub_seed, addr, p);
}

void slhdsa_prf(uint8_t *out,
                 const uint8_t *sk_seed,
                 const uint8_t *pub_seed,
                 const uint8_t addr[32],
                 const slhdsa_params_t *p)
{
    if (p->hash_id == SLHDSA_HASH_SHA2)
        slhdsa_prf_sha2(out, sk_seed, pub_seed, addr, p);
    else
        slhdsa_prf_shake(out, sk_seed, pub_seed, addr, p);
}

void slhdsa_prf_msg(uint8_t *out,
                     const uint8_t *sk_prf,
                     const uint8_t *opt_rand,
                     const uint8_t *msg, size_t msglen,
                     const slhdsa_params_t *p)
{
    if (p->hash_id == SLHDSA_HASH_SHA2)
        slhdsa_prf_msg_sha2(out, sk_prf, opt_rand, msg, msglen, p);
    else
        slhdsa_prf_msg_shake(out, sk_prf, opt_rand, msg, msglen, p);
}

void slhdsa_hash_msg(uint8_t *out,
                      const uint8_t *r,
                      const uint8_t *pk,
                      const uint8_t *msg, size_t msglen,
                      const slhdsa_params_t *p)
{
    if (p->hash_id == SLHDSA_HASH_SHA2)
        slhdsa_hash_msg_sha2(out, r, pk, msg, msglen, p);
    else
        slhdsa_hash_msg_shake(out, r, pk, msg, msglen, p);
}

/* ------------------------------------------------------------------ */
/* Message digest splitting                                             */
/*                                                                      */
/* Split the H_msg output into:                                         */
/*   md:       first ceil(k*a / 8) bytes  (FORS message digest)         */
/*   idx_tree: next bits for tree index   (h - hp bits)                 */
/*   idx_leaf: next bits for leaf index   (hp bits)                     */
/* ------------------------------------------------------------------ */

static void split_digest(const uint8_t *digest,
                          const slhdsa_params_t *p,
                          uint8_t *md,
                          uint64_t *idx_tree,
                          uint32_t *idx_leaf)
{
    uint32_t ka_bytes = ((uint32_t)p->k * p->a + 7) / 8;
    uint32_t tree_bits = p->h - p->hp;
    uint32_t leaf_bits = p->hp;
    uint32_t tree_bytes = (tree_bits + 7) / 8;
    uint32_t leaf_bytes = (leaf_bits + 7) / 8;
    const uint8_t *ptr;
    uint64_t tv = 0;
    uint32_t lv = 0;
    uint32_t i;

    /* Copy FORS message digest */
    memcpy(md, digest, ka_bytes);

    /* Extract tree index */
    ptr = digest + ka_bytes;
    for (i = 0; i < tree_bytes; i++) {
        tv = (tv << 8) | ptr[i];
    }
    /* Mask to tree_bits */
    if (tree_bits < 64)
        tv &= ((uint64_t)1 << tree_bits) - 1;
    *idx_tree = tv;

    /* Extract leaf index */
    ptr = digest + ka_bytes + tree_bytes;
    for (i = 0; i < leaf_bytes; i++) {
        lv = (lv << 8) | ptr[i];
    }
    if (leaf_bits < 32)
        lv &= ((uint32_t)1 << leaf_bits) - 1;
    *idx_leaf = lv;
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/*                                                                      */
/* SK = (SK.seed || SK.prf || PK.seed || PK.root)                       */
/* PK = (PK.seed || PK.root)                                           */
/*                                                                      */
/* SK.seed, SK.prf, PK.seed are random n-byte values.                   */
/* PK.root is the top-level hypertree root.                             */
/* ------------------------------------------------------------------ */

int pqc_slhdsa_keygen(uint8_t *pk, uint8_t *sk,
                       const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    uint8_t *sk_seed  = sk;
    /* sk_prf at sk+n is set by randombytes but not used directly here */
    uint8_t *pk_seed  = sk + 2 * n;
    uint8_t *pk_root  = sk + 3 * n;
    uint8_t addr[32];

    /* Generate random seeds */
    if (pqc_randombytes(sk, 3 * n) != PQC_OK)
        return (int)PQC_ERROR_RNG_FAILED;

    /* Compute PK.root: root of the top-level XMSS tree at layer d-1 */
    memset(addr, 0, 32);
    slhdsa_set_layer_addr(addr, p->d - 1);
    slhdsa_set_tree_addr(addr, 0);

    slhdsa_xmss_root(pk_root, sk_seed, pk_seed, addr, p);

    /* PK = PK.seed || PK.root */
    memcpy(pk, pk_seed, n);
    memcpy(pk + n, pk_root, n);

    return (int)PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/*                                                                      */
/* 1. Generate randomizer R = PRF_msg(SK.prf, opt_rand, M)             */
/* 2. Compute message digest = H_msg(R, PK, M)                         */
/* 3. Split digest into (md, idx_tree, idx_leaf)                        */
/* 4. FORS sign md                                                      */
/* 5. Hypertree sign the FORS public key                                */
/*                                                                      */
/* Signature = R || FORS_SIG || HT_SIG                                  */
/* ------------------------------------------------------------------ */

int pqc_slhdsa_sign(uint8_t *sig, size_t *siglen,
                     const uint8_t *msg, size_t msglen,
                     const uint8_t *sk,
                     const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    const uint8_t *sk_seed = sk;
    const uint8_t *sk_prf  = sk + n;
    const uint8_t *pk_seed = sk + 2 * n;
    const uint8_t *pk_root = sk + 3 * n;
    uint8_t pk[2 * SLHDSA_MAX_N];
    uint8_t opt_rand[SLHDSA_MAX_N];
    uint8_t digest[128]; /* enough for any parameter set */
    uint8_t md[128];
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint8_t addr[32];
    uint8_t fors_pk[SLHDSA_MAX_N];
    uint8_t *sig_ptr = sig;

    /* Construct PK for hashing */
    memcpy(pk, pk_seed, n);
    memcpy(pk + n, pk_root, n);

    /* Generate randomizer.  Use random opt_rand for hedged signing. */
    if (pqc_randombytes(opt_rand, n) != PQC_OK)
        return (int)PQC_ERROR_RNG_FAILED;

    /* R = PRF_msg(SK.prf, opt_rand, M) */
    slhdsa_prf_msg(sig_ptr, sk_prf, opt_rand, msg, msglen, p);
    /* sig_ptr[0..n-1] is now R */

    /* Compute message digest.
     * Zero the buffer first: split_digest may read more bytes than
     * hash_msg writes (ka_bytes + tree_bytes + leaf_bytes can exceed
     * ceil((k*a + h)/8) due to byte-boundary rounding). */
    memset(digest, 0, sizeof(digest));
    slhdsa_hash_msg(digest, sig_ptr, pk, msg, msglen, p);

    sig_ptr += n; /* advance past R */

    /* Split digest */
    split_digest(digest, p, md, &idx_tree, &idx_leaf);

    /* FORS sign */
    memset(addr, 0, 32);
    slhdsa_set_layer_addr(addr, 0);
    slhdsa_set_tree_addr(addr, idx_tree);
    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_FORSTREE);
    slhdsa_set_keypair_addr(addr, idx_leaf);

    slhdsa_fors_sign(sig_ptr, md, sk_seed, pk_seed, addr, p);

    /* Compute FORS public key for hypertree signing */
    slhdsa_fors_pk_from_sig(fors_pk, sig_ptr, md, pk_seed, addr, p);

    sig_ptr += p->fors_sig_bytes;

    /* Hypertree sign the FORS public key */
    slhdsa_ht_sign(sig_ptr, fors_pk, sk_seed, pk_seed,
                    idx_tree, idx_leaf, p);

    *siglen = p->sig_bytes;
    return (int)PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/*                                                                      */
/* 1. Extract R from signature                                          */
/* 2. Compute message digest = H_msg(R, PK, M)                         */
/* 3. Split digest into (md, idx_tree, idx_leaf)                        */
/* 4. Recover FORS public key from FORS signature                       */
/* 5. Verify hypertree signature on FORS public key                     */
/* ------------------------------------------------------------------ */

int pqc_slhdsa_verify(const uint8_t *msg, size_t msglen,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *pk,
                       const slhdsa_params_t *p)
{
    uint32_t n = p->n;
    const uint8_t *pk_seed = pk;
    const uint8_t *pk_root = pk + n;
    const uint8_t *r;
    const uint8_t *fors_sig;
    const uint8_t *ht_sig;
    uint8_t digest[128];
    uint8_t md[128];
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint8_t addr[32];
    uint8_t fors_pk[SLHDSA_MAX_N];

    if (siglen != p->sig_bytes)
        return (int)PQC_ERROR_VERIFICATION_FAILED;

    /* Parse signature */
    r = sig;
    fors_sig = sig + n;
    ht_sig = sig + n + p->fors_sig_bytes;

    /* Compute message digest.
     * Zero the buffer first: split_digest may read more bytes than
     * hash_msg writes (ka_bytes + tree_bytes + leaf_bytes can exceed
     * ceil((k*a + h)/8) due to byte-boundary rounding). */
    memset(digest, 0, sizeof(digest));
    slhdsa_hash_msg(digest, r, pk, msg, msglen, p);

    /* Split digest */
    split_digest(digest, p, md, &idx_tree, &idx_leaf);

    /* Recover FORS public key */
    memset(addr, 0, 32);
    slhdsa_set_layer_addr(addr, 0);
    slhdsa_set_tree_addr(addr, idx_tree);
    slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_FORSTREE);
    slhdsa_set_keypair_addr(addr, idx_leaf);

    slhdsa_fors_pk_from_sig(fors_pk, fors_sig, md, pk_seed, addr, p);

    /* Verify hypertree signature */
    if (slhdsa_ht_verify(fors_pk, ht_sig, pk_seed,
                          idx_tree, idx_leaf, pk_root, p) != 0) {
        return (int)PQC_ERROR_VERIFICATION_FAILED;
    }

    return (int)PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Vtable wrapper functions                                             */
/*                                                                      */
/* Each parameter set gets keygen/sign/verify wrappers that call the    */
/* generic implementation with the appropriate params struct.           */
/* ------------------------------------------------------------------ */

#define DEFINE_SLHDSA_VTABLE_OPS(suffix, params_ptr)                     \
                                                                         \
static pqc_status_t slhdsa_##suffix##_keygen(uint8_t *pk, uint8_t *sk)   \
{                                                                        \
    return (pqc_status_t)pqc_slhdsa_keygen(pk, sk, params_ptr);          \
}                                                                        \
                                                                         \
static pqc_status_t slhdsa_##suffix##_sign(                              \
        uint8_t *sig, size_t *siglen,                                    \
        const uint8_t *msg, size_t msglen,                               \
        const uint8_t *sk)                                               \
{                                                                        \
    return (pqc_status_t)pqc_slhdsa_sign(sig, siglen, msg, msglen,       \
                                          sk, params_ptr);               \
}                                                                        \
                                                                         \
static pqc_status_t slhdsa_##suffix##_verify(                            \
        const uint8_t *msg, size_t msglen,                               \
        const uint8_t *sig, size_t siglen,                               \
        const uint8_t *pk)                                               \
{                                                                        \
    return (pqc_status_t)pqc_slhdsa_verify(msg, msglen, sig, siglen,     \
                                            pk, params_ptr);             \
}

DEFINE_SLHDSA_VTABLE_OPS(sha2_128s,  &SLHDSA_SHA2_128S)
DEFINE_SLHDSA_VTABLE_OPS(sha2_128f,  &SLHDSA_SHA2_128F)
DEFINE_SLHDSA_VTABLE_OPS(sha2_192s,  &SLHDSA_SHA2_192S)
DEFINE_SLHDSA_VTABLE_OPS(sha2_192f,  &SLHDSA_SHA2_192F)
DEFINE_SLHDSA_VTABLE_OPS(sha2_256s,  &SLHDSA_SHA2_256S)
DEFINE_SLHDSA_VTABLE_OPS(sha2_256f,  &SLHDSA_SHA2_256F)
DEFINE_SLHDSA_VTABLE_OPS(shake_128s, &SLHDSA_SHAKE_128S)
DEFINE_SLHDSA_VTABLE_OPS(shake_128f, &SLHDSA_SHAKE_128F)
DEFINE_SLHDSA_VTABLE_OPS(shake_192s, &SLHDSA_SHAKE_192S)
DEFINE_SLHDSA_VTABLE_OPS(shake_192f, &SLHDSA_SHAKE_192F)
DEFINE_SLHDSA_VTABLE_OPS(shake_256s, &SLHDSA_SHAKE_256S)
DEFINE_SLHDSA_VTABLE_OPS(shake_256f, &SLHDSA_SHAKE_256F)

/* ------------------------------------------------------------------ */
/* Vtables — 12 SLH-DSA parameter sets (FIPS 205)                      */
/* ------------------------------------------------------------------ */

#define SLHDSA_VTABLE(suffix, alg_name, level, pk_sz, sk_sz, sig_sz) \
static const pqc_sig_vtable_t slhdsa_##suffix##_vtable = {           \
    .algorithm_name     = alg_name,                                  \
    .security_level     = level,                                     \
    .nist_standard      = "FIPS 205",                                \
    .is_stateful        = 0,                                         \
    .public_key_size    = pk_sz,                                     \
    .secret_key_size    = sk_sz,                                     \
    .max_signature_size = sig_sz,                                    \
    .keygen  = slhdsa_##suffix##_keygen,                             \
    .sign    = slhdsa_##suffix##_sign,                               \
    .verify  = slhdsa_##suffix##_verify,                             \
    .sign_stateful = NULL,                                           \
}

/* SHA2 variants */
SLHDSA_VTABLE(sha2_128s,  PQC_SIG_SLH_DSA_SHA2_128S,
              PQC_SECURITY_LEVEL_1, 32, 64, 7856);
SLHDSA_VTABLE(sha2_128f,  PQC_SIG_SLH_DSA_SHA2_128F,
              PQC_SECURITY_LEVEL_1, 32, 64, 17088);
SLHDSA_VTABLE(sha2_192s,  PQC_SIG_SLH_DSA_SHA2_192S,
              PQC_SECURITY_LEVEL_3, 48, 96, 16224);
SLHDSA_VTABLE(sha2_192f,  PQC_SIG_SLH_DSA_SHA2_192F,
              PQC_SECURITY_LEVEL_3, 48, 96, 35664);
SLHDSA_VTABLE(sha2_256s,  PQC_SIG_SLH_DSA_SHA2_256S,
              PQC_SECURITY_LEVEL_5, 64, 128, 29792);
SLHDSA_VTABLE(sha2_256f,  PQC_SIG_SLH_DSA_SHA2_256F,
              PQC_SECURITY_LEVEL_5, 64, 128, 49856);

/* SHAKE variants */
SLHDSA_VTABLE(shake_128s, PQC_SIG_SLH_DSA_SHAKE_128S,
              PQC_SECURITY_LEVEL_1, 32, 64, 7856);
SLHDSA_VTABLE(shake_128f, PQC_SIG_SLH_DSA_SHAKE_128F,
              PQC_SECURITY_LEVEL_1, 32, 64, 17088);
SLHDSA_VTABLE(shake_192s, PQC_SIG_SLH_DSA_SHAKE_192S,
              PQC_SECURITY_LEVEL_3, 48, 96, 16224);
SLHDSA_VTABLE(shake_192f, PQC_SIG_SLH_DSA_SHAKE_192F,
              PQC_SECURITY_LEVEL_3, 48, 96, 35664);
SLHDSA_VTABLE(shake_256s, PQC_SIG_SLH_DSA_SHAKE_256S,
              PQC_SECURITY_LEVEL_5, 64, 128, 29792);
SLHDSA_VTABLE(shake_256f, PQC_SIG_SLH_DSA_SHAKE_256F,
              PQC_SECURITY_LEVEL_5, 64, 128, 49856);

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_sig_slhdsa_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_128s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_128f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_192s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_192f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_256s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_sha2_256f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_128s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_128f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_192s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_192f_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_256s_vtable);
    rc |= pqc_sig_add_vtable(&slhdsa_shake_256f_vtable);
    return rc;
}
