/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-KEM (FIPS 203) - Module-Lattice-Based Key-Encapsulation Mechanism.
 *
 * Implements the full IND-CCA2-secure KEM via the Fujisaki-Okamoto
 * transform over the IND-CPA-secure K-PKE scheme:
 *
 *   ML-KEM.KeyGen_internal  (Algorithm 16)
 *   ML-KEM.Encaps_internal  (Algorithm 17)
 *   ML-KEM.Decaps_internal  (Algorithm 18)
 *
 * Hash functions used (FIPS 203 notation):
 *   H  = SHA3-256
 *   G  = SHA3-512
 *   J  = SHAKE-256
 */

#include <string.h>

#include "core/kem/mlkem/mlkem.h"
#include "core/kem/mlkem/indcpa.h"
#include "core/kem/mlkem/verify.h"
#include "core/common/hash/sha3.h"
#include "pqc/rand.h"

/* ================================================================= */
/*  Pre-initialised parameter sets                                     */
/* ================================================================= */

const pqc_mlkem_params_t PQC_MLKEM_512 = {
    .name               = "ML-KEM-512",
    .k                  = PQC_MLKEM512_K,
    .eta1               = PQC_MLKEM512_ETA1,
    .eta2               = PQC_MLKEM512_ETA2,
    .du                 = PQC_MLKEM512_DU,
    .dv                 = PQC_MLKEM512_DV,
    .poly_compressed_du = PQC_MLKEM512_POLYCOMPRESSEDBYTES_DU,
    .poly_compressed_dv = PQC_MLKEM512_POLYCOMPRESSEDBYTES_DV,
    .polyvec_bytes      = PQC_MLKEM512_POLYVECBYTES,
    .polyvec_compressed = PQC_MLKEM512_POLYVECCOMPRESSEDBYTES,
    .indcpa_pk_bytes    = PQC_MLKEM512_INDCPA_PUBLICKEYBYTES,
    .indcpa_sk_bytes    = PQC_MLKEM512_INDCPA_SECRETKEYBYTES,
    .indcpa_bytes       = PQC_MLKEM512_INDCPA_BYTES,
    .pk_bytes           = PQC_MLKEM512_PUBLICKEYBYTES,
    .sk_bytes           = PQC_MLKEM512_SECRETKEYBYTES,
    .ct_bytes           = PQC_MLKEM512_CIPHERTEXTBYTES,
    .ss_bytes           = PQC_MLKEM_SSBYTES,
};

const pqc_mlkem_params_t PQC_MLKEM_768 = {
    .name               = "ML-KEM-768",
    .k                  = PQC_MLKEM768_K,
    .eta1               = PQC_MLKEM768_ETA1,
    .eta2               = PQC_MLKEM768_ETA2,
    .du                 = PQC_MLKEM768_DU,
    .dv                 = PQC_MLKEM768_DV,
    .poly_compressed_du = PQC_MLKEM768_POLYCOMPRESSEDBYTES_DU,
    .poly_compressed_dv = PQC_MLKEM768_POLYCOMPRESSEDBYTES_DV,
    .polyvec_bytes      = PQC_MLKEM768_POLYVECBYTES,
    .polyvec_compressed = PQC_MLKEM768_POLYVECCOMPRESSEDBYTES,
    .indcpa_pk_bytes    = PQC_MLKEM768_INDCPA_PUBLICKEYBYTES,
    .indcpa_sk_bytes    = PQC_MLKEM768_INDCPA_SECRETKEYBYTES,
    .indcpa_bytes       = PQC_MLKEM768_INDCPA_BYTES,
    .pk_bytes           = PQC_MLKEM768_PUBLICKEYBYTES,
    .sk_bytes           = PQC_MLKEM768_SECRETKEYBYTES,
    .ct_bytes           = PQC_MLKEM768_CIPHERTEXTBYTES,
    .ss_bytes           = PQC_MLKEM_SSBYTES,
};

const pqc_mlkem_params_t PQC_MLKEM_1024 = {
    .name               = "ML-KEM-1024",
    .k                  = PQC_MLKEM1024_K,
    .eta1               = PQC_MLKEM1024_ETA1,
    .eta2               = PQC_MLKEM1024_ETA2,
    .du                 = PQC_MLKEM1024_DU,
    .dv                 = PQC_MLKEM1024_DV,
    .poly_compressed_du = PQC_MLKEM1024_POLYCOMPRESSEDBYTES_DU,
    .poly_compressed_dv = PQC_MLKEM1024_POLYCOMPRESSEDBYTES_DV,
    .polyvec_bytes      = PQC_MLKEM1024_POLYVECBYTES,
    .polyvec_compressed = PQC_MLKEM1024_POLYVECCOMPRESSEDBYTES,
    .indcpa_pk_bytes    = PQC_MLKEM1024_INDCPA_PUBLICKEYBYTES,
    .indcpa_sk_bytes    = PQC_MLKEM1024_INDCPA_SECRETKEYBYTES,
    .indcpa_bytes       = PQC_MLKEM1024_INDCPA_BYTES,
    .pk_bytes           = PQC_MLKEM1024_PUBLICKEYBYTES,
    .sk_bytes           = PQC_MLKEM1024_SECRETKEYBYTES,
    .ct_bytes           = PQC_MLKEM1024_CIPHERTEXTBYTES,
    .ss_bytes           = PQC_MLKEM_SSBYTES,
};

/* ================================================================= */
/*  ML-KEM.KeyGen_internal (Algorithm 16)                              */
/* ================================================================= */

/*
 * Input: d (32 bytes) - seed for K-PKE key generation
 *        z (32 bytes) - implicit-rejection seed
 * Output: ek (public key), dk (secret key)
 *
 * Secret key layout:
 *   [0 .. indcpa_sk_bytes)            : K-PKE secret key (s in NTT form)
 *   [indcpa_sk_bytes .. +indcpa_pk)   : K-PKE public key (for re-encryption)
 *   [.. +32)                          : H(pk)
 *   [.. +32)                          : z (implicit rejection seed)
 */
pqc_status_t pqc_mlkem_keygen(const pqc_mlkem_params_t *params,
                               uint8_t *pk,
                               uint8_t *sk)
{
    uint8_t d_z[2 * PQC_MLKEM_SYMBYTES]; /* d || z */
    pqc_status_t rc;

    if (!params || !pk || !sk) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }

    /* Step 1: Generate random seeds d and z */
    rc = pqc_randombytes(d_z, 2 * PQC_MLKEM_SYMBYTES);
    if (rc != PQC_OK) {
        return PQC_ERROR_RNG_FAILED;
    }

    /* Step 2: Pass d to K-PKE.KeyGen via the pk buffer (convention) */
    memcpy(pk, d_z, PQC_MLKEM_SYMBYTES);
    pqc_mlkem_indcpa_keygen(pk, sk, params);

    /* Step 3: Assemble full secret key:
     *   sk = sk_pke || pk || H(pk) || z
     */

    /* Copy pk into sk after the IND-CPA secret key */
    memcpy(sk + params->indcpa_sk_bytes, pk, params->indcpa_pk_bytes);

    /* H(pk) */
    pqc_sha3_256(sk + params->indcpa_sk_bytes + params->indcpa_pk_bytes,
                  pk, params->indcpa_pk_bytes);

    /* z (implicit rejection seed) */
    memcpy(sk + params->indcpa_sk_bytes + params->indcpa_pk_bytes + PQC_MLKEM_SYMBYTES,
           d_z + PQC_MLKEM_SYMBYTES,
           PQC_MLKEM_SYMBYTES);

    return PQC_OK;
}

/* ================================================================= */
/*  ML-KEM.Encaps_internal (Algorithm 17)                              */
/* ================================================================= */

/*
 * Input: ek (public key)
 * Output: (K, c)  where K is shared secret, c is ciphertext
 *
 * Steps:
 *   1. m <-$ {0,1}^256  (random 32 bytes)
 *   2. (K, r) = G(m || H(ek))
 *   3. c = K-PKE.Encrypt(ek, m, r)
 *   4. return (K, c)
 */
pqc_status_t pqc_mlkem_encaps(const pqc_mlkem_params_t *params,
                               uint8_t *ct,
                               uint8_t *ss,
                               const uint8_t *pk)
{
    uint8_t m[PQC_MLKEM_SYMBYTES];
    uint8_t h_pk[PQC_MLKEM_SYMBYTES];
    uint8_t g_input[2 * PQC_MLKEM_SYMBYTES];
    uint8_t g_output[2 * PQC_MLKEM_SYMBYTES]; /* (K, r) */
    pqc_status_t rc;

    if (!params || !ct || !ss || !pk) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }

    /* Step 1: m <-$ B^32 */
    rc = pqc_randombytes(m, PQC_MLKEM_SYMBYTES);
    if (rc != PQC_OK) {
        return PQC_ERROR_RNG_FAILED;
    }

    /* Step 2: H(pk) */
    pqc_sha3_256(h_pk, pk, params->pk_bytes);

    /* Step 3: (K, r) = G(m || H(pk)) */
    memcpy(g_input, m, PQC_MLKEM_SYMBYTES);
    memcpy(g_input + PQC_MLKEM_SYMBYTES, h_pk, PQC_MLKEM_SYMBYTES);
    pqc_sha3_512(g_output, g_input, 2 * PQC_MLKEM_SYMBYTES);

    /* Step 4: c = K-PKE.Encrypt(pk, m, r) */
    pqc_mlkem_indcpa_enc(ct, m, pk, g_output + PQC_MLKEM_SYMBYTES, params);

    /* Step 5: Output shared secret K */
    memcpy(ss, g_output, PQC_MLKEM_SYMBYTES);

    return PQC_OK;
}

/* ================================================================= */
/*  ML-KEM.Decaps_internal (Algorithm 18)                              */
/* ================================================================= */

/*
 * Input: dk (secret key), c (ciphertext)
 * Output: K (shared secret)
 *
 * Fujisaki-Okamoto transform with implicit rejection:
 *   1. m' = K-PKE.Decrypt(sk_pke, c)
 *   2. (K', r') = G(m' || h)      where h = H(pk) stored in dk
 *   3. K_bar = J(z || c)           implicit rejection value
 *   4. c' = K-PKE.Encrypt(pk, m', r')
 *   5. if c == c' then K = K'  else K = K_bar    (constant-time)
 */
pqc_status_t pqc_mlkem_decaps(const pqc_mlkem_params_t *params,
                               uint8_t *ss,
                               const uint8_t *ct,
                               const uint8_t *sk)
{
    uint8_t m_prime[PQC_MLKEM_SYMBYTES];
    uint8_t g_input[2 * PQC_MLKEM_SYMBYTES];
    uint8_t g_output[2 * PQC_MLKEM_SYMBYTES]; /* (K', r') */
    uint8_t ct_cmp[1568]; /* max ciphertext size (ML-KEM-1024) */
    uint8_t k_bar[PQC_MLKEM_SYMBYTES]; /* implicit rejection key */
    int fail;

    const uint8_t *sk_pke = sk;
    const uint8_t *pk     = sk + params->indcpa_sk_bytes;
    const uint8_t *h_pk   = sk + params->indcpa_sk_bytes + params->indcpa_pk_bytes;
    const uint8_t *z      = sk + params->indcpa_sk_bytes + params->indcpa_pk_bytes + PQC_MLKEM_SYMBYTES;

    if (!params || !ss || !ct || !sk) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }

    /* Step 1: m' = K-PKE.Decrypt(sk_pke, c) */
    pqc_mlkem_indcpa_dec(m_prime, ct, sk_pke, params);

    /* Step 2: (K', r') = G(m' || h) */
    memcpy(g_input, m_prime, PQC_MLKEM_SYMBYTES);
    memcpy(g_input + PQC_MLKEM_SYMBYTES, h_pk, PQC_MLKEM_SYMBYTES);
    pqc_sha3_512(g_output, g_input, 2 * PQC_MLKEM_SYMBYTES);

    /* Step 3: c' = K-PKE.Encrypt(pk, m', r') */
    pqc_mlkem_indcpa_enc(ct_cmp, m_prime, pk, g_output + PQC_MLKEM_SYMBYTES, params);

    /* Step 4: Compare c and c' in constant time */
    fail = pqc_mlkem_verify(ct, ct_cmp, params->ct_bytes);

    /* Step 5: K_bar = J(z || c)  -- implicit rejection value */
    {
        pqc_shake256_ctx jctx;
        pqc_shake256_init(&jctx);
        pqc_shake256_absorb(&jctx, z, PQC_MLKEM_SYMBYTES);
        pqc_shake256_absorb(&jctx, ct, params->ct_bytes);
        pqc_shake256_finalize(&jctx);
        pqc_shake256_squeeze(&jctx, k_bar, PQC_MLKEM_SYMBYTES);
    }

    /* Step 6: K = (fail == 0) ? K' : K_bar   (constant-time) */
    memcpy(ss, g_output, PQC_MLKEM_SYMBYTES);
    pqc_mlkem_cmov(ss, k_bar, PQC_MLKEM_SYMBYTES, (uint8_t)(fail & 1));

    return PQC_OK;
}

/* ================================================================= */
/*  Vtable registration for the unified KEM API                        */
/* ================================================================= */

#include "pqc/algorithms.h"
#include "core/kem/kem_internal.h"

#define DEFINE_MLKEM_OPS(SUFFIX, PARAMS, LEVEL)                                \
    static pqc_status_t mlkem_##SUFFIX##_keygen(uint8_t *pk, uint8_t *sk) {    \
        return pqc_mlkem_keygen(&PARAMS, pk, sk);                              \
    }                                                                          \
    static pqc_status_t mlkem_##SUFFIX##_encaps(uint8_t *ct, uint8_t *ss,      \
                                                 const uint8_t *pk) {          \
        return pqc_mlkem_encaps(&PARAMS, ct, ss, pk);                          \
    }                                                                          \
    static pqc_status_t mlkem_##SUFFIX##_decaps(uint8_t *ss,                   \
                                                 const uint8_t *ct,            \
                                                 const uint8_t *sk) {          \
        return pqc_mlkem_decaps(&PARAMS, ss, ct, sk);                          \
    }                                                                          \
    static const pqc_kem_vtable_t mlkem_##SUFFIX##_vtable = {                  \
        .algorithm_name    = PQC_KEM_ML_KEM_##SUFFIX,                          \
        .security_level    = PQC_SECURITY_LEVEL_##LEVEL,                       \
        .nist_standard     = "FIPS 203",                                       \
        .public_key_size   = PQC_MLKEM##SUFFIX##_PUBLICKEYBYTES,               \
        .secret_key_size   = PQC_MLKEM##SUFFIX##_SECRETKEYBYTES,               \
        .ciphertext_size   = PQC_MLKEM##SUFFIX##_CIPHERTEXTBYTES,              \
        .shared_secret_size = PQC_MLKEM_SSBYTES,                               \
        .keygen = mlkem_##SUFFIX##_keygen,                                     \
        .encaps = mlkem_##SUFFIX##_encaps,                                     \
        .decaps = mlkem_##SUFFIX##_decaps,                                     \
    };

DEFINE_MLKEM_OPS(512,  PQC_MLKEM_512,  1)
DEFINE_MLKEM_OPS(768,  PQC_MLKEM_768,  3)
DEFINE_MLKEM_OPS(1024, PQC_MLKEM_1024, 5)

int pqc_kem_mlkem_register(void) {
    int rc = 0;
    rc |= pqc_kem_add_vtable(&mlkem_512_vtable);
    rc |= pqc_kem_add_vtable(&mlkem_768_vtable);
    rc |= pqc_kem_add_vtable(&mlkem_1024_vtable);
    return rc;
}
