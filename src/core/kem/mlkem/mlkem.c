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
 *
 * Based on the reference implementation from pq-crystals/kyber (kem.c).
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
 * Following the reference kem.c crypto_kem_keypair logic:
 *   1. Generate 2*SYMBYTES random coins
 *   2. indcpa_keypair_derand(pk, sk, coins)
 *   3. sk = sk_pke || pk || H(pk) || z
 */
pqc_status_t pqc_mlkem_keygen(const pqc_mlkem_params_t *params,
                               uint8_t *pk,
                               uint8_t *sk)
{
    uint8_t coins[2 * PQC_MLKEM_SYMBYTES];
    pqc_status_t rc;

    if (!params || !pk || !sk) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }

    /* Generate random coins: first SYMBYTES = d, second SYMBYTES = z */
    rc = pqc_randombytes(coins, 2 * PQC_MLKEM_SYMBYTES);
    if (rc != PQC_OK) {
        return PQC_ERROR_RNG_FAILED;
    }

    /* IND-CPA key generation from first 32 bytes of coins */
    pqc_mlkem_indcpa_keypair_derand(pk, sk, coins, params);

    /* Assemble full secret key: sk = sk_pke || pk || H(pk) || z */
    memcpy(sk + params->indcpa_sk_bytes, pk, params->pk_bytes);

    /* H(pk) */
    pqc_sha3_256(sk + params->sk_bytes - 2 * PQC_MLKEM_SYMBYTES,
                  pk, params->pk_bytes);

    /* z (value for pseudo-random output on reject) */
    memcpy(sk + params->sk_bytes - PQC_MLKEM_SYMBYTES,
           coins + PQC_MLKEM_SYMBYTES, PQC_MLKEM_SYMBYTES);

    return PQC_OK;
}

/* ================================================================= */
/*  ML-KEM.Encaps_internal (Algorithm 17)                              */
/* ================================================================= */

/*
 * Following the reference kem.c crypto_kem_enc logic:
 *   1. Generate random m
 *   2. H(pk) -> buf+SYMBYTES (multitarget countermeasure)
 *   3. G(m || H(pk)) -> (K, r)
 *   4. indcpa_enc(ct, m, pk, r)
 *   5. return K
 */
pqc_status_t pqc_mlkem_encaps(const pqc_mlkem_params_t *params,
                               uint8_t *ct,
                               uint8_t *ss,
                               const uint8_t *pk)
{
    uint8_t coins[PQC_MLKEM_SYMBYTES];
    uint8_t buf[2 * PQC_MLKEM_SYMBYTES];
    uint8_t kr[2 * PQC_MLKEM_SYMBYTES]; /* will contain key, coins */
    pqc_status_t rc;

    if (!params || !ct || !ss || !pk) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }

    /* Generate random m */
    rc = pqc_randombytes(coins, PQC_MLKEM_SYMBYTES);
    if (rc != PQC_OK) {
        return PQC_ERROR_RNG_FAILED;
    }

    memcpy(buf, coins, PQC_MLKEM_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    pqc_sha3_256(buf + PQC_MLKEM_SYMBYTES, pk, params->pk_bytes);

    /* (K, r) = G(m || H(pk)) */
    pqc_sha3_512(kr, buf, 2 * PQC_MLKEM_SYMBYTES);

    /* coins are in kr+SYMBYTES */
    pqc_mlkem_indcpa_enc(ct, buf, pk, kr + PQC_MLKEM_SYMBYTES, params);

    memcpy(ss, kr, PQC_MLKEM_SYMBYTES);

    return PQC_OK;
}

/* ================================================================= */
/*  ML-KEM.Decaps_internal (Algorithm 18)                              */
/* ================================================================= */

/*
 * Following the reference kem.c crypto_kem_dec logic:
 *   1. indcpa_dec(buf, ct, sk)
 *   2. buf+SYMBYTES = H(pk) from sk
 *   3. G(buf) -> (K', r')
 *   4. indcpa_enc(cmp, buf, pk, r')
 *   5. fail = verify(ct, cmp)
 *   6. rkprf: ss = J(z || ct)
 *   7. cmov(ss, kr, !fail)
 */
pqc_status_t pqc_mlkem_decaps(const pqc_mlkem_params_t *params,
                               uint8_t *ss,
                               const uint8_t *ct,
                               const uint8_t *sk)
{
    int fail;
    uint8_t buf[2 * PQC_MLKEM_SYMBYTES];
    uint8_t kr[2 * PQC_MLKEM_SYMBYTES]; /* will contain key, coins */
    uint8_t cmp[1568]; /* max ciphertext size (ML-KEM-1024) */
    const uint8_t *pk;

    if (!params || !ss || !ct || !sk) {
        return PQC_ERROR_INVALID_ARGUMENT;
    }

    pk = sk + params->indcpa_sk_bytes;

    /* Step 1: m' = indcpa_dec(ct, sk) */
    pqc_mlkem_indcpa_dec(buf, ct, sk, params);

    /* Step 2: Multitarget countermeasure for coins + contributory KEM
     * Copy H(pk) from the secret key into buf */
    memcpy(buf + PQC_MLKEM_SYMBYTES,
           sk + params->sk_bytes - 2 * PQC_MLKEM_SYMBYTES,
           PQC_MLKEM_SYMBYTES);

    /* Step 3: (K', r') = G(m' || H(pk)) */
    pqc_sha3_512(kr, buf, 2 * PQC_MLKEM_SYMBYTES);

    /* Step 4: c' = indcpa_enc(pk, m', r') */
    pqc_mlkem_indcpa_enc(cmp, buf, pk, kr + PQC_MLKEM_SYMBYTES, params);

    /* Step 5: Compare c and c' in constant time */
    fail = pqc_mlkem_verify(ct, cmp, params->ct_bytes);

    /* Step 6: Compute rejection key ss = J(z || ct)  (rkprf) */
    {
        pqc_shake256_ctx jctx;
        pqc_shake256_init(&jctx);
        pqc_shake256_absorb(&jctx, sk + params->sk_bytes - PQC_MLKEM_SYMBYTES,
                             PQC_MLKEM_SYMBYTES);
        pqc_shake256_absorb(&jctx, ct, params->ct_bytes);
        pqc_shake256_finalize(&jctx);
        pqc_shake256_squeeze(&jctx, ss, PQC_MLKEM_SSBYTES);
    }

    /* Step 7: Copy true key to return buffer if fail is false */
    pqc_mlkem_cmov(ss, kr, PQC_MLKEM_SYMBYTES, !fail);

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
