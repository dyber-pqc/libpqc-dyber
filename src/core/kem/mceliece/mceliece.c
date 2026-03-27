/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Classic McEliece KEM - Full implementation.
 *
 * Key encapsulation mechanism based on binary Goppa codes.
 * Implements keygen, encaps, and decaps for all five parameter sets.
 *
 * Secret key layout:
 *   [0 .. (t+1)*2 - 1]         : Goppa polynomial g (t+1 coefficients, 2 bytes each)
 *   [(t+1)*2 .. (t+1)*2 + n*2 - 1] : Support permutation (n elements, 2 bytes each)
 *   [... + 32]                  : Seed s for implicit rejection
 *
 * Public key: systematic part T of the parity-check matrix.
 */

#include <stdlib.h>
#include <string.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/kem/kem_internal.h"
#include "core/common/hash/sha3.h"
#include "mceliece.h"

/* ------------------------------------------------------------------ */
/* Parameter set definitions                                           */
/* ------------------------------------------------------------------ */

static const mceliece_params_t params_348864 = {
    .m = 12, .t = 64, .n = 3488, .k = 2720, .field_size = 4096,
    .pk_bytes = 261120, .sk_bytes = 6492, .ct_bytes = 128, .ss_bytes = 32
};

static const mceliece_params_t params_460896 = {
    .m = 13, .t = 96, .n = 4608, .k = 3360, .field_size = 8192,
    .pk_bytes = 524160, .sk_bytes = 13608, .ct_bytes = 188, .ss_bytes = 32
};

static const mceliece_params_t params_6688128 = {
    .m = 13, .t = 128, .n = 6688, .k = 5024, .field_size = 8192,
    .pk_bytes = 1044992, .sk_bytes = 13932, .ct_bytes = 240, .ss_bytes = 32
};

static const mceliece_params_t params_6960119 = {
    .m = 13, .t = 119, .n = 6960, .k = 5413, .field_size = 8192,
    .pk_bytes = 1047319, .sk_bytes = 13948, .ct_bytes = 226, .ss_bytes = 32
};

static const mceliece_params_t params_8192128 = {
    .m = 13, .t = 128, .n = 8192, .k = 6528, .field_size = 8192,
    .pk_bytes = 1357824, .sk_bytes = 14120, .ct_bytes = 240, .ss_bytes = 32
};

/* ------------------------------------------------------------------ */
/* Secret key encoding/decoding                                        */
/* ------------------------------------------------------------------ */

static void sk_encode(uint8_t *sk, const gf_t *g, const uint16_t *perm,
                      const uint8_t *seed, const mceliece_params_t *p)
{
    int offset = 0;

    /* Goppa polynomial: (t+1) coefficients, 2 bytes each (little-endian) */
    for (int i = 0; i <= p->t; i++) {
        sk[offset++] = (uint8_t)(g[i] & 0xFF);
        sk[offset++] = (uint8_t)(g[i] >> 8);
    }

    /* Support permutation: n elements, 2 bytes each */
    for (int i = 0; i < p->n; i++) {
        sk[offset++] = (uint8_t)(perm[i] & 0xFF);
        sk[offset++] = (uint8_t)(perm[i] >> 8);
    }

    /* Random seed for implicit rejection (32 bytes) */
    memcpy(sk + offset, seed, 32);
}

static void sk_decode(gf_t *g, uint16_t *perm, uint8_t *seed,
                      const uint8_t *sk, const mceliece_params_t *p)
{
    int offset = 0;

    for (int i = 0; i <= p->t; i++) {
        g[i] = (gf_t)((uint16_t)sk[offset] | ((uint16_t)sk[offset + 1] << 8));
        offset += 2;
    }

    for (int i = 0; i < p->n; i++) {
        perm[i] = (uint16_t)((uint16_t)sk[offset] | ((uint16_t)sk[offset + 1] << 8));
        offset += 2;
    }

    memcpy(seed, sk + offset, 32);
}

/* ------------------------------------------------------------------ */
/* Generate random permutation of [0, n)                               */
/* ------------------------------------------------------------------ */

static int gen_permutation(uint16_t *perm, int n)
{
    for (int i = 0; i < n; i++)
        perm[i] = (uint16_t)i;

    uint8_t rbuf[4];
    for (int i = n - 1; i > 0; i--) {
        if (pqc_randombytes(rbuf, 4) != PQC_OK)
            return -1;
        uint32_t r = ((uint32_t)rbuf[0]) |
                     ((uint32_t)rbuf[1] << 8) |
                     ((uint32_t)rbuf[2] << 16) |
                     ((uint32_t)rbuf[3] << 24);
        int j = (int)(r % (uint32_t)(i + 1));
        uint16_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Key generation                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t mceliece_keygen_impl(uint8_t *pk, uint8_t *sk,
                                          const mceliece_params_t *p)
{
    gf_t g[MCELIECE_MAX_T + 1];
    uint16_t *perm = NULL;
    uint8_t seed[32];
    int rc;

    gf_init_tables(p->m);

    /* Permutation needs field_size entries (2^m), which may be > n */
    perm = (uint16_t *)calloc((size_t)p->field_size, sizeof(uint16_t));
    if (!perm)
        return PQC_ERROR_ALLOC;

    /* Generate random seed for implicit rejection */
    if (pqc_randombytes(seed, 32) != PQC_OK) {
        free(perm);
        return PQC_ERROR_RNG_FAILED;
    }

    /* Try to generate a valid key pair */
    int attempts = 0;
    while (attempts < 100) {
        attempts++;

        /* Generate random irreducible Goppa polynomial */
        rc = goppa_gen_irr_poly(g, p->t, p->m);
        if (rc != 0)
            continue;

        /* Generate random permutation for support */
        rc = gen_permutation(perm, p->field_size);
        if (rc != 0) {
            free(perm);
            return PQC_ERROR_RNG_FAILED;
        }

        /* Build systematic parity-check matrix; pk = T */
        rc = goppa_systematic_matrix(pk, g, perm, p);
        if (rc == 0)
            break; /* Success */
    }

    if (attempts >= 100) {
        free(perm);
        return PQC_ERROR_INTERNAL;
    }

    /* Encode secret key */
    sk_encode(sk, g, perm, seed, p);

    pqc_memzero(g, sizeof(g));
    free(perm);

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Encapsulation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t mceliece_encaps_impl(uint8_t *ct, uint8_t *ss,
                                          const uint8_t *pk,
                                          const mceliece_params_t *p)
{
    int e_bytes = (p->n + 7) / 8;
    uint8_t *e = (uint8_t *)calloc(1, (size_t)e_bytes);
    if (!e)
        return PQC_ERROR_ALLOC;

    /* Encrypt: generate random error and compute syndrome */
    if (mceliece_encrypt(ct, e, pk, p) != 0) {
        free(e);
        return PQC_ERROR_INTERNAL;
    }

    /*
     * Shared secret: SHA3-256(1 || e || ct)
     * The "1" byte indicates success.
     */
    size_t hash_input_len = 1 + (size_t)e_bytes + (size_t)p->ct_bytes;
    uint8_t *hash_input = (uint8_t *)calloc(1, hash_input_len);
    if (!hash_input) {
        free(e);
        return PQC_ERROR_ALLOC;
    }

    hash_input[0] = 1; /* success indicator */
    memcpy(hash_input + 1, e, (size_t)e_bytes);
    memcpy(hash_input + 1 + e_bytes, ct, (size_t)p->ct_bytes);

    pqc_sha3_256(ss, hash_input, hash_input_len);

    pqc_memzero(e, (size_t)e_bytes);
    free(e);
    free(hash_input);

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Decapsulation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t mceliece_decaps_impl(uint8_t *ss, const uint8_t *ct,
                                          const uint8_t *sk,
                                          const mceliece_params_t *p)
{
    gf_t g[MCELIECE_MAX_T + 1];
    uint16_t *perm = NULL;
    uint8_t seed[32];
    int e_bytes = (p->n + 7) / 8;
    uint8_t *e = NULL;

    perm = (uint16_t *)calloc((size_t)p->n, sizeof(uint16_t));
    e = (uint8_t *)calloc(1, (size_t)e_bytes);
    if (!perm || !e) {
        free(perm);
        free(e);
        return PQC_ERROR_ALLOC;
    }

    /* Decode secret key */
    sk_decode(g, perm, seed, sk, p);
    gf_init_tables(p->m);

    /* Decrypt: recover error vector */
    int rc = mceliece_decrypt(e, ct, g, perm, p);

    /*
     * Compute shared secret with implicit rejection:
     * On success: ss = SHA3-256(1 || e || ct)
     * On failure: ss = SHA3-256(0 || seed || ct)
     */
    size_t hash_input_len;
    uint8_t *hash_input;

    if (rc == 0) {
        hash_input_len = 1 + (size_t)e_bytes + (size_t)p->ct_bytes;
        hash_input = (uint8_t *)calloc(1, hash_input_len);
        if (!hash_input) {
            free(perm);
            free(e);
            return PQC_ERROR_ALLOC;
        }
        hash_input[0] = 1;
        memcpy(hash_input + 1, e, (size_t)e_bytes);
        memcpy(hash_input + 1 + e_bytes, ct, (size_t)p->ct_bytes);
    } else {
        hash_input_len = 1 + 32 + (size_t)p->ct_bytes;
        hash_input = (uint8_t *)calloc(1, hash_input_len);
        if (!hash_input) {
            free(perm);
            free(e);
            return PQC_ERROR_ALLOC;
        }
        hash_input[0] = 0;
        memcpy(hash_input + 1, seed, 32);
        memcpy(hash_input + 1 + 32, ct, (size_t)p->ct_bytes);
    }

    pqc_sha3_256(ss, hash_input, hash_input_len);

    pqc_memzero(g, sizeof(g));
    pqc_memzero(seed, sizeof(seed));
    pqc_memzero(e, (size_t)e_bytes);
    free(perm);
    free(e);
    free(hash_input);

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Per-variant wrappers                                                */
/* ------------------------------------------------------------------ */

static pqc_status_t mceliece348864_keygen(uint8_t *pk, uint8_t *sk)
{ return mceliece_keygen_impl(pk, sk, &params_348864); }
static pqc_status_t mceliece348864_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return mceliece_encaps_impl(ct, ss, pk, &params_348864); }
static pqc_status_t mceliece348864_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return mceliece_decaps_impl(ss, ct, sk, &params_348864); }

static pqc_status_t mceliece460896_keygen(uint8_t *pk, uint8_t *sk)
{ return mceliece_keygen_impl(pk, sk, &params_460896); }
static pqc_status_t mceliece460896_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return mceliece_encaps_impl(ct, ss, pk, &params_460896); }
static pqc_status_t mceliece460896_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return mceliece_decaps_impl(ss, ct, sk, &params_460896); }

static pqc_status_t mceliece6688128_keygen(uint8_t *pk, uint8_t *sk)
{ return mceliece_keygen_impl(pk, sk, &params_6688128); }
static pqc_status_t mceliece6688128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return mceliece_encaps_impl(ct, ss, pk, &params_6688128); }
static pqc_status_t mceliece6688128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return mceliece_decaps_impl(ss, ct, sk, &params_6688128); }

static pqc_status_t mceliece6960119_keygen(uint8_t *pk, uint8_t *sk)
{ return mceliece_keygen_impl(pk, sk, &params_6960119); }
static pqc_status_t mceliece6960119_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return mceliece_encaps_impl(ct, ss, pk, &params_6960119); }
static pqc_status_t mceliece6960119_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return mceliece_decaps_impl(ss, ct, sk, &params_6960119); }

static pqc_status_t mceliece8192128_keygen(uint8_t *pk, uint8_t *sk)
{ return mceliece_keygen_impl(pk, sk, &params_8192128); }
static pqc_status_t mceliece8192128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return mceliece_encaps_impl(ct, ss, pk, &params_8192128); }
static pqc_status_t mceliece8192128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return mceliece_decaps_impl(ss, ct, sk, &params_8192128); }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_kem_vtable_t mceliece348864_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_348864,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 261120,
    .secret_key_size   = 6492,
    .ciphertext_size   = 128,
    .shared_secret_size = 32,
    .keygen = mceliece348864_keygen,
    .encaps = mceliece348864_encaps,
    .decaps = mceliece348864_decaps,
};

static const pqc_kem_vtable_t mceliece460896_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_460896,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 524160,
    .secret_key_size   = 13608,
    .ciphertext_size   = 188,
    .shared_secret_size = 32,
    .keygen = mceliece460896_keygen,
    .encaps = mceliece460896_encaps,
    .decaps = mceliece460896_decaps,
};

static const pqc_kem_vtable_t mceliece6688128_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_6688128,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 1044992,
    .secret_key_size   = 13932,
    .ciphertext_size   = 240,
    .shared_secret_size = 32,
    .keygen = mceliece6688128_keygen,
    .encaps = mceliece6688128_encaps,
    .decaps = mceliece6688128_decaps,
};

static const pqc_kem_vtable_t mceliece6960119_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_6960119,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 1047319,
    .secret_key_size   = 13948,
    .ciphertext_size   = 226,
    .shared_secret_size = 32,
    .keygen = mceliece6960119_keygen,
    .encaps = mceliece6960119_encaps,
    .decaps = mceliece6960119_decaps,
};

static const pqc_kem_vtable_t mceliece8192128_vtable = {
    .algorithm_name    = PQC_KEM_MCELIECE_8192128,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "Classic McEliece (NIST Round 4)",
    .public_key_size   = 1357824,
    .secret_key_size   = 14120,
    .ciphertext_size   = 240,
    .shared_secret_size = 32,
    .keygen = mceliece8192128_keygen,
    .encaps = mceliece8192128_encaps,
    .decaps = mceliece8192128_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_mceliece_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&mceliece348864_vtable);
    rc |= pqc_kem_add_vtable(&mceliece460896_vtable);
    rc |= pqc_kem_add_vtable(&mceliece6688128_vtable);
    rc |= pqc_kem_add_vtable(&mceliece6960119_vtable);
    rc |= pqc_kem_add_vtable(&mceliece8192128_vtable);
    return rc;
}
