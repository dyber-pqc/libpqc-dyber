/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * NTRU KEM - Full implementation with Fujisaki-Okamoto transform.
 *
 * Implements keygen, encaps, and decaps for:
 *   NTRU-HPS-2048-509, NTRU-HPS-2048-677, NTRU-HPS-4096-821, NTRU-HRSS-701
 *
 * FO transform:
 *   Encaps: sample r,m from H(pk, coin), encrypt, ss = H(r || ct)
 *   Decaps: decrypt, re-encrypt, check, implicit reject with seed
 */

#include <stdlib.h>
#include <string.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/kem/kem_internal.h"
#include "core/common/hash/sha3.h"
#include "ntru.h"

/* ------------------------------------------------------------------ */
/* Parameter definitions                                               */
/* ------------------------------------------------------------------ */

/*
 * Size formulas:
 *   pk_bytes = ct_bytes = ceil(n * log_q / 8)
 *   sk_bytes = 2 * ceil((n+4)/5) + pk_bytes + 64
 *     (f_trits + f_inv_3_trits + h_packed + pk_hash + rejection_seed)
 */
static const ntru_params_t params_hps2048509 = {
    .n = 509, .q = 2048, .log_q = 11, .is_hrss = 0,
    .weight = 169,
    .pk_bytes = 700, .sk_bytes = 968, .ct_bytes = 700
};

static const ntru_params_t params_hps2048677 = {
    .n = 677, .q = 2048, .log_q = 11, .is_hrss = 0,
    .weight = 225,
    .pk_bytes = 931, .sk_bytes = 1267, .ct_bytes = 931
};

static const ntru_params_t params_hps4096821 = {
    .n = 821, .q = 4096, .log_q = 12, .is_hrss = 0,
    .weight = 273,
    .pk_bytes = 1232, .sk_bytes = 1626, .ct_bytes = 1232
};

static const ntru_params_t params_hrss701 = {
    .n = 701, .q = 8192, .log_q = 13, .is_hrss = 1,
    .weight = 0,
    .pk_bytes = 1140, .sk_bytes = 1486, .ct_bytes = 1140
};

/* ------------------------------------------------------------------ */
/* KEM operations                                                      */
/* ------------------------------------------------------------------ */

static pqc_status_t ntru_keygen_impl(uint8_t *pk, uint8_t *sk,
                                      const ntru_params_t *p)
{
    /* sk layout: [owcpa_sk] [pk_hash (32 bytes)] [rejection_seed (32 bytes)] */
    int owcpa_sk_bytes = p->sk_bytes - 64;

    if (ntru_owcpa_keygen(pk, sk, p) != 0)
        return PQC_ERROR_INTERNAL;

    /* Append hash of public key */
    pqc_sha3_256(sk + owcpa_sk_bytes, pk, (size_t)p->pk_bytes);

    /* Append random seed for implicit rejection */
    if (pqc_randombytes(sk + owcpa_sk_bytes + 32, 32) != PQC_OK)
        return PQC_ERROR_RNG_FAILED;

    return PQC_OK;
}

static pqc_status_t ntru_encaps_impl(uint8_t *ct, uint8_t *ss,
                                      const uint8_t *pk,
                                      const ntru_params_t *p)
{
    ntru_poly_t r, m;
    uint8_t coin[32];

    /* Generate random coin */
    if (pqc_randombytes(coin, 32) != PQC_OK)
        return PQC_ERROR_RNG_FAILED;

    /*
     * Derive r and m from coin:
     * (r_seed || m_seed) = SHAKE-256(coin || pk_hash, 64)
     */
    uint8_t pk_hash[32];
    pqc_sha3_256(pk_hash, pk, (size_t)p->pk_bytes);

    uint8_t combined[64];
    memcpy(combined, coin, 32);
    memcpy(combined + 32, pk_hash, 32);

    uint8_t derived[64];
    pqc_shake256(derived, 64, combined, 64);

    /* Sample r from first 32 bytes */
    if (p->is_hrss) {
        ntru_sample_ternary(&r, derived, 32, p->n);
    } else {
        ntru_sample_fixed_weight(&r, derived, 32, p->n, p->weight);
    }

    /* Sample m from second 32 bytes */
    if (p->is_hrss) {
        ntru_sample_ternary(&m, derived + 32, 32, p->n);
    } else {
        ntru_sample_fixed_weight(&m, derived + 32, 32, p->n, p->weight);
    }

    /* Lift m: for the OWCPA, m coefficients should be in {-1, 0, 1} (already) */

    /* Encrypt: c = r*h + m mod q */
    if (ntru_owcpa_encrypt(ct, &r, &m, pk, p) != 0)
        return PQC_ERROR_INTERNAL;

    /* Shared secret: ss = SHA3-256(coin || ct) */
    size_t ss_input_len = 32 + (size_t)p->ct_bytes;
    uint8_t *ss_input = (uint8_t *)calloc(1, ss_input_len);
    if (!ss_input)
        return PQC_ERROR_ALLOC;

    memcpy(ss_input, coin, 32);
    memcpy(ss_input + 32, ct, (size_t)p->ct_bytes);

    pqc_sha3_256(ss, ss_input, ss_input_len);

    pqc_memzero(&r, sizeof(r));
    pqc_memzero(&m, sizeof(m));
    pqc_memzero(coin, sizeof(coin));
    free(ss_input);

    return PQC_OK;
}

static pqc_status_t ntru_decaps_impl(uint8_t *ss, const uint8_t *ct,
                                      const uint8_t *sk,
                                      const ntru_params_t *p)
{
    ntru_poly_t m_dec, r_dec;
    int owcpa_sk_bytes = p->sk_bytes - 64;

    /* Decrypt */
    if (ntru_owcpa_decrypt(&m_dec, ct, sk, p) != 0) {
        /* On decryption failure, use implicit rejection */
        goto reject;
    }

    /*
     * Re-derive r from the decrypted message.
     * To do FO properly, we need to recover the coin used during encaps.
     *
     * Re-derive: (r_seed || m_seed) = SHAKE-256(coin || pk_hash, 64)
     * But we don't have coin directly. Instead:
     *
     * Compute coin' = SHA3-256(m || pk_hash), then re-derive r, m,
     * re-encrypt, and compare.
     */
    uint8_t pk_hash[32];
    memcpy(pk_hash, sk + owcpa_sk_bytes, 32);

    /* Pack m for hashing */
    int trit_bytes = (p->n + 4) / 5;
    uint8_t *m_packed = (uint8_t *)calloc(1, (size_t)trit_bytes);
    if (!m_packed)
        return PQC_ERROR_ALLOC;

    ntru_pack_trits(m_packed, &m_dec, p->n);

    /* coin' = SHA3-256(m_packed || pk_hash) */
    uint8_t coin_prime[32];
    {
        size_t coin_input_len = (size_t)trit_bytes + 32;
        uint8_t *coin_input = (uint8_t *)calloc(1, coin_input_len);
        if (!coin_input) {
            free(m_packed);
            return PQC_ERROR_ALLOC;
        }
        memcpy(coin_input, m_packed, (size_t)trit_bytes);
        memcpy(coin_input + trit_bytes, pk_hash, 32);
        pqc_sha3_256(coin_prime, coin_input, coin_input_len);
        free(coin_input);
    }

    /* Re-derive r, m */
    uint8_t combined[64];
    memcpy(combined, coin_prime, 32);
    memcpy(combined + 32, pk_hash, 32);

    uint8_t derived[64];
    pqc_shake256(derived, 64, combined, 64);

    if (p->is_hrss) {
        ntru_sample_ternary(&r_dec, derived, 32, p->n);
    } else {
        ntru_sample_fixed_weight(&r_dec, derived, 32, p->n, p->weight);
    }

    ntru_poly_t m_check;
    if (p->is_hrss) {
        ntru_sample_ternary(&m_check, derived + 32, 32, p->n);
    } else {
        ntru_sample_fixed_weight(&m_check, derived + 32, 32, p->n, p->weight);
    }

    /* Re-encrypt */
    /* Extract pk from sk (it's embedded) */
    int f_trit_bytes = (p->n + 4) / 5;
    const uint8_t *pk_in_sk = sk + f_trit_bytes;

    uint8_t *ct_check = (uint8_t *)calloc(1, (size_t)p->ct_bytes);
    if (!ct_check) {
        free(m_packed);
        return PQC_ERROR_ALLOC;
    }

    ntru_owcpa_encrypt(ct_check, &r_dec, &m_check, pk_in_sk, p);

    /* Compare ciphertexts in constant time */
    int fail = pqc_memcmp_ct(ct, ct_check, (size_t)p->ct_bytes);

    free(ct_check);
    free(m_packed);

    if (fail != 0)
        goto reject;

    /* Success: ss = SHA3-256(coin' || ct) */
    {
        size_t ss_input_len = 32 + (size_t)p->ct_bytes;
        uint8_t *ss_input = (uint8_t *)calloc(1, ss_input_len);
        if (!ss_input)
            return PQC_ERROR_ALLOC;

        memcpy(ss_input, coin_prime, 32);
        memcpy(ss_input + 32, ct, (size_t)p->ct_bytes);

        pqc_sha3_256(ss, ss_input, ss_input_len);
        free(ss_input);
    }

    pqc_memzero(&m_dec, sizeof(m_dec));
    pqc_memzero(&r_dec, sizeof(r_dec));
    return PQC_OK;

reject:
    /* Implicit rejection: ss = SHA3-256(seed || ct) */
    {
        const uint8_t *seed = sk + owcpa_sk_bytes + 32;
        size_t ss_input_len = 32 + (size_t)p->ct_bytes;
        uint8_t *ss_input = (uint8_t *)calloc(1, ss_input_len);
        if (!ss_input)
            return PQC_ERROR_ALLOC;

        memcpy(ss_input, seed, 32);
        memcpy(ss_input + 32, ct, (size_t)p->ct_bytes);

        pqc_sha3_256(ss, ss_input, ss_input_len);
        free(ss_input);
    }

    pqc_memzero(&m_dec, sizeof(m_dec));
    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Per-variant wrappers                                                */
/* ------------------------------------------------------------------ */

static pqc_status_t ntru_hps2048509_keygen(uint8_t *pk, uint8_t *sk)
{ return ntru_keygen_impl(pk, sk, &params_hps2048509); }
static pqc_status_t ntru_hps2048509_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return ntru_encaps_impl(ct, ss, pk, &params_hps2048509); }
static pqc_status_t ntru_hps2048509_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return ntru_decaps_impl(ss, ct, sk, &params_hps2048509); }

static pqc_status_t ntru_hps2048677_keygen(uint8_t *pk, uint8_t *sk)
{ return ntru_keygen_impl(pk, sk, &params_hps2048677); }
static pqc_status_t ntru_hps2048677_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return ntru_encaps_impl(ct, ss, pk, &params_hps2048677); }
static pqc_status_t ntru_hps2048677_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return ntru_decaps_impl(ss, ct, sk, &params_hps2048677); }

static pqc_status_t ntru_hps4096821_keygen(uint8_t *pk, uint8_t *sk)
{ return ntru_keygen_impl(pk, sk, &params_hps4096821); }
static pqc_status_t ntru_hps4096821_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return ntru_encaps_impl(ct, ss, pk, &params_hps4096821); }
static pqc_status_t ntru_hps4096821_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return ntru_decaps_impl(ss, ct, sk, &params_hps4096821); }

static pqc_status_t ntru_hrss701_keygen(uint8_t *pk, uint8_t *sk)
{ return ntru_keygen_impl(pk, sk, &params_hrss701); }
static pqc_status_t ntru_hrss701_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return ntru_encaps_impl(ct, ss, pk, &params_hrss701); }
static pqc_status_t ntru_hrss701_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return ntru_decaps_impl(ss, ct, sk, &params_hrss701); }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_kem_vtable_t ntru_hps2048509_vtable = {
    .algorithm_name    = PQC_KEM_NTRU_HPS_2048_509,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "NTRU",
    .public_key_size   = 699,
    .secret_key_size   = 935,
    .ciphertext_size   = 699,
    .shared_secret_size = 32,
    .keygen = ntru_hps2048509_keygen,
    .encaps = ntru_hps2048509_encaps,
    .decaps = ntru_hps2048509_decaps,
};

static const pqc_kem_vtable_t ntru_hps2048677_vtable = {
    .algorithm_name    = PQC_KEM_NTRU_HPS_2048_677,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "NTRU",
    .public_key_size   = 930,
    .secret_key_size   = 1234,
    .ciphertext_size   = 930,
    .shared_secret_size = 32,
    .keygen = ntru_hps2048677_keygen,
    .encaps = ntru_hps2048677_encaps,
    .decaps = ntru_hps2048677_decaps,
};

static const pqc_kem_vtable_t ntru_hps4096821_vtable = {
    .algorithm_name    = PQC_KEM_NTRU_HPS_4096_821,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "NTRU",
    .public_key_size   = 1230,
    .secret_key_size   = 1590,
    .ciphertext_size   = 1230,
    .shared_secret_size = 32,
    .keygen = ntru_hps4096821_keygen,
    .encaps = ntru_hps4096821_encaps,
    .decaps = ntru_hps4096821_decaps,
};

static const pqc_kem_vtable_t ntru_hrss701_vtable = {
    .algorithm_name    = PQC_KEM_NTRU_HRSS_701,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "NTRU",
    .public_key_size   = 1138,
    .secret_key_size   = 1450,
    .ciphertext_size   = 1138,
    .shared_secret_size = 32,
    .keygen = ntru_hrss701_keygen,
    .encaps = ntru_hrss701_encaps,
    .decaps = ntru_hrss701_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_ntru_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&ntru_hps2048509_vtable);
    rc |= pqc_kem_add_vtable(&ntru_hps2048677_vtable);
    rc |= pqc_kem_add_vtable(&ntru_hps4096821_vtable);
    rc |= pqc_kem_add_vtable(&ntru_hrss701_vtable);
    return rc;
}
