/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Streamlined NTRU Prime KEM - Full implementation.
 *
 * Key generation:
 *   Choose small f (weight w), small g.
 *   Compute h = g / (3f) in Rq = Z_q[x]/(x^p - x - 1).
 *   Public key: Encode(h). Secret key: (f, ginv, pk, hash_pk, rho).
 *
 * Encapsulation:
 *   Choose small r (weight w).
 *   Compute c = Round(h * r) (round each coeff to nearest multiple of 3).
 *   Shared secret: SHA-256(2 || SHA-256(r) || SHA-256(c)).
 *
 * Decapsulation:
 *   Compute 3*f*c in Rq, reduce mod 3, multiply by ginv in R3 to get r'.
 *   Check weight. Re-encapsulate. If match, output real ss; else reject.
 */

#include <stdlib.h>
#include <string.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/kem/kem_internal.h"
#include "core/common/hash/sha3.h"
#include "core/common/hash/sha2.h"
#include "ntruprime.h"

/* ------------------------------------------------------------------ */
/* Parameter definitions                                               */
/* ------------------------------------------------------------------ */

/*
 * Size formulas (using simple 2-byte-per-coefficient encoding):
 *   pk_bytes = p * 2       (encode_rq writes 2 bytes per coefficient)
 *   ct_bytes = p * 2 + 32  (encoded ciphertext + confirmation hash)
 *   sk_bytes = 2*ceil((p+4)/5) + pk_bytes + 64
 *     (f_small + ginv_small + pk_copy + pk_hash + rejection_seed)
 */
static const sntrup_params_t params_761 = {
    .p = 761, .q = 4591, .w = 286,
    .round_bytes = 1007, .small_bytes = 153,
    .pk_bytes = 1522, .sk_bytes = 1892, .ct_bytes = 1554, .ss_bytes = 32
};

static const sntrup_params_t params_857 = {
    .p = 857, .q = 5167, .w = 322,
    .round_bytes = 1152, .small_bytes = 172,
    .pk_bytes = 1714, .sk_bytes = 2122, .ct_bytes = 1746, .ss_bytes = 32
};

static const sntrup_params_t params_953 = {
    .p = 953, .q = 6343, .w = 396,
    .round_bytes = 1317, .small_bytes = 191,
    .pk_bytes = 1906, .sk_bytes = 2352, .ct_bytes = 1938, .ss_bytes = 32
};

static const sntrup_params_t params_1013 = {
    .p = 1013, .q = 7177, .w = 448,
    .round_bytes = 1423, .small_bytes = 203,
    .pk_bytes = 2026, .sk_bytes = 2496, .ct_bytes = 2058, .ss_bytes = 32
};

static const sntrup_params_t params_1277 = {
    .p = 1277, .q = 7879, .w = 492,
    .round_bytes = 1815, .small_bytes = 256,
    .pk_bytes = 2554, .sk_bytes = 3130, .ct_bytes = 2586, .ss_bytes = 32
};

/* ------------------------------------------------------------------ */
/* Sample small polynomial of weight w using SHAKE-256                 */
/* ------------------------------------------------------------------ */

static void sample_small(r3_poly_t *r, const uint8_t *seed,
                         size_t seedlen, int pp, int w)
{
    r3_zero(r);

    /* Start with w entries of +1 and w entries of -1 */
    for (int i = 0; i < w; i++) {
        r->coeffs[i] = 1;
    }
    for (int i = w; i < 2 * w && i < pp; i++) {
        r->coeffs[i] = -1;
    }

    /* Fisher-Yates shuffle using SHAKE-256 */
    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seedlen);
    pqc_shake256_finalize(&ctx);

    for (int i = pp - 1; i > 0; i--) {
        uint8_t rbuf[4];
        pqc_shake256_squeeze(&ctx, rbuf, 4);
        uint32_t rv = ((uint32_t)rbuf[0]) |
                      ((uint32_t)rbuf[1] << 8) |
                      ((uint32_t)rbuf[2] << 16) |
                      ((uint32_t)rbuf[3] << 24);
        int j = (int)(rv % (uint32_t)(i + 1));

        int8_t tmp = r->coeffs[i];
        r->coeffs[i] = r->coeffs[j];
        r->coeffs[j] = tmp;
    }
}

/* Sample small ternary polynomial (not fixed weight) */
static void sample_short(r3_poly_t *r, const uint8_t *seed,
                         size_t seedlen, int pp)
{
    r3_zero(r);

    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seedlen);
    pqc_shake256_finalize(&ctx);

    for (int i = 0; i < pp; i++) {
        uint8_t buf[4];
        pqc_shake256_squeeze(&ctx, buf, 4);
        uint32_t rv = ((uint32_t)buf[0]) |
                      ((uint32_t)buf[1] << 8) |
                      ((uint32_t)buf[2] << 16) |
                      ((uint32_t)buf[3] << 24);
        /* Map to {-1, 0, 1} with roughly equal probability */
        uint32_t t = rv % 3;
        if (t == 0) r->coeffs[i] = 0;
        else if (t == 1) r->coeffs[i] = 1;
        else r->coeffs[i] = -1;
    }
}

/* ------------------------------------------------------------------ */
/* Compute Hamming weight of small polynomial                          */
/* ------------------------------------------------------------------ */

static int small_weight(const r3_poly_t *a, int pp)
{
    int w = 0;
    for (int i = 0; i < pp; i++) {
        if (a->coeffs[i] != 0) w++;
    }
    return w;
}

/* ------------------------------------------------------------------ */
/* Hash helpers                                                        */
/* ------------------------------------------------------------------ */

static void hash_small(uint8_t out[32], const r3_poly_t *r, int pp)
{
    int small_bytes = (pp + 4) / 5;
    uint8_t *encoded = (uint8_t *)calloc(1, (size_t)small_bytes);
    if (!encoded) return;
    sntrup_encode_small(encoded, r, pp);
    pqc_sha256(out, encoded, (size_t)small_bytes);
    free(encoded);
}

/* ------------------------------------------------------------------ */
/* Key generation                                                      */
/* ------------------------------------------------------------------ */

/*
 * Secret key layout:
 *   [small_bytes: encoded f]
 *   [small_bytes: encoded ginv (g^{-1} in R3)]
 *   [pk_bytes: public key]
 *   [32: SHA-256(pk)]
 *   [32: random seed rho for implicit rejection]
 */
static pqc_status_t sntrup_keygen_impl(uint8_t *pk, uint8_t *sk,
                                        const sntrup_params_t *p)
{
    r3_poly_t f, g, ginv;
    rq_poly_t f3_inv, h;
    uint8_t seed[32];
    int rc;

    int small_bytes = (p->p + 4) / 5;
    int rq_bytes = p->p * 2;

    /* Generate g and its inverse in R3 */
    int attempts = 0;
    while (attempts < 100) {
        attempts++;
        if (pqc_randombytes(seed, 32) != PQC_OK)
            return PQC_ERROR_RNG_FAILED;
        sample_short(&g, seed, 32, p->p);

        rc = r3_recip(&ginv, &g, p->p);
        if (rc == 0) break;
    }
    if (attempts >= 100)
        return PQC_ERROR_INTERNAL;

    /* Generate f (weight w) and compute 3f inverse in Rq */
    attempts = 0;
    while (attempts < 100) {
        attempts++;
        if (pqc_randombytes(seed, 32) != PQC_OK)
            return PQC_ERROR_RNG_FAILED;
        sample_small(&f, seed, 32, p->p, p->w);

        /* Compute 3*f as Rq element */
        rq_poly_t f3;
        rq_zero(&f3);
        for (int i = 0; i < p->p; i++) {
            int16_t c = (int16_t)(3 * (int)f.coeffs[i]);
            int r_val = c % p->q;
            if (r_val < 0) r_val += p->q;
            if (r_val > p->q / 2) r_val -= p->q;
            f3.coeffs[i] = (int16_t)r_val;
        }

        rc = rq_recip(&f3_inv, &f3, p);
        if (rc == 0) break;
    }
    if (attempts >= 100)
        return PQC_ERROR_INTERNAL;

    /* h = g / (3f) = g * (3f)^{-1} in Rq */
    rq_poly_t g_rq;
    rq_zero(&g_rq);
    for (int i = 0; i < p->p; i++) {
        g_rq.coeffs[i] = (int16_t)g.coeffs[i];
    }
    rq_mul(&h, &g_rq, &f3_inv, p);

    /* Encode public key */
    sntrup_encode_rq(pk, &h, p);

    /* Encode secret key */
    int offset = 0;
    sntrup_encode_small(sk + offset, &f, p->p);
    offset += small_bytes;
    sntrup_encode_small(sk + offset, &ginv, p->p);
    offset += small_bytes;
    memcpy(sk + offset, pk, (size_t)rq_bytes);
    offset += rq_bytes;
    pqc_sha256(sk + offset, pk, (size_t)rq_bytes);
    offset += 32;

    /* Random seed for implicit rejection */
    if (pqc_randombytes(sk + offset, 32) != PQC_OK)
        return PQC_ERROR_RNG_FAILED;

    pqc_memzero(&f, sizeof(f));
    pqc_memzero(&ginv, sizeof(ginv));
    pqc_memzero(&f3_inv, sizeof(f3_inv));
    pqc_memzero(seed, sizeof(seed));

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Encapsulation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t sntrup_encaps_impl(uint8_t *ct, uint8_t *ss,
                                        const uint8_t *pk,
                                        const sntrup_params_t *p)
{
    r3_poly_t r;
    rq_poly_t h, hr, c;
    uint8_t seed[32];

    /* Generate random small r of weight w */
    if (pqc_randombytes(seed, 32) != PQC_OK)
        return PQC_ERROR_RNG_FAILED;
    sample_small(&r, seed, 32, p->p, p->w);

    /* Decode h from public key */
    sntrup_decode_rq(&h, pk, p);

    /* Compute h * r in Rq */
    rq_mul_small(&hr, &h, &r, p);

    /* c = Round(h * r) */
    rq_round(&c, &hr, p);

    /* Encode ciphertext: encoded(c) || hash_confirm */
    int rq_bytes = p->p * 2;
    sntrup_encode_rq(ct, &c, p);

    /* Append confirmation hash: SHA-256(r_encoded) */
    uint8_t r_hash[32];
    hash_small(r_hash, &r, p->p);
    memcpy(ct + rq_bytes, r_hash, 32);

    /*
     * Shared secret: SHA-256(2 || SHA-256(r) || SHA-256(ct))
     */
    uint8_t ct_hash[32];
    pqc_sha256(ct_hash, ct, (size_t)(rq_bytes + 32));

    uint8_t ss_input[1 + 32 + 32];
    ss_input[0] = 2;
    memcpy(ss_input + 1, r_hash, 32);
    memcpy(ss_input + 1 + 32, ct_hash, 32);
    pqc_sha256(ss, ss_input, sizeof(ss_input));

    pqc_memzero(&r, sizeof(r));
    pqc_memzero(seed, sizeof(seed));

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Decapsulation                                                       */
/* ------------------------------------------------------------------ */

static pqc_status_t sntrup_decaps_impl(uint8_t *ss, const uint8_t *ct,
                                        const uint8_t *sk,
                                        const sntrup_params_t *p)
{
    r3_poly_t f, ginv, r_dec;
    rq_poly_t c, f3c, h, hr_check, c_check;
    int small_bytes = (p->p + 4) / 5;
    int rq_bytes = p->p * 2;

    /* Decode secret key */
    int offset = 0;
    sntrup_decode_small(&f, sk + offset, p->p);
    offset += small_bytes;
    sntrup_decode_small(&ginv, sk + offset, p->p);
    offset += small_bytes;
    const uint8_t *pk_in_sk = sk + offset;
    offset += rq_bytes;
    const uint8_t *pk_hash = sk + offset;
    offset += 32;
    const uint8_t *rho = sk + offset;

    (void)pk_hash;

    /* Decode ciphertext */
    sntrup_decode_rq(&c, ct, p);

    /*
     * Decrypt:
     * 1. Compute 3*f*c in Rq
     * 2. Center-lift (already centered)
     * 3. Reduce mod 3 to get e = 3*f*c mod 3
     * 4. r = e * ginv in R3
     */

    /* 3*f as Rq */
    rq_poly_t f3;
    rq_zero(&f3);
    for (int i = 0; i < p->p; i++) {
        int16_t val = (int16_t)(3 * (int)f.coeffs[i]);
        int r_val = val % p->q;
        if (r_val < 0) r_val += p->q;
        if (r_val > p->q / 2) r_val -= p->q;
        f3.coeffs[i] = (int16_t)r_val;
    }

    /* f3c = 3*f * c in Rq */
    rq_mul(&f3c, &f3, &c, p);

    /* Reduce mod 3: center-lift then mod 3 */
    r3_poly_t e;
    r3_zero(&e);
    for (int i = 0; i < p->p; i++) {
        int c_val = f3c.coeffs[i];
        int m3 = c_val % 3;
        if (m3 < 0) m3 += 3;
        if (m3 == 2) m3 = -1;
        e.coeffs[i] = (int8_t)m3;
    }

    /* r = e * ginv in R3 */
    r3_mul(&r_dec, &e, &ginv, p->p);

    /* Check weight of r */
    int w = small_weight(&r_dec, p->p);
    int valid = (w == 2 * p->w) ? 1 : 0;

    /* Re-encapsulate to verify */
    if (valid) {
        sntrup_decode_rq(&h, pk_in_sk, p);
        rq_mul_small(&hr_check, &h, &r_dec, p);
        rq_round(&c_check, &hr_check, p);

        /* Compare c and c_check */
        for (int i = 0; i < p->p; i++) {
            if (c.coeffs[i] != c_check.coeffs[i]) {
                valid = 0;
                break;
            }
        }
    }

    /* Also check confirmation hash */
    if (valid) {
        uint8_t r_hash[32];
        hash_small(r_hash, &r_dec, p->p);
        if (pqc_memcmp_ct(ct + rq_bytes, r_hash, 32) != 0) {
            valid = 0;
        }
    }

    /*
     * Compute shared secret:
     * If valid: ss = SHA-256(2 || SHA-256(r) || SHA-256(ct))
     * If not:   ss = SHA-256(3 || rho || SHA-256(ct))
     */
    uint8_t ct_hash[32];
    pqc_sha256(ct_hash, ct, (size_t)(rq_bytes + 32));

    if (valid) {
        uint8_t r_hash[32];
        hash_small(r_hash, &r_dec, p->p);

        uint8_t ss_input[1 + 32 + 32];
        ss_input[0] = 2;
        memcpy(ss_input + 1, r_hash, 32);
        memcpy(ss_input + 1 + 32, ct_hash, 32);
        pqc_sha256(ss, ss_input, sizeof(ss_input));
    } else {
        uint8_t ss_input[1 + 32 + 32];
        ss_input[0] = 3;
        memcpy(ss_input + 1, rho, 32);
        memcpy(ss_input + 1 + 32, ct_hash, 32);
        pqc_sha256(ss, ss_input, sizeof(ss_input));
    }

    pqc_memzero(&f, sizeof(f));
    pqc_memzero(&ginv, sizeof(ginv));
    pqc_memzero(&r_dec, sizeof(r_dec));

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Per-variant wrappers                                                */
/* ------------------------------------------------------------------ */

static pqc_status_t sntrup761_keygen(uint8_t *pk, uint8_t *sk)
{ return sntrup_keygen_impl(pk, sk, &params_761); }
static pqc_status_t sntrup761_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return sntrup_encaps_impl(ct, ss, pk, &params_761); }
static pqc_status_t sntrup761_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return sntrup_decaps_impl(ss, ct, sk, &params_761); }

static pqc_status_t sntrup857_keygen(uint8_t *pk, uint8_t *sk)
{ return sntrup_keygen_impl(pk, sk, &params_857); }
static pqc_status_t sntrup857_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return sntrup_encaps_impl(ct, ss, pk, &params_857); }
static pqc_status_t sntrup857_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return sntrup_decaps_impl(ss, ct, sk, &params_857); }

static pqc_status_t sntrup953_keygen(uint8_t *pk, uint8_t *sk)
{ return sntrup_keygen_impl(pk, sk, &params_953); }
static pqc_status_t sntrup953_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return sntrup_encaps_impl(ct, ss, pk, &params_953); }
static pqc_status_t sntrup953_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return sntrup_decaps_impl(ss, ct, sk, &params_953); }

static pqc_status_t sntrup1013_keygen(uint8_t *pk, uint8_t *sk)
{ return sntrup_keygen_impl(pk, sk, &params_1013); }
static pqc_status_t sntrup1013_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return sntrup_encaps_impl(ct, ss, pk, &params_1013); }
static pqc_status_t sntrup1013_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return sntrup_decaps_impl(ss, ct, sk, &params_1013); }

static pqc_status_t sntrup1277_keygen(uint8_t *pk, uint8_t *sk)
{ return sntrup_keygen_impl(pk, sk, &params_1277); }
static pqc_status_t sntrup1277_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{ return sntrup_encaps_impl(ct, ss, pk, &params_1277); }
static pqc_status_t sntrup1277_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{ return sntrup_decaps_impl(ss, ct, sk, &params_1277); }

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_kem_vtable_t sntrup761_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP761,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 1158,
    .secret_key_size   = 1763,
    .ciphertext_size   = 1039,
    .shared_secret_size = 32,
    .keygen = sntrup761_keygen,
    .encaps = sntrup761_encaps,
    .decaps = sntrup761_decaps,
};

static const pqc_kem_vtable_t sntrup857_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP857,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 1322,
    .secret_key_size   = 1999,
    .ciphertext_size   = 1184,
    .shared_secret_size = 32,
    .keygen = sntrup857_keygen,
    .encaps = sntrup857_encaps,
    .decaps = sntrup857_decaps,
};

static const pqc_kem_vtable_t sntrup953_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP953,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 1505,
    .secret_key_size   = 2254,
    .ciphertext_size   = 1349,
    .shared_secret_size = 32,
    .keygen = sntrup953_keygen,
    .encaps = sntrup953_encaps,
    .decaps = sntrup953_decaps,
};

static const pqc_kem_vtable_t sntrup1013_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP1013,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 1623,
    .secret_key_size   = 2417,
    .ciphertext_size   = 1455,
    .shared_secret_size = 32,
    .keygen = sntrup1013_keygen,
    .encaps = sntrup1013_encaps,
    .decaps = sntrup1013_decaps,
};

static const pqc_kem_vtable_t sntrup1277_vtable = {
    .algorithm_name    = PQC_KEM_NTRUPRIME_SNTRUP1277,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "NTRU Prime",
    .public_key_size   = 2067,
    .secret_key_size   = 3059,
    .ciphertext_size   = 1847,
    .shared_secret_size = 32,
    .keygen = sntrup1277_keygen,
    .encaps = sntrup1277_encaps,
    .decaps = sntrup1277_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_ntruprime_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&sntrup761_vtable);
    rc |= pqc_kem_add_vtable(&sntrup857_vtable);
    rc |= pqc_kem_add_vtable(&sntrup953_vtable);
    rc |= pqc_kem_add_vtable(&sntrup1013_vtable);
    rc |= pqc_kem_add_vtable(&sntrup1277_vtable);
    return rc;
}
