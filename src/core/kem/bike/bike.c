/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE (Bit-Flipping Key Encapsulation) KEM - full implementation.
 *
 * BIKE is a code-based KEM built on QC-MDPC codes. The secret key
 * consists of two sparse polynomials (h0, h1) of weight w/2 each.
 * The public key is h = h1 * h0^{-1} mod (x^r - 1). Encapsulation
 * samples an error vector (e0, e1) of weight t, computes
 * c0 = e0 + e1*h, c1 = SHA(e0||e1). Decapsulation uses the
 * bit-flipping decoder to recover the error and verify.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/kem/kem_internal.h"
#include "core/common/hash/sha3.h"
#include "core/common/hash/sha2.h"
#include "bike.h"
#include "bike_params.h"

/* ------------------------------------------------------------------ */
/* Pack/unpack helpers                                                  */
/* ------------------------------------------------------------------ */

static void poly_to_bytes(uint8_t *out, const uint64_t *poly, uint32_t r)
{
    uint32_t r_bytes = (r + 7) / 8;
    memcpy(out, poly, r_bytes);
    uint32_t rem = r % 8;
    if (rem) {
        out[r_bytes - 1] &= (uint8_t)((1u << rem) - 1);
    }
}

static void bytes_to_poly(uint64_t *poly, const uint8_t *in, uint32_t r)
{
    uint32_t r_bytes = (r + 7) / 8;
    uint32_t r_words = (r + 63) / 64;
    memset(poly, 0, r_words * sizeof(uint64_t));
    memcpy(poly, in, r_bytes);
    uint32_t rem = r % 64;
    if (rem) {
        poly[r_words - 1] &= ((uint64_t)1 << rem) - 1;
    }
}

/* ------------------------------------------------------------------ */
/* Key packing                                                          */
/*                                                                      */
/* pk = h (r bits packed into ceil(r/8) bytes)                         */
/* sk = seed (32 bytes) || h0 (r bits) || h1 (r bits) || sigma (32)    */
/* ------------------------------------------------------------------ */

static void bike_pk_pack(uint8_t *pk, const uint64_t *h,
                         const bike_params_t *params)
{
    poly_to_bytes(pk, h, params->r);
}

static void bike_pk_unpack(uint64_t *h, const uint8_t *pk,
                           const bike_params_t *params)
{
    bytes_to_poly(h, pk, params->r);
}

static void bike_sk_pack(uint8_t *sk,
                         const uint8_t *seed,
                         const uint64_t *h0, const uint64_t *h1,
                         const uint8_t *sigma,
                         const bike_params_t *params)
{
    uint32_t r_bytes = params->r_bytes;
    uint32_t offset = 0;

    memcpy(sk + offset, seed, BIKE_SEED_BYTES);
    offset += BIKE_SEED_BYTES;

    poly_to_bytes(sk + offset, h0, params->r);
    offset += r_bytes;

    poly_to_bytes(sk + offset, h1, params->r);
    offset += r_bytes;

    memcpy(sk + offset, sigma, BIKE_SHARED_SECRET_BYTES);
}

static void bike_sk_unpack(uint8_t *seed,
                           uint64_t *h0, uint64_t *h1,
                           uint8_t *sigma,
                           const uint8_t *sk,
                           const bike_params_t *params)
{
    uint32_t r_bytes = params->r_bytes;
    uint32_t offset = 0;

    memcpy(seed, sk + offset, BIKE_SEED_BYTES);
    offset += BIKE_SEED_BYTES;

    bytes_to_poly(h0, sk + offset, params->r);
    offset += r_bytes;

    bytes_to_poly(h1, sk + offset, params->r);
    offset += r_bytes;

    memcpy(sigma, sk + offset, BIKE_SHARED_SECRET_BYTES);
}

/* ------------------------------------------------------------------ */
/* Ciphertext packing                                                   */
/*                                                                      */
/* ct = c0 (r bits) || c1 (32 bytes, the hash commitment)              */
/* ------------------------------------------------------------------ */

static void bike_ct_pack(uint8_t *ct,
                         const uint64_t *c0, const uint8_t *c1_hash,
                         const bike_params_t *params)
{
    poly_to_bytes(ct, c0, params->r);
    memcpy(ct + params->r_bytes, c1_hash, BIKE_SHARED_SECRET_BYTES);
}

static void bike_ct_unpack(uint64_t *c0, uint8_t *c1_hash,
                           const uint8_t *ct,
                           const bike_params_t *params)
{
    bytes_to_poly(c0, ct, params->r);
    memcpy(c1_hash, ct + params->r_bytes, BIKE_SHARED_SECRET_BYTES);
}

/* ------------------------------------------------------------------ */
/* Hash function: H(e0 || e1) -> 32 bytes                              */
/* ------------------------------------------------------------------ */

static void bike_hash_e(uint8_t *out,
                        const uint64_t *e0, const uint64_t *e1,
                        const bike_params_t *params)
{
    pqc_sha256_ctx ctx;
    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, (const uint8_t *)e0,
                      params->r_words * sizeof(uint64_t));
    pqc_sha256_update(&ctx, (const uint8_t *)e1,
                      params->r_words * sizeof(uint64_t));
    pqc_sha256_final(&ctx, out);
}

/* Hash for shared secret: K(m || ct) -> 32 bytes */
static void bike_hash_k(uint8_t *ss,
                        const uint64_t *e0, const uint64_t *e1,
                        const uint8_t *ct,
                        const bike_params_t *params)
{
    pqc_sha256_ctx ctx;
    pqc_sha256_init(&ctx);
    pqc_sha256_update(&ctx, (const uint8_t *)e0,
                      params->r_words * sizeof(uint64_t));
    pqc_sha256_update(&ctx, (const uint8_t *)e1,
                      params->r_words * sizeof(uint64_t));
    pqc_sha256_update(&ctx, ct, params->ct_bytes);
    pqc_sha256_final(&ctx, ss);
}

/* ------------------------------------------------------------------ */
/* Internal keygen                                                      */
/* ------------------------------------------------------------------ */

void bike_keygen_internal(uint8_t *pk, uint8_t *sk,
                          const bike_params_t *params)
{
    uint32_t r = params->r;
    uint32_t r_words = params->r_words;
    uint8_t seed[BIKE_SEED_BYTES];
    uint8_t sigma[BIKE_SHARED_SECRET_BYTES];
    uint64_t *h0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *h1 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *h0_inv = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *h  = (uint64_t *)calloc(r_words, sizeof(uint64_t));

    if (!h0 || !h1 || !h0_inv || !h) {
        free(h0); free(h1); free(h0_inv); free(h);
        return;
    }

    /* Generate random seed */
    pqc_randombytes(seed, BIKE_SEED_BYTES);

    /* Generate sigma for implicit rejection */
    pqc_randombytes(sigma, BIKE_SHARED_SECRET_BYTES);

    /* Sample h0 and h1 as sparse polynomials of weight w/2 */
    uint8_t domain_h0[BIKE_SEED_BYTES + 1];
    uint8_t domain_h1[BIKE_SEED_BYTES + 1];
    memcpy(domain_h0, seed, BIKE_SEED_BYTES);
    domain_h0[BIKE_SEED_BYTES] = 0x01;
    memcpy(domain_h1, seed, BIKE_SEED_BYTES);
    domain_h1[BIKE_SEED_BYTES] = 0x02;

    bike_sample_sparse(h0, params->half_w, r,
                       domain_h0, sizeof(domain_h0));
    bike_sample_sparse(h1, params->half_w, r,
                       domain_h1, sizeof(domain_h1));

    /* Compute h = h1 * h0^{-1} mod (x^r - 1) */
    bike_gf2x_inv(h0_inv, h0, r);
    bike_gf2x_mul(h, h1, h0_inv, r);

    /* Pack keys */
    bike_pk_pack(pk, h, params);
    bike_sk_pack(sk, seed, h0, h1, sigma, params);

    /* Cleanup */
    pqc_memzero(seed, sizeof(seed));
    pqc_memzero(h0, r_words * sizeof(uint64_t));
    pqc_memzero(h1, r_words * sizeof(uint64_t));
    pqc_memzero(h0_inv, r_words * sizeof(uint64_t));
    free(h0); free(h1); free(h0_inv); free(h);
}

/* ------------------------------------------------------------------ */
/* Internal encaps                                                      */
/* ------------------------------------------------------------------ */

void bike_encaps_internal(uint8_t *ct, uint8_t *ss,
                          const uint8_t *pk,
                          const bike_params_t *params)
{
    uint32_t r = params->r;
    uint32_t r_words = params->r_words;

    uint64_t *h  = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *e0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *e1 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *c0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));

    if (!h || !e0 || !e1 || !c0) {
        free(h); free(e0); free(e1); free(c0);
        return;
    }

    /* Unpack public key */
    bike_pk_unpack(h, pk, params);

    /* Sample error (e0, e1) of weight t */
    uint8_t error_seed[BIKE_SEED_BYTES];
    pqc_randombytes(error_seed, BIKE_SEED_BYTES);
    bike_sample_error(e0, e1, params->t, r, error_seed, BIKE_SEED_BYTES);

    /* Compute c0 = e0 + e1 * h mod (x^r - 1) */
    {
        uint64_t *tmp = (uint64_t *)calloc(r_words, sizeof(uint64_t));
        if (tmp) {
            bike_gf2x_mul(tmp, e1, h, r);
            bike_gf2x_add(c0, e0, tmp, r_words);
            free(tmp);
        }
    }

    /* Compute c1 = H(e0 || e1) */
    uint8_t c1_hash[BIKE_SHARED_SECRET_BYTES];
    bike_hash_e(c1_hash, e0, e1, params);

    /* Pack ciphertext */
    bike_ct_pack(ct, c0, c1_hash, params);

    /* Compute shared secret = K(e0 || e1 || ct) */
    bike_hash_k(ss, e0, e1, ct, params);

    /* Cleanup */
    pqc_memzero(error_seed, sizeof(error_seed));
    pqc_memzero(e0, r_words * sizeof(uint64_t));
    pqc_memzero(e1, r_words * sizeof(uint64_t));
    free(h); free(e0); free(e1); free(c0);
}

/* ------------------------------------------------------------------ */
/* Internal decaps                                                      */
/* ------------------------------------------------------------------ */

int bike_decaps_internal(uint8_t *ss, const uint8_t *ct,
                         const uint8_t *sk,
                         const bike_params_t *params)
{
    uint32_t r = params->r;
    uint32_t r_words = params->r_words;

    uint8_t seed[BIKE_SEED_BYTES];
    uint8_t sigma[BIKE_SHARED_SECRET_BYTES];
    uint64_t *h0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *h1 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *c0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *syndrome = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *e0_prime = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *e1_prime = (uint64_t *)calloc(r_words, sizeof(uint64_t));

    if (!h0 || !h1 || !c0 || !syndrome || !e0_prime || !e1_prime) {
        free(h0); free(h1); free(c0); free(syndrome);
        free(e0_prime); free(e1_prime);
        return -1;
    }

    /* Unpack secret key */
    bike_sk_unpack(seed, h0, h1, sigma, sk, params);

    /* Unpack ciphertext */
    uint8_t c1_hash[BIKE_SHARED_SECRET_BYTES];
    bike_ct_unpack(c0, c1_hash, ct, params);

    /* Compute syndrome = c0 * h0 (with block-structured approach)
     * In BIKE, the syndrome for (c0, c1) with parity check (h0, h1) is:
     * s = c0 * h0 mod (x^r - 1) */
    bike_gf2x_mul(syndrome, c0, h0, r);

    /* Decode: recover error (e0', e1') */
    int decode_ok = bike_decode(e0_prime, e1_prime, syndrome, h0, h1, params);

    /* Verify: recompute c1' = H(e0' || e1') and compare with c1 */
    uint8_t c1_hash_prime[BIKE_SHARED_SECRET_BYTES];
    bike_hash_e(c1_hash_prime, e0_prime, e1_prime, params);

    int valid = (decode_ok == 0) ? 1 : 0;
    if (valid) {
        /* Constant-time comparison */
        if (pqc_memcmp_ct(c1_hash, c1_hash_prime,
                          BIKE_SHARED_SECRET_BYTES) != 0) {
            valid = 0;
        }
    }

    if (valid) {
        /* ss = K(e0' || e1' || ct) */
        bike_hash_k(ss, e0_prime, e1_prime, ct, params);
    } else {
        /* Implicit rejection: ss = K(sigma || ct) */
        pqc_sha256_ctx ctx;
        pqc_sha256_init(&ctx);
        pqc_sha256_update(&ctx, sigma, BIKE_SHARED_SECRET_BYTES);
        pqc_sha256_update(&ctx, ct, params->ct_bytes);
        pqc_sha256_final(&ctx, ss);
    }

    /* Cleanup */
    pqc_memzero(seed, sizeof(seed));
    pqc_memzero(sigma, sizeof(sigma));
    pqc_memzero(h0, r_words * sizeof(uint64_t));
    pqc_memzero(h1, r_words * sizeof(uint64_t));
    pqc_memzero(e0_prime, r_words * sizeof(uint64_t));
    pqc_memzero(e1_prime, r_words * sizeof(uint64_t));
    free(h0); free(h1); free(c0); free(syndrome);
    free(e0_prime); free(e1_prime);

    return valid ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Per-level wrappers                                                   */
/* ------------------------------------------------------------------ */

static pqc_status_t bike_l1_keygen(uint8_t *pk, uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l1(&p);
    bike_keygen_internal(pk, sk, &p);
    return PQC_OK;
}

static pqc_status_t bike_l1_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    bike_params_t p;
    bike_params_init_l1(&p);
    bike_encaps_internal(ct, ss, pk, &p);
    return PQC_OK;
}

static pqc_status_t bike_l1_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l1(&p);
    int rc = bike_decaps_internal(ss, ct, sk, &p);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

static pqc_status_t bike_l3_keygen(uint8_t *pk, uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l3(&p);
    bike_keygen_internal(pk, sk, &p);
    return PQC_OK;
}

static pqc_status_t bike_l3_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    bike_params_t p;
    bike_params_init_l3(&p);
    bike_encaps_internal(ct, ss, pk, &p);
    return PQC_OK;
}

static pqc_status_t bike_l3_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l3(&p);
    int rc = bike_decaps_internal(ss, ct, sk, &p);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

static pqc_status_t bike_l5_keygen(uint8_t *pk, uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l5(&p);
    bike_keygen_internal(pk, sk, &p);
    return PQC_OK;
}

static pqc_status_t bike_l5_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    bike_params_t p;
    bike_params_init_l5(&p);
    bike_encaps_internal(ct, ss, pk, &p);
    return PQC_OK;
}

static pqc_status_t bike_l5_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l5(&p);
    int rc = bike_decaps_internal(ss, ct, sk, &p);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_kem_vtable_t bike_l1_vtable = {
    .algorithm_name    = PQC_KEM_BIKE_L1,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "BIKE (NIST Round 4)",
    .public_key_size   = BIKE_L1_PK_BYTES,
    .secret_key_size   = BIKE_L1_SK_BYTES,
    .ciphertext_size   = BIKE_L1_CT_BYTES,
    .shared_secret_size = BIKE_SHARED_SECRET_BYTES,
    .keygen            = bike_l1_keygen,
    .encaps            = bike_l1_encaps,
    .decaps            = bike_l1_decaps,
};

static const pqc_kem_vtable_t bike_l3_vtable = {
    .algorithm_name    = PQC_KEM_BIKE_L3,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "BIKE (NIST Round 4)",
    .public_key_size   = BIKE_L3_PK_BYTES,
    .secret_key_size   = BIKE_L3_SK_BYTES,
    .ciphertext_size   = BIKE_L3_CT_BYTES,
    .shared_secret_size = BIKE_SHARED_SECRET_BYTES,
    .keygen            = bike_l3_keygen,
    .encaps            = bike_l3_encaps,
    .decaps            = bike_l3_decaps,
};

static const pqc_kem_vtable_t bike_l5_vtable = {
    .algorithm_name    = PQC_KEM_BIKE_L5,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "BIKE (NIST Round 4)",
    .public_key_size   = BIKE_L5_PK_BYTES,
    .secret_key_size   = BIKE_L5_SK_BYTES,
    .ciphertext_size   = BIKE_L5_CT_BYTES,
    .shared_secret_size = BIKE_SHARED_SECRET_BYTES,
    .keygen            = bike_l5_keygen,
    .encaps            = bike_l5_encaps,
    .decaps            = bike_l5_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_bike_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&bike_l1_vtable);
    rc |= pqc_kem_add_vtable(&bike_l3_vtable);
    rc |= pqc_kem_add_vtable(&bike_l5_vtable);
    return rc;
}
