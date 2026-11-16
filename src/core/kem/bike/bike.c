/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE (Bit Flipping Key Encapsulation), round 4 specification v5.1.
 *
 * Table 3 of the specification, with the encodings fixed by its official
 * known-answer tests (tests/kat/bike):
 *
 *   KeyGen:  64 random bytes; the first 32 seed (h0, h1) via
 *            Algorithm 3 (sampling.c), the last 32 are sigma.
 *            h = h1 * h0^-1.  pk = h,  sk = h0 || h1 || sigma.
 *   Encaps:  m <- 32 random bytes; (e0, e1) = H(m);
 *            c = (e0 + e1 h, m XOR L(e0, e1));  K = K(m, c).
 *   Decaps:  e' = decoder(c0 h0, h0, h1), with a decoding failure read
 *            as e' = (0, 0);  m' = c1 XOR L(e');
 *            K = K(m', c) if e' = H(m'), else K(sigma, c).
 *
 *   L(e0, e1) = SHA3-384(e0 || e1), first 32 bytes
 *   K(m, c)   = SHA3-384(m || c0 || c1), first 32 bytes
 *
 * Polynomials are encoded in ceil(r/8) bytes, least significant bit
 * first. (The specification text names SHA384; the reference
 * implementation and the KATs use SHA3-384.)
 *
 * Before 0.3.0 this file implemented a different KEM on the same code:
 * it sampled the error directly, sent H(e) as c1, keyed on e, and stored
 * a seed in the secret key. Nothing it produced interoperated with BIKE.
 *
 * Every step is constant time with respect to secrets, including the
 * choice between K(m', c) and K(sigma, c).
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
#include "bike.h"
#include "bike_params.h"
#include "core/common/ct_ops.h"

#define BIKE_M_BYTES  32     /* l = 256 bits: m, sigma, c1, K */

/* ------------------------------------------------------------------ */
/* Encoding                                                             */
/* ------------------------------------------------------------------ */

static void poly_to_bytes(uint8_t *out, const uint64_t *poly, uint32_t r)
{
    uint32_t r_bytes = (r + 7) / 8, i;
    uint8_t last = (uint8_t)(r % 8 ? (1u << (r % 8)) - 1 : 0xFF);
    for (i = 0; i < r_bytes; i++) {
        uint8_t b = (uint8_t)(poly[i / 8] >> (8 * (i % 8)));
        out[i] = i + 1 == r_bytes ? (uint8_t)(b & last) : b;   /* r public */
    }
}

static void bytes_to_poly(uint64_t *poly, const uint8_t *in, uint32_t r)
{
    uint32_t r_bytes = (r + 7) / 8, r_words = (r + 63) / 64, i;
    memset(poly, 0, r_words * sizeof(uint64_t));
    for (i = 0; i < r_bytes; i++)
        poly[i / 8] |= (uint64_t)in[i] << (8 * (i % 8));
    if (r % 64)
        poly[r_words - 1] &= ((uint64_t)1 << (r % 64)) - 1;
}

/* ------------------------------------------------------------------ */
/* L and K                                                              */
/* ------------------------------------------------------------------ */

/* out = L(e0, e1) = first 32 bytes of SHA3-384(e0 || e1). */
static int bike_L(uint8_t out[BIKE_M_BYTES], const uint64_t *e0,
                  const uint64_t *e1, const bike_params_t *p)
{
    uint8_t dg[PQC_SHA3_384_BYTES];
    uint8_t *buf = (uint8_t *)malloc(2 * p->r_bytes);
    if (!buf) return -1;
    poly_to_bytes(buf, e0, p->r);
    poly_to_bytes(buf + p->r_bytes, e1, p->r);
    pqc_sha3_384(dg, buf, 2 * p->r_bytes);
    memcpy(out, dg, BIKE_M_BYTES);
    pqc_memzero(buf, 2 * p->r_bytes);
    pqc_memzero(dg, sizeof dg);
    free(buf);
    return 0;
}

/* ss = K(m, c) = first 32 bytes of SHA3-384(m || c0 || c1). */
static int bike_K(uint8_t ss[BIKE_M_BYTES], const uint8_t m[BIKE_M_BYTES],
                  const uint8_t *ct, const bike_params_t *p)
{
    uint8_t dg[PQC_SHA3_384_BYTES];
    uint8_t *buf = (uint8_t *)malloc(BIKE_M_BYTES + p->ct_bytes);
    if (!buf) return -1;
    memcpy(buf, m, BIKE_M_BYTES);
    memcpy(buf + BIKE_M_BYTES, ct, p->ct_bytes);
    pqc_sha3_384(dg, buf, BIKE_M_BYTES + p->ct_bytes);
    memcpy(ss, dg, BIKE_M_BYTES);
    pqc_memzero(buf, BIKE_M_BYTES + p->ct_bytes);
    pqc_memzero(dg, sizeof dg);
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

int bike_keygen_internal(uint8_t *pk, uint8_t *sk,
                         const bike_params_t *params)
{
    uint32_t r = params->r, r_words = params->r_words;
    uint8_t seeds[2 * 32];
    int rc = -1;
    uint64_t *h0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *h1 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *h0_inv = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *h = (uint64_t *)calloc(r_words, sizeof(uint64_t));

    if (!h0 || !h1 || !h0_inv || !h)
        goto out;

    /* One call for both seeds, as the KATs require. A failing RNG must
     * not leave a key derived from stale stack contents. */
    if (pqc_randombytes(seeds, sizeof seeds) != PQC_OK)
        goto out;

    bike_sample_keys(h0, h1, seeds, params);
    if (bike_gf2x_inv(h0_inv, h0, r) != 0)
        goto out;
    bike_gf2x_mul(h, h1, h0_inv, r);

    poly_to_bytes(pk, h, r);
    poly_to_bytes(sk, h0, r);
    poly_to_bytes(sk + params->r_bytes, h1, r);
    memcpy(sk + 2 * params->r_bytes, seeds + 32, BIKE_M_BYTES);   /* sigma */
    rc = 0;

out:
    pqc_memzero(seeds, sizeof seeds);
    if (h0) pqc_memzero(h0, r_words * sizeof(uint64_t));
    if (h1) pqc_memzero(h1, r_words * sizeof(uint64_t));
    if (h0_inv) pqc_memzero(h0_inv, r_words * sizeof(uint64_t));
    free(h0); free(h1); free(h0_inv); free(h);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Encapsulation                                                        */
/* ------------------------------------------------------------------ */

int bike_encaps_internal(uint8_t *ct, uint8_t *ss,
                         const uint8_t *pk,
                         const bike_params_t *params)
{
    uint32_t r = params->r, r_words = params->r_words, i;
    uint8_t m[BIKE_M_BYTES], l[BIKE_M_BYTES];
    int rc = -1;
    uint64_t *h  = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *e0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *e1 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *c0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));

    if (!h || !e0 || !e1 || !c0)
        goto out;
    if (pqc_randombytes(m, BIKE_M_BYTES) != PQC_OK)
        goto out;

    bytes_to_poly(h, pk, r);
    bike_sample_error(e0, e1, m, params);              /* (e0, e1) = H(m) */

    bike_gf2x_mul(c0, e1, h, r);                        /* c0 = e0 + e1 h */
    bike_gf2x_add(c0, c0, e0, r_words);
    poly_to_bytes(ct, c0, r);

    if (bike_L(l, e0, e1, params) != 0)                 /* c1 = m ^ L(e) */
        goto out;
    for (i = 0; i < BIKE_M_BYTES; i++)
        ct[params->r_bytes + i] = m[i] ^ l[i];

    if (bike_K(ss, m, ct, params) != 0)                 /* K = K(m, c) */
        goto out;
    rc = 0;

out:
    pqc_memzero(m, sizeof m);
    pqc_memzero(l, sizeof l);
    if (e0) pqc_memzero(e0, r_words * sizeof(uint64_t));
    if (e1) pqc_memzero(e1, r_words * sizeof(uint64_t));
    free(h); free(e0); free(e1); free(c0);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Decapsulation                                                        */
/* ------------------------------------------------------------------ */

int bike_decaps_internal(uint8_t *ss, const uint8_t *ct,
                         const uint8_t *sk,
                         const bike_params_t *params)
{
    uint32_t r = params->r, r_words = params->r_words, i;
    uint8_t m[BIKE_M_BYTES], l[BIKE_M_BYTES];
    const uint8_t *sigma = sk + 2 * params->r_bytes;
    uint64_t diff = 0, okmask;
    uint32_t valid;
    int ok, rc = -1;
    uint64_t *h0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *h1 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *c0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *e0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *e1 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *f0 = (uint64_t *)calloc(r_words, sizeof(uint64_t));
    uint64_t *f1 = (uint64_t *)calloc(r_words, sizeof(uint64_t));

    if (!h0 || !h1 || !c0 || !e0 || !e1 || !f0 || !f1)
        goto out;

    bytes_to_poly(h0, sk, r);
    bytes_to_poly(h1, sk + params->r_bytes, r);
    bytes_to_poly(c0, ct, r);

    /* 1: e' = decoder(c0 h0, h0, h1); a failure (ok = 0) is e' = (0, 0). */
    ok = bike_decode_ct(e0, e1, c0, h0, h1, params);
    if (ok < 0)                       /* allocation failure only */
        goto out;
    okmask = 0 - (uint64_t)ok;
    for (i = 0; i < r_words; i++) {
        e0[i] &= okmask;
        e1[i] &= okmask;
    }

    /* 2: m' = c1 XOR L(e') */
    if (bike_L(l, e0, e1, params) != 0)
        goto out;
    for (i = 0; i < BIKE_M_BYTES; i++)
        m[i] = ct[params->r_bytes + i] ^ l[i];

    /* 3: valid iff e' = H(m'), compared without branching. */
    bike_sample_error(f0, f1, m, params);
    for (i = 0; i < r_words; i++)
        diff |= (e0[i] ^ f0[i]) | (e1[i] ^ f1[i]);
    valid = (uint32_t)(((diff | (0 - diff)) >> 63) ^ 1);

    /*
     * K = K(m', c) if valid, else K(sigma, c): select the first input by
     * mask and hash once, so neither the control flow nor the hash
     * inputs' lengths depend on validity.
     */
    pqc_ct_cmov(m, sigma, BIKE_M_BYTES, valid ^ 1u);
    if (bike_K(ss, m, ct, params) != 0)
        goto out;
    rc = 0;

out:
    pqc_memzero(m, sizeof m);
    pqc_memzero(l, sizeof l);
    if (h0) pqc_memzero(h0, r_words * sizeof(uint64_t));
    if (h1) pqc_memzero(h1, r_words * sizeof(uint64_t));
    if (e0) pqc_memzero(e0, r_words * sizeof(uint64_t));
    if (e1) pqc_memzero(e1, r_words * sizeof(uint64_t));
    if (f0) pqc_memzero(f0, r_words * sizeof(uint64_t));
    if (f1) pqc_memzero(f1, r_words * sizeof(uint64_t));
    free(h0); free(h1); free(c0); free(e0); free(e1); free(f0); free(f1);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Per-level wrappers                                                   */
/* ------------------------------------------------------------------ */

static pqc_status_t bike_l1_keygen(uint8_t *pk, uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l1(&p);
    if (bike_keygen_internal(pk, sk, &p) != 0)
        return PQC_ERROR_RNG_FAILED;
    return PQC_OK;
}

static pqc_status_t bike_l1_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    bike_params_t p;
    bike_params_init_l1(&p);
    if (bike_encaps_internal(ct, ss, pk, &p) != 0)
        return PQC_ERROR_RNG_FAILED;
    return PQC_OK;
}

static pqc_status_t bike_l1_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l1(&p);
    /* The validity bit never escapes (implicit rejection): the only
     * failure reported is running out of memory, which does not depend
     * on the ciphertext. */
    if (bike_decaps_internal(ss, ct, sk, &p) != 0)
        return PQC_ERROR_ALLOC;
    return PQC_OK;
}

static pqc_status_t bike_l3_keygen(uint8_t *pk, uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l3(&p);
    if (bike_keygen_internal(pk, sk, &p) != 0)
        return PQC_ERROR_RNG_FAILED;
    return PQC_OK;
}

static pqc_status_t bike_l3_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    bike_params_t p;
    bike_params_init_l3(&p);
    if (bike_encaps_internal(ct, ss, pk, &p) != 0)
        return PQC_ERROR_RNG_FAILED;
    return PQC_OK;
}

static pqc_status_t bike_l3_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l3(&p);
    /* The validity bit never escapes (implicit rejection): the only
     * failure reported is running out of memory, which does not depend
     * on the ciphertext. */
    if (bike_decaps_internal(ss, ct, sk, &p) != 0)
        return PQC_ERROR_ALLOC;
    return PQC_OK;
}

static pqc_status_t bike_l5_keygen(uint8_t *pk, uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l5(&p);
    if (bike_keygen_internal(pk, sk, &p) != 0)
        return PQC_ERROR_RNG_FAILED;
    return PQC_OK;
}

static pqc_status_t bike_l5_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    bike_params_t p;
    bike_params_init_l5(&p);
    if (bike_encaps_internal(ct, ss, pk, &p) != 0)
        return PQC_ERROR_RNG_FAILED;
    return PQC_OK;
}

static pqc_status_t bike_l5_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    bike_params_t p;
    bike_params_init_l5(&p);
    /* The validity bit never escapes (implicit rejection): the only
     * failure reported is running out of memory, which does not depend
     * on the ciphertext. */
    if (bike_decaps_internal(ss, ct, sk, &p) != 0)
        return PQC_ERROR_ALLOC;
    return PQC_OK;
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
