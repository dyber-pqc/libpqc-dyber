/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC (Hamming Quasi-Cyclic) KEM - full implementation.
 *
 * HQC is a code-based KEM built on quasi-cyclic codes. The public key
 * is h = x + y * s in (F_2[X] / (X^n - 1)), where (x, y) is the
 * secret key and s is derived from a public seed. Encapsulation
 * samples (r1, r2, e) and computes u = r1 + r2*s, v = r2*h + e + encode(m).
 * Decapsulation recovers m via y*u + v = y*r1 + r2*(y*s + h) + e + encode(m),
 * then applies the concatenated code decoder.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/kem/kem_internal.h"
#include "core/common/hash/sha3.h"
#include "core/common/hash/sha2.h"
#include "hqc.h"
#include "hqc_params.h"

/* ------------------------------------------------------------------ */
/* Maximum allocation sizes (stack-based)                               */
/* ------------------------------------------------------------------ */

#define HQC_VEC_N_WORDS   ((HQC_MAX_N + 63) / 64)
#define HQC_VEC_N1N2_WORDS ((HQC_MAX_N1N2 + 63) / 64)

/* ------------------------------------------------------------------ */
/* Vector operations in F_2[X] / (X^n - 1)                             */
/* ------------------------------------------------------------------ */

void hqc_vect_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                  uint32_t n)
{
    uint32_t n_words = (n + 63) / 64;
    for (uint32_t i = 0; i < n_words; i++) {
        o[i] = a[i] ^ b[i];
    }
}

/*
 * Polynomial multiplication: o = a * b mod (X^n - 1).
 * Uses schoolbook multiplication on the dense representation,
 * then word-based reduction modulo (X^n - 1).
 */
void hqc_vect_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                  uint32_t n)
{
    uint32_t n_words = (n + 63) / 64;
    /* Product can have up to 2n-1 bits, so need (2n-1+63)/64 + 1 words */
    uint32_t result_words = n_words * 2 + 1;
    uint64_t result[HQC_VEC_N_WORDS * 2 + 2];

    memset(result, 0, result_words * sizeof(uint64_t));

    /* Schoolbook multiplication: for each set bit in b,
     * XOR the shifted copy of a into result */
    for (uint32_t i = 0; i < n; i++) {
        if (!((b[i / 64] >> (i % 64)) & 1)) continue;

        uint32_t word_offset = i / 64;
        uint32_t bit_offset  = i % 64;

        if (bit_offset == 0) {
            for (uint32_t j = 0; j < n_words; j++) {
                result[word_offset + j] ^= a[j];
            }
        } else {
            for (uint32_t j = 0; j < n_words; j++) {
                result[word_offset + j]     ^= a[j] << bit_offset;
                result[word_offset + j + 1] ^= a[j] >> (64 - bit_offset);
            }
        }
    }

    /*
     * Reduce modulo (X^n - 1) using word-level operations.
     * For each bit at position p >= n in result, it wraps to position p - n.
     * We shift the upper portion (bits n..2n-2) and XOR it into the lower.
     */
    {
        uint32_t bit_off = n % 64;
        uint32_t word_off = n / 64;

        if (bit_off == 0) {
            /* n is a multiple of 64: just XOR upper words into lower */
            for (uint32_t j = 0; j < n_words; j++) {
                result[j] ^= result[word_off + j];
            }
        } else {
            /* General case: the upper bits start at bit_off within word word_off */
            for (uint32_t j = 0; j < n_words; j++) {
                uint64_t hi = result[word_off + j] >> bit_off;
                if (word_off + j + 1 < result_words) {
                    hi |= result[word_off + j + 1] << (64 - bit_off);
                }
                result[j] ^= hi;
            }
        }
    }

    memcpy(o, result, n_words * sizeof(uint64_t));
    /* Clear trailing bits above n */
    uint32_t rem = n % 64;
    if (rem) {
        o[n_words - 1] &= ((uint64_t)1 << rem) - 1;
    }
}

/* ------------------------------------------------------------------ */
/* Sample a random vector from a seed using SHAKE256                     */
/* ------------------------------------------------------------------ */

void hqc_vect_set_random(uint64_t *v, uint32_t n,
                         const uint8_t *seed, size_t seedlen)
{
    uint32_t n_bytes = (n + 7) / 8;
    uint32_t n_words = (n + 63) / 64;
    uint8_t buf[HQC_MAX_N_BYTES];

    pqc_shake256(buf, n_bytes, seed, seedlen);

    memset(v, 0, n_words * sizeof(uint64_t));
    memcpy(v, buf, n_bytes);

    /* Clear trailing bits */
    uint32_t rem = n % 64;
    if (rem) {
        v[n_words - 1] &= ((uint64_t)1 << rem) - 1;
    }
}

/* ------------------------------------------------------------------ */
/* Sample a random vector of given Hamming weight using SHAKE256        */
/* ------------------------------------------------------------------ */

void hqc_vect_set_random_fixed_weight(uint64_t *v, uint32_t weight,
                                       uint32_t n,
                                       const uint8_t *seed, size_t seedlen)
{
    uint32_t n_words = (n + 63) / 64;
    memset(v, 0, n_words * sizeof(uint64_t));

    /* Use SHAKE256 to generate random positions via rejection sampling */
    pqc_shake256_ctx ctx;
    pqc_shake256_init(&ctx);
    pqc_shake256_absorb(&ctx, seed, seedlen);
    pqc_shake256_finalize(&ctx);

    uint32_t count = 0;
    uint32_t positions[512]; /* max weight across all parameter sets */

    while (count < weight) {
        uint8_t buf[4];
        pqc_shake256_squeeze(&ctx, buf, 4);
        uint32_t pos = ((uint32_t)buf[0] |
                        ((uint32_t)buf[1] << 8) |
                        ((uint32_t)buf[2] << 16) |
                        ((uint32_t)buf[3] << 24));
        pos = pos % n;

        /* Check for duplicate positions */
        int dup = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (positions[i] == pos) {
                dup = 1;
                break;
            }
        }
        if (!dup) {
            positions[count] = pos;
            v[pos / 64] |= (uint64_t)1 << (pos % 64);
            count++;
        }
    }

    pqc_memzero(&ctx, sizeof(ctx));
}

/* ------------------------------------------------------------------ */
/* Extract bits from a vector into a byte array for coding              */
/* ------------------------------------------------------------------ */

static void vect_to_code_bytes(uint8_t *dest, const uint64_t *src,
                               uint32_t nbits)
{
    uint32_t nbytes = (nbits + 7) / 8;
    memcpy(dest, src, nbytes);
    uint32_t rem = nbits % 8;
    if (rem) {
        dest[nbytes - 1] &= (uint8_t)((1u << rem) - 1);
    }
}

static void code_bytes_to_vect(uint64_t *dest, const uint8_t *src,
                               uint32_t nbits)
{
    uint32_t nbytes = (nbits + 7) / 8;
    uint32_t nwords = (nbits + 63) / 64;
    memset(dest, 0, nwords * sizeof(uint64_t));
    memcpy(dest, src, nbytes);
    uint32_t rem = nbits % 64;
    if (rem) {
        dest[nwords - 1] &= ((uint64_t)1 << rem) - 1;
    }
}

/* ------------------------------------------------------------------ */
/* Internal keygen                                                      */
/* ------------------------------------------------------------------ */

void hqc_keygen_internal(uint8_t *pk, uint8_t *sk,
                         const hqc_params_t *params)
{
    uint32_t n = params->n;
    uint8_t seed_sk[HQC_SEED_BYTES];
    uint8_t seed_pk[HQC_SEED_BYTES];
    uint64_t x[HQC_VEC_N_WORDS];
    uint64_t y[HQC_VEC_N_WORDS];
    uint64_t s[HQC_VEC_N_WORDS];
    uint64_t h[HQC_VEC_N_WORDS];
    uint64_t tmp[HQC_VEC_N_WORDS];

    /* Generate random seeds */
    pqc_randombytes(seed_sk, HQC_SEED_BYTES);
    pqc_randombytes(seed_pk, HQC_SEED_BYTES);

    /* Derive x (weight w) and y (weight w) from seed_sk */
    uint8_t domain_x[HQC_SEED_BYTES + 1];
    uint8_t domain_y[HQC_SEED_BYTES + 1];
    memcpy(domain_x, seed_sk, HQC_SEED_BYTES);
    domain_x[HQC_SEED_BYTES] = 0x01;
    memcpy(domain_y, seed_sk, HQC_SEED_BYTES);
    domain_y[HQC_SEED_BYTES] = 0x02;

    hqc_vect_set_random_fixed_weight(x, params->w, n,
                                      domain_x, sizeof(domain_x));
    hqc_vect_set_random_fixed_weight(y, params->w, n,
                                      domain_y, sizeof(domain_y));

    /* Derive public vector s from seed_pk */
    hqc_vect_set_random(s, n, seed_pk, HQC_SEED_BYTES);

    /* Compute h = x + y * s mod (X^n - 1) */
    hqc_vect_mul(tmp, y, s, n);
    hqc_vect_add(h, x, tmp, n);

    /* Pack keys */
    hqc_pk_pack(pk, seed_pk, h, params);
    hqc_sk_pack(sk, seed_sk, pk, params);

    /* Cleanup */
    pqc_memzero(seed_sk, sizeof(seed_sk));
    pqc_memzero(x, sizeof(x));
    pqc_memzero(y, sizeof(y));
}

/* ------------------------------------------------------------------ */
/* Internal encaps                                                      */
/* ------------------------------------------------------------------ */

void hqc_encaps_internal(uint8_t *ct, uint8_t *ss,
                         const uint8_t *pk,
                         const hqc_params_t *params)
{
    uint32_t n = params->n;
    uint32_t k = params->k;
    uint32_t n1n2 = params->n1n2;
    uint8_t seed_pk[HQC_SEED_BYTES];
    uint64_t h[HQC_VEC_N_WORDS];
    uint64_t s[HQC_VEC_N_WORDS];
    uint64_t r1[HQC_VEC_N_WORDS];
    uint64_t r2[HQC_VEC_N_WORDS];
    uint64_t e[HQC_VEC_N1N2_WORDS];
    uint64_t u[HQC_VEC_N_WORDS];
    uint64_t v[HQC_VEC_N1N2_WORDS];
    uint64_t tmp[HQC_VEC_N_WORDS];
    uint8_t m[HQC_MAX_K];
    uint8_t encoded[HQC_MAX_N1N2_BYTES];
    uint8_t salt[HQC_SALT_SIZE_BYTES];
    uint8_t theta_seed[HQC_SHA512_BYTES];

    /* Unpack public key */
    hqc_pk_unpack(seed_pk, h, pk, params);
    hqc_vect_set_random(s, n, seed_pk, HQC_SEED_BYTES);

    /* Generate random message m */
    pqc_randombytes(m, k);

    /* Generate salt */
    pqc_randombytes(salt, HQC_SALT_SIZE_BYTES);

    /* Derive theta = SHA512(m || pk || salt) for randomness */
    {
        pqc_sha512_ctx hash_ctx;
        pqc_sha512_init(&hash_ctx);
        pqc_sha512_update(&hash_ctx, m, k);
        pqc_sha512_update(&hash_ctx, pk, params->pk_bytes);
        pqc_sha512_update(&hash_ctx, salt, HQC_SALT_SIZE_BYTES);
        pqc_sha512_final(&hash_ctx, theta_seed);
    }

    /* Derive r1, r2, e from theta */
    uint8_t domain_r1[HQC_SHA512_BYTES + 1];
    uint8_t domain_r2[HQC_SHA512_BYTES + 1];
    uint8_t domain_e[HQC_SHA512_BYTES + 1];
    memcpy(domain_r1, theta_seed, HQC_SHA512_BYTES);
    domain_r1[HQC_SHA512_BYTES] = 0x01;
    memcpy(domain_r2, theta_seed, HQC_SHA512_BYTES);
    domain_r2[HQC_SHA512_BYTES] = 0x02;
    memcpy(domain_e, theta_seed, HQC_SHA512_BYTES);
    domain_e[HQC_SHA512_BYTES] = 0x03;

    hqc_vect_set_random_fixed_weight(r1, params->wr, n,
                                      domain_r1, sizeof(domain_r1));
    hqc_vect_set_random_fixed_weight(r2, params->wr, n,
                                      domain_r2, sizeof(domain_r2));
    /* e is sampled over n1n2 bits */
    memset(e, 0, sizeof(e));
    hqc_vect_set_random_fixed_weight(e, params->we, n1n2,
                                      domain_e, sizeof(domain_e));

    /* Encode message using concatenated code */
    hqc_code_encode(encoded, m, params);

    /* Compute u = r1 + r2 * s mod (X^n - 1) */
    hqc_vect_mul(tmp, r2, s, n);
    hqc_vect_add(u, r1, tmp, n);

    /* Compute v = r2 * h (projected to n1n2 bits) + e + encode(m) */
    {
        uint64_t r2h[HQC_VEC_N_WORDS];
        hqc_vect_mul(r2h, r2, h, n);

        /* Truncate r2h to n1n2 bits and store in v */
        uint32_t n1n2_words = (n1n2 + 63) / 64;
        memset(v, 0, n1n2_words * sizeof(uint64_t));
        uint32_t copy_words = n1n2_words < (uint32_t)HQC_VEC_N_WORDS ?
                              n1n2_words : (uint32_t)HQC_VEC_N_WORDS;
        memcpy(v, r2h, copy_words * sizeof(uint64_t));
        uint32_t rem = n1n2 % 64;
        if (rem) {
            v[n1n2_words - 1] &= ((uint64_t)1 << rem) - 1;
        }

        /* v = v + e */
        for (uint32_t i = 0; i < n1n2_words; i++) {
            v[i] ^= e[i];
        }

        /* v = v + encode(m) */
        uint64_t enc_vect[HQC_VEC_N1N2_WORDS];
        code_bytes_to_vect(enc_vect, encoded, n1n2);
        for (uint32_t i = 0; i < n1n2_words; i++) {
            v[i] ^= enc_vect[i];
        }
    }

    /* Pack ciphertext */
    hqc_ct_pack(ct, u, v, salt, params);

    /* Compute shared secret = SHA512(m || ct) */
    {
        pqc_sha512_ctx hash_ctx;
        pqc_sha512_init(&hash_ctx);
        pqc_sha512_update(&hash_ctx, m, k);
        pqc_sha512_update(&hash_ctx, ct, params->ct_bytes);
        pqc_sha512_final(&hash_ctx, ss);
    }

    /* Cleanup */
    pqc_memzero(m, sizeof(m));
    pqc_memzero(theta_seed, sizeof(theta_seed));
    pqc_memzero(r1, sizeof(r1));
    pqc_memzero(r2, sizeof(r2));
    pqc_memzero(e, sizeof(e));
}

/* ------------------------------------------------------------------ */
/* Internal decaps                                                      */
/* ------------------------------------------------------------------ */

int hqc_decaps_internal(uint8_t *ss, const uint8_t *ct,
                        const uint8_t *sk,
                        const hqc_params_t *params)
{
    uint32_t n = params->n;
    uint32_t k = params->k;
    uint32_t n1n2 = params->n1n2;
    uint8_t seed_sk[HQC_SEED_BYTES];
    uint8_t pk_buf[HQC_MAX_PK_BYTES];
    uint8_t seed_pk[HQC_SEED_BYTES];
    uint64_t x[HQC_VEC_N_WORDS];
    uint64_t y[HQC_VEC_N_WORDS];
    uint64_t h[HQC_VEC_N_WORDS];
    uint64_t s[HQC_VEC_N_WORDS];
    uint64_t u[HQC_VEC_N_WORDS];
    uint64_t v[HQC_VEC_N1N2_WORDS];
    uint8_t salt[HQC_SALT_SIZE_BYTES];
    uint8_t m_prime[HQC_MAX_K];
    uint8_t decoded_bytes[HQC_MAX_N1N2_BYTES];

    /* Unpack secret key */
    hqc_sk_unpack(seed_sk, pk_buf, sk, params);

    /* Re-derive x, y from seed_sk */
    uint8_t domain_x[HQC_SEED_BYTES + 1];
    uint8_t domain_y[HQC_SEED_BYTES + 1];
    memcpy(domain_x, seed_sk, HQC_SEED_BYTES);
    domain_x[HQC_SEED_BYTES] = 0x01;
    memcpy(domain_y, seed_sk, HQC_SEED_BYTES);
    domain_y[HQC_SEED_BYTES] = 0x02;

    hqc_vect_set_random_fixed_weight(x, params->w, n,
                                      domain_x, sizeof(domain_x));
    hqc_vect_set_random_fixed_weight(y, params->w, n,
                                      domain_y, sizeof(domain_y));

    /* Unpack public key to get h and seed_pk */
    hqc_pk_unpack(seed_pk, h, pk_buf, params);
    hqc_vect_set_random(s, n, seed_pk, HQC_SEED_BYTES);

    /* Unpack ciphertext */
    hqc_ct_unpack(u, v, salt, ct, params);

    /* Compute y * u mod (X^n - 1) */
    uint64_t yu[HQC_VEC_N_WORDS];
    hqc_vect_mul(yu, y, u, n);

    /* Compute v - y*u (XOR in GF(2)): this should approximate encode(m) + noise */
    uint32_t n1n2_words = (n1n2 + 63) / 64;
    uint64_t diff[HQC_VEC_N1N2_WORDS];
    memset(diff, 0, sizeof(diff));

    /* Copy v into diff */
    memcpy(diff, v, n1n2_words * sizeof(uint64_t));

    /* XOR truncated yu */
    uint32_t copy_words = n1n2_words < (uint32_t)HQC_VEC_N_WORDS ?
                          n1n2_words : (uint32_t)HQC_VEC_N_WORDS;
    for (uint32_t i = 0; i < copy_words; i++) {
        diff[i] ^= yu[i];
    }
    uint32_t rem = n1n2 % 64;
    if (rem) {
        diff[n1n2_words - 1] &= ((uint64_t)1 << rem) - 1;
    }

    /* Convert diff to bytes and decode */
    vect_to_code_bytes(decoded_bytes, diff, n1n2);
    int decode_rc = hqc_code_decode(m_prime, decoded_bytes, params);

    /* Re-encapsulate to verify */
    uint8_t theta_seed[HQC_SHA512_BYTES];
    {
        pqc_sha512_ctx hash_ctx;
        pqc_sha512_init(&hash_ctx);
        pqc_sha512_update(&hash_ctx, m_prime, k);
        pqc_sha512_update(&hash_ctx, pk_buf, params->pk_bytes);
        pqc_sha512_update(&hash_ctx, salt, HQC_SALT_SIZE_BYTES);
        pqc_sha512_final(&hash_ctx, theta_seed);
    }

    /* Re-derive r1', r2', e' and recompute u', v' */
    uint64_t r1p[HQC_VEC_N_WORDS], r2p[HQC_VEC_N_WORDS];
    uint64_t ep[HQC_VEC_N1N2_WORDS];
    uint64_t up[HQC_VEC_N_WORDS], vp[HQC_VEC_N1N2_WORDS];

    uint8_t dr1[HQC_SHA512_BYTES + 1], dr2[HQC_SHA512_BYTES + 1];
    uint8_t de[HQC_SHA512_BYTES + 1];
    memcpy(dr1, theta_seed, HQC_SHA512_BYTES); dr1[HQC_SHA512_BYTES] = 0x01;
    memcpy(dr2, theta_seed, HQC_SHA512_BYTES); dr2[HQC_SHA512_BYTES] = 0x02;
    memcpy(de,  theta_seed, HQC_SHA512_BYTES); de[HQC_SHA512_BYTES]  = 0x03;

    hqc_vect_set_random_fixed_weight(r1p, params->wr, n, dr1, sizeof(dr1));
    hqc_vect_set_random_fixed_weight(r2p, params->wr, n, dr2, sizeof(dr2));
    memset(ep, 0, sizeof(ep));
    hqc_vect_set_random_fixed_weight(ep, params->we, n1n2, de, sizeof(de));

    /* Recompute u' = r1' + r2' * s */
    {
        uint64_t tmp[HQC_VEC_N_WORDS];
        hqc_vect_mul(tmp, r2p, s, n);
        hqc_vect_add(up, r1p, tmp, n);
    }

    /* Recompute v' = r2'*h + e' + encode(m') */
    {
        uint64_t r2h[HQC_VEC_N_WORDS];
        uint8_t re_encoded[HQC_MAX_N1N2_BYTES];
        hqc_vect_mul(r2h, r2p, h, n);
        hqc_code_encode(re_encoded, m_prime, params);

        memset(vp, 0, n1n2_words * sizeof(uint64_t));
        uint32_t cw = n1n2_words < (uint32_t)HQC_VEC_N_WORDS ?
                      n1n2_words : (uint32_t)HQC_VEC_N_WORDS;
        memcpy(vp, r2h, cw * sizeof(uint64_t));
        if (rem) vp[n1n2_words - 1] &= ((uint64_t)1 << rem) - 1;

        for (uint32_t i = 0; i < n1n2_words; i++) {
            vp[i] ^= ep[i];
        }
        uint64_t enc_vect[HQC_VEC_N1N2_WORDS];
        code_bytes_to_vect(enc_vect, re_encoded, n1n2);
        for (uint32_t i = 0; i < n1n2_words; i++) {
            vp[i] ^= enc_vect[i];
        }
    }

    /* Compare u == u' and v == v' */
    uint32_t n_words = (n + 63) / 64;
    int valid = (decode_rc == 0) ? 1 : 0;

    if (valid) {
        for (uint32_t i = 0; i < n_words; i++) {
            if (u[i] != up[i]) { valid = 0; break; }
        }
    }
    if (valid) {
        for (uint32_t i = 0; i < n1n2_words; i++) {
            if (v[i] != vp[i]) { valid = 0; break; }
        }
    }

    /* Compute shared secret */
    if (valid) {
        /* ss = SHA512(m' || ct) */
        pqc_sha512_ctx hash_ctx;
        pqc_sha512_init(&hash_ctx);
        pqc_sha512_update(&hash_ctx, m_prime, k);
        pqc_sha512_update(&hash_ctx, ct, params->ct_bytes);
        pqc_sha512_final(&hash_ctx, ss);
    } else {
        /* Implicit rejection: ss = SHA512(seed_sk || ct) */
        pqc_sha512_ctx hash_ctx;
        pqc_sha512_init(&hash_ctx);
        pqc_sha512_update(&hash_ctx, seed_sk, HQC_SEED_BYTES);
        pqc_sha512_update(&hash_ctx, ct, params->ct_bytes);
        pqc_sha512_final(&hash_ctx, ss);
    }

    /* Cleanup */
    pqc_memzero(seed_sk, sizeof(seed_sk));
    pqc_memzero(x, sizeof(x));
    pqc_memzero(y, sizeof(y));
    pqc_memzero(m_prime, sizeof(m_prime));
    pqc_memzero(theta_seed, sizeof(theta_seed));

    return valid ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Per-level wrappers                                                   */
/* ------------------------------------------------------------------ */

static pqc_status_t hqc128_keygen(uint8_t *pk, uint8_t *sk)
{
    hqc_params_t p;
    hqc_params_init_128(&p);
    hqc_keygen_internal(pk, sk, &p);
    return PQC_OK;
}

static pqc_status_t hqc128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    hqc_params_t p;
    hqc_params_init_128(&p);
    hqc_encaps_internal(ct, ss, pk, &p);
    return PQC_OK;
}

static pqc_status_t hqc128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    hqc_params_t p;
    hqc_params_init_128(&p);
    int rc = hqc_decaps_internal(ss, ct, sk, &p);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

static pqc_status_t hqc192_keygen(uint8_t *pk, uint8_t *sk)
{
    hqc_params_t p;
    hqc_params_init_192(&p);
    hqc_keygen_internal(pk, sk, &p);
    return PQC_OK;
}

static pqc_status_t hqc192_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    hqc_params_t p;
    hqc_params_init_192(&p);
    hqc_encaps_internal(ct, ss, pk, &p);
    return PQC_OK;
}

static pqc_status_t hqc192_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    hqc_params_t p;
    hqc_params_init_192(&p);
    int rc = hqc_decaps_internal(ss, ct, sk, &p);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

static pqc_status_t hqc256_keygen(uint8_t *pk, uint8_t *sk)
{
    hqc_params_t p;
    hqc_params_init_256(&p);
    hqc_keygen_internal(pk, sk, &p);
    return PQC_OK;
}

static pqc_status_t hqc256_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    hqc_params_t p;
    hqc_params_init_256(&p);
    hqc_encaps_internal(ct, ss, pk, &p);
    return PQC_OK;
}

static pqc_status_t hqc256_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    hqc_params_t p;
    hqc_params_init_256(&p);
    int rc = hqc_decaps_internal(ss, ct, sk, &p);
    return (rc == 0) ? PQC_OK : PQC_ERROR_DECAPSULATION_FAILED;
}

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

static const pqc_kem_vtable_t hqc128_vtable = {
    .algorithm_name    = PQC_KEM_HQC_128,
    .security_level    = PQC_SECURITY_LEVEL_1,
    .nist_standard     = "HQC (NIST Round 4)",
    .public_key_size   = HQC_128_PK_BYTES,
    .secret_key_size   = HQC_128_SK_BYTES,
    .ciphertext_size   = HQC_128_CT_BYTES,
    .shared_secret_size = HQC_SHARED_SECRET_BYTES,
    .keygen            = hqc128_keygen,
    .encaps            = hqc128_encaps,
    .decaps            = hqc128_decaps,
};

static const pqc_kem_vtable_t hqc192_vtable = {
    .algorithm_name    = PQC_KEM_HQC_192,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "HQC (NIST Round 4)",
    .public_key_size   = HQC_192_PK_BYTES,
    .secret_key_size   = HQC_192_SK_BYTES,
    .ciphertext_size   = HQC_192_CT_BYTES,
    .shared_secret_size = HQC_SHARED_SECRET_BYTES,
    .keygen            = hqc192_keygen,
    .encaps            = hqc192_encaps,
    .decaps            = hqc192_decaps,
};

static const pqc_kem_vtable_t hqc256_vtable = {
    .algorithm_name    = PQC_KEM_HQC_256,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "HQC (NIST Round 4)",
    .public_key_size   = HQC_256_PK_BYTES,
    .secret_key_size   = HQC_256_SK_BYTES,
    .ciphertext_size   = HQC_256_CT_BYTES,
    .shared_secret_size = HQC_SHARED_SECRET_BYTES,
    .keygen            = hqc256_keygen,
    .encaps            = hqc256_encaps,
    .decaps            = hqc256_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_kem_hqc_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&hqc128_vtable);
    rc |= pqc_kem_add_vtable(&hqc192_vtable);
    rc |= pqc_kem_add_vtable(&hqc256_vtable);
    return rc;
}
