/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ECDSA over NIST P-256 (FIPS 186-5).
 *
 * Deterministic nonce generation per RFC 6979 using HMAC-SHA-256.
 * Signature format: (r, s), each 32 bytes big-endian.
 */

#include <string.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/rand.h"
#include "core/common/hash/sha2.h"
#include "field_p256.h"
#include "ecdsa_p256.h"

/* Defined in field_p256.c */
extern uint64_t sub256_v2(p256_fe r, const p256_fe a, const p256_fe b);

/* ------------------------------------------------------------------ */
/* RFC 6979 deterministic nonce generation                              */
/* ------------------------------------------------------------------ */

/*
 * Generates k deterministically from the private key and message hash.
 * Uses HMAC-SHA-256 as the internal HMAC.
 *
 * Input: x (private key scalar, 32 bytes), h1 (message hash, 32 bytes)
 * Output: k (nonce scalar, 32 bytes), guaranteed in [1, n-1]
 */
static void rfc6979_generate_k(uint8_t k_out[32], const uint8_t x[32],
                                 const uint8_t h1[32])
{
    uint8_t V[32], K[32];
    uint8_t data[32 + 1 + 32 + 32]; /* V || 0x00/0x01 || x || h1 */

    /* Step b: V = 0x01 0x01 ... 0x01 (32 bytes) */
    memset(V, 0x01, 32);

    /* Step c: K = 0x00 0x00 ... 0x00 (32 bytes) */
    memset(K, 0x00, 32);

    /* Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)) */
    memcpy(data, V, 32);
    data[32] = 0x00;
    memcpy(data + 33, x, 32);
    memcpy(data + 65, h1, 32);
    pqc_hmac_sha256(K, K, 32, data, 97);

    /* Step e: V = HMAC_K(V) */
    pqc_hmac_sha256(V, K, 32, V, 32);

    /* Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) */
    memcpy(data, V, 32);
    data[32] = 0x01;
    memcpy(data + 33, x, 32);
    memcpy(data + 65, h1, 32);
    pqc_hmac_sha256(K, K, 32, data, 97);

    /* Step g: V = HMAC_K(V) */
    pqc_hmac_sha256(V, K, 32, V, 32);

    /* Step h: Generate k candidates */
    for (int attempts = 0; attempts < 100; attempts++) {
        /* V = HMAC_K(V) */
        pqc_hmac_sha256(V, K, 32, V, 32);

        /* Check if V is a valid k (in [1, n-1]) */
        p256_fe k_fe;
        p256_scalar_frombytes(k_fe, V);

        /* Check k != 0 */
        if (p256_fe_is_zero(k_fe)) goto retry;

        /* Check k < n */
        if (p256_fe_cmp(k_fe, P256_N) >= 0) goto retry;

        memcpy(k_out, V, 32);
        pqc_memzero(V, sizeof(V));
        pqc_memzero(K, sizeof(K));
        return;

retry:
        /* K = HMAC_K(V || 0x00) */
        memcpy(data, V, 32);
        data[32] = 0x00;
        pqc_hmac_sha256(K, K, 32, data, 33);
        /* V = HMAC_K(V) */
        pqc_hmac_sha256(V, K, 32, V, 32);
    }

    /* Should not reach here with valid inputs */
    pqc_memzero(V, sizeof(V));
    pqc_memzero(K, sizeof(K));
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

int ecdsa_p256_keygen(uint8_t pk[64], uint8_t sk[64])
{
    uint8_t scalar[32];
    pqc_status_t rc;

    /* Generate random scalar in [1, n-1] */
    do {
        rc = pqc_randombytes(scalar, 32);
        if (rc != PQC_OK)
            return (int)rc;

        uint8_t z = 0;
        for (int i = 0; i < 32; i++) z |= scalar[i];
        if (z == 0) continue;

        p256_fe s_fe;
        p256_scalar_frombytes(s_fe, scalar);
        if (p256_fe_cmp(s_fe, P256_N) >= 0) continue;

        break;
    } while (1);

    /* Compute public key: Q = scalar * G */
    p256_point Q;
    p256_point_scalar_mult_base(&Q, scalar);

    uint8_t x[32], y[32];
    p256_point_to_affine(x, y, &Q);

    /* pk = X || Y */
    memcpy(pk, x, 32);
    memcpy(pk + 32, y, 32);

    /* sk = scalar || X (private scalar + public x for RFC 6979) */
    memcpy(sk, scalar, 32);
    memcpy(sk + 32, x, 32);

    pqc_memzero(scalar, sizeof(scalar));

    return 0;
}

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

int ecdsa_p256_sign(uint8_t sig[64], const uint8_t *msg, size_t msglen,
                     const uint8_t sk[64])
{
    /* Hash the message */
    uint8_t h[32];
    pqc_sha256(h, msg, msglen);

    const uint8_t *d = sk;  /* Private scalar */

    /* Generate deterministic k */
    uint8_t k_bytes[32];
    rfc6979_generate_k(k_bytes, d, h);

    /* Compute R = k * G */
    p256_point R;
    p256_point_scalar_mult_base(&R, k_bytes);

    /* r = R.x mod n */
    uint8_t rx[32], ry[32];
    p256_point_to_affine(rx, ry, &R);

    p256_fe r_fe, k_fe, d_fe, h_fe;
    p256_scalar_frombytes(r_fe, rx);

    /* Reduce r mod n (r_fe might be >= n since it's a field element mod p) */
    if (p256_fe_cmp(r_fe, P256_N) >= 0) {
        p256_fe tmp;
        sub256_v2(tmp, r_fe, P256_N);
        p256_fe_copy(r_fe, tmp);
    }

    /* Check r != 0 */
    if (p256_fe_is_zero(r_fe)) {
        pqc_memzero(k_bytes, sizeof(k_bytes));
        return -1;
    }

    /* s = k^{-1} * (h + r*d) mod n */
    p256_scalar_frombytes(k_fe, k_bytes);
    p256_scalar_frombytes(d_fe, d);
    p256_scalar_frombytes(h_fe, h);

    p256_fe rd, s_fe, k_inv;

    /* rd = r * d mod n */
    p256_scalar_mul(rd, r_fe, d_fe);

    /* h + r*d mod n */
    p256_scalar_add(s_fe, h_fe, rd);

    /* k^{-1} mod n */
    p256_scalar_inv(k_inv, k_fe);

    /* s = k_inv * (h + r*d) mod n */
    p256_scalar_mul(s_fe, k_inv, s_fe);

    /* Check s != 0 */
    if (p256_fe_is_zero(s_fe)) {
        pqc_memzero(k_bytes, sizeof(k_bytes));
        return -1;
    }

    /* Encode signature: r || s, each 32 bytes big-endian */
    p256_scalar_tobytes(sig, r_fe);
    p256_scalar_tobytes(sig + 32, s_fe);

    pqc_memzero(k_bytes, sizeof(k_bytes));
    pqc_memzero(&k_fe, sizeof(k_fe));
    pqc_memzero(&d_fe, sizeof(d_fe));

    return 0;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

int ecdsa_p256_verify(const uint8_t *msg, size_t msglen,
                       const uint8_t sig[64], const uint8_t pk[64])
{
    /* Decode r and s */
    p256_fe r_fe, s_fe;
    p256_scalar_frombytes(r_fe, sig);
    p256_scalar_frombytes(s_fe, sig + 32);

    /* Check r, s in [1, n-1] */
    if (p256_fe_is_zero(r_fe) || p256_fe_is_zero(s_fe))
        return -1;
    if (p256_fe_cmp(r_fe, P256_N) >= 0 || p256_fe_cmp(s_fe, P256_N) >= 0)
        return -1;

    /* Hash the message */
    uint8_t h[32];
    pqc_sha256(h, msg, msglen);

    p256_fe h_fe;
    p256_scalar_frombytes(h_fe, h);

    /* w = s^{-1} mod n */
    p256_fe w;
    p256_scalar_inv(w, s_fe);

    /* u1 = h * w mod n */
    p256_fe u1;
    p256_scalar_mul(u1, h_fe, w);

    /* u2 = r * w mod n */
    p256_fe u2;
    p256_scalar_mul(u2, r_fe, w);

    /* Compute R = u1*G + u2*Q */
    uint8_t u1_bytes[32], u2_bytes[32];
    p256_scalar_tobytes(u1_bytes, u1);
    p256_scalar_tobytes(u2_bytes, u2);

    p256_point P1, P2, R;
    p256_point_scalar_mult_base(&P1, u1_bytes);

    /* Decode public key */
    uint8_t pk_uncompressed[65];
    pk_uncompressed[0] = 0x04;
    memcpy(pk_uncompressed + 1, pk, 64);
    p256_point Q;
    if (p256_point_decode(&Q, pk_uncompressed) != 0)
        return -1;

    p256_point_scalar_mult(&P2, u2_bytes, &Q);
    p256_point_add(&R, &P1, &P2);

    if (p256_point_is_zero(&R))
        return -1;

    /* v = R.x mod n */
    uint8_t rx[32], ry[32];
    p256_point_to_affine(rx, ry, &R);

    p256_fe v;
    p256_scalar_frombytes(v, rx);
    if (p256_fe_cmp(v, P256_N) >= 0) {
        p256_fe tmp;
        sub256_v2(tmp, v, P256_N);
        p256_fe_copy(v, tmp);
    }

    /* Check v == r */
    if (p256_fe_cmp(v, r_fe) != 0)
        return -1;

    return 0;
}
