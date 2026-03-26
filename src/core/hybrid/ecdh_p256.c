/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ECDH over NIST P-256.
 *
 * Key agreement using elliptic curve Diffie-Hellman on the NIST P-256
 * curve. The shared secret is the SHA-256 hash of the x-coordinate of
 * the shared point.
 */

#include <string.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/rand.h"
#include "core/common/hash/sha2.h"
#include "field_p256.h"
#include "ecdh_p256.h"

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

int ecdh_p256_keygen(uint8_t pk[65], uint8_t sk[32])
{
    pqc_status_t rc;

    /* Generate random scalar in [1, n-1] */
    do {
        rc = pqc_randombytes(sk, 32);
        if (rc != PQC_OK)
            return (int)rc;

        /* Ensure sk < n by clearing the top bit if needed */
        sk[0] &= 0xFF;  /* Keep as is -- n is close to 2^256 */

        /* Check sk != 0 */
        uint8_t z = 0;
        for (int i = 0; i < 32; i++) z |= sk[i];
        if (z == 0) continue;

        /* Check sk < n */
        p256_fe sk_fe, n_fe;
        p256_scalar_frombytes(sk_fe, sk);
        p256_fe_copy(n_fe, P256_N);
        if (p256_fe_cmp(sk_fe, n_fe) >= 0) continue;

        break;
    } while (1);

    /* pk = sk * G */
    p256_point Q;
    p256_point_scalar_mult_base(&Q, sk);
    p256_point_encode(pk, &Q);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Shared secret computation                                            */
/* ------------------------------------------------------------------ */

int ecdh_p256_shared_secret(uint8_t ss[32], const uint8_t pk[65],
                             const uint8_t sk[32])
{
    /* Decode the peer's public key */
    p256_point P;
    if (p256_point_decode(&P, pk) != 0)
        return -1;

    /* Compute shared point: S = sk * P */
    p256_point S;
    p256_point_scalar_mult(&S, sk, &P);

    /* Check for point at infinity */
    if (p256_point_is_zero(&S))
        return -1;

    /* Extract x-coordinate */
    uint8_t x[32], y[32];
    p256_point_to_affine(x, y, &S);

    /* Hash the x-coordinate to produce the shared secret */
    pqc_sha256(ss, x, 32);

    pqc_memzero(x, sizeof(x));
    pqc_memzero(y, sizeof(y));

    return 0;
}
