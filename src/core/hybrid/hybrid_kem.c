/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hybrid KEM schemes (PQC + classical).
 *
 * Hybrid KEMs combine a post-quantum KEM with a classical key agreement.
 * The combined shared secret is derived from both components so that
 * security holds even if one primitive is broken.
 *
 * Supported combinations:
 *   - ML-KEM-768 + X25519
 *   - ML-KEM-1024 + ECDH-P256
 */

#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "pqc/rand.h"
#include "core/kem/kem_internal.h"
#include "core/kem/mlkem/mlkem.h"
#include "core/common/hash/sha2.h"

#include "x25519.h"
#include "ecdh_p256.h"

/* ================================================================== */
/*  ML-KEM-768 + X25519                                                 */
/*                                                                      */
/*  Key sizes:                                                          */
/*    pk = ML-KEM-768 pk (1184) + X25519 pk (32) = 1216                 */
/*    sk = ML-KEM-768 sk (2400) + X25519 sk (32) = 2432                 */
/*    ct = ML-KEM-768 ct (1088) + X25519 ephemeral pk (32) = 1120       */
/*    ss = SHA-256(ss_mlkem || ss_x25519) = 32 bytes (padded to 64)     */
/* ================================================================== */

/* Offsets within concatenated keys */
#define MLKEM768_PK_BYTES  1184
#define MLKEM768_SK_BYTES  2400
#define MLKEM768_CT_BYTES  1088
#define MLKEM768_SS_BYTES  32

#define X25519_PK_BYTES    32
#define X25519_SK_BYTES    32
#define X25519_SS_BYTES    32

static pqc_status_t hybrid_mlkem768_x25519_keygen(uint8_t *pk, uint8_t *sk)
{
    pqc_status_t rc;

    /* Generate ML-KEM-768 keypair */
    rc = pqc_mlkem_keygen(&PQC_MLKEM_768, pk, sk);
    if (rc != PQC_OK)
        return rc;

    /* Generate X25519 keypair */
    int ret = x25519_keygen(pk + MLKEM768_PK_BYTES, sk + MLKEM768_SK_BYTES);
    if (ret != 0)
        return PQC_ERROR_RNG_FAILED;

    return PQC_OK;
}

static pqc_status_t hybrid_mlkem768_x25519_encaps(uint8_t *ct, uint8_t *ss,
                                                    const uint8_t *pk)
{
    pqc_status_t rc;
    uint8_t ss_mlkem[MLKEM768_SS_BYTES];
    uint8_t ss_x25519[X25519_SS_BYTES];

    /* ML-KEM-768 encapsulation */
    rc = pqc_mlkem_encaps(&PQC_MLKEM_768, ct, ss_mlkem, pk);
    if (rc != PQC_OK)
        return rc;

    /* X25519: generate ephemeral keypair, compute shared secret */
    uint8_t eph_sk[X25519_SK_BYTES];
    uint8_t eph_pk[X25519_PK_BYTES];

    int ret = x25519_keygen(eph_pk, eph_sk);
    if (ret != 0) {
        pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
        return PQC_ERROR_RNG_FAILED;
    }

    /* Ciphertext for X25519 is the ephemeral public key */
    memcpy(ct + MLKEM768_CT_BYTES, eph_pk, X25519_PK_BYTES);

    /* Compute X25519 shared secret with peer's static public key */
    ret = x25519_shared_secret(ss_x25519, pk + MLKEM768_PK_BYTES, eph_sk);
    pqc_memzero(eph_sk, sizeof(eph_sk));
    if (ret != 0) {
        pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
        return PQC_ERROR_INTERNAL;
    }

    /* Combine shared secrets: ss = SHA-256(ss_mlkem || ss_x25519) */
    /* We output 64 bytes: SHA-256(ss_mlkem || ss_x25519) || SHA-256(ss_x25519 || ss_mlkem) */
    uint8_t combined[MLKEM768_SS_BYTES + X25519_SS_BYTES];
    memcpy(combined, ss_mlkem, MLKEM768_SS_BYTES);
    memcpy(combined + MLKEM768_SS_BYTES, ss_x25519, X25519_SS_BYTES);

    pqc_sha256(ss, combined, sizeof(combined));

    /* Second half: reverse order for domain separation */
    uint8_t combined2[X25519_SS_BYTES + MLKEM768_SS_BYTES];
    memcpy(combined2, ss_x25519, X25519_SS_BYTES);
    memcpy(combined2 + X25519_SS_BYTES, ss_mlkem, MLKEM768_SS_BYTES);
    pqc_sha256(ss + 32, combined2, sizeof(combined2));

    pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
    pqc_memzero(ss_x25519, sizeof(ss_x25519));
    pqc_memzero(combined, sizeof(combined));
    pqc_memzero(combined2, sizeof(combined2));

    return PQC_OK;
}

static pqc_status_t hybrid_mlkem768_x25519_decaps(uint8_t *ss, const uint8_t *ct,
                                                    const uint8_t *sk)
{
    pqc_status_t rc;
    uint8_t ss_mlkem[MLKEM768_SS_BYTES];
    uint8_t ss_x25519[X25519_SS_BYTES];

    /* ML-KEM-768 decapsulation */
    rc = pqc_mlkem_decaps(&PQC_MLKEM_768, ss_mlkem, ct, sk);
    if (rc != PQC_OK)
        return rc;

    /* X25519: compute shared secret using our static sk and their ephemeral pk */
    const uint8_t *eph_pk = ct + MLKEM768_CT_BYTES;
    const uint8_t *my_sk = sk + MLKEM768_SK_BYTES;

    int ret = x25519_shared_secret(ss_x25519, eph_pk, my_sk);
    if (ret != 0) {
        pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
        return PQC_ERROR_INTERNAL;
    }

    /* Combine shared secrets identically to encaps */
    uint8_t combined[MLKEM768_SS_BYTES + X25519_SS_BYTES];
    memcpy(combined, ss_mlkem, MLKEM768_SS_BYTES);
    memcpy(combined + MLKEM768_SS_BYTES, ss_x25519, X25519_SS_BYTES);

    pqc_sha256(ss, combined, sizeof(combined));

    uint8_t combined2[X25519_SS_BYTES + MLKEM768_SS_BYTES];
    memcpy(combined2, ss_x25519, X25519_SS_BYTES);
    memcpy(combined2 + X25519_SS_BYTES, ss_mlkem, MLKEM768_SS_BYTES);
    pqc_sha256(ss + 32, combined2, sizeof(combined2));

    pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
    pqc_memzero(ss_x25519, sizeof(ss_x25519));
    pqc_memzero(combined, sizeof(combined));
    pqc_memzero(combined2, sizeof(combined2));

    return PQC_OK;
}

/* ================================================================== */
/*  ML-KEM-1024 + ECDH-P256                                            */
/*                                                                      */
/*  Key sizes:                                                          */
/*    pk = ML-KEM-1024 pk (1568) + P-256 pk (65) = 1633                 */
/*    sk = ML-KEM-1024 sk (3168) + P-256 sk (32) + P-256 pk (33 pad) = 3233 */
/*    ct = ML-KEM-1024 ct (1568) + P-256 ephemeral pk (65) = 1633       */
/*    ss = 64 bytes (KDF output from both shared secrets)               */
/* ================================================================== */

#define MLKEM1024_PK_BYTES  1568
#define MLKEM1024_SK_BYTES  3168
#define MLKEM1024_CT_BYTES  1568
#define MLKEM1024_SS_BYTES  32

#define P256_PK_BYTES       65   /* Uncompressed: 04 || X || Y */
#define P256_SK_BYTES       32
#define P256_SS_BYTES       32

static pqc_status_t hybrid_mlkem1024_p256_keygen(uint8_t *pk, uint8_t *sk)
{
    pqc_status_t rc;

    /* Generate ML-KEM-1024 keypair */
    rc = pqc_mlkem_keygen(&PQC_MLKEM_1024, pk, sk);
    if (rc != PQC_OK)
        return rc;

    /* Generate ECDH-P256 keypair */
    /* pk layout: mlkem_pk (1568) || p256_pk (65) */
    /* sk layout: mlkem_sk (3168) || p256_sk (32) || padding (33) */
    uint8_t p256_pk[65], p256_sk[32];
    int ret = ecdh_p256_keygen(p256_pk, p256_sk);
    if (ret != 0) {
        pqc_memzero(sk, MLKEM1024_SK_BYTES);
        return PQC_ERROR_RNG_FAILED;
    }

    memcpy(pk + MLKEM1024_PK_BYTES, p256_pk, P256_PK_BYTES);
    memcpy(sk + MLKEM1024_SK_BYTES, p256_sk, P256_SK_BYTES);
    /* Store the P-256 public key in remaining sk space for later use */
    memcpy(sk + MLKEM1024_SK_BYTES + P256_SK_BYTES, p256_pk, 33);

    pqc_memzero(p256_sk, sizeof(p256_sk));

    return PQC_OK;
}

static pqc_status_t hybrid_mlkem1024_p256_encaps(uint8_t *ct, uint8_t *ss,
                                                   const uint8_t *pk)
{
    pqc_status_t rc;
    uint8_t ss_mlkem[MLKEM1024_SS_BYTES];
    uint8_t ss_p256[P256_SS_BYTES];

    /* ML-KEM-1024 encapsulation */
    rc = pqc_mlkem_encaps(&PQC_MLKEM_1024, ct, ss_mlkem, pk);
    if (rc != PQC_OK)
        return rc;

    /* ECDH-P256: generate ephemeral keypair, compute shared secret */
    uint8_t eph_pk[P256_PK_BYTES], eph_sk[P256_SK_BYTES];
    int ret = ecdh_p256_keygen(eph_pk, eph_sk);
    if (ret != 0) {
        pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
        return PQC_ERROR_RNG_FAILED;
    }

    memcpy(ct + MLKEM1024_CT_BYTES, eph_pk, P256_PK_BYTES);

    ret = ecdh_p256_shared_secret(ss_p256, pk + MLKEM1024_PK_BYTES, eph_sk);
    pqc_memzero(eph_sk, sizeof(eph_sk));
    if (ret != 0) {
        pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
        return PQC_ERROR_INTERNAL;
    }

    /* Combine: ss = SHA-256(ss_mlkem || ss_p256) || SHA-256(ss_p256 || ss_mlkem) */
    uint8_t combined[MLKEM1024_SS_BYTES + P256_SS_BYTES];
    memcpy(combined, ss_mlkem, MLKEM1024_SS_BYTES);
    memcpy(combined + MLKEM1024_SS_BYTES, ss_p256, P256_SS_BYTES);
    pqc_sha256(ss, combined, sizeof(combined));

    uint8_t combined2[P256_SS_BYTES + MLKEM1024_SS_BYTES];
    memcpy(combined2, ss_p256, P256_SS_BYTES);
    memcpy(combined2 + P256_SS_BYTES, ss_mlkem, MLKEM1024_SS_BYTES);
    pqc_sha256(ss + 32, combined2, sizeof(combined2));

    pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
    pqc_memzero(ss_p256, sizeof(ss_p256));
    pqc_memzero(combined, sizeof(combined));
    pqc_memzero(combined2, sizeof(combined2));

    return PQC_OK;
}

static pqc_status_t hybrid_mlkem1024_p256_decaps(uint8_t *ss, const uint8_t *ct,
                                                   const uint8_t *sk)
{
    pqc_status_t rc;
    uint8_t ss_mlkem[MLKEM1024_SS_BYTES];
    uint8_t ss_p256[P256_SS_BYTES];

    /* ML-KEM-1024 decapsulation */
    rc = pqc_mlkem_decaps(&PQC_MLKEM_1024, ss_mlkem, ct, sk);
    if (rc != PQC_OK)
        return rc;

    /* ECDH-P256: compute shared secret */
    const uint8_t *eph_pk = ct + MLKEM1024_CT_BYTES;
    const uint8_t *my_sk = sk + MLKEM1024_SK_BYTES;

    int ret = ecdh_p256_shared_secret(ss_p256, eph_pk, my_sk);
    if (ret != 0) {
        pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
        return PQC_ERROR_INTERNAL;
    }

    /* Combine identically to encaps */
    uint8_t combined[MLKEM1024_SS_BYTES + P256_SS_BYTES];
    memcpy(combined, ss_mlkem, MLKEM1024_SS_BYTES);
    memcpy(combined + MLKEM1024_SS_BYTES, ss_p256, P256_SS_BYTES);
    pqc_sha256(ss, combined, sizeof(combined));

    uint8_t combined2[P256_SS_BYTES + MLKEM1024_SS_BYTES];
    memcpy(combined2, ss_p256, P256_SS_BYTES);
    memcpy(combined2 + P256_SS_BYTES, ss_mlkem, MLKEM1024_SS_BYTES);
    pqc_sha256(ss + 32, combined2, sizeof(combined2));

    pqc_memzero(ss_mlkem, sizeof(ss_mlkem));
    pqc_memzero(ss_p256, sizeof(ss_p256));
    pqc_memzero(combined, sizeof(combined));
    pqc_memzero(combined2, sizeof(combined2));

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/*
 * ML-KEM-768 + X25519:
 * pk = ML-KEM-768 pk (1184) + X25519 pk (32) = 1216
 * sk = ML-KEM-768 sk (2400) + X25519 sk (32) = 2432
 * ct = ML-KEM-768 ct (1088) + X25519 ephemeral pk (32) = 1120
 * ss = 64 (KDF output from both shared secrets)
 */
static const pqc_kem_vtable_t hybrid_mlkem768_x25519_vtable = {
    .algorithm_name    = PQC_KEM_HYBRID_MLKEM768_X25519,
    .security_level    = PQC_SECURITY_LEVEL_3,
    .nist_standard     = "Hybrid (FIPS 203 + RFC 7748)",
    .public_key_size   = 1216,
    .secret_key_size   = 2432,
    .ciphertext_size   = 1120,
    .shared_secret_size = 64,
    .keygen = hybrid_mlkem768_x25519_keygen,
    .encaps = hybrid_mlkem768_x25519_encaps,
    .decaps = hybrid_mlkem768_x25519_decaps,
};

/*
 * ML-KEM-1024 + P-256 (ECDH):
 * pk = ML-KEM-1024 pk (1568) + P-256 uncompressed pk (65) = 1633
 * sk = ML-KEM-1024 sk (3168) + P-256 sk (65) = 3233
 * ct = ML-KEM-1024 ct (1568) + P-256 ephemeral pk (65) = 1633
 * ss = 64 (KDF output from both shared secrets)
 */
static const pqc_kem_vtable_t hybrid_mlkem1024_p256_vtable = {
    .algorithm_name    = PQC_KEM_HYBRID_MLKEM1024_P256,
    .security_level    = PQC_SECURITY_LEVEL_5,
    .nist_standard     = "Hybrid (FIPS 203 + FIPS 186-5)",
    .public_key_size   = 1633,
    .secret_key_size   = 3233,
    .ciphertext_size   = 1633,
    .shared_secret_size = 64,
    .keygen = hybrid_mlkem1024_p256_keygen,
    .encaps = hybrid_mlkem1024_p256_encaps,
    .decaps = hybrid_mlkem1024_p256_decaps,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_hybrid_kem_register(void)
{
    int rc = 0;
    rc |= pqc_kem_add_vtable(&hybrid_mlkem768_x25519_vtable);
    rc |= pqc_kem_add_vtable(&hybrid_mlkem1024_p256_vtable);
    return rc;
}
