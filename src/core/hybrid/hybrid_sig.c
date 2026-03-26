/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hybrid signature schemes (PQC + classical).
 *
 * Hybrid signatures concatenate a post-quantum signature with a
 * classical one. Verification requires both to succeed, ensuring
 * security holds even if one algorithm is broken.
 *
 * Supported combinations:
 *   - ML-DSA-65 + Ed25519
 *   - ML-DSA-87 + ECDSA-P256
 */

#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "pqc/common.h"
#include "pqc/algorithms.h"
#include "core/sig/sig_internal.h"
#include "core/sig/mldsa/mldsa.h"

#include "ed25519.h"
#include "ecdsa_p256.h"

/* ================================================================== */
/*  ML-DSA-65 + Ed25519                                                 */
/*                                                                      */
/*  Key sizes:                                                          */
/*    pk = ML-DSA-65 pk (1952) + Ed25519 pk (32) = 1984                 */
/*    sk = ML-DSA-65 sk (4032) + Ed25519 sk (32) = 4064                 */
/*    sig = ML-DSA-65 sig (3309) + Ed25519 sig (64) = 3373              */
/* ================================================================== */

#define MLDSA65_PK_BYTES  1952
#define MLDSA65_SK_BYTES  4032
#define MLDSA65_SIG_BYTES 3309

#define ED25519_PK_BYTES  32
#define ED25519_SK_BYTES  32
#define ED25519_SIG_BYTES 64

static pqc_status_t hybrid_mldsa65_ed25519_keygen(uint8_t *pk, uint8_t *sk)
{
    pqc_status_t rc;

    /* Generate ML-DSA-65 keypair */
    rc = pqc_mldsa_keygen(&PQC_MLDSA_65, pk, sk);
    if (rc != PQC_OK)
        return rc;

    /* Generate Ed25519 keypair */
    int ret = ed25519_keygen(pk + MLDSA65_PK_BYTES, sk + MLDSA65_SK_BYTES);
    if (ret != 0)
        return PQC_ERROR_RNG_FAILED;

    return PQC_OK;
}

static pqc_status_t hybrid_mldsa65_ed25519_sign(uint8_t *sig, size_t *siglen,
                                                   const uint8_t *msg, size_t msglen,
                                                   const uint8_t *sk)
{
    pqc_status_t rc;

    /* ML-DSA-65 signing */
    size_t mldsa_siglen = 0;
    rc = pqc_mldsa_sign(&PQC_MLDSA_65, sig, &mldsa_siglen, msg, msglen, sk);
    if (rc != PQC_OK)
        return rc;

    /* Ed25519 signing */
    int ret = ed25519_sign(sig + MLDSA65_SIG_BYTES, msg, msglen,
                            sk + MLDSA65_SK_BYTES);
    if (ret != 0)
        return PQC_ERROR_INTERNAL;

    *siglen = MLDSA65_SIG_BYTES + ED25519_SIG_BYTES;
    return PQC_OK;
}

static pqc_status_t hybrid_mldsa65_ed25519_verify(const uint8_t *msg, size_t msglen,
                                                     const uint8_t *sig, size_t siglen,
                                                     const uint8_t *pk)
{
    if (siglen != MLDSA65_SIG_BYTES + ED25519_SIG_BYTES)
        return PQC_ERROR_INVALID_ARGUMENT;

    /* Verify ML-DSA-65 signature */
    pqc_status_t rc = pqc_mldsa_verify(&PQC_MLDSA_65, msg, msglen,
                                         sig, MLDSA65_SIG_BYTES, pk);
    if (rc != PQC_OK)
        return rc;

    /* Verify Ed25519 signature */
    int ret = ed25519_verify(msg, msglen,
                              sig + MLDSA65_SIG_BYTES,
                              pk + MLDSA65_PK_BYTES);
    if (ret != 0)
        return PQC_ERROR_VERIFICATION_FAILED;

    return PQC_OK;
}

/* ================================================================== */
/*  ML-DSA-87 + ECDSA-P256                                             */
/*                                                                      */
/*  Key sizes:                                                          */
/*    pk = ML-DSA-87 pk (2592) + P-256 pk (64) = 2656                  */
/*    sk = ML-DSA-87 sk (4896) + P-256 sk (64) = 4960                  */
/*    sig = ML-DSA-87 sig (4627) + ECDSA sig (64) = 4691               */
/* ================================================================== */

#define MLDSA87_PK_BYTES  2592
#define MLDSA87_SK_BYTES  4896
#define MLDSA87_SIG_BYTES 4627

#define ECDSA_PK_BYTES    64
#define ECDSA_SK_BYTES    64
#define ECDSA_SIG_BYTES   64

static pqc_status_t hybrid_mldsa87_p256_keygen(uint8_t *pk, uint8_t *sk)
{
    pqc_status_t rc;

    /* Generate ML-DSA-87 keypair */
    rc = pqc_mldsa_keygen(&PQC_MLDSA_87, pk, sk);
    if (rc != PQC_OK)
        return rc;

    /* Generate ECDSA-P256 keypair */
    int ret = ecdsa_p256_keygen(pk + MLDSA87_PK_BYTES,
                                 sk + MLDSA87_SK_BYTES);
    if (ret != 0)
        return PQC_ERROR_RNG_FAILED;

    return PQC_OK;
}

static pqc_status_t hybrid_mldsa87_p256_sign(uint8_t *sig, size_t *siglen,
                                                const uint8_t *msg, size_t msglen,
                                                const uint8_t *sk)
{
    pqc_status_t rc;

    /* ML-DSA-87 signing */
    size_t mldsa_siglen = 0;
    rc = pqc_mldsa_sign(&PQC_MLDSA_87, sig, &mldsa_siglen, msg, msglen, sk);
    if (rc != PQC_OK)
        return rc;

    /* ECDSA-P256 signing */
    int ret = ecdsa_p256_sign(sig + MLDSA87_SIG_BYTES, msg, msglen,
                               sk + MLDSA87_SK_BYTES);
    if (ret != 0)
        return PQC_ERROR_INTERNAL;

    *siglen = MLDSA87_SIG_BYTES + ECDSA_SIG_BYTES;
    return PQC_OK;
}

static pqc_status_t hybrid_mldsa87_p256_verify(const uint8_t *msg, size_t msglen,
                                                  const uint8_t *sig, size_t siglen,
                                                  const uint8_t *pk)
{
    if (siglen != MLDSA87_SIG_BYTES + ECDSA_SIG_BYTES)
        return PQC_ERROR_INVALID_ARGUMENT;

    /* Verify ML-DSA-87 signature */
    pqc_status_t rc = pqc_mldsa_verify(&PQC_MLDSA_87, msg, msglen,
                                         sig, MLDSA87_SIG_BYTES, pk);
    if (rc != PQC_OK)
        return rc;

    /* Verify ECDSA-P256 signature */
    int ret = ecdsa_p256_verify(msg, msglen,
                                 sig + MLDSA87_SIG_BYTES,
                                 pk + MLDSA87_PK_BYTES);
    if (ret != 0)
        return PQC_ERROR_VERIFICATION_FAILED;

    return PQC_OK;
}

/* ------------------------------------------------------------------ */
/* Vtables                                                              */
/* ------------------------------------------------------------------ */

/*
 * ML-DSA-65 + Ed25519:
 * pk = ML-DSA-65 pk (1952) + Ed25519 pk (32) = 1984
 * sk = ML-DSA-65 sk (4032) + Ed25519 sk (32) = 4064
 * sig = ML-DSA-65 sig (3309) + Ed25519 sig (64) = 3373
 */
static const pqc_sig_vtable_t hybrid_mldsa65_ed25519_vtable = {
    .algorithm_name     = PQC_SIG_HYBRID_MLDSA65_ED25519,
    .security_level     = PQC_SECURITY_LEVEL_3,
    .nist_standard      = "Hybrid (FIPS 204 + EdDSA)",
    .is_stateful        = 0,
    .public_key_size    = 1984,
    .secret_key_size    = 4064,
    .max_signature_size = 3373,
    .keygen  = hybrid_mldsa65_ed25519_keygen,
    .sign    = hybrid_mldsa65_ed25519_sign,
    .verify  = hybrid_mldsa65_ed25519_verify,
    .sign_stateful = NULL,
};

/*
 * ML-DSA-87 + ECDSA-P256:
 * pk = ML-DSA-87 pk (2592) + P-256 uncompressed pk (64) = 2656
 * sk = ML-DSA-87 sk (4896) + P-256 sk (64) = 4960
 * sig = ML-DSA-87 sig (4627) + ECDSA-P256 sig (64) = 4691
 */
static const pqc_sig_vtable_t hybrid_mldsa87_p256_vtable = {
    .algorithm_name     = PQC_SIG_HYBRID_MLDSA87_P256,
    .security_level     = PQC_SECURITY_LEVEL_5,
    .nist_standard      = "Hybrid (FIPS 204 + FIPS 186-5)",
    .is_stateful        = 0,
    .public_key_size    = 2656,
    .secret_key_size    = 4960,
    .max_signature_size = 4691,
    .keygen  = hybrid_mldsa87_p256_keygen,
    .sign    = hybrid_mldsa87_p256_sign,
    .verify  = hybrid_mldsa87_p256_verify,
    .sign_stateful = NULL,
};

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

int pqc_hybrid_sig_register(void)
{
    int rc = 0;
    rc |= pqc_sig_add_vtable(&hybrid_mldsa65_ed25519_vtable);
    rc |= pqc_sig_add_vtable(&hybrid_mldsa87_p256_vtable);
    return rc;
}
