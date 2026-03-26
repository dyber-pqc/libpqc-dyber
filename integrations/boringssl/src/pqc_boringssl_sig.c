/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * BoringSSL Integration — Signature / Authentication
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Implements TLS CertificateVerify handling and SignatureScheme
 * registration for ML-DSA and SLH-DSA variants.
 */

#include "pqc_boringssl.h"
#include "pqc_boringssl_internal.h"

#include <pqc/sig.h>
#include <pqc/algorithms.h>
#include <pqc/common.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>

#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------- */
/* Signature scheme table                                                      */
/* -------------------------------------------------------------------------- */

typedef struct {
    const char *algorithm;
    uint16_t    tls_sigalg_id;
    size_t      pk_size;
    size_t      sk_size;
    size_t      max_sig_size;
} pqc_bssl_sigscheme_t;

static const pqc_bssl_sigscheme_t sig_schemes[] = {
    { "ML-DSA-44",         0x0901,  1312,  2560,  2420 },
    { "ML-DSA-65",         0x0902,  1952,  4032,  3309 },
    { "ML-DSA-87",         0x0903,  2592,  4896,  4627 },
    { "SLH-DSA-SHA2-128s", 0x0904,    32,    64,  7856 },
    { "SLH-DSA-SHA2-128f", 0x0905,    32,    64, 17088 },
    { "SLH-DSA-SHA2-192s", 0x0906,    48,    96, 16224 },
    { "SLH-DSA-SHA2-192f", 0x0907,    48,    96, 35664 },
    { "SLH-DSA-SHA2-256s", 0x0908,    64,   128, 29792 },
    { "SLH-DSA-SHA2-256f", 0x0909,    64,   128, 49856 },
};
static const size_t sig_scheme_count =
    sizeof(sig_schemes) / sizeof(sig_schemes[0]);

static const pqc_bssl_sigscheme_t *find_scheme(const char *algorithm)
{
    for (size_t i = 0; i < sig_scheme_count; i++) {
        if (strcmp(sig_schemes[i].algorithm, algorithm) == 0)
            return &sig_schemes[i];
    }
    return NULL;
}

static const pqc_bssl_sigscheme_t *find_scheme_by_id(uint16_t id)
{
    for (size_t i = 0; i < sig_scheme_count; i++) {
        if (sig_schemes[i].tls_sigalg_id == id)
            return &sig_schemes[i];
    }
    return NULL;
}

/* -------------------------------------------------------------------------- */
/* CertificateVerify — sign                                                    */
/* -------------------------------------------------------------------------- */

/*
 * Sign the transcript hash for a TLS CertificateVerify message using
 * a PQC signature algorithm identified by its TLS SignatureScheme ID.
 *
 *   sigalg_id  - TLS SignatureScheme code (e.g. 0x0901 for ML-DSA-44)
 *   sk         - signer's secret key
 *   sk_len     - length of the secret key
 *   msg        - transcript hash to sign
 *   msg_len    - length of msg
 *   sig_out    - output buffer (must be >= max_sig_size bytes)
 *   sig_len    - actual signature length on output
 *
 * Returns 1 on success, 0 on failure.
 */
int pqc_bssl_sig_certificate_verify_sign(
        uint16_t sigalg_id,
        const uint8_t *sk, size_t sk_len,
        const uint8_t *msg, size_t msg_len,
        uint8_t *sig_out, size_t *sig_len)
{
    const pqc_bssl_sigscheme_t *scheme = find_scheme_by_id(sigalg_id);
    if (!scheme)
        return 0;

    if (sk_len < scheme->sk_size)
        return 0;

    PQC_SIG *sig_ctx = pqc_sig_new(scheme->algorithm);
    if (!sig_ctx)
        return 0;

    pqc_status_t rc = pqc_sig_sign(sig_ctx, sig_out, sig_len,
                                    msg, msg_len, sk);

    pqc_sig_free(sig_ctx);
    return rc == PQC_OK ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* CertificateVerify — verify                                                  */
/* -------------------------------------------------------------------------- */

int pqc_bssl_sig_certificate_verify_check(
        uint16_t sigalg_id,
        const uint8_t *pk, size_t pk_len,
        const uint8_t *msg, size_t msg_len,
        const uint8_t *sig, size_t sig_len)
{
    const pqc_bssl_sigscheme_t *scheme = find_scheme_by_id(sigalg_id);
    if (!scheme)
        return 0;

    if (pk_len < scheme->pk_size)
        return 0;

    PQC_SIG *sig_ctx = pqc_sig_new(scheme->algorithm);
    if (!sig_ctx)
        return 0;

    pqc_status_t rc = pqc_sig_verify(sig_ctx, msg, msg_len,
                                      sig, sig_len, pk);

    pqc_sig_free(sig_ctx);
    return rc == PQC_OK ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* Certificate chain validation support                                        */
/* -------------------------------------------------------------------------- */

/*
 * Verify a certificate's PQC signature given the issuer's public key.
 * This is used in X.509 certificate chain validation when the leaf or
 * intermediate certificate is signed with a PQC algorithm.
 */
int pqc_bssl_sig_verify_cert(
        const char *algorithm,
        const uint8_t *pk, size_t pk_len,
        const uint8_t *tbs, size_t tbs_len,
        const uint8_t *sig, size_t sig_len)
{
    const pqc_bssl_sigscheme_t *scheme = find_scheme(algorithm);
    if (!scheme)
        return 0;

    if (pk_len < scheme->pk_size)
        return 0;

    PQC_SIG *sig_ctx = pqc_sig_new(algorithm);
    if (!sig_ctx)
        return 0;

    pqc_status_t rc = pqc_sig_verify(sig_ctx, tbs, tbs_len,
                                      sig, sig_len, pk);

    pqc_sig_free(sig_ctx);
    return rc == PQC_OK ? 1 : 0;
}

/* -------------------------------------------------------------------------- */
/* Public APIs                                                                 */
/* -------------------------------------------------------------------------- */

int pqc_bssl_sig_init(void)
{
    /* Signature scheme table is static; nothing to initialize. */
    return 1;
}

int pqc_bssl_sig_register_scheme(SSL_CTX *ctx, const char *algorithm)
{
    if (!ctx || !algorithm)
        return 0;

    const pqc_bssl_sigscheme_t *scheme = find_scheme(algorithm);
    if (!scheme)
        return 0;

    /*
     * BoringSSL does not currently expose a public C API for registering
     * custom SignatureScheme values. The actual signing and verification
     * logic is implemented in the functions above and can be invoked
     * from custom BoringSSL hooks or patches.
     *
     * For portable usage, see the standalone TLS integration layer
     * (integrations/tls/) which works with any TLS library.
     */
    (void)ctx;
    return 1;
}
