/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * BoringSSL Integration Shim
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Provides PQC algorithm support within BoringSSL via a direct API shim
 * layer. BoringSSL does not expose a provider model, so this integration
 * registers custom EVP_PKEY methods, NamedGroup entries, and
 * SignatureScheme entries needed for TLS 1.3 with PQC.
 */

#ifndef PQC_BORINGSSL_H
#define PQC_BORINGSSL_H

#include <openssl/ssl.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Export / visibility                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(PQC_BORINGSSL_DLL_EXPORT)
        #define PQC_BSSL_API __declspec(dllexport)
    #elif defined(PQC_BORINGSSL_SHARED)
        #define PQC_BSSL_API __declspec(dllimport)
    #else
        #define PQC_BSSL_API
    #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
    #define PQC_BSSL_API __attribute__((visibility("default")))
#else
    #define PQC_BSSL_API
#endif

/* -------------------------------------------------------------------------- */
/* Initialization                                                              */
/* -------------------------------------------------------------------------- */

/*
 * Initialize PQC algorithms in BoringSSL.
 *
 * Registers custom NIDs, EVP_PKEY methods, NamedGroup entries, and
 * SignatureScheme entries for all supported PQC algorithms. Must be
 * called once before any other PQC_BoringSSL_* function.
 *
 * Returns 1 on success, 0 on failure.
 */
PQC_BSSL_API int PQC_BoringSSL_init(void);

/* -------------------------------------------------------------------------- */
/* KEM / Key Exchange registration                                             */
/* -------------------------------------------------------------------------- */

/*
 * Register an ML-KEM variant for TLS key exchange on the given SSL_CTX.
 *
 *   algorithm - one of: "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
 *
 * Returns 1 on success, 0 on failure.
 */
PQC_BSSL_API int PQC_BoringSSL_register_kem(SSL_CTX *ctx,
                                              const char *algorithm);

/*
 * Register all hybrid key-exchange groups on the given SSL_CTX.
 *
 * Currently registers:
 *   - X25519 + ML-KEM-768   (group ID 0x6399)
 *   - P-256  + ML-KEM-768   (group ID 0x639A)
 *
 * Returns 1 on success, 0 on failure.
 */
PQC_BSSL_API int PQC_BoringSSL_register_hybrid_groups(SSL_CTX *ctx);

/* -------------------------------------------------------------------------- */
/* Signature / Authentication registration                                     */
/* -------------------------------------------------------------------------- */

/*
 * Register an ML-DSA or SLH-DSA variant for TLS authentication on the
 * given SSL_CTX.
 *
 *   algorithm - e.g. "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
 *               "SLH-DSA-SHA2-128s", etc.
 *
 * Returns 1 on success, 0 on failure.
 */
PQC_BSSL_API int PQC_BoringSSL_register_sig(SSL_CTX *ctx,
                                              const char *algorithm);

/* -------------------------------------------------------------------------- */
/* EVP_PKEY method accessors (advanced)                                        */
/* -------------------------------------------------------------------------- */

/*
 * Retrieve the EVP_PKEY_METHOD for a PQC KEM identified by NID.
 * Returns NULL if the NID was not registered by PQC_BoringSSL_init().
 */
PQC_BSSL_API const EVP_PKEY_METHOD *PQC_BoringSSL_kem_method(int nid);

/*
 * Retrieve the EVP_PKEY_METHOD for a PQC signature scheme identified
 * by NID. Returns NULL if the NID was not registered.
 */
PQC_BSSL_API const EVP_PKEY_METHOD *PQC_BoringSSL_sig_method(int nid);

/* -------------------------------------------------------------------------- */
/* NID constants (assigned after PQC_BoringSSL_init)                           */
/* -------------------------------------------------------------------------- */

/*
 * Retrieve the BoringSSL NID for a named PQC algorithm. Returns 0
 * (NID_undef) if the algorithm name is not recognized.
 */
PQC_BSSL_API int PQC_BoringSSL_get_nid(const char *algorithm);

#ifdef __cplusplus
}
#endif

#endif /* PQC_BORINGSSL_H */
