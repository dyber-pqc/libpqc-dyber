/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Standalone TLS Integration Layer
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Provides TLS 1.3 hybrid key exchange and PQC signature support that
 * works with any TLS library (OpenSSL, BoringSSL, or custom).
 *
 * Implements:
 *   - draft-ietf-tls-hybrid-design (hybrid key exchange)
 *   - draft-connolly-tls-mlkem-key-agreement (ML-KEM in TLS 1.3)
 *   - FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA
 */

#ifndef PQC_TLS_H
#define PQC_TLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Export / visibility                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)
    #if defined(PQC_TLS_DLL_EXPORT)
        #define PQC_TLS_API __declspec(dllexport)
    #elif defined(PQC_TLS_SHARED)
        #define PQC_TLS_API __declspec(dllimport)
    #else
        #define PQC_TLS_API
    #endif
#elif defined(__GNUC__) && __GNUC__ >= 4
    #define PQC_TLS_API __attribute__((visibility("default")))
#else
    #define PQC_TLS_API
#endif

/* -------------------------------------------------------------------------- */
/* Named group IDs (IANA codepoints)                                           */
/* -------------------------------------------------------------------------- */

/* Pure PQC groups */
#define PQC_TLS_GROUP_MLKEM512              0x0200
#define PQC_TLS_GROUP_MLKEM768              0x0201
#define PQC_TLS_GROUP_MLKEM1024             0x0202

/* Hybrid groups */
#define PQC_TLS_GROUP_X25519_MLKEM768       0x6399  /* Chrome / Cloudflare */
#define PQC_TLS_GROUP_SECP256R1_MLKEM768    0x639A

/* -------------------------------------------------------------------------- */
/* Signature algorithm IDs (TLS SignatureScheme)                                */
/* -------------------------------------------------------------------------- */

#define PQC_TLS_SIGALG_MLDSA44             0x0901
#define PQC_TLS_SIGALG_MLDSA65             0x0902
#define PQC_TLS_SIGALG_MLDSA87             0x0903
#define PQC_TLS_SIGALG_SLHDSA_SHA2_128S    0x0904
#define PQC_TLS_SIGALG_SLHDSA_SHA2_128F    0x0905
#define PQC_TLS_SIGALG_SLHDSA_SHA2_192S    0x0906
#define PQC_TLS_SIGALG_SLHDSA_SHA2_192F    0x0907
#define PQC_TLS_SIGALG_SLHDSA_SHA2_256S    0x0908
#define PQC_TLS_SIGALG_SLHDSA_SHA2_256F    0x0909

/* -------------------------------------------------------------------------- */
/* TLS 1.3 Key Share API                                                       */
/* -------------------------------------------------------------------------- */

typedef struct pqc_tls_keyshare_s PQC_TLS_KeyShare;

/*
 * Create a new key-share context for the specified TLS named group.
 * Returns NULL if the group_id is not supported.
 */
PQC_TLS_API PQC_TLS_KeyShare *pqc_tls_keyshare_new(uint16_t group_id);

/*
 * Free a key-share context. Zeroizes all secret material.
 */
PQC_TLS_API void pqc_tls_keyshare_free(PQC_TLS_KeyShare *ks);

/*
 * Client-side: generate a key share for the ClientHello.
 *
 *   key_share_out  - output buffer for the client key share
 *   key_share_len  - on input: size of buffer; on output: bytes written
 *
 * Returns 0 on success, -1 on failure.
 */
PQC_TLS_API int pqc_tls_keyshare_generate(PQC_TLS_KeyShare *ks,
                                            uint8_t *key_share_out,
                                            size_t *key_share_len);

/*
 * Server-side: process the client key share and produce the server
 * key share and shared secret.
 *
 *   client_share      - the client's key share from ClientHello
 *   client_share_len  - length of client_share
 *   server_share_out  - output buffer for the server key share
 *   server_share_len  - on input: size of buffer; on output: bytes written
 *   shared_secret_out - output buffer for the shared secret
 *   shared_secret_len - on input: size of buffer; on output: bytes written
 *
 * Returns 0 on success, -1 on failure.
 */
PQC_TLS_API int pqc_tls_keyshare_encapsulate(
        PQC_TLS_KeyShare *ks,
        const uint8_t *client_share, size_t client_share_len,
        uint8_t *server_share_out, size_t *server_share_len,
        uint8_t *shared_secret_out, size_t *shared_secret_len);

/*
 * Client-side: process the server key share to recover the shared secret.
 *
 *   server_share      - the server's key share from ServerHello
 *   server_share_len  - length of server_share
 *   shared_secret_out - output buffer for the shared secret
 *   shared_secret_len - on input: size of buffer; on output: bytes written
 *
 * Returns 0 on success, -1 on failure.
 */
PQC_TLS_API int pqc_tls_keyshare_decapsulate(
        PQC_TLS_KeyShare *ks,
        const uint8_t *server_share, size_t server_share_len,
        uint8_t *shared_secret_out, size_t *shared_secret_len);

/* -------------------------------------------------------------------------- */
/* TLS 1.3 Signature API (CertificateVerify)                                   */
/* -------------------------------------------------------------------------- */

/*
 * Sign a message using a PQC signature algorithm.
 *
 *   sig_alg  - TLS SignatureScheme code (e.g. PQC_TLS_SIGALG_MLDSA65)
 *   sk       - signer's secret key
 *   sk_len   - length of sk
 *   msg      - message to sign (typically the transcript hash)
 *   msg_len  - length of msg
 *   sig_out  - output buffer for the signature
 *   sig_len  - on input: size of buffer; on output: actual sig length
 *
 * Returns 0 on success, -1 on failure.
 */
PQC_TLS_API int pqc_tls_sign(uint16_t sig_alg,
                               const uint8_t *sk, size_t sk_len,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig_out, size_t *sig_len);

/*
 * Verify a PQC signature.
 *
 *   sig_alg  - TLS SignatureScheme code
 *   pk       - signer's public key
 *   pk_len   - length of pk
 *   msg      - signed message
 *   msg_len  - length of msg
 *   sig      - signature to verify
 *   sig_len  - length of sig
 *
 * Returns 0 if the signature is valid, -1 on failure.
 */
PQC_TLS_API int pqc_tls_verify(uint16_t sig_alg,
                                 const uint8_t *pk, size_t pk_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);

/* -------------------------------------------------------------------------- */
/* Group size queries                                                          */
/* -------------------------------------------------------------------------- */

/*
 * Return the size of the client key share for the given group, or 0
 * if the group is not supported.
 */
PQC_TLS_API size_t pqc_tls_group_client_share_size(uint16_t group_id);

/*
 * Return the size of the server key share (ciphertext) for the given
 * group, or 0 if not supported.
 */
PQC_TLS_API size_t pqc_tls_group_server_share_size(uint16_t group_id);

/*
 * Return the shared secret size for the given group, or 0 if not
 * supported.
 */
PQC_TLS_API size_t pqc_tls_group_shared_secret_size(uint16_t group_id);

/* -------------------------------------------------------------------------- */
/* Group / signature algorithm enumeration                                     */
/* -------------------------------------------------------------------------- */

/*
 * Return the human-readable name for a NamedGroup code, or NULL if not
 * recognized. E.g. 0x6399 -> "X25519+ML-KEM-768".
 */
PQC_TLS_API const char *pqc_tls_group_name(uint16_t group_id);

/*
 * Return the human-readable name for a SignatureScheme code, or NULL
 * if not recognized.
 */
PQC_TLS_API const char *pqc_tls_sigalg_name(uint16_t sig_alg);

/* -------------------------------------------------------------------------- */
/* TLS 1.2 compatibility (limited)                                             */
/* -------------------------------------------------------------------------- */

/*
 * Register hybrid key exchange extensions for TLS 1.2.
 *
 *   ssl_ctx - pointer to an SSL_CTX (cast to void* for portability)
 *
 * Only hybrid modes are practical in TLS 1.2; pure PQC key exchange
 * requires TLS 1.3.
 *
 * Returns 0 on success, -1 on failure.
 */
PQC_TLS_API int pqc_tls12_register_hybrid_kex(void *ssl_ctx);

#ifdef __cplusplus
}
#endif

#endif /* PQC_TLS_H */
