/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * BoringSSL Integration — Internal declarations
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#ifndef PQC_BORINGSSL_INTERNAL_H
#define PQC_BORINGSSL_INTERNAL_H

#include <openssl/ssl.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Hybrid group identifiers (internal enum)                                    */
/* -------------------------------------------------------------------------- */

enum {
    PQC_BSSL_GROUP_X25519_MLKEM768   = 1,
    PQC_BSSL_GROUP_SECP256R1_MLKEM768 = 2,
};

/* -------------------------------------------------------------------------- */
/* Hybrid group definition                                                     */
/* -------------------------------------------------------------------------- */

typedef struct {
    const char *name;           /* e.g. "X25519+ML-KEM-768" */
    int         group_type;     /* PQC_BSSL_GROUP_* enum value */
    uint16_t    tls_group_id;   /* IANA NamedGroup codepoint */
} pqc_bssl_hybrid_group_def_t;

/* -------------------------------------------------------------------------- */
/* KEM sub-module (pqc_boringssl_kem.c)                                        */
/* -------------------------------------------------------------------------- */

/* One-time initialization for KEM key-share callbacks. */
int pqc_bssl_kem_init(void);

/* Register a pure PQC KEM group on an SSL_CTX. */
int pqc_bssl_kem_register_group(SSL_CTX *ctx, const char *algorithm);

/* Register a hybrid KEM group on an SSL_CTX. */
int pqc_bssl_kem_register_hybrid_group(
        SSL_CTX *ctx, const pqc_bssl_hybrid_group_def_t *def);

/* -------------------------------------------------------------------------- */
/* Signature sub-module (pqc_boringssl_sig.c)                                  */
/* -------------------------------------------------------------------------- */

/* One-time initialization for signature scheme callbacks. */
int pqc_bssl_sig_init(void);

/* Register a PQC signature scheme on an SSL_CTX. */
int pqc_bssl_sig_register_scheme(SSL_CTX *ctx, const char *algorithm);

#ifdef __cplusplus
}
#endif

#endif /* PQC_BORINGSSL_INTERNAL_H */
