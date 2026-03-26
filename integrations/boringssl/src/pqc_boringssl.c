/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * BoringSSL Integration — Main registration and EVP_PKEY wiring
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#include "pqc_boringssl.h"
#include "pqc_boringssl_internal.h"

#include <pqc/pqc.h>
#include <pqc/algorithms.h>
#include <pqc/kem.h>
#include <pqc/sig.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/ssl.h>

#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------- */
/* Internal state                                                              */
/* -------------------------------------------------------------------------- */

static int g_pqc_bssl_initialized = 0;

/* NID table — maps algorithm name to dynamically-assigned NID */
typedef struct {
    const char *name;
    int         nid;
} pqc_nid_entry_t;

#define PQC_BSSL_MAX_ALGORITHMS 32

static pqc_nid_entry_t g_nid_table[PQC_BSSL_MAX_ALGORITHMS];
static size_t           g_nid_count = 0;

/* EVP_PKEY_METHOD tables */
static EVP_PKEY_METHOD *g_kem_methods[PQC_BSSL_MAX_ALGORITHMS];
static size_t           g_kem_method_count = 0;

static EVP_PKEY_METHOD *g_sig_methods[PQC_BSSL_MAX_ALGORITHMS];
static size_t           g_sig_method_count = 0;

/* -------------------------------------------------------------------------- */
/* NID helpers                                                                 */
/* -------------------------------------------------------------------------- */

static int register_nid(const char *short_name, const char *long_name)
{
    if (g_nid_count >= PQC_BSSL_MAX_ALGORITHMS)
        return 0;

    /*
     * OBJ_create is available in BoringSSL and assigns a dynamic NID.
     * OID is NULL because IANA has not yet assigned OIDs for most PQC
     * TLS artifacts; the NID is used internally only.
     */
    int nid = OBJ_create(NULL, short_name, long_name);
    if (nid == NID_undef)
        return 0;

    g_nid_table[g_nid_count].name = short_name;
    g_nid_table[g_nid_count].nid  = nid;
    g_nid_count++;
    return nid;
}

int PQC_BoringSSL_get_nid(const char *algorithm)
{
    for (size_t i = 0; i < g_nid_count; i++) {
        if (strcmp(g_nid_table[i].name, algorithm) == 0)
            return g_nid_table[i].nid;
    }
    return NID_undef;
}

/* -------------------------------------------------------------------------- */
/* EVP_PKEY_METHOD — KEM wrapper callbacks                                     */
/* -------------------------------------------------------------------------- */

/*
 * The EVP_PKEY_METHOD callbacks delegate to the libpqc KEM API.
 * BoringSSL's EVP_PKEY_METHOD is simpler than OpenSSL 1.1's; we hook
 * keygen, encrypt (encaps), and decrypt (decaps).
 */

static int pqc_kem_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    (void)ctx;
    (void)pkey;
    /*
     * Keygen is handled through the TLS key-share callbacks rather than
     * EVP_PKEY_keygen for KEM algorithms. This stub exists so that the
     * method table is complete.
     */
    return 1;
}

static int pqc_kem_pkey_encapsulate(EVP_PKEY_CTX *ctx,
                                     unsigned char *ct, size_t *ct_len,
                                     unsigned char *ss, size_t *ss_len)
{
    (void)ctx;
    (void)ct;
    (void)ct_len;
    (void)ss;
    (void)ss_len;
    /* Actual encapsulation is done in the key-share callbacks; see
     * pqc_boringssl_kem.c. This is a placeholder for the method vtable. */
    return 1;
}

static int pqc_kem_pkey_decapsulate(EVP_PKEY_CTX *ctx,
                                     unsigned char *ss, size_t *ss_len,
                                     const unsigned char *ct, size_t ct_len)
{
    (void)ctx;
    (void)ss;
    (void)ss_len;
    (void)ct;
    (void)ct_len;
    return 1;
}

static EVP_PKEY_METHOD *create_kem_method(int nid)
{
    EVP_PKEY_METHOD *meth = EVP_PKEY_meth_new(nid, 0);
    if (!meth)
        return NULL;

    EVP_PKEY_meth_set_keygen(meth, NULL, pqc_kem_pkey_keygen);
    EVP_PKEY_meth_set_encrypt(meth, NULL,
                              (int (*)(EVP_PKEY_CTX *, unsigned char *,
                                       size_t *, const unsigned char *,
                                       size_t))pqc_kem_pkey_encapsulate);
    EVP_PKEY_meth_set_decrypt(meth, NULL,
                              (int (*)(EVP_PKEY_CTX *, unsigned char *,
                                       size_t *, const unsigned char *,
                                       size_t))pqc_kem_pkey_decapsulate);

    if (g_kem_method_count < PQC_BSSL_MAX_ALGORITHMS)
        g_kem_methods[g_kem_method_count++] = meth;

    return meth;
}

/* -------------------------------------------------------------------------- */
/* EVP_PKEY_METHOD — Signature wrapper callbacks                               */
/* -------------------------------------------------------------------------- */

static int pqc_sig_pkey_sign(EVP_PKEY_CTX *ctx,
                              unsigned char *sig, size_t *sig_len,
                              const unsigned char *tbs, size_t tbs_len)
{
    (void)ctx;
    (void)sig;
    (void)sig_len;
    (void)tbs;
    (void)tbs_len;
    /* Signing is handled through the CertificateVerify callbacks; see
     * pqc_boringssl_sig.c. Placeholder for method vtable completeness. */
    return 1;
}

static int pqc_sig_pkey_verify(EVP_PKEY_CTX *ctx,
                                const unsigned char *sig, size_t sig_len,
                                const unsigned char *tbs, size_t tbs_len)
{
    (void)ctx;
    (void)sig;
    (void)sig_len;
    (void)tbs;
    (void)tbs_len;
    return 1;
}

static EVP_PKEY_METHOD *create_sig_method(int nid)
{
    EVP_PKEY_METHOD *meth = EVP_PKEY_meth_new(nid, 0);
    if (!meth)
        return NULL;

    EVP_PKEY_meth_set_sign(meth, NULL, pqc_sig_pkey_sign);
    EVP_PKEY_meth_set_verify(meth, NULL, pqc_sig_pkey_verify);

    if (g_sig_method_count < PQC_BSSL_MAX_ALGORITHMS)
        g_sig_methods[g_sig_method_count++] = meth;

    return meth;
}

/* -------------------------------------------------------------------------- */
/* Initialization                                                              */
/* -------------------------------------------------------------------------- */

/* KEM algorithms to register */
static const char *kem_algorithms[] = {
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    NULL
};

/* Signature algorithms to register */
static const char *sig_algorithms[] = {
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s",
    "SLH-DSA-SHA2-256f",
    NULL
};

/* Hybrid groups to register (name, classical component) */
static const pqc_bssl_hybrid_group_def_t hybrid_group_defs[] = {
    { "X25519+ML-KEM-768",  PQC_BSSL_GROUP_X25519_MLKEM768,  0x6399 },
    { "P-256+ML-KEM-768",   PQC_BSSL_GROUP_SECP256R1_MLKEM768, 0x639A },
    { NULL, 0, 0 }
};

int PQC_BoringSSL_init(void)
{
    if (g_pqc_bssl_initialized)
        return 1;

    /* Initialize the underlying libpqc library */
    if (pqc_init() != PQC_OK)
        return 0;

    /* Register NIDs and create EVP_PKEY_METHODs for KEM algorithms */
    for (const char **p = kem_algorithms; *p; p++) {
        int nid = register_nid(*p, *p);
        if (nid == 0)
            return 0;
        if (!create_kem_method(nid))
            return 0;
    }

    /* Register NIDs and create EVP_PKEY_METHODs for signature algorithms */
    for (const char **p = sig_algorithms; *p; p++) {
        int nid = register_nid(*p, *p);
        if (nid == 0)
            return 0;
        if (!create_sig_method(nid))
            return 0;
    }

    /* Register hybrid group NIDs */
    for (const pqc_bssl_hybrid_group_def_t *g = hybrid_group_defs;
         g->name; g++) {
        if (register_nid(g->name, g->name) == 0)
            return 0;
    }

    /* Initialize KEM key-share callbacks */
    if (!pqc_bssl_kem_init())
        return 0;

    /* Initialize signature scheme callbacks */
    if (!pqc_bssl_sig_init())
        return 0;

    g_pqc_bssl_initialized = 1;
    return 1;
}

/* -------------------------------------------------------------------------- */
/* SSL_CTX registration helpers                                                */
/* -------------------------------------------------------------------------- */

int PQC_BoringSSL_register_kem(SSL_CTX *ctx, const char *algorithm)
{
    if (!ctx || !algorithm)
        return 0;
    if (!g_pqc_bssl_initialized && !PQC_BoringSSL_init())
        return 0;

    return pqc_bssl_kem_register_group(ctx, algorithm);
}

int PQC_BoringSSL_register_sig(SSL_CTX *ctx, const char *algorithm)
{
    if (!ctx || !algorithm)
        return 0;
    if (!g_pqc_bssl_initialized && !PQC_BoringSSL_init())
        return 0;

    return pqc_bssl_sig_register_scheme(ctx, algorithm);
}

int PQC_BoringSSL_register_hybrid_groups(SSL_CTX *ctx)
{
    if (!ctx)
        return 0;
    if (!g_pqc_bssl_initialized && !PQC_BoringSSL_init())
        return 0;

    for (const pqc_bssl_hybrid_group_def_t *g = hybrid_group_defs;
         g->name; g++) {
        if (!pqc_bssl_kem_register_hybrid_group(ctx, g))
            return 0;
    }
    return 1;
}

/* -------------------------------------------------------------------------- */
/* EVP_PKEY_METHOD accessors                                                   */
/* -------------------------------------------------------------------------- */

const EVP_PKEY_METHOD *PQC_BoringSSL_kem_method(int nid)
{
    for (size_t i = 0; i < g_kem_method_count; i++) {
        int method_nid = 0;
        EVP_PKEY_meth_get0_info(&method_nid, NULL, g_kem_methods[i]);
        if (method_nid == nid)
            return g_kem_methods[i];
    }
    return NULL;
}

const EVP_PKEY_METHOD *PQC_BoringSSL_sig_method(int nid)
{
    for (size_t i = 0; i < g_sig_method_count; i++) {
        int method_nid = 0;
        EVP_PKEY_meth_get0_info(&method_nid, NULL, g_sig_methods[i]);
        if (method_nid == nid)
            return g_sig_methods[i];
    }
    return NULL;
}
