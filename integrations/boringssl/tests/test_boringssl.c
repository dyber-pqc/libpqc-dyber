/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * BoringSSL Integration Tests
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#include "pqc_boringssl.h"

#include <pqc/pqc.h>
#include <pqc/kem.h>
#include <pqc/sig.h>
#include <pqc/algorithms.h>
#include <pqc/common.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Helpers                                                                     */
/* -------------------------------------------------------------------------- */

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_BEGIN(name)                                            \
    do {                                                            \
        tests_run++;                                                \
        printf("  %-50s ", (name));                                 \
        fflush(stdout);                                             \
    } while (0)

#define TEST_PASS()                                                 \
    do { tests_passed++; printf("[PASS]\n"); } while (0)

#define TEST_FAIL(msg)                                              \
    do { printf("[FAIL] %s\n", (msg)); } while (0)

#define REQUIRE(cond, msg)                                          \
    do {                                                            \
        if (!(cond)) { TEST_FAIL(msg); return; }                   \
    } while (0)

/* -------------------------------------------------------------------------- */
/* Test: library initialization                                                */
/* -------------------------------------------------------------------------- */

static void test_init(void)
{
    TEST_BEGIN("PQC_BoringSSL_init");
    int rc = PQC_BoringSSL_init();
    REQUIRE(rc == 1, "initialization failed");
    /* Idempotent: second call must also succeed */
    rc = PQC_BoringSSL_init();
    REQUIRE(rc == 1, "re-initialization failed");
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: NID lookup                                                            */
/* -------------------------------------------------------------------------- */

static void test_nid_lookup(void)
{
    TEST_BEGIN("NID lookup for ML-KEM-768");
    int nid = PQC_BoringSSL_get_nid("ML-KEM-768");
    REQUIRE(nid != 0, "NID_undef returned");
    TEST_PASS();

    TEST_BEGIN("NID lookup for ML-DSA-65");
    nid = PQC_BoringSSL_get_nid("ML-DSA-65");
    REQUIRE(nid != 0, "NID_undef returned");
    TEST_PASS();

    TEST_BEGIN("NID lookup for unknown algorithm");
    nid = PQC_BoringSSL_get_nid("INVALID-ALGO");
    REQUIRE(nid == 0, "expected NID_undef for unknown algorithm");
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: EVP_PKEY_METHOD retrieval                                             */
/* -------------------------------------------------------------------------- */

static void test_evp_methods(void)
{
    TEST_BEGIN("EVP_PKEY_METHOD for ML-KEM-512");
    int nid = PQC_BoringSSL_get_nid("ML-KEM-512");
    const EVP_PKEY_METHOD *m = PQC_BoringSSL_kem_method(nid);
    REQUIRE(m != NULL, "method is NULL");
    TEST_PASS();

    TEST_BEGIN("EVP_PKEY_METHOD for ML-DSA-44");
    nid = PQC_BoringSSL_get_nid("ML-DSA-44");
    const EVP_PKEY_METHOD *s = PQC_BoringSSL_sig_method(nid);
    REQUIRE(s != NULL, "method is NULL");
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: SSL_CTX registration (KEM)                                            */
/* -------------------------------------------------------------------------- */

static void test_register_kem(void)
{
    TEST_BEGIN("PQC_BoringSSL_register_kem(ML-KEM-768)");

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    REQUIRE(ctx != NULL, "SSL_CTX_new failed");

    int rc = PQC_BoringSSL_register_kem(ctx, "ML-KEM-768");
    REQUIRE(rc == 1, "register_kem failed");

    SSL_CTX_free(ctx);
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: SSL_CTX registration (signatures)                                     */
/* -------------------------------------------------------------------------- */

static void test_register_sig(void)
{
    TEST_BEGIN("PQC_BoringSSL_register_sig(ML-DSA-65)");

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    REQUIRE(ctx != NULL, "SSL_CTX_new failed");

    int rc = PQC_BoringSSL_register_sig(ctx, "ML-DSA-65");
    REQUIRE(rc == 1, "register_sig failed");

    SSL_CTX_free(ctx);
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: hybrid group registration                                             */
/* -------------------------------------------------------------------------- */

static void test_register_hybrid(void)
{
    TEST_BEGIN("PQC_BoringSSL_register_hybrid_groups");

    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    REQUIRE(ctx != NULL, "SSL_CTX_new failed");

    int rc = PQC_BoringSSL_register_hybrid_groups(ctx);
    REQUIRE(rc == 1, "register_hybrid_groups failed");

    SSL_CTX_free(ctx);
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: NULL / invalid argument handling                                       */
/* -------------------------------------------------------------------------- */

static void test_null_handling(void)
{
    TEST_BEGIN("NULL ctx handling");
    REQUIRE(PQC_BoringSSL_register_kem(NULL, "ML-KEM-768") == 0,
            "should fail with NULL ctx");
    REQUIRE(PQC_BoringSSL_register_sig(NULL, "ML-DSA-65") == 0,
            "should fail with NULL ctx");
    REQUIRE(PQC_BoringSSL_register_hybrid_groups(NULL) == 0,
            "should fail with NULL ctx");
    TEST_PASS();

    TEST_BEGIN("NULL algorithm handling");
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    REQUIRE(ctx != NULL, "SSL_CTX_new failed");
    REQUIRE(PQC_BoringSSL_register_kem(ctx, NULL) == 0,
            "should fail with NULL algorithm");
    REQUIRE(PQC_BoringSSL_register_sig(ctx, NULL) == 0,
            "should fail with NULL algorithm");
    SSL_CTX_free(ctx);
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: underlying PQC KEM round-trip (via libpqc directly)                   */
/* -------------------------------------------------------------------------- */

static void test_kem_roundtrip(const char *algorithm)
{
    char label[64];
    snprintf(label, sizeof(label), "KEM round-trip: %s", algorithm);
    TEST_BEGIN(label);

    PQC_KEM *kem = pqc_kem_new(algorithm);
    REQUIRE(kem != NULL, "pqc_kem_new failed");

    size_t pk_sz = pqc_kem_public_key_size(kem);
    size_t sk_sz = pqc_kem_secret_key_size(kem);
    size_t ct_sz = pqc_kem_ciphertext_size(kem);
    size_t ss_sz = pqc_kem_shared_secret_size(kem);

    uint8_t *pk = malloc(pk_sz);
    uint8_t *sk = malloc(sk_sz);
    uint8_t *ct = malloc(ct_sz);
    uint8_t *ss1 = malloc(ss_sz);
    uint8_t *ss2 = malloc(ss_sz);

    REQUIRE(pk && sk && ct && ss1 && ss2, "allocation failed");

    REQUIRE(pqc_kem_keygen(kem, pk, sk) == PQC_OK, "keygen failed");
    REQUIRE(pqc_kem_encaps(kem, ct, ss1, pk) == PQC_OK, "encaps failed");
    REQUIRE(pqc_kem_decaps(kem, ss2, ct, sk) == PQC_OK, "decaps failed");
    REQUIRE(memcmp(ss1, ss2, ss_sz) == 0, "shared secrets differ");

    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    pqc_kem_free(kem);
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: underlying PQC signature round-trip (via libpqc directly)             */
/* -------------------------------------------------------------------------- */

static void test_sig_roundtrip(const char *algorithm)
{
    char label[64];
    snprintf(label, sizeof(label), "SIG round-trip: %s", algorithm);
    TEST_BEGIN(label);

    PQC_SIG *sig = pqc_sig_new(algorithm);
    REQUIRE(sig != NULL, "pqc_sig_new failed");

    size_t pk_sz  = pqc_sig_public_key_size(sig);
    size_t sk_sz  = pqc_sig_secret_key_size(sig);
    size_t sig_sz = pqc_sig_max_signature_size(sig);

    uint8_t *pk = malloc(pk_sz);
    uint8_t *sk = malloc(sk_sz);
    uint8_t *signature = malloc(sig_sz);
    size_t  sig_len = 0;

    REQUIRE(pk && sk && signature, "allocation failed");

    const uint8_t msg[] = "BoringSSL integration test message";
    size_t msg_len = sizeof(msg) - 1;

    REQUIRE(pqc_sig_keygen(sig, pk, sk) == PQC_OK, "keygen failed");
    REQUIRE(pqc_sig_sign(sig, signature, &sig_len,
                          msg, msg_len, sk) == PQC_OK, "sign failed");
    REQUIRE(pqc_sig_verify(sig, msg, msg_len,
                            signature, sig_len, pk) == PQC_OK,
            "verify failed");

    /* Tamper with signature and check rejection */
    signature[0] ^= 0xFF;
    REQUIRE(pqc_sig_verify(sig, msg, msg_len,
                            signature, sig_len, pk) != PQC_OK,
            "tampered signature should not verify");

    free(pk); free(sk); free(signature);
    pqc_sig_free(sig);
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Main                                                                        */
/* -------------------------------------------------------------------------- */

int main(void)
{
    printf("=== BoringSSL Integration Tests ===\n\n");

    /* Initialization */
    test_init();

    /* NID and method lookups */
    test_nid_lookup();
    test_evp_methods();

    /* SSL_CTX registration */
    test_register_kem();
    test_register_sig();
    test_register_hybrid();
    test_null_handling();

    /* Underlying KEM round-trips */
    printf("\n--- KEM Round-Trips ---\n");
    test_kem_roundtrip("ML-KEM-512");
    test_kem_roundtrip("ML-KEM-768");
    test_kem_roundtrip("ML-KEM-1024");

    /* Underlying signature round-trips */
    printf("\n--- Signature Round-Trips ---\n");
    test_sig_roundtrip("ML-DSA-44");
    test_sig_roundtrip("ML-DSA-65");
    test_sig_roundtrip("ML-DSA-87");

    printf("\n=== Results: %d / %d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
