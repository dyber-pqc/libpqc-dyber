/*
 * libpqc-dyber OpenSSL 3.x Provider — Integration Tests
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Tests that the PQC provider loads correctly and that KEM and signature
 * operations work through the OpenSSL EVP API.
 *
 * Build with:
 *   cc -o test_openssl_provider test_openssl_provider.c -lcrypto
 * Run with:
 *   OPENSSL_MODULES=/path/to/provider/dir ./test_openssl_provider
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

/* ========================================================================== */
/* Helpers                                                                     */
/* ========================================================================== */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg)                                   \
    do {                                                         \
        tests_run++;                                             \
        if (!(cond)) {                                           \
            fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
            ERR_print_errors_fp(stderr);                         \
            tests_failed++;                                      \
        } else {                                                 \
            printf("  PASS: %s\n", msg);                         \
            tests_passed++;                                      \
        }                                                        \
    } while (0)

static void print_openssl_errors(void)
{
    ERR_print_errors_fp(stderr);
}

/* ========================================================================== */
/* Test: Provider loads                                                        */
/* ========================================================================== */

static OSSL_PROVIDER *prov_pqc = NULL;
static OSSL_PROVIDER *prov_default = NULL;

static int test_provider_load(void)
{
    printf("\n--- Test: Provider Load ---\n");

    /* Load the default provider (needed for base operations) */
    prov_default = OSSL_PROVIDER_load(NULL, "default");
    TEST_ASSERT(prov_default != NULL, "Load default provider");

    /* Load our PQC provider */
    prov_pqc = OSSL_PROVIDER_load(NULL, "pqc_provider");
    TEST_ASSERT(prov_pqc != NULL, "Load pqc_provider");

    if (prov_pqc == NULL) {
        fprintf(stderr, "Could not load pqc_provider. Ensure OPENSSL_MODULES "
                "environment variable points to the provider directory.\n");
        print_openssl_errors();
        return 0;
    }

    /* Verify provider name */
    const char *name = OSSL_PROVIDER_get0_name(prov_pqc);
    TEST_ASSERT(name != NULL && strcmp(name, "pqc_provider") == 0,
                "Provider name is 'pqc_provider'");

    return 1;
}

/* ========================================================================== */
/* Test: List available KEM algorithms                                         */
/* ========================================================================== */

static void kem_algorithm_cb(EVP_KEM *kem, void *arg)
{
    int *count = (int *)arg;
    const char *name = EVP_KEM_get0_name(kem);
    const char *prov = OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(kem));
    if (prov != NULL && strcmp(prov, "pqc_provider") == 0) {
        printf("    KEM: %s (provider: %s)\n", name, prov);
        (*count)++;
    }
}

static void test_list_kem_algorithms(void)
{
    printf("\n--- Test: List KEM Algorithms ---\n");
    int count = 0;
    EVP_KEM_do_all_provided(NULL, kem_algorithm_cb, &count);
    TEST_ASSERT(count > 0, "At least one KEM algorithm is registered");
    printf("  Found %d KEM algorithms from pqc_provider\n", count);
}

/* ========================================================================== */
/* Test: List available signature algorithms                                   */
/* ========================================================================== */

static void sig_algorithm_cb(EVP_SIGNATURE *sig, void *arg)
{
    int *count = (int *)arg;
    const char *name = EVP_SIGNATURE_get0_name(sig);
    const char *prov = OSSL_PROVIDER_get0_name(
                           EVP_SIGNATURE_get0_provider(sig));
    if (prov != NULL && strcmp(prov, "pqc_provider") == 0) {
        printf("    SIG: %s (provider: %s)\n", name, prov);
        (*count)++;
    }
}

static void test_list_sig_algorithms(void)
{
    printf("\n--- Test: List Signature Algorithms ---\n");
    int count = 0;
    EVP_SIGNATURE_do_all_provided(NULL, sig_algorithm_cb, &count);
    TEST_ASSERT(count > 0, "At least one signature algorithm is registered");
    printf("  Found %d signature algorithms from pqc_provider\n", count);
}

/* ========================================================================== */
/* Test: ML-KEM-768 keygen + encaps + decaps                                   */
/* ========================================================================== */

static void test_kem_mlkem768(void)
{
    printf("\n--- Test: ML-KEM-768 KEM ---\n");

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    unsigned char *ct = NULL, *ss_enc = NULL, *ss_dec = NULL;
    size_t ct_len = 0, ss_enc_len = 0, ss_dec_len = 0;
    int ok;

    /* Key generation */
    kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    TEST_ASSERT(kctx != NULL, "Create keygen context for ML-KEM-768");
    if (kctx == NULL) goto cleanup;

    ok = EVP_PKEY_keygen_init(kctx);
    TEST_ASSERT(ok == 1, "Init keygen for ML-KEM-768");

    ok = EVP_PKEY_keygen(kctx, &pkey);
    TEST_ASSERT(ok == 1 && pkey != NULL, "Generate ML-KEM-768 keypair");
    if (pkey == NULL) goto cleanup;

    /* Encapsulate */
    ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    TEST_ASSERT(ectx != NULL, "Create encapsulate context");
    if (ectx == NULL) goto cleanup;

    ok = EVP_PKEY_encapsulate_init(ectx, NULL);
    TEST_ASSERT(ok == 1, "Init encapsulate");

    /* Query sizes */
    ok = EVP_PKEY_encapsulate(ectx, NULL, &ct_len, NULL, &ss_enc_len);
    TEST_ASSERT(ok == 1, "Query encapsulate sizes");
    TEST_ASSERT(ct_len > 0 && ss_enc_len > 0, "Encapsulate sizes are non-zero");

    ct = OPENSSL_malloc(ct_len);
    ss_enc = OPENSSL_malloc(ss_enc_len);
    TEST_ASSERT(ct != NULL && ss_enc != NULL, "Allocate encapsulate buffers");

    ok = EVP_PKEY_encapsulate(ectx, ct, &ct_len, ss_enc, &ss_enc_len);
    TEST_ASSERT(ok == 1, "Encapsulate succeeds");

    /* Decapsulate */
    dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    TEST_ASSERT(dctx != NULL, "Create decapsulate context");
    if (dctx == NULL) goto cleanup;

    ok = EVP_PKEY_decapsulate_init(dctx, NULL);
    TEST_ASSERT(ok == 1, "Init decapsulate");

    ok = EVP_PKEY_decapsulate(dctx, NULL, &ss_dec_len, ct, ct_len);
    TEST_ASSERT(ok == 1, "Query decapsulate size");

    ss_dec = OPENSSL_malloc(ss_dec_len);
    TEST_ASSERT(ss_dec != NULL, "Allocate decapsulate buffer");

    ok = EVP_PKEY_decapsulate(dctx, ss_dec, &ss_dec_len, ct, ct_len);
    TEST_ASSERT(ok == 1, "Decapsulate succeeds");

    /* Verify shared secrets match */
    TEST_ASSERT(ss_enc_len == ss_dec_len, "Shared secret lengths match");
    if (ss_enc_len == ss_dec_len) {
        ok = (memcmp(ss_enc, ss_dec, ss_enc_len) == 0);
        TEST_ASSERT(ok, "Shared secrets match");
    }

cleanup:
    OPENSSL_free(ct);
    OPENSSL_free(ss_enc);
    OPENSSL_free(ss_dec);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
}

/* ========================================================================== */
/* Test: ML-DSA-65 keygen + sign + verify                                      */
/* ========================================================================== */

static void test_sig_mldsa65(void)
{
    printf("\n--- Test: ML-DSA-65 Signature ---\n");

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ok;

    const unsigned char msg[] = "Post-quantum test message for ML-DSA-65";
    const size_t msglen = sizeof(msg) - 1;

    /* Key generation */
    kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    TEST_ASSERT(kctx != NULL, "Create keygen context for ML-DSA-65");
    if (kctx == NULL) goto cleanup;

    ok = EVP_PKEY_keygen_init(kctx);
    TEST_ASSERT(ok == 1, "Init keygen for ML-DSA-65");

    ok = EVP_PKEY_keygen(kctx, &pkey);
    TEST_ASSERT(ok == 1 && pkey != NULL, "Generate ML-DSA-65 keypair");
    if (pkey == NULL) goto cleanup;

    /* Sign via DigestSign (message-based, no digest) */
    mdctx = EVP_MD_CTX_new();
    TEST_ASSERT(mdctx != NULL, "Create MD context");
    if (mdctx == NULL) goto cleanup;

    ok = EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL);
    TEST_ASSERT(ok == 1, "Init DigestSign for ML-DSA-65");

    ok = EVP_DigestSignUpdate(mdctx, msg, msglen);
    TEST_ASSERT(ok == 1, "DigestSign update");

    /* Query signature size */
    ok = EVP_DigestSignFinal(mdctx, NULL, &siglen);
    TEST_ASSERT(ok == 1 && siglen > 0, "Query signature size");

    sig = OPENSSL_malloc(siglen);
    TEST_ASSERT(sig != NULL, "Allocate signature buffer");

    ok = EVP_DigestSignFinal(mdctx, sig, &siglen);
    TEST_ASSERT(ok == 1, "DigestSign final (sign)");

    /* Verify */
    EVP_MD_CTX_free(mdctx);
    mdctx = EVP_MD_CTX_new();
    TEST_ASSERT(mdctx != NULL, "Create verify MD context");
    if (mdctx == NULL) goto cleanup;

    ok = EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL);
    TEST_ASSERT(ok == 1, "Init DigestVerify for ML-DSA-65");

    ok = EVP_DigestVerifyUpdate(mdctx, msg, msglen);
    TEST_ASSERT(ok == 1, "DigestVerify update");

    ok = EVP_DigestVerifyFinal(mdctx, sig, siglen);
    TEST_ASSERT(ok == 1, "DigestVerify final (verify OK)");

    /* Tamper with signature and verify again — should fail */
    if (siglen > 0) {
        sig[0] ^= 0xFF;
        EVP_MD_CTX_free(mdctx);
        mdctx = EVP_MD_CTX_new();
        if (mdctx != NULL) {
            EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL);
            EVP_DigestVerifyUpdate(mdctx, msg, msglen);
            ok = EVP_DigestVerifyFinal(mdctx, sig, siglen);
            TEST_ASSERT(ok != 1, "Tampered signature correctly rejected");
        }
    }

cleanup:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
}

/* ========================================================================== */
/* Test: Hybrid X25519+ML-KEM-768 KEM                                          */
/* ========================================================================== */

static void test_hybrid_kem(void)
{
    printf("\n--- Test: Hybrid X25519+ML-KEM-768 KEM ---\n");

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ectx = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    unsigned char *ct = NULL, *ss_enc = NULL, *ss_dec = NULL;
    size_t ct_len = 0, ss_enc_len = 0, ss_dec_len = 0;
    int ok;

    /* Key generation */
    kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768+X25519", NULL);
    TEST_ASSERT(kctx != NULL, "Create keygen context for ML-KEM-768+X25519");
    if (kctx == NULL) goto cleanup;

    ok = EVP_PKEY_keygen_init(kctx);
    TEST_ASSERT(ok == 1, "Init keygen for hybrid KEM");

    ok = EVP_PKEY_keygen(kctx, &pkey);
    TEST_ASSERT(ok == 1 && pkey != NULL, "Generate hybrid KEM keypair");
    if (pkey == NULL) goto cleanup;

    /* Encapsulate */
    ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    TEST_ASSERT(ectx != NULL, "Create hybrid encapsulate context");
    if (ectx == NULL) goto cleanup;

    ok = EVP_PKEY_encapsulate_init(ectx, NULL);
    TEST_ASSERT(ok == 1, "Init hybrid encapsulate");

    ok = EVP_PKEY_encapsulate(ectx, NULL, &ct_len, NULL, &ss_enc_len);
    TEST_ASSERT(ok == 1 && ct_len > 0, "Query hybrid encapsulate sizes");

    ct = OPENSSL_malloc(ct_len);
    ss_enc = OPENSSL_malloc(ss_enc_len);

    ok = EVP_PKEY_encapsulate(ectx, ct, &ct_len, ss_enc, &ss_enc_len);
    TEST_ASSERT(ok == 1, "Hybrid encapsulate succeeds");

    /* Decapsulate */
    dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    TEST_ASSERT(dctx != NULL, "Create hybrid decapsulate context");
    if (dctx == NULL) goto cleanup;

    ok = EVP_PKEY_decapsulate_init(dctx, NULL);
    TEST_ASSERT(ok == 1, "Init hybrid decapsulate");

    ok = EVP_PKEY_decapsulate(dctx, NULL, &ss_dec_len, ct, ct_len);
    TEST_ASSERT(ok == 1, "Query hybrid decapsulate size");

    ss_dec = OPENSSL_malloc(ss_dec_len);
    ok = EVP_PKEY_decapsulate(dctx, ss_dec, &ss_dec_len, ct, ct_len);
    TEST_ASSERT(ok == 1, "Hybrid decapsulate succeeds");

    TEST_ASSERT(ss_enc_len == ss_dec_len, "Hybrid shared secret lengths match");
    if (ss_enc_len == ss_dec_len) {
        ok = (memcmp(ss_enc, ss_dec, ss_enc_len) == 0);
        TEST_ASSERT(ok, "Hybrid shared secrets match");
    }

cleanup:
    OPENSSL_free(ct);
    OPENSSL_free(ss_enc);
    OPENSSL_free(ss_dec);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
}

/* ========================================================================== */
/* Test: Key properties via EVP_PKEY_get_params                                */
/* ========================================================================== */

static void test_key_properties(void)
{
    printf("\n--- Test: Key Properties ---\n");

    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ok;

    kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
    TEST_ASSERT(kctx != NULL, "Create keygen context for key properties test");
    if (kctx == NULL) return;

    EVP_PKEY_keygen_init(kctx);
    ok = EVP_PKEY_keygen(kctx, &pkey);
    TEST_ASSERT(ok == 1 && pkey != NULL, "Generate key for properties test");
    if (pkey == NULL) goto cleanup;

    int security_bits = 0;
    ok = EVP_PKEY_get_security_bits(pkey);
    security_bits = ok;
    TEST_ASSERT(security_bits > 0, "Security bits > 0");
    printf("  ML-KEM-768 security bits: %d\n", security_bits);

    int bits = EVP_PKEY_get_bits(pkey);
    TEST_ASSERT(bits > 0, "Key bits > 0");
    printf("  ML-KEM-768 key bits: %d\n", bits);

cleanup:
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(pkey);
}

/* ========================================================================== */
/* main                                                                        */
/* ========================================================================== */

int main(void)
{
    printf("=== libpqc-dyber OpenSSL Provider Tests ===\n");

    /* Load providers */
    if (!test_provider_load()) {
        fprintf(stderr, "\nProvider load failed — aborting remaining tests.\n");
        return 1;
    }

    /* Run test suites */
    test_list_kem_algorithms();
    test_list_sig_algorithms();
    test_kem_mlkem768();
    test_sig_mldsa65();
    test_hybrid_kem();
    test_key_properties();

    /* Cleanup */
    if (prov_pqc != NULL)
        OSSL_PROVIDER_unload(prov_pqc);
    if (prov_default != NULL)
        OSSL_PROVIDER_unload(prov_default);

    /* Summary */
    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return (tests_failed > 0) ? 1 : 0;
}
