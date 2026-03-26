/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * TLS Integration Tests — Key Share Round-Trips
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#include "pqc_tls.h"

#include <pqc/pqc.h>
#include <pqc/kem.h>
#include <pqc/sig.h>
#include <pqc/algorithms.h>
#include <pqc/common.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Test helpers                                                                */
/* -------------------------------------------------------------------------- */

static int tests_run    = 0;
static int tests_passed = 0;

#define TEST_BEGIN(name)                                            \
    do {                                                            \
        tests_run++;                                                \
        printf("  %-55s ", (name));                                 \
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
/* Test: pure PQC key share round-trip                                         */
/* -------------------------------------------------------------------------- */

static void test_keyshare_roundtrip(uint16_t group_id)
{
    char label[80];
    const char *name = pqc_tls_group_name(group_id);
    snprintf(label, sizeof(label), "Key share round-trip: %s (0x%04X)",
             name ? name : "?", group_id);
    TEST_BEGIN(label);

    /* Query sizes */
    size_t client_sz = pqc_tls_group_client_share_size(group_id);
    size_t server_sz = pqc_tls_group_server_share_size(group_id);
    size_t ss_sz     = pqc_tls_group_shared_secret_size(group_id);

    REQUIRE(client_sz > 0, "unknown client share size");
    REQUIRE(server_sz > 0, "unknown server share size");
    REQUIRE(ss_sz > 0, "unknown shared secret size");

    /* Allocate buffers */
    uint8_t *client_share  = malloc(client_sz);
    uint8_t *server_share  = malloc(server_sz);
    uint8_t *client_secret = malloc(ss_sz);
    uint8_t *server_secret = malloc(ss_sz);

    REQUIRE(client_share && server_share && client_secret && server_secret,
            "allocation failed");

    /* --- Client: generate key share --- */
    PQC_TLS_KeyShare *client_ks = pqc_tls_keyshare_new(group_id);
    REQUIRE(client_ks != NULL, "pqc_tls_keyshare_new failed (client)");

    size_t client_share_len = client_sz;
    int rc = pqc_tls_keyshare_generate(client_ks,
                                        client_share, &client_share_len);
    REQUIRE(rc == 0, "keyshare_generate failed");
    REQUIRE(client_share_len > 0, "zero-length client share");

    /* --- Server: encapsulate --- */
    PQC_TLS_KeyShare *server_ks = pqc_tls_keyshare_new(group_id);
    REQUIRE(server_ks != NULL, "pqc_tls_keyshare_new failed (server)");

    size_t server_share_len = server_sz;
    size_t server_secret_len = ss_sz;
    rc = pqc_tls_keyshare_encapsulate(server_ks,
                                       client_share, client_share_len,
                                       server_share, &server_share_len,
                                       server_secret, &server_secret_len);
    REQUIRE(rc == 0, "keyshare_encapsulate failed");
    REQUIRE(server_share_len > 0, "zero-length server share");
    REQUIRE(server_secret_len > 0, "zero-length server secret");

    /* --- Client: decapsulate --- */
    size_t client_secret_len = ss_sz;
    rc = pqc_tls_keyshare_decapsulate(client_ks,
                                       server_share, server_share_len,
                                       client_secret, &client_secret_len);
    REQUIRE(rc == 0, "keyshare_decapsulate failed");
    REQUIRE(client_secret_len == server_secret_len,
            "secret lengths differ");

    /* --- Verify shared secrets match --- */
    REQUIRE(memcmp(client_secret, server_secret, client_secret_len) == 0,
            "shared secrets do not match");

    /* Cleanup */
    pqc_tls_keyshare_free(client_ks);
    pqc_tls_keyshare_free(server_ks);
    free(client_share);
    free(server_share);
    free(client_secret);
    free(server_secret);

    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: group name and size queries                                           */
/* -------------------------------------------------------------------------- */

static void test_group_queries(void)
{
    TEST_BEGIN("Group name query: ML-KEM-768");
    const char *name = pqc_tls_group_name(PQC_TLS_GROUP_MLKEM768);
    REQUIRE(name != NULL, "NULL name");
    REQUIRE(strcmp(name, "ML-KEM-768") == 0, "wrong name");
    TEST_PASS();

    TEST_BEGIN("Group name query: X25519+ML-KEM-768");
    name = pqc_tls_group_name(PQC_TLS_GROUP_X25519_MLKEM768);
    REQUIRE(name != NULL, "NULL name");
    REQUIRE(strcmp(name, "X25519+ML-KEM-768") == 0, "wrong name");
    TEST_PASS();

    TEST_BEGIN("Group name query: unknown group");
    name = pqc_tls_group_name(0xFFFF);
    REQUIRE(name == NULL, "expected NULL for unknown group");
    TEST_PASS();

    TEST_BEGIN("Size query: ML-KEM-512 client share");
    size_t sz = pqc_tls_group_client_share_size(PQC_TLS_GROUP_MLKEM512);
    REQUIRE(sz == 800, "expected 800");
    TEST_PASS();

    TEST_BEGIN("Size query: X25519+ML-KEM-768 client share");
    sz = pqc_tls_group_client_share_size(PQC_TLS_GROUP_X25519_MLKEM768);
    REQUIRE(sz == 32 + 1184, "expected 32 + 1184 = 1216");
    TEST_PASS();

    TEST_BEGIN("Size query: unknown group returns 0");
    sz = pqc_tls_group_client_share_size(0xFFFF);
    REQUIRE(sz == 0, "expected 0");
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: signature algorithm queries                                           */
/* -------------------------------------------------------------------------- */

static void test_sigalg_queries(void)
{
    TEST_BEGIN("Sigalg name query: ML-DSA-65");
    const char *name = pqc_tls_sigalg_name(PQC_TLS_SIGALG_MLDSA65);
    REQUIRE(name != NULL, "NULL name");
    REQUIRE(strcmp(name, "ML-DSA-65") == 0, "wrong name");
    TEST_PASS();

    TEST_BEGIN("Sigalg name query: SLH-DSA-SHA2-128s");
    name = pqc_tls_sigalg_name(PQC_TLS_SIGALG_SLHDSA_SHA2_128S);
    REQUIRE(name != NULL, "NULL name");
    REQUIRE(strcmp(name, "SLH-DSA-SHA2-128s") == 0, "wrong name");
    TEST_PASS();

    TEST_BEGIN("Sigalg name query: unknown sigalg");
    name = pqc_tls_sigalg_name(0xFFFF);
    REQUIRE(name == NULL, "expected NULL for unknown sigalg");
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: sign / verify round-trip                                              */
/* -------------------------------------------------------------------------- */

static void test_sign_verify(uint16_t sigalg_id)
{
    char label[80];
    const char *name = pqc_tls_sigalg_name(sigalg_id);
    snprintf(label, sizeof(label), "Sign/verify: %s (0x%04X)",
             name ? name : "?", sigalg_id);
    TEST_BEGIN(label);

    /* We need to get sizes from the algorithm name */
    const char *alg = name;
    REQUIRE(alg != NULL, "unknown sigalg");

    PQC_SIG *sig_ctx = pqc_sig_new(alg);
    REQUIRE(sig_ctx != NULL, "pqc_sig_new failed");

    size_t pk_sz  = pqc_sig_public_key_size(sig_ctx);
    size_t sk_sz  = pqc_sig_secret_key_size(sig_ctx);
    size_t sig_sz = pqc_sig_max_signature_size(sig_ctx);

    uint8_t *pk  = malloc(pk_sz);
    uint8_t *sk  = malloc(sk_sz);
    uint8_t *sig = malloc(sig_sz);
    REQUIRE(pk && sk && sig, "allocation failed");

    /* Keygen */
    REQUIRE(pqc_sig_keygen(sig_ctx, pk, sk) == PQC_OK, "keygen failed");
    pqc_sig_free(sig_ctx);

    const uint8_t msg[] = "TLS CertificateVerify test transcript hash";
    size_t msg_len = sizeof(msg) - 1;

    /* Sign via TLS API */
    size_t sig_len = sig_sz;
    int rc = pqc_tls_sign(sigalg_id, sk, sk_sz, msg, msg_len, sig, &sig_len);
    REQUIRE(rc == 0, "pqc_tls_sign failed");
    REQUIRE(sig_len > 0, "zero-length signature");

    /* Verify via TLS API */
    rc = pqc_tls_verify(sigalg_id, pk, pk_sz, msg, msg_len, sig, sig_len);
    REQUIRE(rc == 0, "pqc_tls_verify failed");

    /* Tamper and re-verify */
    sig[0] ^= 0xFF;
    rc = pqc_tls_verify(sigalg_id, pk, pk_sz, msg, msg_len, sig, sig_len);
    REQUIRE(rc != 0, "tampered signature should not verify");

    free(pk); free(sk); free(sig);
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: keyshare with NULL arguments                                          */
/* -------------------------------------------------------------------------- */

static void test_null_args(void)
{
    TEST_BEGIN("keyshare_new with unsupported group");
    PQC_TLS_KeyShare *ks = pqc_tls_keyshare_new(0xFFFF);
    REQUIRE(ks == NULL, "expected NULL for unsupported group");
    TEST_PASS();

    TEST_BEGIN("keyshare_generate with NULL key share");
    uint8_t buf[16];
    size_t len = sizeof(buf);
    int rc = pqc_tls_keyshare_generate(NULL, buf, &len);
    REQUIRE(rc != 0, "expected failure");
    TEST_PASS();

    TEST_BEGIN("keyshare_free(NULL) is safe");
    pqc_tls_keyshare_free(NULL);  /* must not crash */
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Test: decapsulate before generate should fail                               */
/* -------------------------------------------------------------------------- */

static void test_decaps_before_generate(void)
{
    TEST_BEGIN("Decapsulate before generate should fail");
    PQC_TLS_KeyShare *ks = pqc_tls_keyshare_new(PQC_TLS_GROUP_MLKEM768);
    REQUIRE(ks != NULL, "keyshare_new failed");

    uint8_t buf[64];
    size_t len = sizeof(buf);
    uint8_t fake_server[1088];
    memset(fake_server, 0, sizeof(fake_server));

    int rc = pqc_tls_keyshare_decapsulate(ks, fake_server,
                                           sizeof(fake_server),
                                           buf, &len);
    REQUIRE(rc != 0, "expected failure when decaps called before generate");

    pqc_tls_keyshare_free(ks);
    TEST_PASS();
}

/* -------------------------------------------------------------------------- */
/* Main                                                                        */
/* -------------------------------------------------------------------------- */

int main(void)
{
    printf("=== TLS Key Share Integration Tests ===\n\n");

    if (pqc_init() != PQC_OK) {
        fprintf(stderr, "Failed to initialize libpqc\n");
        return 1;
    }

    /* Group and sigalg queries */
    printf("--- Group and Sigalg Queries ---\n");
    test_group_queries();
    test_sigalg_queries();

    /* NULL / error handling */
    printf("\n--- Error Handling ---\n");
    test_null_args();
    test_decaps_before_generate();

    /* Pure PQC key share round-trips */
    printf("\n--- Pure PQC Key Share Round-Trips ---\n");
    test_keyshare_roundtrip(PQC_TLS_GROUP_MLKEM512);
    test_keyshare_roundtrip(PQC_TLS_GROUP_MLKEM768);
    test_keyshare_roundtrip(PQC_TLS_GROUP_MLKEM1024);

    /* Hybrid key share round-trips (requires OpenSSL/BoringSSL) */
    printf("\n--- Hybrid Key Share Round-Trips ---\n");
#ifdef PQC_TLS_HAVE_OPENSSL
    test_keyshare_roundtrip(PQC_TLS_GROUP_X25519_MLKEM768);
    test_keyshare_roundtrip(PQC_TLS_GROUP_SECP256R1_MLKEM768);
#else
    printf("  %-55s [SKIP] (no OpenSSL)\n",
           "Key share round-trip: X25519+ML-KEM-768");
    printf("  %-55s [SKIP] (no OpenSSL)\n",
           "Key share round-trip: P-256+ML-KEM-768");
#endif

    /* Signature round-trips */
    printf("\n--- Signature Round-Trips ---\n");
    test_sign_verify(PQC_TLS_SIGALG_MLDSA44);
    test_sign_verify(PQC_TLS_SIGALG_MLDSA65);
    test_sign_verify(PQC_TLS_SIGALG_MLDSA87);
    test_sign_verify(PQC_TLS_SIGALG_SLHDSA_SHA2_128S);

    printf("\n=== Results: %d / %d passed ===\n", tests_passed, tests_run);

    pqc_cleanup();
    return tests_passed == tests_run ? 0 : 1;
}
