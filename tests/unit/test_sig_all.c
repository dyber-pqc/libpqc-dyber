/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Signature round-trip test for all enabled algorithms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqc/pqc.h"

static const uint8_t test_message[] = "libpqc-dyber test message for signature verification";

static int test_sig_roundtrip(const char *alg_name) {
    PQC_SIG *sig = pqc_sig_new(alg_name);
    if (!sig) {
        fprintf(stderr, "  SKIP: %s (not available)\n", alg_name);
        return 0;
    }

    size_t pk_len = pqc_sig_public_key_size(sig);
    size_t sk_len = pqc_sig_secret_key_size(sig);
    size_t max_sig_len = pqc_sig_max_signature_size(sig);

    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *signature = calloc(1, max_sig_len);
    size_t sig_len = 0;

    if (!pk || !sk || !signature) {
        fprintf(stderr, "  FAIL: %s (allocation failed)\n", alg_name);
        goto fail;
    }

    pqc_status_t rc;

    rc = pqc_sig_keygen(sig, pk, sk);
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s keygen returned %d\n", alg_name, rc);
        goto fail;
    }

    if (pqc_sig_is_stateful(sig)) {
        rc = pqc_sig_sign_stateful(sig, signature, &sig_len,
                                    test_message, sizeof(test_message), sk);
    } else {
        rc = pqc_sig_sign(sig, signature, &sig_len,
                          test_message, sizeof(test_message), sk);
    }
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s sign returned %d\n", alg_name, rc);
        goto fail;
    }

    rc = pqc_sig_verify(sig, test_message, sizeof(test_message),
                         signature, sig_len, pk);
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s verify returned %d\n", alg_name, rc);
        goto fail;
    }

    /* Verify that a wrong message fails */
    uint8_t wrong_msg[] = "wrong message";
    rc = pqc_sig_verify(sig, wrong_msg, sizeof(wrong_msg),
                         signature, sig_len, pk);
    if (rc == PQC_OK) {
        fprintf(stderr, "  FAIL: %s verify accepted wrong message\n", alg_name);
        goto fail;
    }

    printf("  PASS: %s (pk=%zu sk=%zu sig=%zu/%zu)%s\n",
           alg_name, pk_len, sk_len, sig_len, max_sig_len,
           pqc_sig_is_stateful(sig) ? " [stateful]" : "");

    free(pk); free(sk); free(signature);
    pqc_sig_free(sig);
    return 0;

fail:
    free(pk); free(sk); free(signature);
    pqc_sig_free(sig);
    return 1;
}

int main(void) {
    pqc_init();

    printf("libpqc-dyber Signature Tests\n");
    printf("============================\n");

    int failures = 0;
    int count = pqc_sig_algorithm_count();

    printf("Testing %d signature algorithms:\n\n", count);

    for (int i = 0; i < count; i++) {
        const char *name = pqc_sig_algorithm_name(i);
        failures += test_sig_roundtrip(name);
    }

    printf("\n%d/%d algorithms tested, %d failures\n",
           count, count, failures);

    pqc_cleanup();
    return failures > 0 ? 1 : 0;
}
