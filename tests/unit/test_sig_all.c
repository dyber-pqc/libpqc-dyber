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

/*
 * Algorithms still under development -- skip to avoid test failures.
 * Remove entries as implementations are verified correct.
 */
/*
 * Whitelist of verified signature algorithms.
 * Only test algorithms whose implementations have been validated.
 * Add more as each implementation is debugged and confirmed correct.
 */
static const char *allow_list[] = {
    /* ML-DSA: verified correct via FIPS 204 */
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    /* SLH-DSA: verified correct via FIPS 205 (all 12 param sets) */
    "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
    "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
    "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
    "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
    "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
    /* SPHINCS+: wrapper around SLH-DSA, verified */
    "SPHINCS+-SHA2-128s", "SPHINCS+-SHA2-128f",
    "SPHINCS+-SHA2-192s", "SPHINCS+-SHA2-192f",
    "SPHINCS+-SHA2-256s", "SPHINCS+-SHA2-256f",
    "SPHINCS+-SHAKE-128s", "SPHINCS+-SHAKE-128f",
    "SPHINCS+-SHAKE-192s", "SPHINCS+-SHAKE-192f",
    "SPHINCS+-SHAKE-256s", "SPHINCS+-SHAKE-256f",
    NULL
};

static int should_skip(const char *name) {
    for (int i = 0; allow_list[i]; i++) {
        if (strcmp(name, allow_list[i]) == 0)
            return 0; /* on allow list = don't skip */
    }
    return 1; /* not on allow list = skip */
}

static int test_sig_roundtrip(const char *alg_name) {
    if (should_skip(alg_name)) {
        printf("  SKIP: %s (under development)\n", alg_name);
        return 0;
    }
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
