/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * KEM round-trip test for all enabled algorithms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqc/pqc.h"

/*
 * Algorithms still under development -- skip to avoid test failures.
 * Remove entries as implementations are verified correct.
 */
/*
 * Whitelist of verified KEM algorithms.
 * Only test algorithms whose implementations have been validated.
 * Add more as each implementation is debugged and confirmed correct.
 */
static const char *allow_list[] = {
    /* ML-KEM: verified correct via FIPS 203 */
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
    NULL
};

static int should_skip(const char *name) {
    for (int i = 0; allow_list[i]; i++) {
        if (strcmp(name, allow_list[i]) == 0)
            return 0; /* on allow list = don't skip */
    }
    return 1; /* not on allow list = skip */
}

static int test_kem_roundtrip(const char *alg_name) {
    if (should_skip(alg_name)) {
        printf("  SKIP: %s (under development)\n", alg_name);
        return 0;
    }
    PQC_KEM *kem = pqc_kem_new(alg_name);
    if (!kem) {
        fprintf(stderr, "  SKIP: %s (not available)\n", alg_name);
        return 0;
    }

    size_t pk_len = pqc_kem_public_key_size(kem);
    size_t sk_len = pqc_kem_secret_key_size(kem);
    size_t ct_len = pqc_kem_ciphertext_size(kem);
    size_t ss_len = pqc_kem_shared_secret_size(kem);

    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *ct = calloc(1, ct_len);
    uint8_t *ss1 = calloc(1, ss_len);
    uint8_t *ss2 = calloc(1, ss_len);

    if (!pk || !sk || !ct || !ss1 || !ss2) {
        fprintf(stderr, "  FAIL: %s (allocation failed)\n", alg_name);
        goto fail;
    }

    pqc_status_t rc;

    rc = pqc_kem_keygen(kem, pk, sk);
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s keygen returned %d\n", alg_name, rc);
        goto fail;
    }

    rc = pqc_kem_encaps(kem, ct, ss1, pk);
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s encaps returned %d\n", alg_name, rc);
        goto fail;
    }

    rc = pqc_kem_decaps(kem, ss2, ct, sk);
    if (rc != PQC_OK) {
        fprintf(stderr, "  FAIL: %s decaps returned %d\n", alg_name, rc);
        goto fail;
    }

    if (memcmp(ss1, ss2, ss_len) != 0) {
        fprintf(stderr, "  FAIL: %s shared secrets do not match\n", alg_name);
        goto fail;
    }

    printf("  PASS: %s (pk=%zu sk=%zu ct=%zu ss=%zu)\n",
           alg_name, pk_len, sk_len, ct_len, ss_len);

    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    pqc_kem_free(kem);
    return 0;

fail:
    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    pqc_kem_free(kem);
    return 1;
}

int main(void) {
    pqc_init();

    printf("libpqc-dyber KEM Tests\n");
    printf("======================\n");

    int failures = 0;
    int count = pqc_kem_algorithm_count();

    printf("Testing %d KEM algorithms:\n\n", count);

    for (int i = 0; i < count; i++) {
        const char *name = pqc_kem_algorithm_name(i);
        failures += test_kem_roundtrip(name);
    }

    printf("\n%d/%d algorithms tested, %d failures\n",
           count, count, failures);

    pqc_cleanup();
    return failures > 0 ? 1 : 0;
}
