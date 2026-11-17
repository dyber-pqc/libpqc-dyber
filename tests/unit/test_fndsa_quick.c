/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * FN-DSA key generation, signing and verification, for both parameter sets.
 *
 * FN-DSA key generation currently always fails (CHANGELOG.md, known
 * issues). Until 0.3.0 this test printed "FAIL" and exited 0 anyway, so CI
 * reported it as passing. It now reports what happened:
 *
 *   exit 0  every parameter set round-trips
 *   exit 1  anything else; if key generation is what failed, the line
 *           "KNOWN FAILURE: <name> key generation" is printed
 *
 * tests/CMakeLists.txt registers it as an expected failure that checks
 * that line and the absence of sanitizer reports, rather than the exit
 * status: key generation still runs under ASan, UBSan and Valgrind, and a
 * memory error there still fails CI. Once key generation works the line
 * is no longer printed and ctest fails, which is the signal to make this a
 * normal test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pqc/pqc.h"

static int run(const char *name)
{
    static const uint8_t msg[] = "FN-DSA round-trip";
    PQC_SIG *sig = pqc_sig_new(name);
    uint8_t *pk, *sk, *s;
    size_t s_len = 0;
    pqc_status_t rc;
    int ok = 0;

    if (!sig) {
        printf("%s: not in this build\n", name);
        return -1;
    }
    pk = malloc(pqc_sig_public_key_size(sig));
    sk = malloc(pqc_sig_secret_key_size(sig));
    s  = malloc(pqc_sig_max_signature_size(sig));
    if (!pk || !sk || !s) {
        printf("%s: allocation failed\n", name);
        goto out;
    }

    rc = pqc_sig_keygen(sig, pk, sk);
    if (rc != PQC_OK) {
        printf("KNOWN FAILURE: %s key generation returned %s\n",
               name, pqc_status_string(rc));
        goto out;
    }
    rc = pqc_sig_sign(sig, s, &s_len, msg, sizeof msg, sk);
    if (rc != PQC_OK) {
        printf("FAIL: %s sign returned %s\n", name, pqc_status_string(rc));
        goto out;
    }
    if (s_len > pqc_sig_max_signature_size(sig)) {
        printf("FAIL: %s signature of %zu bytes exceeds the maximum %zu\n",
               name, s_len, pqc_sig_max_signature_size(sig));
        goto out;
    }
    rc = pqc_sig_verify(sig, msg, sizeof msg, s, s_len, pk);
    if (rc != PQC_OK) {
        printf("FAIL: %s verify returned %s\n", name, pqc_status_string(rc));
        goto out;
    }
    s[s_len / 2] ^= 1;
    if (pqc_sig_verify(sig, msg, sizeof msg, s, s_len, pk) == PQC_OK) {
        printf("FAIL: %s accepted a modified signature\n", name);
        goto out;
    }
    printf("PASS: %s round-trips\n", name);
    ok = 1;
out:
    free(pk); free(sk); free(s);
    pqc_sig_free(sig);
    return ok;
}

int main(void)
{
    static const char *names[] = { "FN-DSA-512", "FN-DSA-1024" };
    int i, failed = 0, present = 0;

    if (pqc_init() != PQC_OK) {
        printf("FAIL: pqc_init\n");
        return 1;
    }
    /* FN-DSA is hidden as experimental until key generation works. */
    pqc_set_experimental(1);
    for (i = 0; i < 2; i++) {
        int r = run(names[i]);
        if (r < 0) continue;
        present++;
        if (!r) failed = 1;
    }
    pqc_cleanup();
    if (!present) {
        printf("FN-DSA not in this build\n");
        return 77;
    }
    return failed;
}
