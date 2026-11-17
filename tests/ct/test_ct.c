/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Constant-time check ("ctgrind"). Run under Valgrind memcheck:
 *
 *   valgrind --error-exitcode=1 test_ct kem ML-KEM-768
 *   valgrind --error-exitcode=1 test_ct sig ML-DSA-65
 *   test_ct --list
 *
 * The RNG is replaced by one that marks every byte it returns as
 * undefined. Everything derived from those bytes -- secret keys, nonces,
 * ephemeral values, shared secrets -- stays undefined, and memcheck
 * reports any branch or memory index that depends on it.
 *
 * Operations covered, with what the harness treats as public:
 *   KEM: keygen (pk declassified on return), encaps (ct declassified),
 *        decaps of a valid ciphertext and of a modified one (the implicit
 *        rejection path), using the still-secret sk.
 *   SIG: keygen (pk declassified), sign (signature and its length
 *        declassified), using the still-secret sk.
 * Verification takes only public inputs and is run for sanity only.
 *
 * A clean run means memcheck saw no secret-dependent branch or address on
 * the code paths this input exercised, in this build, on this CPU. It is
 * strong evidence, not a proof: it does not see variable-time instructions
 * (e.g. division on some CPUs), paths not taken, or what a different
 * compiler or flag set would emit.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <valgrind/memcheck.h>

#include "pqc/pqc.h"

#define SECRET(p, n)  ((void)VALGRIND_MAKE_MEM_UNDEFINED((p), (n)))
#define PUBLIC(p, n)  ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))

/* Deterministic so that runs are reproducible; the bytes are then
 * poisoned, so their values do not matter to memcheck. */
static uint64_t rng_state = 0x0123456789abcdefULL;

static pqc_status_t poisoned_rng(uint8_t *buf, size_t len, void *ctx)
{
    size_t i;
    (void)ctx;
    for (i = 0; i < len; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        buf[i] = (uint8_t)rng_state;
    }
    SECRET(buf, len);
    return PQC_OK;
}

static int failed = 0;

static void step(const char *what)
{
    /* Written to stderr so that it interleaves with memcheck's reports
     * and the driver can attribute each one to an operation. */
    fprintf(stderr, "==ct== %s\n", what);
}

static int check(pqc_status_t rc, const char *what)
{
    PUBLIC(&rc, sizeof rc);
    if (rc != PQC_OK) {
        fprintf(stderr, "==ct== FUNCTIONAL: %s returned %s\n",
                what, pqc_status_string(rc));
        failed = 1;
        return 0;
    }
    return 1;
}

static int run_kem(const char *name)
{
    PQC_KEM *kem = pqc_kem_new(name);
    uint8_t *pk, *sk, *ct, *ss1, *ss2, *ss3;
    size_t pk_len, sk_len, ct_len, ss_len;

    if (!kem) {
        fprintf(stderr, "==ct== not available: %s\n", name);
        return 2;
    }
    pk_len = pqc_kem_public_key_size(kem);
    sk_len = pqc_kem_secret_key_size(kem);
    ct_len = pqc_kem_ciphertext_size(kem);
    ss_len = pqc_kem_shared_secret_size(kem);
    pk = malloc(pk_len); sk = malloc(sk_len); ct = malloc(ct_len);
    ss1 = malloc(ss_len); ss2 = malloc(ss_len); ss3 = malloc(ss_len);
    if (!pk || !sk || !ct || !ss1 || !ss2 || !ss3) {
        fprintf(stderr, "==ct== out of memory\n");
        return 2;
    }

    step("keygen");
    if (!check(pqc_kem_keygen(kem, pk, sk), "keygen")) goto out;
    PUBLIC(pk, pk_len);

    step("encaps");
    if (!check(pqc_kem_encaps(kem, ct, ss1, pk), "encaps")) goto out;
    PUBLIC(ct, ct_len);

    step("decaps");
    if (!check(pqc_kem_decaps(kem, ss2, ct, sk), "decaps")) goto out;

    step("decaps-reject");
    ct[0] ^= 1;
    if (!check(pqc_kem_decaps(kem, ss3, ct, sk), "decaps (modified ct)"))
        goto out;

    step("done");
    /* Functional sanity, outside the region under test. */
    PUBLIC(ss1, ss_len); PUBLIC(ss2, ss_len); PUBLIC(ss3, ss_len);
    if (memcmp(ss1, ss2, ss_len) != 0) {
        fprintf(stderr, "==ct== FUNCTIONAL: decaps disagrees with encaps\n");
        failed = 1;
    }
out:
    free(pk); free(sk); free(ct); free(ss1); free(ss2); free(ss3);
    pqc_kem_free(kem);
    return failed;
}

static int run_sig(const char *name)
{
    static const uint8_t msg[] = "libpqc-dyber constant-time check";
    PQC_SIG *sig = pqc_sig_new(name);
    uint8_t *pk, *sk, *s;
    size_t pk_len, sk_len, s_max, s_len = 0;
    pqc_status_t rc;

    if (!sig) {
        fprintf(stderr, "==ct== not available: %s\n", name);
        return 2;
    }
    pk_len = pqc_sig_public_key_size(sig);
    sk_len = pqc_sig_secret_key_size(sig);
    s_max  = pqc_sig_max_signature_size(sig);
    pk = malloc(pk_len); sk = malloc(sk_len); s = malloc(s_max);
    if (!pk || !sk || !s) {
        fprintf(stderr, "==ct== out of memory\n");
        return 2;
    }

    step("keygen");
    if (!check(pqc_sig_keygen(sig, pk, sk), "keygen")) goto out;
    PUBLIC(pk, pk_len);

    step("sign");
    if (pqc_sig_is_stateful(sig))
        rc = pqc_sig_sign_stateful(sig, s, &s_len, msg, sizeof msg - 1, sk);
    else
        rc = pqc_sig_sign(sig, s, &s_len, msg, sizeof msg - 1, sk);
    if (!check(rc, "sign")) goto out;
    PUBLIC(&s_len, sizeof s_len);
    if (s_len > s_max) {
        fprintf(stderr, "==ct== FUNCTIONAL: signature longer than maximum\n");
        failed = 1;
        goto out;
    }
    PUBLIC(s, s_len);

    step("done");
    rc = pqc_sig_verify(sig, msg, sizeof msg - 1, s, s_len, pk);
    if (rc != PQC_OK) {
        fprintf(stderr, "==ct== FUNCTIONAL: signature does not verify\n");
        failed = 1;
    }
out:
    free(pk); free(sk); free(s);
    pqc_sig_free(sig);
    return failed;
}

int main(int argc, char **argv)
{
    int i;

    /* --all covers the experimental algorithms too. */
    pqc_set_experimental(1);

    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        for (i = 0; i < pqc_kem_algorithm_count(); i++) {
            const char *n = pqc_kem_algorithm_name(i);
            if (n && pqc_kem_is_enabled(n)) printf("kem\t%s\n", n);
        }
        for (i = 0; i < pqc_sig_algorithm_count(); i++) {
            const char *n = pqc_sig_algorithm_name(i);
            if (n && pqc_sig_is_enabled(n)) printf("sig\t%s\n", n);
        }
        return 0;
    }
    if (argc != 3) {
        fprintf(stderr, "usage: %s --list | kem NAME | sig NAME\n", argv[0]);
        return 2;
    }

    if (pqc_init() != PQC_OK) return 2;
    pqc_set_rng(poisoned_rng, NULL);

    if (strcmp(argv[1], "kem") == 0) return run_kem(argv[2]);
    if (strcmp(argv[1], "sig") == 0) return run_sig(argv[2]);
    fprintf(stderr, "unknown kind '%s'\n", argv[1]);
    return 2;
}
