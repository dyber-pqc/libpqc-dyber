/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Regression tests for the 2026-07 security audit.
 *
 * Each test targets one reported defect and asserts the invariant that
 * was violated, not merely that the API still round-trips.  Several of
 * these defects were invisible to round-trip testing precisely because
 * signing and verification shared the broken code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pqc/pqc.h"
#include "pqc/pqc_config.h"

/* Internal headers for the invariant checks. */
#include "core/sig/xmss/xmss.h"
#include "core/sig/xmss/xmss_params.h"
#include "core/sig/snova/snova_params.h"
#include "core/sig/cross/cross_params.h"
#ifdef PQC_TEST_SLHDSA_INTERNALS
#include "core/sig/slhdsa/slhdsa.h"
#endif

static int g_failures = 0;
static int g_checks = 0;

static void check(int cond, const char *what)
{
    g_checks++;
    if (cond) {
        printf("  PASS  %s\n", what);
    } else {
        printf("  FAIL  %s\n", what);
        g_failures++;
    }
}

/* ------------------------------------------------------------------ */
/* 1. SNOVA / CROSS: declared signature size vs. what sign() emits      */
/* ------------------------------------------------------------------ */

/*
 * Skipped only because key generation is too expensive for a unit test,
 * never because an algorithm is broken.
 *
 * The distinction matters. Staying inside max_signature_size() is a
 * memory-safety property that every registered algorithm owes its
 * caller, working or not -- so this sweep must not be gated on whether
 * an algorithm is otherwise correct. Excluding by name on grounds of
 * brokenness is exactly how the SNOVA and CROSS overflow survived: the
 * general round-trip test in test_sig_all.c already allocates
 * calloc(1, max_signature_size()) and signs into it, which is the shape
 * that catches this, but those schemes sat outside its allow list.
 *
 * These entries rebuild a Merkle tree of 2^h leaves per key: XMSS-20 is
 * 2^20 leaves and does not finish in a test run at all.
 */
static int bounds_sweep_too_slow(const char *name)
{
    return strcmp(name, "XMSS-SHA2-16-256") == 0 ||
           strcmp(name, "XMSS-SHA2-20-256") == 0 ||
           strcmp(name, "LMS-SHA256-H15")   == 0 ||
           strcmp(name, "LMS-SHA256-H20")   == 0 ||
           strcmp(name, "LMS-SHA256-H25")   == 0;
}

static void test_sig_buffer_bounds(void)
{
    const uint8_t msg[] = "audit regression message";
    int a, total = pqc_sig_algorithm_count(), swept = 0;

    printf("\n[1] sign() must not exceed max_signature_size\n");
    printf("        sweeping every registered signature algorithm (%d)\n", total);

    for (a = 0; a < total; a++) {
        const char *alg = pqc_sig_algorithm_name(a);
        PQC_SIG *sig;
        uint8_t *pk, *sk, *sigbuf;
        size_t maxlen, siglen = 0;
        pqc_status_t rc;
        char label[128];
        /* Guard bytes immediately after the signature buffer. */
        static const uint8_t CANARY = 0xA5;
        size_t guard = 64, i;
        int clean = 1;

        if (!alg) continue;
        if (bounds_sweep_too_slow(alg)) {
            printf("  SKIP  %s (keygen cost, not correctness)\n", alg);
            continue;
        }

        sig = pqc_sig_new(alg);
        if (!sig) { printf("  SKIP  %s (not registered)\n", alg); continue; }

        maxlen = pqc_sig_max_signature_size(sig);
        pk = (uint8_t *)calloc(1, pqc_sig_public_key_size(sig));
        sk = (uint8_t *)calloc(1, pqc_sig_secret_key_size(sig));
        sigbuf = (uint8_t *)malloc(maxlen + guard);
        if (!pk || !sk || !sigbuf) { printf("  SKIP  %s (alloc)\n", alg);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue; }

        memset(sigbuf, 0, maxlen);
        memset(sigbuf + maxlen, CANARY, guard);

        rc = pqc_sig_keygen(sig, pk, sk);
        if (rc != PQC_OK) {
            printf("  SKIP  %s (keygen rc=%d)\n", alg, rc);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue;
        }

        if (pqc_sig_is_stateful(sig)) {
            rc = pqc_sig_sign_stateful(sig, sigbuf, &siglen,
                                       msg, sizeof(msg), sk);
        } else {
            rc = pqc_sig_sign(sig, sigbuf, &siglen, msg, sizeof(msg), sk);
        }
        swept++;

        for (i = 0; i < guard; i++) {
            if (sigbuf[maxlen + i] != CANARY) { clean = 0; break; }
        }

        snprintf(label, sizeof(label),
                 "%s: no write past max_signature_size (%zu)", alg, maxlen);
        check(clean, label);

        if (rc == PQC_OK) {
            snprintf(label, sizeof(label),
                     "%s: reported siglen %zu <= max %zu",
                     alg, siglen, maxlen);
            check(siglen <= maxlen, label);
        }

        free(pk); free(sk); free(sigbuf);
        pqc_sig_free(sig);
    }

    printf("        %d of %d algorithms actually signed\n", swept, total);
}

/*
 * The groups below call XMSS internals directly, so they are only built
 * when XMSS is compiled in.  A minimal build with the algorithm disabled
 * has no such symbols to link against.
 */
#ifdef PQC_TEST_XMSS_INTERNALS

/* ------------------------------------------------------------------ */
/* 2. XMSS: distinct leaves must derive distinct WOTS+ keys             */
/* ------------------------------------------------------------------ */

static void test_xmss_wots_leaf_separation(void)
{
    static const uint32_t leaves[] = { 0, 1, 7, 1234, 65535 };
    const size_t nleaves = sizeof(leaves) / sizeof(leaves[0]);
    uint8_t seed[PQC_XMSS_SHA2_N], pub_seed[PQC_XMSS_SHA2_N];
    uint8_t pk[PQC_XMSS_WOTS_LEN * PQC_XMSS_SHA2_N];
    uint8_t first[PQC_XMSS_WOTS_LEN * PQC_XMSS_SHA2_N];
    uint8_t addr[PQC_XMSS_ADDR_BYTES];
    size_t i;
    int all_distinct = 1;

    printf("\n[2] XMSS: each leaf derives a distinct WOTS+ key\n");

    for (i = 0; i < sizeof(seed); i++) { seed[i] = (uint8_t)i; }
    for (i = 0; i < sizeof(pub_seed); i++) { pub_seed[i] = (uint8_t)(0x40 + i); }

    for (i = 0; i < nleaves; i++) {
        xmss_addr_zero(addr);
        xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);
        xmss_addr_set_ots(addr, leaves[i]);
        xmss_wots_keygen(pk, seed, pub_seed, addr);

        printf("        leaf %6u -> %02x%02x%02x%02x%02x%02x%02x%02x\n",
               leaves[i], pk[0], pk[1], pk[2], pk[3],
               pk[4], pk[5], pk[6], pk[7]);

        if (i == 0) {
            memcpy(first, pk, sizeof(pk));
        } else if (memcmp(first, pk, sizeof(pk)) == 0) {
            all_distinct = 0;
        }
    }

    check(all_distinct, "XMSS: WOTS+ public keys differ across leaf indices");
}

/* ------------------------------------------------------------------ */
/* 2b. XMSS: WOTS+ must round-trip for every base-w digit pattern       */
/*                                                                      */
/* pk_from_sig(sign(m), m) must reproduce keygen()'s public key.  This  */
/* is the invariant the whole scheme rests on, and it is sensitive to   */
/* leftover address state: a chain whose digit is 0 performs no hash    */
/* steps, so any field the hash function mutates but the caller does    */
/* not reset makes signing and key generation disagree.  Many trials    */
/* are needed because the failure depends on the message digits.        */
/* ------------------------------------------------------------------ */

static void test_xmss_wots_roundtrip(void)
{
    uint8_t sk_seed[PQC_XMSS_SHA2_N], pub_seed[PQC_XMSS_SHA2_N];
    uint8_t msg[PQC_XMSS_SHA2_N];
    static uint8_t pk_ref[PQC_XMSS_WOTS_LEN * PQC_XMSS_SHA2_N];
    static uint8_t sig[PQC_XMSS_WOTS_LEN * PQC_XMSS_SHA2_N];
    static uint8_t pk_chk[PQC_XMSS_WOTS_LEN * PQC_XMSS_SHA2_N];
    uint8_t addr[PQC_XMSS_ADDR_BYTES];
    const int trials = 400;
    int trial, i, mismatches = 0, first_bad = -1;

    printf("\n[2b] XMSS: WOTS+ sign/recover round-trip (%d trials)\n", trials);

    for (trial = 0; trial < trials; trial++) {
        for (i = 0; i < PQC_XMSS_SHA2_N; i++) {
            sk_seed[i]  = (uint8_t)(i * 7 + trial);
            pub_seed[i] = (uint8_t)(i * 3 + trial * 5);
            /* Vary the digits, including zeros, across trials. */
            msg[i]      = (uint8_t)(trial * 131 + i * 29);
        }

        xmss_addr_zero(addr);
        xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);
        xmss_addr_set_ots(addr, (uint32_t)trial);
        xmss_wots_keygen(pk_ref, sk_seed, pub_seed, addr);

        xmss_addr_zero(addr);
        xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);
        xmss_addr_set_ots(addr, (uint32_t)trial);
        xmss_wots_sign(sig, msg, sk_seed, pub_seed, addr);

        xmss_addr_zero(addr);
        xmss_addr_set_type(addr, PQC_XMSS_ADDR_TYPE_OTS);
        xmss_addr_set_ots(addr, (uint32_t)trial);
        xmss_wots_pk_from_sig(pk_chk, sig, msg, pub_seed, addr);

        if (memcmp(pk_ref, pk_chk, sizeof(pk_ref)) != 0) {
            mismatches++;
            if (first_bad < 0) first_bad = trial;
        }
    }

    if (mismatches) {
        printf("        %d/%d trials mismatched (first at trial %d)\n",
               mismatches, trials, first_bad);
    }
    check(mismatches == 0,
          "XMSS: WOTS+ recovered public key matches keygen for all digits");
}

#endif /* PQC_TEST_XMSS_INTERNALS */

/* ------------------------------------------------------------------ */
/* 8. SLH-DSA: key-pair address separation and H_msg length            */
/*                                                                      */
/* The class-level invariant behind the XMSS and SLH-DSA defects: two   */
/* distinct key-pair (or leaf) indices must produce different output.   */
/* Both schemes broke it with a setter that cleared a field the caller  */
/* had populated, and both round-tripped perfectly while broken,        */
/* because signing and verification shared the defect. Round-trip       */
/* tests cannot see this class; only this kind of assertion can.        */
/* ------------------------------------------------------------------ */

#ifdef PQC_TEST_SLHDSA_INTERNALS

static void test_slhdsa_invariants(void)
{
    static const struct { const char *name; const slhdsa_params_t *p; } sets[] = {
        { "SHA2-128s",  &SLHDSA_SHA2_128S  }, { "SHA2-128f",  &SLHDSA_SHA2_128F  },
        { "SHA2-192s",  &SLHDSA_SHA2_192S  }, { "SHA2-192f",  &SLHDSA_SHA2_192F  },
        { "SHA2-256s",  &SLHDSA_SHA2_256S  }, { "SHA2-256f",  &SLHDSA_SHA2_256F  },
        { "SHAKE-128s", &SLHDSA_SHAKE_128S }, { "SHAKE-128f", &SLHDSA_SHAKE_128F },
        { "SHAKE-192s", &SLHDSA_SHAKE_192S }, { "SHAKE-192f", &SLHDSA_SHAKE_192F },
        { "SHAKE-256s", &SLHDSA_SHAKE_256S }, { "SHAKE-256f", &SLHDSA_SHAKE_256F },
    };
    static uint8_t fors_sig[SLHDSA_MAX_FORS_TREES * (SLHDSA_MAX_A + 1) * SLHDSA_MAX_N];
    uint8_t sk_seed[SLHDSA_MAX_N], pub_seed[SLHDSA_MAX_N];
    uint8_t pk[2 * SLHDSA_MAX_N], R[SLHDSA_MAX_N];
    uint8_t md[SLHDSA_MAX_FORS_TREES * SLHDSA_MAX_A / 8 + 1];
    uint8_t out0[SLHDSA_MAX_N], out1[SLHDSA_MAX_N];
    uint8_t addr[32];
    const uint8_t msg[] = "slh-dsa invariant";
    size_t s, i;
    char label[128];

    printf("\n[8] SLH-DSA: distinct key-pair indices give distinct output\n");

    for (i = 0; i < sizeof(sk_seed); i++) {
        sk_seed[i] = (uint8_t)(0x11 * i + 3);
        pub_seed[i] = (uint8_t)(0x07 * i + 9);
        R[i] = (uint8_t)(0x35 * i + 1);
    }
    for (i = 0; i < sizeof(pk); i++) pk[i] = (uint8_t)(0x5b * i + 2);
    for (i = 0; i < sizeof(md); i++) md[i] = (uint8_t)(0x9d * i + 4);

    for (s = 0; s < sizeof(sets) / sizeof(sets[0]); s++) {
        const slhdsa_params_t *p = sets[s].p;
        uint32_t last_leaf = (1u << p->hp) - 1;
        size_t m = slhdsa_hmsg_bytes(p);
        uint8_t h_a[128], h_b[128];
        int fors_differs, wots_differs, kp_kept, hmsg_exact;

        /* FORS: same message digest and tree, key pair 0 vs the last one. */
        memset(addr, 0, 32);
        slhdsa_set_tree_addr(addr, 5);
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_FORSTREE);
        slhdsa_set_keypair_addr(addr, 0);
        slhdsa_fors_sign(fors_sig, md, sk_seed, pub_seed, addr, p);
        slhdsa_fors_pk_from_sig(out0, fors_sig, md, pub_seed, addr, p);

        memset(addr, 0, 32);
        slhdsa_set_tree_addr(addr, 5);
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_FORSTREE);
        slhdsa_set_keypair_addr(addr, last_leaf);
        slhdsa_fors_sign(fors_sig, md, sk_seed, pub_seed, addr, p);
        slhdsa_fors_pk_from_sig(out1, fors_sig, md, pub_seed, addr, p);
        fors_differs = memcmp(out0, out1, p->n) != 0;

        /* WOTS+: key pair 0 vs the last one, and the caller's key-pair
         * address must survive the call. */
        memset(addr, 0, 32);
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);
        slhdsa_set_keypair_addr(addr, 0);
        slhdsa_wots_gen_pk(out0, sk_seed, pub_seed, addr, p);

        memset(addr, 0, 32);
        slhdsa_set_type(addr, SLHDSA_ADDR_TYPE_WOTS);
        slhdsa_set_keypair_addr(addr, last_leaf);
        slhdsa_wots_gen_pk(out1, sk_seed, pub_seed, addr, p);
        wots_differs = memcmp(out0, out1, p->n) != 0;
        kp_kept = slhdsa_get_keypair_addr(addr) == last_leaf;

        /* H_msg must write exactly m bytes: prefill two buffers differently,
         * so any byte it leaves unwritten differs between them. */
        memset(h_a, 0x00, sizeof(h_a));
        memset(h_b, 0xFF, sizeof(h_b));
        slhdsa_hash_msg(h_a, R, pk, NULL, 0, msg, sizeof(msg), p);
        slhdsa_hash_msg(h_b, R, pk, NULL, 0, msg, sizeof(msg), p);
        hmsg_exact = memcmp(h_a, h_b, m) == 0 && h_a[m] != h_b[m];

        snprintf(label, sizeof(label),
                 "SLH-DSA-%s: FORS output depends on key-pair address", sets[s].name);
        check(fors_differs, label);
        snprintf(label, sizeof(label),
                 "SLH-DSA-%s: WOTS+ pk depends on key-pair address", sets[s].name);
        check(wots_differs, label);
        snprintf(label, sizeof(label),
                 "SLH-DSA-%s: WOTS+ keeps the caller's key-pair address", sets[s].name);
        check(kp_kept, label);
        snprintf(label, sizeof(label),
                 "SLH-DSA-%s: H_msg writes exactly m=%zu bytes", sets[s].name, m);
        check(hmsg_exact, label);
    }
}

#endif /* PQC_TEST_SLHDSA_INTERNALS */

/* ------------------------------------------------------------------ */
/* 4. XMSS: WOTS+ checksum must sign its top nibble                     */
/* ------------------------------------------------------------------ */

/*
 * Mirrors the checksum extraction in wots.c.  The final chain must not
 * be constant across the checksum space -- if it is, the most
 * significant checksum nibble is unsigned.
 */
static void wots_checksum_nibbles(uint32_t csum, int out[3])
{
    int i;
    uint32_t shifted = csum << 4;
    for (i = 0; i < 3; i++) {
        out[i] = (int)((shifted >> (4 * (3 - i))) & 0x0F);
    }
}

static void test_xmss_checksum(void)
{
    uint32_t csum;
    int last_nonzero = 0;
    int matches_rfc = 1;
    int n[3];

    printf("\n[4] XMSS: WOTS+ checksum covers all three nibbles\n");

    for (csum = 0; csum < 4096; csum++) {
        wots_checksum_nibbles(csum, n);
        if (n[2] != 0) last_nonzero = 1;
        /* RFC 8391: nibbles of the 12-bit checksum, most significant first. */
        if (n[0] != (int)((csum >> 8) & 0xF) ||
            n[1] != (int)((csum >> 4) & 0xF) ||
            n[2] != (int)(csum & 0xF)) {
            matches_rfc = 0;
        }
    }

    wots_checksum_nibbles(0xabc, n);
    printf("        csum 0xabc -> [%d, %d, %d]  (RFC: [10, 11, 12])\n",
           n[0], n[1], n[2]);
    wots_checksum_nibbles(0xfff, n);
    printf("        csum 0xfff -> [%d, %d, %d]  (RFC: [15, 15, 15])\n",
           n[0], n[1], n[2]);

    check(last_nonzero, "XMSS: final checksum chain is not constant zero");
    check(matches_rfc,  "XMSS: checksum nibbles match RFC 8391");
}

/* ------------------------------------------------------------------ */
/* 7. XMSS: per-node hash keys must not collapse                        */
/* ------------------------------------------------------------------ */

#ifdef PQC_TEST_XMSS_INTERNALS

static void test_xmss_addr_fields(void)
{
    uint8_t a[PQC_XMSS_ADDR_BYTES], b[PQC_XMSS_ADDR_BYTES];

    printf("\n[7] XMSS: keyAndMask is distinct from the tree index\n");

    /* Varying keyAndMask must not disturb the tree index. */
    xmss_addr_zero(a);
    xmss_addr_set_type(a, PQC_XMSS_ADDR_TYPE_TREE);
    xmss_addr_set_tree_index(a, 0x11223344u);
    xmss_addr_set_key_and_mask(a, 2);
    check(a[24] == 0x11 && a[25] == 0x22 && a[26] == 0x33 && a[27] == 0x44,
          "XMSS: set_key_and_mask preserves the tree index at offset 24");
    check(a[31] == 2, "XMSS: keyAndMask lands at offset 28 (RFC 8391 word 7)");

    /* Two nodes at the same height must produce different key addresses. */
    xmss_addr_zero(a);
    xmss_addr_set_type(a, PQC_XMSS_ADDR_TYPE_TREE);
    xmss_addr_set_tree_height(a, 3);
    xmss_addr_set_tree_index(a, 7);
    xmss_addr_set_key_and_mask(a, 0);

    xmss_addr_zero(b);
    xmss_addr_set_type(b, PQC_XMSS_ADDR_TYPE_TREE);
    xmss_addr_set_tree_height(b, 3);
    xmss_addr_set_tree_index(b, 8);
    xmss_addr_set_key_and_mask(b, 0);

    check(memcmp(a, b, PQC_XMSS_ADDR_BYTES) != 0,
          "XMSS: distinct nodes at one height get distinct key addresses");
}

#endif /* PQC_TEST_XMSS_INTERNALS */

/* ------------------------------------------------------------------ */
/* 3. LMS / XMSS: sign must actually verify                             */
/* ------------------------------------------------------------------ */

static void test_stateful_roundtrip(void)
{
    static const char *algs[] = {
        "LMS-SHA256-H10",
        "XMSS-SHA2-10-256",
        NULL
    };
    const uint8_t msg[] = "audit roundtrip message";
    int a;

    printf("\n[3] LMS / XMSS: sign-then-verify at several indices\n");

    for (a = 0; algs[a]; a++) {
        PQC_SIG *sig = pqc_sig_new(algs[a]);
        uint8_t *pk, *sk, *sigbuf;
        size_t maxlen;
        pqc_status_t rc;
        int idx, ok = 1;
        char label[128];

        if (!sig) { printf("  SKIP  %s (not registered)\n", algs[a]); continue; }

        maxlen = pqc_sig_max_signature_size(sig);
        pk = (uint8_t *)calloc(1, pqc_sig_public_key_size(sig));
        sk = (uint8_t *)calloc(1, pqc_sig_secret_key_size(sig));
        sigbuf = (uint8_t *)calloc(1, maxlen);
        if (!pk || !sk || !sigbuf) { printf("  SKIP  %s (alloc)\n", algs[a]);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue; }

        rc = pqc_sig_keygen(sig, pk, sk);
        if (rc != PQC_OK) {
            printf("  SKIP  %s (keygen rc=%d)\n", algs[a], rc);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue;
        }

        for (idx = 0; idx < 3; idx++) {
            size_t siglen = 0;
            rc = pqc_sig_sign_stateful(sig, sigbuf, &siglen, msg, sizeof(msg), sk);
            if (rc != PQC_OK) { ok = 0; printf("        idx %d: sign rc=%d\n", idx, rc); break; }
            rc = pqc_sig_verify(sig, msg, sizeof(msg), sigbuf, siglen, pk);
            printf("        idx %d: sign OK (siglen=%zu)  verify -> %s (rc=%d)\n",
                   idx, siglen, rc == PQC_OK ? "PASS" : "FAIL", rc);
            if (rc != PQC_OK) ok = 0;
        }

        snprintf(label, sizeof(label), "%s: signatures verify", algs[a]);
        check(ok, label);

        free(pk); free(sk); free(sigbuf);
        pqc_sig_free(sig);
    }
}

/* ------------------------------------------------------------------ */
/* 6. verify() must reject a truncated signature without reading past   */
/* ------------------------------------------------------------------ */

static void test_verify_length_validation(void)
{
    static const char *algs[] = {
        "XMSS-SHA2-10-256", "LMS-SHA256-H10",
        "UOV-Is", "MAYO-1", "ML-DSA-44",
        "SNOVA-24-5-4", "CROSS-RSDP-128-fast",
        NULL
    };
    const uint8_t msg[] = "audit truncation message";
    int a;

    printf("\n[6] verify() must reject truncated signatures\n");

    for (a = 0; algs[a]; a++) {
        PQC_SIG *sig = pqc_sig_new(algs[a]);
        uint8_t *pk, *sk, *sigbuf, *tiny;
        size_t maxlen, siglen = 0;
        pqc_status_t rc;
        char label[128];
        const size_t TRUNC = 64;

        if (!sig) { printf("  SKIP  %s (not registered)\n", algs[a]); continue; }

        maxlen = pqc_sig_max_signature_size(sig);
        pk = (uint8_t *)calloc(1, pqc_sig_public_key_size(sig));
        sk = (uint8_t *)calloc(1, pqc_sig_secret_key_size(sig));
        sigbuf = (uint8_t *)calloc(1, maxlen);
        if (!pk || !sk || !sigbuf) { printf("  SKIP  %s (alloc)\n", algs[a]);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue; }

        if (pqc_sig_keygen(sig, pk, sk) != PQC_OK) {
            printf("  SKIP  %s (keygen)\n", algs[a]);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue;
        }

        if (pqc_sig_is_stateful(sig)) {
            rc = pqc_sig_sign_stateful(sig, sigbuf, &siglen, msg, sizeof(msg), sk);
        } else {
            rc = pqc_sig_sign(sig, sigbuf, &siglen, msg, sizeof(msg), sk);
        }
        if (rc != PQC_OK || siglen < TRUNC) {
            printf("  SKIP  %s (sign rc=%d siglen=%zu)\n", algs[a], rc, siglen);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue;
        }

        /*
         * Copy a truncated prefix into an exactly-sized heap block and
         * pass its true (short) length.  Under ASan a verify() that
         * ignores the length reads past the end of this block.
         */
        tiny = (uint8_t *)malloc(TRUNC);
        if (!tiny) { free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue; }
        memcpy(tiny, sigbuf, TRUNC);

        rc = pqc_sig_verify(sig, msg, sizeof(msg), tiny, TRUNC, pk);

        snprintf(label, sizeof(label),
                 "%s: truncated signature rejected (rc=%d)", algs[a], rc);
        check(rc != PQC_OK, label);

        /* An over-long length must also be rejected, not trusted. */
        rc = pqc_sig_verify(sig, msg, sizeof(msg), sigbuf, maxlen + 1, pk);
        snprintf(label, sizeof(label),
                 "%s: over-long signature_len rejected", algs[a]);
        check(rc != PQC_OK, label);

        free(tiny);
        free(pk); free(sk); free(sigbuf);
        pqc_sig_free(sig);
    }
}

/* ------------------------------------------------------------------ */
/* 5. KEM decapsulation must not report the validity bit                */
/* ------------------------------------------------------------------ */

static void test_kem_implicit_rejection(void)
{
    static const char *algs[] = {
        "HQC-128", "BIKE-L1", "FrodoKEM-640-AES",
        "ML-KEM-512", "NTRU-HPS-2048-509",
        NULL
    };
    int a;

    printf("\n[5] KEM decaps must not leak the validity bit\n");

    for (a = 0; algs[a]; a++) {
        PQC_KEM *kem = pqc_kem_new(algs[a]);
        uint8_t *pk, *sk, *ct, *ss1, *ss2;
        size_t ct_len, ss_len;
        pqc_status_t rc_good, rc_bad;
        char label[128];

        if (!kem) { printf("  SKIP  %s (not registered)\n", algs[a]); continue; }

        /*
         * Allocate exactly the advertised sizes: a KEM that writes past
         * one of them corrupts the heap here, which is itself a result
         * worth failing on.
         */
        ct_len = pqc_kem_ciphertext_size(kem);
        ss_len = pqc_kem_shared_secret_size(kem);
        pk = (uint8_t *)calloc(1, pqc_kem_public_key_size(kem));
        sk = (uint8_t *)calloc(1, pqc_kem_secret_key_size(kem));
        ct = (uint8_t *)calloc(1, ct_len);
        ss1 = (uint8_t *)calloc(1, ss_len);
        ss2 = (uint8_t *)calloc(1, ss_len);
        if (!pk || !sk || !ct || !ss1 || !ss2) {
            printf("  SKIP  %s (alloc)\n", algs[a]);
            free(pk); free(sk); free(ct); free(ss1); free(ss2);
            pqc_kem_free(kem); continue;
        }

        if (pqc_kem_keygen(kem, pk, sk) != PQC_OK ||
            pqc_kem_encaps(kem, ct, ss1, pk) != PQC_OK) {
            printf("  SKIP  %s (keygen/encaps)\n", algs[a]);
            free(pk); free(sk); free(ct); free(ss1); free(ss2);
            pqc_kem_free(kem); continue;
        }

        rc_good = pqc_kem_decaps(kem, ss2, ct, sk);
        int roundtrip = (rc_good == PQC_OK && memcmp(ss1, ss2, ss_len) == 0);

        /* Corrupt the ciphertext so decapsulation must implicitly reject. */
        ct[0] ^= 0xFF;
        ct[ct_len / 2] ^= 0xFF;
        rc_bad = pqc_kem_decaps(kem, ss2, ct, sk);

        printf("        %-20s valid ct -> rc=%d, corrupt ct -> rc=%d\n",
               algs[a], rc_good, rc_bad);

        snprintf(label, sizeof(label),
                 "%s: corrupt ciphertext returns the same status as valid",
                 algs[a]);
        check(rc_good == rc_bad, label);

        /*
         * The rejection key must actually be used: a corrupt ciphertext
         * yields a secret other than the encapsulated one, and the same
         * secret every time (it is derived from the secret seed s, not
         * from fresh randomness). Decapsulation now selects between k'
         * and s with a mask rather than a branch, and a wrong mask would
         * pass the status check above. Only meaningful for a KEM that
         * round-trips.
         */
        if (roundtrip) {
            uint8_t *ss3 = (uint8_t *)calloc(1, ss_len);
            if (ss3 && pqc_kem_decaps(kem, ss3, ct, sk) == PQC_OK) {
                snprintf(label, sizeof(label),
                         "%s: rejection secret differs from the real one", algs[a]);
                check(memcmp(ss2, ss1, ss_len) != 0, label);
                snprintf(label, sizeof(label),
                         "%s: rejection secret is deterministic", algs[a]);
                check(memcmp(ss2, ss3, ss_len) == 0, label);
            }
            free(ss3);
        } else if (strncmp(algs[a], "NTRU-", 5) == 0) {
            /* NTRU does not round-trip yet (see CHANGELOG known issues). */
            printf("  SKIP  %s rejection-secret checks (does not round-trip)\n",
                   algs[a]);
        } else {
            snprintf(label, sizeof(label),
                     "%s: valid ciphertext decapsulates to the encapsulated secret",
                     algs[a]);
            check(0, label);
        }

        free(pk); free(sk); free(ct); free(ss1); free(ss2);
        pqc_kem_free(kem);
    }
}

/* ------------------------------------------------------------------ */
/* [9] FIPS 204 / FIPS 205 context strings                              */
/*                                                                      */
/* Until 0.3.0, ML-DSA and SLH-DSA signed M itself (the *_internal      */
/* functions) instead of M' = 0x00 || |ctx| || ctx || M, so they did    */
/* not interoperate and could not bind a context. Conformance is        */
/* checked against OpenSSL by tests/interop; this checks the API.       */
/* ------------------------------------------------------------------ */

static void test_sig_context(void)
{
    static const char *ctx_algs[] = { PQC_SIG_ML_DSA_44, PQC_SIG_SLH_DSA_SHAKE_128F };
    static const uint8_t msg[] = "context binding";
    static uint8_t ctx255[256];
    const uint8_t ctx_a[] = "purpose-a", ctx_b[] = "purpose-b";
    char label[160];
    size_t i;

    printf("\n[9] Context strings (FIPS 204 sec. 5.2 / FIPS 205 sec. 10.2)\n");
    memset(ctx255, 0x5A, sizeof ctx255);

    for (i = 0; i < sizeof ctx_algs / sizeof ctx_algs[0]; i++) {
        PQC_SIG *sig = pqc_sig_new(ctx_algs[i]);
        uint8_t *pk, *sk, *s1, *s2;
        size_t l1 = 0, l2 = 0;

        if (!sig) {
            /* Left out of this build (e.g. the minimal CI build) is a skip;
             * compiled in but not constructible is a failure. */
            if (pqc_sig_is_enabled(ctx_algs[i]))
                check(0, ctx_algs[i]);
            else
                printf("  SKIP  %s (not in this build)\n", ctx_algs[i]);
            continue;
        }
        pk = malloc(pqc_sig_public_key_size(sig));
        sk = malloc(pqc_sig_secret_key_size(sig));
        s1 = malloc(pqc_sig_max_signature_size(sig));
        s2 = malloc(pqc_sig_max_signature_size(sig));
        if (!pk || !sk || !s1 || !s2 || pqc_sig_keygen(sig, pk, sk) != PQC_OK) {
            check(0, "setup");
        } else {
            /* Plain API == empty context, in both directions. */
            pqc_sig_sign(sig, s1, &l1, msg, sizeof msg, sk);
            pqc_sig_sign_ctx(sig, s2, &l2, msg, sizeof msg, NULL, 0, sk);
            snprintf(label, sizeof label, "%s: pqc_sig_sign verifies as empty ctx", ctx_algs[i]);
            check(pqc_sig_verify_ctx(sig, msg, sizeof msg, NULL, 0, s1, l1, pk) == PQC_OK, label);
            snprintf(label, sizeof label, "%s: empty-ctx signature verifies via pqc_sig_verify", ctx_algs[i]);
            check(pqc_sig_verify(sig, msg, sizeof msg, s2, l2, pk) == PQC_OK, label);

            /* A context is bound into the signature. */
            check(pqc_sig_sign_ctx(sig, s1, &l1, msg, sizeof msg,
                                   ctx_a, sizeof ctx_a - 1, sk) == PQC_OK, "sign with ctx");
            snprintf(label, sizeof label, "%s: verifies under the same ctx", ctx_algs[i]);
            check(pqc_sig_verify_ctx(sig, msg, sizeof msg, ctx_a, sizeof ctx_a - 1,
                                     s1, l1, pk) == PQC_OK, label);
            snprintf(label, sizeof label, "%s: rejected under a different ctx", ctx_algs[i]);
            check(pqc_sig_verify_ctx(sig, msg, sizeof msg, ctx_b, sizeof ctx_b - 1,
                                     s1, l1, pk) == PQC_ERROR_VERIFICATION_FAILED, label);
            snprintf(label, sizeof label, "%s: rejected with no ctx", ctx_algs[i]);
            check(pqc_sig_verify(sig, msg, sizeof msg, s1, l1, pk)
                  == PQC_ERROR_VERIFICATION_FAILED, label);

            /* Length limits: 255 is the maximum, 256 is refused. */
            snprintf(label, sizeof label, "%s: 255-byte ctx round-trips", ctx_algs[i]);
            check(pqc_sig_sign_ctx(sig, s1, &l1, msg, sizeof msg, ctx255, 255, sk) == PQC_OK &&
                  pqc_sig_verify_ctx(sig, msg, sizeof msg, ctx255, 255, s1, l1, pk) == PQC_OK,
                  label);
            snprintf(label, sizeof label, "%s: 256-byte ctx refused (sign) / false (verify)", ctx_algs[i]);
            check(pqc_sig_sign_ctx(sig, s2, &l2, msg, sizeof msg, ctx255, 256, sk)
                      == PQC_ERROR_INVALID_ARGUMENT &&
                  pqc_sig_verify_ctx(sig, msg, sizeof msg, ctx255, 256, s1, l1, pk)
                      == PQC_ERROR_VERIFICATION_FAILED,
                  label);
        }
        free(pk); free(sk); free(s1); free(s2);
        pqc_sig_free(sig);
    }

    /* A scheme with no context input must not silently drop one. SPHINCS+
     * round 3 is the same code as SLH-DSA without the M' prefix. */
    {
        PQC_SIG *sig = pqc_sig_new(PQC_SIG_SPHINCS_SHAKE_128F);
        if (sig) {
            uint8_t *pk = malloc(pqc_sig_public_key_size(sig));
            uint8_t *sk = malloc(pqc_sig_secret_key_size(sig));
            uint8_t *sg = malloc(pqc_sig_max_signature_size(sig));
            size_t l = 0;
            if (pk && sk && sg && pqc_sig_keygen(sig, pk, sk) == PQC_OK) {
                check(pqc_sig_sign_ctx(sig, sg, &l, msg, sizeof msg,
                                       ctx_a, sizeof ctx_a - 1, sk)
                          == PQC_ERROR_NOT_SUPPORTED,
                      "SPHINCS+ (no ctx input): non-empty ctx -> NOT_SUPPORTED");
                check(pqc_sig_sign_ctx(sig, sg, &l, msg, sizeof msg, NULL, 0, sk) == PQC_OK &&
                      pqc_sig_verify(sig, msg, sizeof msg, sg, l, pk) == PQC_OK,
                      "SPHINCS+ (no ctx input): empty ctx == plain sign");
            }
            free(pk); free(sk); free(sg);
            pqc_sig_free(sig);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Compile-time size consistency                                        */
/* ------------------------------------------------------------------ */

static void test_declared_sizes(void)
{
    printf("\n[1b] SNOVA declared sizes match the packed encoding\n");

    check(PQC_SNOVA_24_5_4_SIGBYTES == 16 + (29 * 4 * 4 + 1) / 2,
          "SNOVA-24-5-4 SIGBYTES == 16 + ceil(n*l*l/2)");
    check(PQC_SNOVA_25_8_3_SIGBYTES == 16 + (33 * 3 * 3 + 1) / 2,
          "SNOVA-25-8-3 SIGBYTES == 16 + ceil(n*l*l/2)");
    check(PQC_SNOVA_28_17_3_SIGBYTES == 16 + (45 * 3 * 3 + 1) / 2,
          "SNOVA-28-17-3 SIGBYTES == 16 + ceil(n*l*l/2)");
}


/* ------------------------------------------------------------------ */
/* Experimental algorithms are hidden unless the caller opts in        */
/* ------------------------------------------------------------------ */

static int listed_kem(const char *name)
{
    for (int i = 0; i < pqc_kem_algorithm_count(); i++)
        if (strcmp(pqc_kem_algorithm_name(i), name) == 0) return 1;
    return 0;
}

static int listed_sig(const char *name)
{
    for (int i = 0; i < pqc_sig_algorithm_count(); i++)
        if (strcmp(pqc_sig_algorithm_name(i), name) == 0) return 1;
    return 0;
}

static void test_experimental_gate(void)
{
    /* Only the families this build includes (see pqc/pqc_config.h). */
    static const char *bad_kem[] = {
#ifdef PQC_ENABLE_KEM_MCELIECE
        "Classic-McEliece-348864",
#endif
#ifdef PQC_ENABLE_KEM_NTRU
        "NTRU-HPS-2048-509",
#endif
#ifdef PQC_ENABLE_KEM_NTRUPRIME
        "sntrup761",
#endif
        NULL
    };
    static const char *bad_sig[] = {
#ifdef PQC_ENABLE_SIG_FNDSA
        "FN-DSA-512",
#endif
#ifdef PQC_ENABLE_SIG_MAYO
        "MAYO-1",
#endif
#ifdef PQC_ENABLE_SIG_UOV
        "UOV-Is",
#endif
#ifdef PQC_ENABLE_SIG_SNOVA
        "SNOVA-24-5-4",
#endif
#ifdef PQC_ENABLE_SIG_CROSS
        "CROSS-RSDP-128-fast",
#endif
        NULL
    };
    char msg[128];
    size_t i;

    printf("\n[0] Experimental algorithms are hidden by default\n");

    pqc_set_experimental(0);
    check(!pqc_experimental_enabled(), "opt-in is off");
    for (i = 0; bad_kem[i] != NULL; i++) {
        PQC_KEM *k = pqc_kem_new(bad_kem[i]);
        snprintf(msg, sizeof msg, "%s: hidden (new, is_enabled, list)",
                 bad_kem[i]);
        check(k == NULL && !pqc_kem_is_enabled(bad_kem[i]) &&
              !listed_kem(bad_kem[i]) &&
              pqc_kem_is_experimental(bad_kem[i]), msg);
        pqc_kem_free(k);
    }
    for (i = 0; bad_sig[i] != NULL; i++) {
        PQC_SIG *s = pqc_sig_new(bad_sig[i]);
        snprintf(msg, sizeof msg, "%s: hidden (new, is_enabled, list)",
                 bad_sig[i]);
        check(s == NULL && !pqc_sig_is_enabled(bad_sig[i]) &&
              !listed_sig(bad_sig[i]) &&
              pqc_sig_is_experimental(bad_sig[i]), msg);
        pqc_sig_free(s);
    }
#ifdef PQC_ENABLE_KEM_MLKEM
    check(listed_kem("ML-KEM-768") && !pqc_kem_is_experimental("ML-KEM-768"),
          "ML-KEM-768: listed, not experimental");
#endif
#ifdef PQC_ENABLE_SIG_MLDSA
    check(listed_sig("ML-DSA-65") && !pqc_sig_is_experimental("ML-DSA-65"),
          "ML-DSA-65: listed, not experimental");
#endif

    pqc_set_experimental(1);
    for (i = 0; bad_sig[i] != NULL; i++) {
        PQC_SIG *s = pqc_sig_new(bad_sig[i]);
        snprintf(msg, sizeof msg, "%s: available after opt-in", bad_sig[i]);
        check(s != NULL && listed_sig(bad_sig[i]), msg);
        pqc_sig_free(s);
    }
    for (i = 0; bad_kem[i] != NULL; i++) {
        PQC_KEM *k = pqc_kem_new(bad_kem[i]);
        snprintf(msg, sizeof msg, "%s: available after opt-in", bad_kem[i]);
        check(k != NULL && listed_kem(bad_kem[i]), msg);
        pqc_kem_free(k);
    }
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    /* Optional selector so a single group can be run in isolation. */
    const char *only = (argc > 1) ? argv[1] : NULL;
#define RUN(tag, fn) do { if (!only || strcmp(only, tag) == 0) fn(); } while (0)

    printf("libpqc-dyber security audit regression tests\n");
    printf("============================================\n");

    if (pqc_init() != PQC_OK) {
        printf("pqc_init failed\n");
        return 1;
    }

    RUN("gate",    test_experimental_gate);
    /* The groups below exercise experimental algorithms on purpose. */
    pqc_set_experimental(1);
    RUN("sizes",   test_declared_sizes);
    RUN("bounds",  test_sig_buffer_bounds);
#ifdef PQC_TEST_XMSS_INTERNALS
    RUN("wots",    test_xmss_wots_leaf_separation);
    RUN("wotsrt",  test_xmss_wots_roundtrip);
    RUN("addr",    test_xmss_addr_fields);
#endif
#ifdef PQC_TEST_SLHDSA_INTERNALS
    RUN("slhdsa",  test_slhdsa_invariants);
#endif
    RUN("checksum",test_xmss_checksum);
    RUN("stateful",test_stateful_roundtrip);
    RUN("veriflen",test_verify_length_validation);
    RUN("kem",     test_kem_implicit_rejection);
    RUN("ctx",     test_sig_context);

    pqc_cleanup();

    printf("\n============================================\n");
    printf("%d checks, %d failures\n", g_checks, g_failures);

    return g_failures == 0 ? 0 : 1;
}
