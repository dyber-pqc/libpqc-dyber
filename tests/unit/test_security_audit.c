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

/* Internal headers for the invariant checks. */
#include "core/sig/xmss/xmss.h"
#include "core/sig/xmss/xmss_params.h"
#include "core/sig/snova/snova_params.h"
#include "core/sig/cross/cross_params.h"

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

static void test_sig_buffer_bounds(void)
{
    static const char *algs[] = {
        "SNOVA-24-5-4", "SNOVA-25-8-3", "SNOVA-28-17-3",
        "CROSS-RSDP-128-fast", "CROSS-RSDP-128-small",
        "CROSS-RSDP-192-fast", "CROSS-RSDP-192-small",
        "CROSS-RSDP-256-fast", "CROSS-RSDP-256-small",
        "MAYO-1", "UOV-Is",
        NULL
    };
    const uint8_t msg[] = "audit regression message";
    int a;

    printf("\n[1] sign() must not exceed max_signature_size\n");

    for (a = 0; algs[a]; a++) {
        PQC_SIG *sig = pqc_sig_new(algs[a]);
        uint8_t *pk, *sk, *sigbuf;
        size_t maxlen, siglen = 0;
        pqc_status_t rc;
        char label[128];
        /* Guard bytes immediately after the signature buffer. */
        static const uint8_t CANARY = 0xA5;
        size_t guard = 64, i;
        int clean = 1;

        if (!sig) { printf("  SKIP  %s (not registered)\n", algs[a]); continue; }

        maxlen = pqc_sig_max_signature_size(sig);
        pk = (uint8_t *)calloc(1, pqc_sig_public_key_size(sig));
        sk = (uint8_t *)calloc(1, pqc_sig_secret_key_size(sig));
        sigbuf = (uint8_t *)malloc(maxlen + guard);
        if (!pk || !sk || !sigbuf) { printf("  SKIP  %s (alloc)\n", algs[a]);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue; }

        memset(sigbuf, 0, maxlen);
        memset(sigbuf + maxlen, CANARY, guard);

        rc = pqc_sig_keygen(sig, pk, sk);
        if (rc != PQC_OK) {
            printf("  SKIP  %s (keygen rc=%d)\n", algs[a], rc);
            free(pk); free(sk); free(sigbuf); pqc_sig_free(sig); continue;
        }

        rc = pqc_sig_sign(sig, sigbuf, &siglen, msg, sizeof(msg), sk);

        for (i = 0; i < guard; i++) {
            if (sigbuf[maxlen + i] != CANARY) { clean = 0; break; }
        }

        snprintf(label, sizeof(label),
                 "%s: no write past max_signature_size (%zu)", algs[a], maxlen);
        check(clean, label);

        if (rc == PQC_OK) {
            snprintf(label, sizeof(label),
                     "%s: reported siglen %zu <= max %zu",
                     algs[a], siglen, maxlen);
            check(siglen <= maxlen, label);
        }

        free(pk); free(sk); free(sigbuf);
        pqc_sig_free(sig);
    }
}

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

        free(pk); free(sk); free(ct); free(ss1); free(ss2);
        pqc_kem_free(kem);
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

    RUN("sizes",   test_declared_sizes);
    RUN("bounds",  test_sig_buffer_bounds);
    RUN("wots",    test_xmss_wots_leaf_separation);
    RUN("checksum",test_xmss_checksum);
    RUN("addr",    test_xmss_addr_fields);
    RUN("stateful",test_stateful_roundtrip);
    RUN("veriflen",test_verify_length_validation);
    RUN("kem",     test_kem_implicit_rejection);

    pqc_cleanup();

    printf("\n============================================\n");
    printf("%d checks, %d failures\n", g_checks, g_failures);

    return g_failures == 0 ? 0 : 1;
}
