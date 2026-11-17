/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * HQC known-answer test against the official HQC v5.1.0 KATs.
 *
 * For each level this regenerates the complete response file -- 100
 * vectors of seed, pk, sk, ct, ss from NIST's AES-256 CTR DRBG, as the
 * reference's tests/kats/test_kat.c does -- and compares its SHA-256
 * with that of the official file:
 *
 *   kats/ref/hqc-1/PQCkemKAT_32.rsp   (HQC-128)
 *   kats/ref/hqc-3/PQCkemKAT_32.rsp   (HQC-192)
 *   kats/ref/hqc-5/PQCkemKAT_32.rsp   (HQC-256)
 *
 * from https://gitlab.com/pqc-hqc/hqc, tag v5.1.0 (commit 06567ccbad10;
 * archive hqc-v5.1.0.tar.gz, SHA-256
 * 66fa3238403dc45bf3b63d097c05d307407d6bf5655582d536ced4c2a0464c7f).
 * Only the hashes are kept here. It also decapsulates every vector and
 * checks implicit rejection against an independent computation.
 *
 *   test_kat_hqc [LEVEL] [OUTDIR]
 *
 * LEVEL (1, 3 or 5) limits the run to one level; OUTDIR writes the
 * regenerated files there, to diff against the official ones.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"
#include "core/common/hash/sha2.h"
#include "core/common/hash/sha3.h"
#include "nist_drbg.h"

static nist_drbg_t drbg;

static pqc_status_t kat_rng(uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    nist_drbg_randombytes(&drbg, buf, len);
    return PQC_OK;
}

typedef struct {
    char *p;
    size_t len, cap;
} sbuf_t;

static void put(sbuf_t *b, const char *s, size_t n)
{
    if (b->len + n + 1 > b->cap) {
        b->cap = (b->len + n + 1) * 2;
        b->p = (char *)realloc(b->p, b->cap);
        if (!b->p) { fprintf(stderr, "out of memory\n"); exit(2); }
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
}

static void puts_(sbuf_t *b, const char *s) { put(b, s, strlen(s)); }

static void put_hex(sbuf_t *b, const char *label, const uint8_t *v, size_t n)
{
    static const char hx[] = "0123456789ABCDEF";
    size_t i;
    char two[2];
    puts_(b, label);
    puts_(b, " = ");
    for (i = 0; i < n; i++) {
        two[0] = hx[v[i] >> 4];
        two[1] = hx[v[i] & 15];
        put(b, two, 2);
    }
    puts_(b, "\n");
}

/*
 * The implicit-rejection secret, computed from the specification rather
 * than the implementation: sigma is bytes [32, 32+k) of
 * SHAKE256(sk || k) (sk is the 32-byte KEM seed, k the message length,
 * which is also the XOF domain byte), and
 *   K_bar = SHA3-256(SHA3-256(pk || 0x01) || sigma || c || 0x03).
 */
static void rejection_secret(uint8_t out[32], const uint8_t *pk, size_t pkl,
                             const uint8_t *sk, const uint8_t *ct, size_t ctl,
                             size_t k)
{
    uint8_t seed_dom[33], xof[32 + 32], hek[32];
    uint8_t *buf = malloc(pkl + 1 > 32 + 32 + ctl + 1 ? pkl + 1 : 32 + 32 + ctl + 1);
    if (!buf) { fprintf(stderr, "out of memory\n"); exit(2); }

    memcpy(seed_dom, sk, 32);
    seed_dom[32] = (uint8_t)k;
    pqc_shake256(xof, 32 + k, seed_dom, 33);

    memcpy(buf, pk, pkl);
    buf[pkl] = 0x01;
    pqc_sha3_256(hek, buf, pkl + 1);

    memcpy(buf, hek, 32);
    memcpy(buf + 32, xof + 32, k);
    memcpy(buf + 32 + k, ct, ctl);
    buf[32 + k + ctl] = 0x03;
    pqc_sha3_256(out, buf, 32 + k + ctl + 1);
    free(buf);
}

static int run_level(int level, const char *alg, size_t k,
                     const char *expect_hex, const char *outdir)
{
    PQC_KEM *kem = pqc_kem_new(alg);
    uint8_t entropy[48], seeds[100][48], digest[32], *pk, *sk, *ct, *ss, *ss2;
    size_t pkl, skl, ctl, ssl;
    sbuf_t out = {0};
    char line[64], got_hex[65];
    int i, bad_decaps = 0;

    if (!kem) {
        printf("  SKIP  %s (not in this build)\n", alg);
        return 0;
    }
    pkl = pqc_kem_public_key_size(kem);
    skl = pqc_kem_secret_key_size(kem);
    ctl = pqc_kem_ciphertext_size(kem);
    ssl = pqc_kem_shared_secret_size(kem);
    pk = malloc(pkl); sk = malloc(skl); ct = malloc(ctl);
    ss = malloc(ssl); ss2 = malloc(ssl);
    if (!pk || !sk || !ct || !ss || !ss2) return 1;

    /* Master DRBG on 0..47, one 48-byte seed per count (PQCgenKAT_kem). */
    for (i = 0; i < 48; i++) entropy[i] = (uint8_t)i;
    nist_drbg_init(&drbg, entropy);
    for (i = 0; i < 100; i++)
        nist_drbg_randombytes(&drbg, seeds[i], 48);

    snprintf(line, sizeof line, "# HQC-%d\n\n", level);
    puts_(&out, line);
    pqc_set_rng(kat_rng, NULL);
    for (i = 0; i < 100; i++) {
        snprintf(line, sizeof line, "count = %d\n", i);
        puts_(&out, line);
        put_hex(&out, "seed", seeds[i], 48);
        nist_drbg_init(&drbg, seeds[i]);
        if (pqc_kem_keygen(kem, pk, sk) != PQC_OK ||
            pqc_kem_encaps(kem, ct, ss, pk) != PQC_OK) {
            printf("  FAIL  %s count %d: keygen/encaps error\n", alg, i);
            pqc_set_rng(NULL, NULL);
            return 1;
        }
        put_hex(&out, "pk", pk, pkl);
        put_hex(&out, "sk", sk, skl);
        put_hex(&out, "ct", ct, ctl);
        put_hex(&out, "ss", ss, ssl);
        puts_(&out, "\n");
        if (pqc_kem_decaps(kem, ss2, ct, sk) != PQC_OK ||
            memcmp(ss, ss2, ssl) != 0)
            bad_decaps++;
    }
    pqc_set_rng(NULL, NULL);

    pqc_sha256(digest, (const uint8_t *)out.p, out.len);
    for (i = 0; i < 32; i++)
        snprintf(got_hex + 2 * i, 3, "%02x", digest[i]);

    if (outdir) {
        char path[512];
        FILE *f;
        snprintf(path, sizeof path, "%s/hqc-%d-PQCkemKAT_32.rsp", outdir, level);
        f = fopen(path, "wb");
        if (f) { fwrite(out.p, 1, out.len, f); fclose(f); }
    }

    printf("  %s  %s: regenerated hqc-%d/PQCkemKAT_32.rsp, sha256 %s\n",
           strcmp(got_hex, expect_hex) == 0 ? "PASS" : "FAIL", alg, level,
           got_hex);
    printf("  %s  %s: 100/100 vectors decapsulate to the encapsulated secret\n",
           bad_decaps ? "FAIL" : "PASS", alg);
    if (bad_decaps)
        printf("        (%d failed)\n", bad_decaps);

    /*
     * Implicit rejection, which the KATs do not exercise: a modified
     * ciphertext must decapsulate to K_bar (see rejection_secret), in
     * u, in v and in the salt. Uses the last vector's keys.
     */
    {
        static const char *part[3] = { "u", "v", "salt" };
        size_t at[3];
        int j;
        at[0] = 10;                 /* inside u */
        at[1] = ctl - 16 - 10;      /* inside v */
        at[2] = ctl - 5;            /* inside the salt */
        for (j = 0; j < 3; j++) {
            uint8_t expect[32];
            int ok;
            ct[at[j]] ^= 0x01;
            rejection_secret(expect, pk, pkl, sk, ct, ctl, k);
            ok = pqc_kem_decaps(kem, ss2, ct, sk) == PQC_OK &&
                 memcmp(ss2, expect, 32) == 0 && memcmp(ss2, ss, 32) != 0;
            ct[at[j]] ^= 0x01;
            printf("  %s  %s: ciphertext modified in %s gives K_bar\n",
                   ok ? "PASS" : "FAIL", alg, part[j]);
            bad_decaps += !ok;
        }
    }

    free(out.p); free(pk); free(sk); free(ct); free(ss); free(ss2);
    pqc_kem_free(kem);
    return (strcmp(got_hex, expect_hex) != 0) + (bad_decaps != 0);
}

int main(int argc, char **argv)
{
    static const struct {
        int level;
        const char *alg;
        size_t k;
        const char *sha256;
    } L[] = {
        { 1, "HQC-128", 16,
          "c3f6ce304a00685e3aa356ef7cd81dbb35d985a1ff7123610bed9582e3638c1e" },
        { 3, "HQC-192", 24,
          "7dcb2b670d1e108c0d7dc0c88b466c63c121de5ac4f96fd2e868c7040065a4ff" },
        { 5, "HQC-256", 32,
          "e5066df4ec3dbe012d60a4a66ce5e0c2f1996d11af8a8eb66333f15b51095edb" },
    };
    int only = argc > 1 ? atoi(argv[1]) : 0, failures = 0;
    const char *outdir = argc > 2 ? argv[2] : NULL;
    size_t i;

    printf("HQC known-answer tests (official HQC v5.1.0 KATs)\n");
    if (pqc_init() != PQC_OK) return 2;
    if (nist_aes256_selftest() != 0) {
        printf("  FAIL  AES-256 does not match FIPS 197 C.3\n");
        return 1;
    }
    printf("  PASS  AES-256 (FIPS 197 C.3) for the NIST DRBG\n");
    for (i = 0; i < sizeof L / sizeof L[0]; i++)
        if (!only || only == L[i].level)
            failures += run_level(L[i].level, L[i].alg, L[i].k, L[i].sha256,
                                  outdir);
    printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
