/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * BIKE known-answer test against the official round 4 KATs.
 *
 * For each level this regenerates the complete NIST response file --
 * 100 vectors of seed, pk, sk, ct, ss, from NIST's AES-256 CTR DRBG
 * exactly as PQCgenKAT_kem does -- and compares its SHA-256 with that of
 * the official file:
 *
 *   KAT/PQCkemKAT_BIKE_3114.rsp   (Level 1)
 *   KAT/PQCkemKAT_BIKE_6198.rsp   (Level 3)
 *   KAT/PQCkemKAT_BIKE_10276.rsp  (Level 5)
 *
 * from BIKE-Round4.zip, NIST's round 4 submission package (SHA-256
 * 456909897370ebcbb6f0b386e85488a26a83c43f73e7e22e3f43f5c57a2411a7).
 * The files are 1.3 to 4.1 MB, so only their hashes are kept here, as
 * liboqs does. It also decapsulates every vector and checks the result.
 *
 *   test_kat_bike [LEVEL] [OUTDIR]
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

static int run_level(const char *alg, const char *official,
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

    /* PQCgenKAT_kem: master DRBG on 0..47, one 48-byte seed per count. */
    for (i = 0; i < 48; i++) entropy[i] = (uint8_t)i;
    nist_drbg_init(&drbg, entropy);
    for (i = 0; i < 100; i++)
        nist_drbg_randombytes(&drbg, seeds[i], 48);

    puts_(&out, "# BIKE\n\n");
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
        snprintf(path, sizeof path, "%s/%s", outdir, official);
        f = fopen(path, "wb");
        if (f) { fwrite(out.p, 1, out.len, f); fclose(f); }
    }

    printf("  %s  %s: regenerated %s, sha256 %s\n",
           strcmp(got_hex, expect_hex) == 0 ? "PASS" : "FAIL", alg,
           official, got_hex);
    printf("  %s  %s: 100/100 vectors decapsulate to the encapsulated secret\n",
           bad_decaps ? "FAIL" : "PASS", alg);
    if (bad_decaps)
        printf("        (%d failed)\n", bad_decaps);

    /*
     * Implicit rejection, which the KATs do not exercise: for a modified
     * ciphertext c', decapsulation must return K(sigma, c') =
     * SHA3-384(sigma || c')[0..32), sigma being the last 32 bytes of sk.
     * (Uses the last vector's keys and ciphertext.)
     */
    {
        uint8_t *buf = malloc(32 + ctl), dg[PQC_SHA3_384_BYTES];
        int ok;
        if (!buf) return 1;
        ct[ctl / 2] ^= 0x01;
        memcpy(buf, sk + skl - 32, 32);
        memcpy(buf + 32, ct, ctl);
        pqc_sha3_384(dg, buf, 32 + ctl);
        ok = pqc_kem_decaps(kem, ss2, ct, sk) == PQC_OK &&
             memcmp(ss2, dg, 32) == 0;
        printf("  %s  %s: modified ciphertext gives K(sigma, c')\n",
               ok ? "PASS" : "FAIL", alg);
        bad_decaps += !ok;
        free(buf);
    }

    free(out.p); free(pk); free(sk); free(ct); free(ss); free(ss2);
    pqc_kem_free(kem);
    return (strcmp(got_hex, expect_hex) != 0) + (bad_decaps != 0);
}

int main(int argc, char **argv)
{
    static const struct {
        int level;
        const char *alg, *file, *sha256;
    } L[] = {
        { 1, "BIKE-L1", "PQCkemKAT_BIKE_3114.rsp",
          "77853f4831ce668ed3a620218ad7d1dc9eeb920d5c33c9c4c4011fafe773699c" },
        { 3, "BIKE-L3", "PQCkemKAT_BIKE_6198.rsp",
          "4af64774c8152072bcbdb9f916f04848079a4b119d1a6b4b96fd5371b1addec3" },
        { 5, "BIKE-L5", "PQCkemKAT_BIKE_10276.rsp",
          "568188a47b53d35ed9622d53b094aa7ddf814ce43d5c503190d5910d4bc1824f" },
    };
    int only = argc > 1 ? atoi(argv[1]) : 0, failures = 0;
    const char *outdir = argc > 2 ? argv[2] : NULL;
    size_t i;

    printf("BIKE known-answer tests (official round 4 KATs)\n");
    if (pqc_init() != PQC_OK) return 2;
    if (nist_aes256_selftest() != 0) {
        printf("  FAIL  AES-256 does not match FIPS 197 C.3\n");
        return 1;
    }
    printf("  PASS  AES-256 (FIPS 197 C.3) for the NIST DRBG\n");
    for (i = 0; i < sizeof L / sizeof L[0]; i++)
        if (!only || only == L[i].level)
            failures += run_level(L[i].alg, L[i].file, L[i].sha256, outdir);
    printf("%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
