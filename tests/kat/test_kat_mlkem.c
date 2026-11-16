/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-KEM (FIPS 203) against NIST's ACVP vectors.
 *
 *   test_kat_mlkem tests/kat/mlkem_acvp.txt
 *
 * The vector file is converted from usnistgov/ACVP-Server by
 * tests/kat/tools/acvp_mlkem_to_kat.py (provenance in its header):
 *
 *   keygen   ML-KEM.KeyGen_internal(d, z)      -> ek, dk     (75 tests)
 *   encap    ML-KEM.Encaps_internal(ek, m)     -> c, K       (75)
 *   decap    ML-KEM.Decaps(dk, c)              -> K          (30, including
 *            ciphertexts that must be implicitly rejected)
 *   ekcheck  FIPS 203 sec. 7.2 modulus check on ek            (30)
 *   dkcheck  FIPS 203 sec. 7.3 hash check on dk               (30)
 *
 * ACVP gives d, z and m directly rather than a DRBG seed, so this feeds
 * them through the library's RNG hook (pqc_set_rng), and fails a test if
 * the library draws a different number of bytes than FIPS 203 says:
 * 64 (d || z) for key generation, 32 (m) for encapsulation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"
#include "core/common/hash/sha2.h"

/* ------------------------------------------------------------------ */
/* Deterministic RNG: hands out exactly the bytes queued.               */
/* ------------------------------------------------------------------ */

static uint8_t rng_buf[64];
static size_t rng_len, rng_pos;
static int rng_overrun;

static pqc_status_t queued_rng(uint8_t *out, size_t len, void *ctx)
{
    (void)ctx;
    if (rng_pos + len > rng_len) {
        rng_overrun = 1;
        memset(out, 0, len);
        return PQC_ERROR_RNG_FAILED;
    }
    memcpy(out, rng_buf + rng_pos, len);
    rng_pos += len;
    return PQC_OK;
}

static void rng_queue(const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
    memcpy(rng_buf, a, al);
    if (bl) memcpy(rng_buf + al, b, bl);
    rng_len = al + bl;
    rng_pos = 0;
    rng_overrun = 0;
}

/* ------------------------------------------------------------------ */
/* Parsing                                                              */
/* ------------------------------------------------------------------ */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes a hex field into a fresh buffer; *len gets the byte count. */
static uint8_t *unhex(const char *s, size_t *len)
{
    size_t n = strlen(s), i;
    uint8_t *b;
    if (n % 2) return NULL;
    b = (uint8_t *)malloc(n / 2 ? n / 2 : 1);
    if (!b) return NULL;
    for (i = 0; i < n / 2; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(b); return NULL; }
        b[i] = (uint8_t)(hi << 4 | lo);
    }
    *len = n / 2;
    return b;
}

static int same_sha256(const uint8_t *data, size_t len, const char *hex)
{
    uint8_t d[32];
    char got[65];
    int i;
    pqc_sha256(d, data, len);
    for (i = 0; i < 32; i++)
        snprintf(got + 2 * i, 3, "%02x", d[i]);
    return strcmp(got, hex) == 0;
}

/* ------------------------------------------------------------------ */

typedef struct { int run, failed; } tally_t;

static void record(tally_t *t, int ok, const char *kind, const char *set,
                   const char *tc, const char *why)
{
    t->run++;
    if (!ok) {
        t->failed++;
        if (t->failed <= 20)
            printf("  FAIL  %s ML-KEM-%s tcId %s: %s\n", kind, set, tc, why);
    }
}

int main(int argc, char **argv)
{
    static char line[32768];
    const char *names[] = { "keygen", "encap", "decap", "ekcheck", "dkcheck" };
    tally_t tally[5] = {{0, 0}};
    FILE *f;
    int i, total_failed = 0, total_run = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s mlkem_acvp.txt\n", argv[0]);
        return 2;
    }
    f = fopen(argv[1], "r");
    if (!f) { perror(argv[1]); return 2; }
    if (pqc_init() != PQC_OK) return 2;
    pqc_set_rng(queued_rng, NULL);

    printf("ML-KEM (FIPS 203) against NIST ACVP vectors\n");

    while (fgets(line, sizeof line, f)) {
        char *tok[8];
        int nt = 0, kind;
        char alg[32];
        PQC_KEM *kem;
        char *s;

        if (line[0] == '#' || line[0] == '\n') continue;
        for (s = strtok(line, " \r\n"); s && nt < 8; s = strtok(NULL, " \r\n"))
            tok[nt++] = s;
        for (kind = 0; kind < 5; kind++)
            if (nt && strcmp(tok[0], names[kind]) == 0) break;
        if (kind == 5 || nt < 4) {
            printf("  FAIL  malformed line\n");
            total_failed++;
            continue;
        }
        snprintf(alg, sizeof alg, "ML-KEM-%s", tok[1]);
        kem = pqc_kem_new(alg);
        if (!kem) continue;     /* parameter set not in this build */

        {
            size_t pkl = pqc_kem_public_key_size(kem);
            size_t skl = pqc_kem_secret_key_size(kem);
            size_t ctl = pqc_kem_ciphertext_size(kem);
            size_t ssl = pqc_kem_shared_secret_size(kem);
            uint8_t *pk = malloc(pkl), *sk = malloc(skl), *ct = malloc(ctl);
            uint8_t *ss = malloc(ssl);
            size_t l1 = 0, l2 = 0, l3 = 0;
            uint8_t *a = NULL, *b = NULL, *c = NULL;
            pqc_status_t rc;

            switch (kind) {
            case 0: /* keygen d z H(ek) H(dk) */
                a = unhex(tok[3], &l1);
                b = unhex(tok[4], &l2);
                if (nt != 7 || !a || !b || l1 != 32 || l2 != 32) {
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "bad vector");
                    break;
                }
                rng_queue(a, 32, b, 32);
                rc = pqc_kem_keygen(kem, pk, sk);
                if (rc != PQC_OK || rng_overrun || rng_pos != 64)
                    record(&tally[kind], 0, names[kind], tok[1], tok[2],
                           "did not draw exactly d || z (64 bytes)");
                else if (!same_sha256(pk, pkl, tok[5]))
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "ek differs");
                else
                    record(&tally[kind], same_sha256(sk, skl, tok[6]),
                           names[kind], tok[1], tok[2], "dk differs");
                break;

            case 1: /* encap ek m H(c) K */
                a = unhex(tok[3], &l1);
                b = unhex(tok[4], &l2);
                c = unhex(tok[6], &l3);
                if (nt != 7 || !a || !b || !c || l1 != pkl || l2 != 32 || l3 != ssl) {
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "bad vector");
                    break;
                }
                rng_queue(b, 32, NULL, 0);
                rc = pqc_kem_encaps(kem, ct, ss, a);
                if (rc != PQC_OK || rng_overrun || rng_pos != 32)
                    record(&tally[kind], 0, names[kind], tok[1], tok[2],
                           "did not draw exactly m (32 bytes)");
                else if (!same_sha256(ct, ctl, tok[5]))
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "c differs");
                else
                    record(&tally[kind], memcmp(ss, c, ssl) == 0,
                           names[kind], tok[1], tok[2], "K differs");
                break;

            case 2: /* decap dk c K */
                a = unhex(tok[3], &l1);
                b = unhex(tok[4], &l2);
                c = unhex(tok[5], &l3);
                if (nt != 6 || !a || !b || !c || l1 != skl || l2 != ctl || l3 != ssl) {
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "bad vector");
                    break;
                }
                rc = pqc_kem_decaps(kem, ss, b, a);
                record(&tally[kind], rc == PQC_OK && memcmp(ss, c, ssl) == 0,
                       names[kind], tok[1], tok[2],
                       rc != PQC_OK ? "decaps returned an error" : "K differs");
                break;

            case 3: { /* ekcheck ek PASS */
                int expect = atoi(tok[4]);
                a = unhex(tok[3], &l1);
                if (nt != 5 || !a || l1 != pkl) {
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "bad vector");
                    break;
                }
                memset(rng_buf, 0x5a, 32);
                rng_len = 32; rng_pos = 0; rng_overrun = 0;
                rc = pqc_kem_encaps(kem, ct, ss, a);
                record(&tally[kind], (rc == PQC_OK) == (expect == 1),
                       names[kind], tok[1], tok[2],
                       expect ? "valid ek rejected"
                              : "ek failing the modulus check was accepted");
                break;
            }

            case 4: { /* dkcheck dk PASS */
                int expect = atoi(tok[4]);
                a = unhex(tok[3], &l1);
                if (nt != 5 || !a || l1 != skl) {
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "bad vector");
                    break;
                }
                memset(ct, 0, ctl);
                rc = pqc_kem_decaps(kem, ss, ct, a);
                record(&tally[kind], (rc == PQC_OK) == (expect == 1),
                       names[kind], tok[1], tok[2],
                       expect ? "valid dk rejected"
                              : "dk failing the hash check was accepted");
                break;
            }
            }
            free(a); free(b); free(c);
            free(pk); free(sk); free(ct); free(ss);
        }
        pqc_kem_free(kem);
    }
    fclose(f);
    pqc_set_rng(NULL, NULL);

    for (i = 0; i < 5; i++) {
        printf("  %s  %-8s %d/%d\n", tally[i].failed ? "FAIL" : "PASS",
               names[i], tally[i].run - tally[i].failed, tally[i].run);
        total_failed += tally[i].failed;
        total_run += tally[i].run;
    }
    if (total_run == 0) {
        printf("ML-KEM not in this build\n");
        return 77;
    }
    printf("%d/%d passed\n", total_run - total_failed, total_run);
    return total_failed ? 1 : 0;
}
