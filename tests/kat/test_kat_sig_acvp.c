/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) against NIST's ACVP vectors.
 *
 *   test_kat_sig_acvp [--sample N] tests/kat/mldsa_acvp.txt
 *   test_kat_sig_acvp [--sample N] tests/kat/slhdsa_acvp.txt
 *
 * --sample N runs only the first N signing vectors of each parameter set
 * (key generation and verification always run in full). SLH-DSA signing
 * is slow -- the 168 vectors take minutes in an optimised build and far
 * longer in a debug or sanitizer build -- so ctest runs a sample and the
 * CI known-answer job runs everything.
 *
 * The vector files are converted from usnistgov/ACVP-Server by
 * tests/kat/tools/acvp_sig_to_kat.py; their headers give the source
 * commit and file hashes, and count the ACVP groups that cannot be run
 * because libpqc-dyber has no API for them (the internal interface,
 * pre-hash signing, ML-DSA external-mu).
 *
 *   keygen  key generation from the seed(s)         -> pk, sk
 *   siggen  pqc_sig_sign_ctx(sk, msg, ctx)           -> signature
 *           (deterministic and hedged)
 *   sigver  pqc_sig_verify_ctx(pk, msg, ctx, sig)    -> accept / reject
 *
 * Seeds and signing randomness are fed through the RNG hook, and a test
 * fails if the library draws a different number of bytes than the
 * standard says (ML-DSA: 32 for xi, 32 for rnd; SLH-DSA: 3n for
 * SK.seed || SK.prf || PK.seed, n for opt_rand).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"
#include "core/common/hash/sha2.h"

static uint8_t rng_buf[128];
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

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* "-" is the empty string. Returns NULL on malformed hex. */
static uint8_t *unhex(const char *s, size_t *len)
{
    size_t n, i;
    uint8_t *b;
    if (strcmp(s, "-") == 0) s = "";
    n = strlen(s);
    if (n % 2) return NULL;
    b = (uint8_t *)malloc(n / 2 + 1);
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

/* Reads one line of any length; returns NULL at end of file. */
static char *read_line(FILE *f, char **buf, size_t *cap)
{
    size_t len = 0;
    if (!*buf) {
        *cap = 65536;
        *buf = (char *)malloc(*cap);
        if (!*buf) return NULL;
    }
    for (;;) {
        if (!fgets(*buf + len, (int)(*cap - len), f))
            return len ? *buf : NULL;
        len += strlen(*buf + len);
        if (len && (*buf)[len - 1] == '\n')
            return *buf;
        if (len + 1 >= *cap) {
            char *nb = (char *)realloc(*buf, *cap * 2);
            if (!nb) return NULL;
            *buf = nb;
            *cap *= 2;
        }
    }
}

typedef struct { int run, failed; } tally_t;

/* Signing vectors seen so far per algorithm, for --sample. */
static struct { char alg[48]; int n; } seen[64];

static int take_sample(const char *alg, int limit)
{
    int i;
    if (limit <= 0) return 1;
    for (i = 0; i < 64 && seen[i].alg[0]; i++)
        if (strcmp(seen[i].alg, alg) == 0)
            return ++seen[i].n <= limit;
    if (i < 64) {
        snprintf(seen[i].alg, sizeof seen[i].alg, "%s", alg);
        seen[i].n = 1;
    }
    return 1;
}

static void record(tally_t *t, int ok, const char *kind, const char *alg,
                   const char *tc, const char *why)
{
    t->run++;
    if (!ok) {
        t->failed++;
        if (t->failed <= 20)
            printf("  FAIL  %s %s tcId %s: %s\n", kind, alg, tc, why);
    }
}

int main(int argc, char **argv)
{
    static const char *names[] = { "keygen", "siggen", "sigver" };
    tally_t tally[3] = {{0, 0}};
    char *line = NULL;
    size_t cap = 0;
    FILE *f;
    int i, total_run = 0, total_failed = 0, sample = 0, skipped = 0;
    const char *path;

    if (argc == 4 && strcmp(argv[1], "--sample") == 0) {
        sample = atoi(argv[2]);
        path = argv[3];
    } else if (argc == 2) {
        path = argv[1];
    } else {
        fprintf(stderr, "usage: %s [--sample N] VECTOR_FILE\n", argv[0]);
        return 2;
    }
    f = fopen(path, "r");
    if (!f) { perror(path); return 2; }
    if (pqc_init() != PQC_OK) return 2;
    pqc_set_rng(queued_rng, NULL);

    while (read_line(f, &line, &cap)) {
        char *tok[10];
        int nt = 0, kind;
        PQC_SIG *sig;
        char *s;

        if (line[0] == '#') {
            if (strncmp(line, "# not converted", 15) == 0 ||
                strncmp(line, "# ML-DSA", 8) == 0 ||
                strncmp(line, "# SLH-DSA", 9) == 0)
                printf("%s", line);
            continue;
        }
        if (line[0] == '\n' || line[0] == '\r') continue;
        for (s = strtok(line, " \r\n"); s && nt < 10; s = strtok(NULL, " \r\n"))
            tok[nt++] = s;
        for (kind = 0; kind < 3; kind++)
            if (nt && strcmp(tok[0], names[kind]) == 0) break;
        if (kind == 3 || nt < 4) {
            printf("  FAIL  malformed line\n");
            total_failed++;
            continue;
        }
        if (kind == 1 && !take_sample(tok[1], sample)) {
            skipped++;
            continue;
        }
        sig = pqc_sig_new(tok[1]);
        if (!sig) continue;     /* not in this build */

        {
            size_t pkl = pqc_sig_public_key_size(sig);
            size_t skl = pqc_sig_secret_key_size(sig);
            size_t sgl = pqc_sig_max_signature_size(sig);
            uint8_t *pk = malloc(pkl), *sk = malloc(skl), *sg = malloc(sgl);
            uint8_t *a = NULL, *m = NULL, *c = NULL, *r = NULL;
            size_t la = 0, lm = 0, lc = 0, lr = 0, outlen = 0;
            pqc_status_t rc;

            switch (kind) {
            case 0: /* keygen ALG TCID RNG H(pk) H(sk) */
                r = unhex(tok[3], &lr);
                if (nt != 6 || !r || lr > sizeof rng_buf) {
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "bad vector");
                    break;
                }
                memcpy(rng_buf, r, lr);
                rng_len = lr; rng_pos = 0; rng_overrun = 0;
                rc = pqc_sig_keygen(sig, pk, sk);
                if (rc != PQC_OK || rng_overrun || rng_pos != lr)
                    record(&tally[kind], 0, names[kind], tok[1], tok[2],
                           "did not draw exactly the specified seed bytes");
                else if (!same_sha256(pk, pkl, tok[4]))
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "pk differs");
                else
                    record(&tally[kind], same_sha256(sk, skl, tok[5]),
                           names[kind], tok[1], tok[2], "sk differs");
                break;

            case 1: /* siggen ALG TCID sk msg ctx RNG H(sig) */
                a = unhex(tok[3], &la);
                m = unhex(tok[4], &lm);
                c = unhex(tok[5], &lc);
                r = unhex(tok[6], &lr);
                if (nt != 8 || !a || !m || !c || !r || la != skl ||
                    lr > sizeof rng_buf) {
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "bad vector");
                    break;
                }
                memcpy(rng_buf, r, lr);
                rng_len = lr; rng_pos = 0; rng_overrun = 0;
                rc = pqc_sig_sign_ctx(sig, sg, &outlen, m, lm, c, lc, a);
                if (rc != PQC_OK || rng_overrun || rng_pos != lr)
                    record(&tally[kind], 0, names[kind], tok[1], tok[2],
                           "did not draw exactly the specified randomness");
                else
                    record(&tally[kind], same_sha256(sg, outlen, tok[7]),
                           names[kind], tok[1], tok[2], "signature differs");
                break;

            case 2: { /* sigver ALG TCID pk msg ctx sig PASS */
                int expect;
                a = unhex(tok[3], &la);
                m = unhex(tok[4], &lm);
                c = unhex(tok[5], &lc);
                r = unhex(tok[6], &lr);
                if (nt != 8 || !a || !m || !c || !r || la != pkl) {
                    record(&tally[kind], 0, names[kind], tok[1], tok[2], "bad vector");
                    break;
                }
                expect = atoi(tok[7]);
                rc = pqc_sig_verify_ctx(sig, m, lm, c, lc, r, lr, a);
                record(&tally[kind], (rc == PQC_OK) == (expect == 1),
                       names[kind], tok[1], tok[2],
                       expect ? "valid signature rejected"
                              : "invalid signature accepted");
                break;
            }
            }
            free(a); free(m); free(c); free(r);
            free(pk); free(sk); free(sg);
        }
        pqc_sig_free(sig);
    }
    fclose(f);
    free(line);
    pqc_set_rng(NULL, NULL);

    for (i = 0; i < 3; i++) {
        printf("  %s  %-7s %d/%d\n", tally[i].failed ? "FAIL" : "PASS",
               names[i], tally[i].run - tally[i].failed, tally[i].run);
        total_failed += tally[i].failed;
        total_run += tally[i].run;
    }
    if (total_run == 0) {
        printf("not in this build\n");
        return 77;
    }
    printf("%d/%d passed\n", total_run - total_failed, total_run);
    if (skipped)
        printf("(--sample %d: %d signing vectors not run)\n", sample, skipped);
    return total_failed ? 1 : 0;
}
