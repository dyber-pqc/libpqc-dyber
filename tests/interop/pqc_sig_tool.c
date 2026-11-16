/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Minimal command-line front end to the public signature API, used by
 * tests/interop/openssl_interop.py to exchange keys and signatures with an
 * independent implementation. Not installed.
 *
 *   pqc_sig_tool keygen ALG PK_OUT SK_OUT
 *   pqc_sig_tool sign   ALG SK_IN  MSG_IN CTX_HEX SIG_OUT
 *   pqc_sig_tool verify ALG PK_IN  MSG_IN CTX_HEX SIG_IN
 *
 * CTX_HEX is the context string in hex; "-" means empty. verify exits 0 if
 * the signature is valid, 1 if not, 2 on usage or I/O error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    long sz;

    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(sz > 0 ? (size_t)sz : 1);
    if (buf && sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    *len = sz > 0 ? (size_t)sz : 0;
    return buf;
}

static int write_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    int ok;

    if (!f) return -1;
    ok = fwrite(buf, 1, len, f) == len;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

static int parse_hex(const char *hex, unsigned char *out, size_t *outlen)
{
    size_t n, i;

    if (strcmp(hex, "-") == 0) { *outlen = 0; return 0; }
    n = strlen(hex);
    if (n % 2 || n / 2 > 256) return -1;
    for (i = 0; i < n / 2; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (unsigned char)b;
    }
    *outlen = n / 2;
    return 0;
}

int main(int argc, char **argv)
{
    PQC_SIG *sig;
    int rc = 2;

    if (argc < 5) {
        fprintf(stderr, "usage: see source\n");
        return 2;
    }
    if (pqc_init() != PQC_OK) return 2;
    sig = pqc_sig_new(argv[2]);
    if (!sig) {
        fprintf(stderr, "unknown algorithm %s\n", argv[2]);
        return 2;
    }

    if (strcmp(argv[1], "keygen") == 0 && argc == 5) {
        unsigned char *pk = malloc(pqc_sig_public_key_size(sig));
        unsigned char *sk = malloc(pqc_sig_secret_key_size(sig));
        if (pk && sk && pqc_sig_keygen(sig, pk, sk) == PQC_OK &&
            write_file(argv[3], pk, pqc_sig_public_key_size(sig)) == 0 &&
            write_file(argv[4], sk, pqc_sig_secret_key_size(sig)) == 0)
            rc = 0;
        free(pk);
        free(sk);
    } else if ((strcmp(argv[1], "sign") == 0 ||
                strcmp(argv[1], "verify") == 0) && argc == 7) {
        unsigned char ctx[256];
        size_t ctxlen, keylen, msglen, siglen;
        unsigned char *key = read_file(argv[3], &keylen);
        unsigned char *msg = read_file(argv[4], &msglen);

        if (!key || !msg || parse_hex(argv[5], ctx, &ctxlen) != 0) {
            fprintf(stderr, "bad input\n");
        } else if (argv[1][0] == 's') {
            unsigned char *s = malloc(pqc_sig_max_signature_size(sig));
            pqc_status_t st;
            siglen = 0;
            st = s ? pqc_sig_sign_ctx(sig, s, &siglen, msg, msglen,
                                      ctx, ctxlen, key) : PQC_ERROR_ALLOC;
            if (st == PQC_OK && write_file(argv[6], s, siglen) == 0)
                rc = 0;
            else
                fprintf(stderr, "sign failed: %d\n", (int)st);
            free(s);
        } else {
            unsigned char *s = read_file(argv[6], &siglen);
            if (s) {
                pqc_status_t st = pqc_sig_verify_ctx(sig, msg, msglen,
                                                     ctx, ctxlen,
                                                     s, siglen, key);
                rc = (st == PQC_OK) ? 0 : 1;
                free(s);
            }
        }
        free(key);
        free(msg);
    }

    pqc_sig_free(sig);
    return rc;
}
