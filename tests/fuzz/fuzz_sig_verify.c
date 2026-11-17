/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * libFuzzer target: signature verification on untrusted input.
 *
 * Verification is where a signature scheme meets attacker-controlled
 * bytes: the signature, the message, the context string, and often the
 * public key. It must reject or accept every input without reading or
 * writing out of bounds, hitting undefined behaviour, or hanging.
 *
 * Input layout:  [alg] [mode] [payload...]
 *   alg   selects an enabled signature algorithm (modulo the count)
 *   mode  0: payload is the signature, verified against a valid key
 *         1: payload is public key || signature (attacker-chosen key)
 *         2: payload is XORed over a valid signature, so mutations get
 *            past the length and format checks into the arithmetic
 *         3: a valid signature, with the payload as the context string
 *            (up to 300 bytes, so lengths over the 255-byte limit occur)
 *         4: payload is a valid signature truncated or extended to a
 *            fuzzed length
 *
 * Valid keys and signatures are made on first use of each algorithm with
 * a deterministic RNG. Algorithms whose key generation fails or is too
 * slow (fuzz_common.h) are fuzzed in mode 1 only.
 */
#include "fuzz_common.h"

#define MAX_ALGS 128

static const uint8_t MSG[] = "libpqc-dyber fuzz message";

typedef struct {
    const char *name;
    PQC_SIG *sig;
    uint8_t *pk, *sk, *s;
    size_t pk_len, s_max, s_len;
    int state;              /* 0 = untried, 1 = have keys, -1 = none */
} alg_t;

static alg_t algs[MAX_ALGS];
static int n_algs;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int i;
    (void)argc; (void)argv;
    pqc_init();
    /* Also exercise the algorithms that are hidden by default as
     * experimental (known not to work): bounds and memory safety
     * still matter for them. */
    pqc_set_experimental(1);
    pqc_set_rng(fuzz_rng, NULL);
    for (i = 0; i < pqc_sig_algorithm_count() && n_algs < MAX_ALGS; i++) {
        const char *name = pqc_sig_algorithm_name(i);
        PQC_SIG *sig;
        if (!name || !pqc_sig_is_enabled(name)) continue;
        sig = pqc_sig_new(name);
        if (!sig) continue;
        algs[n_algs].name = name;
        algs[n_algs].sig = sig;
        algs[n_algs].pk_len = pqc_sig_public_key_size(sig);
        algs[n_algs].s_max = pqc_sig_max_signature_size(sig);
        n_algs++;
    }
    return 0;
}

static int have_keys(alg_t *a, uint32_t idx)
{
    pqc_status_t rc;
    size_t sk_len;

    if (a->state) return a->state > 0;
    a->state = -1;
    if (fuzz_keygen_too_slow(a->name)) return 0;

    fuzz_reseed(idx);
    sk_len = pqc_sig_secret_key_size(a->sig);
    a->pk = (uint8_t *)malloc(a->pk_len);
    a->sk = (uint8_t *)malloc(sk_len);
    a->s  = (uint8_t *)malloc(a->s_max);
    if (!a->pk || !a->sk || !a->s) abort();
    if (pqc_sig_keygen(a->sig, a->pk, a->sk) != PQC_OK) return 0;
    if (pqc_sig_is_stateful(a->sig))
        rc = pqc_sig_sign_stateful(a->sig, a->s, &a->s_len, MSG, sizeof MSG, a->sk);
    else
        rc = pqc_sig_sign(a->sig, a->s, &a->s_len, MSG, sizeof MSG, a->sk);
    if (rc != PQC_OK || a->s_len == 0 || a->s_len > a->s_max) return 0;
    a->state = 1;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    alg_t *a;
    uint32_t idx;
    int mode;
    uint8_t *buf;

    if (size < 2 || n_algs == 0) return 0;
    idx = data[0] % (uint32_t)n_algs;
    mode = data[1] % 5;
    data += 2; size -= 2;
    a = &algs[idx];

    if (mode != 1 && !have_keys(a, idx))
        mode = 1;

    switch (mode) {
    case 0:
        buf = fuzz_fill(size, data, size);
        (void)pqc_sig_verify(a->sig, MSG, sizeof MSG, buf, size, a->pk);
        free(buf);
        break;

    case 1: {
        size_t pk_part = size < a->pk_len ? size : a->pk_len;
        uint8_t *pk = fuzz_fill(a->pk_len, data, pk_part);
        size_t s_len = size - pk_part;
        buf = fuzz_fill(s_len, data + pk_part, s_len);
        (void)pqc_sig_verify(a->sig, MSG, sizeof MSG, buf, s_len, pk);
        free(pk);
        free(buf);
        break;
    }

    case 2: {
        size_t i;
        buf = fuzz_fill(a->s_len, a->s, a->s_len);
        for (i = 0; i < size; i++)
            buf[i % a->s_len] ^= data[i];
        (void)pqc_sig_verify(a->sig, MSG, sizeof MSG, buf, a->s_len, a->pk);
        free(buf);
        break;
    }

    case 3: {
        size_t ctx_len = size > 300 ? 300 : size;
        uint8_t *ctx = fuzz_fill(ctx_len, data, ctx_len);
        buf = fuzz_fill(a->s_len, a->s, a->s_len);
        (void)pqc_sig_verify_ctx(a->sig, MSG, sizeof MSG, ctx, ctx_len,
                                 buf, a->s_len, a->pk);
        free(ctx);
        free(buf);
        break;
    }

    case 4: {
        /* Length in [0, 2 * s_len]; the bytes stay those of a valid
         * signature (zero beyond its end). */
        size_t want = 0, i;
        for (i = 0; i < size && i < 4; i++)
            want = (want << 8) | data[i];
        want %= 2 * a->s_len + 1;
        buf = (uint8_t *)calloc(want ? want : 1, 1);
        if (!buf) abort();
        memcpy(buf, a->s, want < a->s_len ? want : a->s_len);
        (void)pqc_sig_verify(a->sig, MSG, sizeof MSG, buf, want, a->pk);
        free(buf);
        break;
    }
    }
    return 0;
}
