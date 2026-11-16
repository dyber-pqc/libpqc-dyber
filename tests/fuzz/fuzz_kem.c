/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * libFuzzer target: KEM decapsulation and encapsulation on untrusted input.
 *
 * Decapsulation takes an attacker's ciphertext; encapsulation parses the
 * recipient's public key, which may come from anywhere. Both must handle
 * every input without memory errors, undefined behaviour or hangs, and
 * decapsulation must not fail on a malformed ciphertext (it implicitly
 * rejects instead).
 *
 * Input layout:  [alg] [mode] [payload...]
 *   alg   selects an enabled KEM (modulo the count)
 *   mode  0: payload, repeated to the ciphertext size, is decapsulated
 *         1: payload is XORed over a valid ciphertext and decapsulated
 *         2: payload, repeated to the public-key size, is encapsulated to
 *
 * Valid keys are made on first use of each algorithm with a deterministic
 * RNG. Algorithms whose key generation fails or is too slow
 * (fuzz_common.h) are fuzzed in mode 2 only.
 */
#include "fuzz_common.h"

#define MAX_ALGS 128

typedef struct {
    const char *name;
    PQC_KEM *kem;
    uint8_t *pk, *sk, *ct;
    size_t pk_len, sk_len, ct_len, ss_len;
    int state;              /* 0 = untried, 1 = have keys, -1 = none */
} alg_t;

static alg_t algs[MAX_ALGS];
static int n_algs;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    int i;
    (void)argc; (void)argv;
    pqc_init();
    pqc_set_rng(fuzz_rng, NULL);
    for (i = 0; i < pqc_kem_algorithm_count() && n_algs < MAX_ALGS; i++) {
        const char *name = pqc_kem_algorithm_name(i);
        PQC_KEM *kem;
        if (!name || !pqc_kem_is_enabled(name)) continue;
        kem = pqc_kem_new(name);
        if (!kem) continue;
        algs[n_algs].name = name;
        algs[n_algs].kem = kem;
        algs[n_algs].pk_len = pqc_kem_public_key_size(kem);
        algs[n_algs].sk_len = pqc_kem_secret_key_size(kem);
        algs[n_algs].ct_len = pqc_kem_ciphertext_size(kem);
        algs[n_algs].ss_len = pqc_kem_shared_secret_size(kem);
        n_algs++;
    }
    return 0;
}

static int have_keys(alg_t *a, uint32_t idx)
{
    uint8_t *ss;
    int ok;

    if (a->state) return a->state > 0;
    a->state = -1;
    if (fuzz_keygen_too_slow(a->name)) return 0;

    fuzz_reseed(idx);
    a->pk = (uint8_t *)malloc(a->pk_len);
    a->sk = (uint8_t *)malloc(a->sk_len);
    a->ct = (uint8_t *)malloc(a->ct_len);
    ss = (uint8_t *)malloc(a->ss_len);
    if (!a->pk || !a->sk || !a->ct || !ss) abort();
    ok = pqc_kem_keygen(a->kem, a->pk, a->sk) == PQC_OK &&
         pqc_kem_encaps(a->kem, a->ct, ss, a->pk) == PQC_OK;
    free(ss);
    if (!ok) return 0;
    a->state = 1;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    alg_t *a;
    uint32_t idx;
    int mode;
    uint8_t *buf, *ss;

    if (size < 2 || n_algs == 0) return 0;
    idx = data[0] % (uint32_t)n_algs;
    mode = data[1] % 3;
    data += 2; size -= 2;
    a = &algs[idx];

    if (mode != 2 && !have_keys(a, idx))
        mode = 2;

    ss = (uint8_t *)malloc(a->ss_len);
    if (!ss) abort();

    switch (mode) {
    case 0:
        buf = fuzz_fill(a->ct_len, data, size);
        (void)pqc_kem_decaps(a->kem, ss, buf, a->sk);
        free(buf);
        break;

    case 1: {
        size_t i;
        buf = fuzz_fill(a->ct_len, a->ct, a->ct_len);
        for (i = 0; i < size; i++)
            buf[i % a->ct_len] ^= data[i];
        (void)pqc_kem_decaps(a->kem, ss, buf, a->sk);
        free(buf);
        break;
    }

    case 2: {
        uint8_t *ct = (uint8_t *)malloc(a->ct_len);
        if (!ct) abort();
        buf = fuzz_fill(a->pk_len, data, size);
        fuzz_reseed(idx ^ 0x5A5A5A5Au);
        (void)pqc_kem_encaps(a->kem, ct, ss, buf);
        free(ct);
        free(buf);
        break;
    }
    }
    free(ss);
    return 0;
}
