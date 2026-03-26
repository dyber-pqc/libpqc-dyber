/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Signature performance benchmarks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pqc/pqc.h"

#define BENCH_ITERATIONS 100

static const uint8_t bench_msg[] = "Benchmark message for libpqc-dyber signature performance testing";

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void bench_sig(const char *name) {
    PQC_SIG *sig = pqc_sig_new(name);
    if (!sig) return;

    size_t pk_len = pqc_sig_public_key_size(sig);
    size_t sk_len = pqc_sig_secret_key_size(sig);
    size_t max_sig_len = pqc_sig_max_signature_size(sig);

    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *signature = calloc(1, max_sig_len);
    size_t sig_len;

    if (!pk || !sk || !signature) goto done;

    double t_keygen = 0, t_sign = 0, t_verify = 0;

    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        double t0 = get_time_ms();
        pqc_sig_keygen(sig, pk, sk);
        double t1 = get_time_ms();
        pqc_sig_sign(sig, signature, &sig_len, bench_msg, sizeof(bench_msg), sk);
        double t2 = get_time_ms();
        pqc_sig_verify(sig, bench_msg, sizeof(bench_msg), signature, sig_len, pk);
        double t3 = get_time_ms();

        t_keygen += (t1 - t0);
        t_sign += (t2 - t1);
        t_verify += (t3 - t2);
    }

    printf("%-30s  keygen: %8.3f ms  sign: %8.3f ms  verify: %8.3f ms\n",
           name,
           t_keygen / BENCH_ITERATIONS,
           t_sign / BENCH_ITERATIONS,
           t_verify / BENCH_ITERATIONS);

done:
    free(pk); free(sk); free(signature);
    pqc_sig_free(sig);
}

int main(void) {
    pqc_init();

    printf("libpqc-dyber Signature Benchmarks (%d iterations)\n", BENCH_ITERATIONS);
    printf("==================================================\n\n");

    for (int i = 0; i < pqc_sig_algorithm_count(); i++) {
        bench_sig(pqc_sig_algorithm_name(i));
    }

    pqc_cleanup();
    return 0;
}
