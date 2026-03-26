/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * KEM performance benchmarks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pqc/pqc.h"

#define BENCH_ITERATIONS 100

static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void bench_kem(const char *name) {
    PQC_KEM *kem = pqc_kem_new(name);
    if (!kem) return;

    size_t pk_len = pqc_kem_public_key_size(kem);
    size_t sk_len = pqc_kem_secret_key_size(kem);
    size_t ct_len = pqc_kem_ciphertext_size(kem);
    size_t ss_len = pqc_kem_shared_secret_size(kem);

    uint8_t *pk = calloc(1, pk_len);
    uint8_t *sk = calloc(1, sk_len);
    uint8_t *ct = calloc(1, ct_len);
    uint8_t *ss = calloc(1, ss_len);

    if (!pk || !sk || !ct || !ss) goto done;

    double t_keygen = 0, t_encaps = 0, t_decaps = 0;

    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        double t0 = get_time_ms();
        pqc_kem_keygen(kem, pk, sk);
        double t1 = get_time_ms();
        pqc_kem_encaps(kem, ct, ss, pk);
        double t2 = get_time_ms();
        pqc_kem_decaps(kem, ss, ct, sk);
        double t3 = get_time_ms();

        t_keygen += (t1 - t0);
        t_encaps += (t2 - t1);
        t_decaps += (t3 - t2);
    }

    printf("%-30s  keygen: %8.3f ms  encaps: %8.3f ms  decaps: %8.3f ms\n",
           name,
           t_keygen / BENCH_ITERATIONS,
           t_encaps / BENCH_ITERATIONS,
           t_decaps / BENCH_ITERATIONS);

done:
    free(pk); free(sk); free(ct); free(ss);
    pqc_kem_free(kem);
}

int main(void) {
    pqc_init();

    printf("libpqc-dyber KEM Benchmarks (%d iterations)\n", BENCH_ITERATIONS);
    printf("=============================================\n\n");

    for (int i = 0; i < pqc_kem_algorithm_count(); i++) {
        bench_kem(pqc_kem_algorithm_name(i));
    }

    pqc_cleanup();
    return 0;
}
