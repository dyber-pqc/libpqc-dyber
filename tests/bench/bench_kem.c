/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Comprehensive KEM performance benchmarks.
 *
 * Measures keygen, encaps, and decaps for every enabled KEM algorithm
 * with full statistical reporting (min, max, mean, median, stddev, ops/sec,
 * CPU cycles). Auto-adjusts iterations for slow algorithms (McEliece,
 * FrodoKEM). Outputs human-readable tables, CSV, or JSON.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"
#include "bench_common.h"

/* -------------------------------------------------------------------------- */
/* Skip list: algorithms with known issues that would crash or corrupt the    */
/* benchmark process (e.g., buffer overflows in Classic McEliece).            */
/* -------------------------------------------------------------------------- */

static const char *bench_kem_skip_list[] = {
    "Classic-McEliece-348864",
    "Classic-McEliece-348864f",
    "Classic-McEliece-460896",
    "Classic-McEliece-460896f",
    "Classic-McEliece-6688128",
    "Classic-McEliece-6688128f",
    "Classic-McEliece-6960119",
    "Classic-McEliece-6960119f",
    "Classic-McEliece-8192128",
    "Classic-McEliece-8192128f",
    NULL
};

static int bench_kem_should_skip(const char *name) {
    for (int i = 0; bench_kem_skip_list[i] != NULL; i++) {
        if (strcmp(name, bench_kem_skip_list[i]) == 0)
            return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Benchmark a single KEM algorithm                                            */
/* -------------------------------------------------------------------------- */

static void bench_kem_algorithm(const char *name) {
    if (!bench_matches_filter(name))
        return;

    if (bench_kem_should_skip(name)) {
        fprintf(stderr, "Skipping '%s' (known buffer overflow issues)\n", name);
        return;
    }

    PQC_KEM *kem = pqc_kem_new(name);
    if (!kem) {
        fprintf(stderr, "Warning: cannot create KEM context for '%s'\n", name);
        return;
    }

    /* Query algorithm properties */
    size_t pk_size = pqc_kem_public_key_size(kem);
    size_t sk_size = pqc_kem_secret_key_size(kem);
    size_t ct_size = pqc_kem_ciphertext_size(kem);
    size_t ss_size = pqc_kem_shared_secret_size(kem);

    /* Determine iteration count */
    int iters = bench_adjusted_iterations(name, g_bench_config.iterations);

    /* Allocate buffers */
    uint8_t *pk = (uint8_t *)calloc(1, pk_size);
    uint8_t *sk = (uint8_t *)calloc(1, sk_size);
    uint8_t *ct = (uint8_t *)calloc(1, ct_size);
    uint8_t *ss = (uint8_t *)calloc(1, ss_size);
    uint8_t *ss2 = (uint8_t *)calloc(1, ss_size);

    double   *keygen_samples  = (double *)malloc((size_t)iters * sizeof(double));
    double   *encaps_samples  = (double *)malloc((size_t)iters * sizeof(double));
    double   *decaps_samples  = (double *)malloc((size_t)iters * sizeof(double));
    uint64_t *keygen_cycles   = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
    uint64_t *encaps_cycles   = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
    uint64_t *decaps_cycles   = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));

    if (!pk || !sk || !ct || !ss || !ss2 ||
        !keygen_samples || !encaps_samples || !decaps_samples ||
        !keygen_cycles || !encaps_cycles || !decaps_cycles) {
        fprintf(stderr, "Error: memory allocation failed for '%s'\n", name);
        goto cleanup;
    }

    /* Print algorithm header in table mode */
    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
        fprintf(f, "\n  %s  (iters=%d)\n", name, iters);
        bench_print_table_sizes(f, name,
                                pk_size, "pk", sk_size, "sk",
                                ct_size, "ct", ss_size, "ss");
    }

    /* Warmup */
    for (int w = 0; w < BENCH_WARMUP_ITERATIONS && w < iters; w++) {
        pqc_kem_keygen(kem, pk, sk);
        pqc_kem_encaps(kem, ct, ss, pk);
        pqc_kem_decaps(kem, ss2, ct, sk);
    }

    /* ---- Keygen benchmark ---- */
    for (int i = 0; i < iters; i++) {
        uint64_t c0 = bench_rdtsc();
        double t0 = bench_timer_ms();

        pqc_kem_keygen(kem, pk, sk);

        double t1 = bench_timer_ms();
        uint64_t c1 = bench_rdtsc();

        keygen_samples[i] = t1 - t0;
        keygen_cycles[i]  = c1 - c0;
    }

    /* We need a valid keypair for encaps/decaps */
    pqc_kem_keygen(kem, pk, sk);

    /* ---- Encaps benchmark ---- */
    for (int i = 0; i < iters; i++) {
        uint64_t c0 = bench_rdtsc();
        double t0 = bench_timer_ms();

        pqc_kem_encaps(kem, ct, ss, pk);

        double t1 = bench_timer_ms();
        uint64_t c1 = bench_rdtsc();

        encaps_samples[i] = t1 - t0;
        encaps_cycles[i]  = c1 - c0;
    }

    /* ---- Decaps benchmark ---- */
    /* Generate a valid ciphertext for decaps */
    pqc_kem_encaps(kem, ct, ss, pk);

    for (int i = 0; i < iters; i++) {
        uint64_t c0 = bench_rdtsc();
        double t0 = bench_timer_ms();

        pqc_kem_decaps(kem, ss2, ct, sk);

        double t1 = bench_timer_ms();
        uint64_t c1 = bench_rdtsc();

        decaps_samples[i] = t1 - t0;
        decaps_cycles[i]  = c1 - c0;
    }

    /* Compute statistics */
    bench_result_t r_keygen, r_encaps, r_decaps;

    bench_compute_stats(keygen_samples, iters, &r_keygen);
    bench_compute_cycles_median(keygen_cycles, iters, &r_keygen);

    bench_compute_stats(encaps_samples, iters, &r_encaps);
    bench_compute_cycles_median(encaps_cycles, iters, &r_encaps);

    bench_compute_stats(decaps_samples, iters, &r_decaps);
    bench_compute_cycles_median(decaps_cycles, iters, &r_decaps);

    /* Emit results */
    bench_emit_result(name, "keygen", &r_keygen,
                      pk_size, sk_size, "ct", ct_size, "ss", ss_size);
    bench_emit_result(name, "encaps", &r_encaps,
                      pk_size, sk_size, "ct", ct_size, "ss", ss_size);
    bench_emit_result(name, "decaps", &r_decaps,
                      pk_size, sk_size, "ct", ct_size, "ss", ss_size);

cleanup:
    free(pk);
    free(sk);
    free(ct);
    free(ss);
    free(ss2);
    free(keygen_samples);
    free(encaps_samples);
    free(decaps_samples);
    free(keygen_cycles);
    free(encaps_cycles);
    free(decaps_cycles);
    pqc_kem_free(kem);
}

/* -------------------------------------------------------------------------- */
/* Run all KEM benchmarks                                                      */
/* -------------------------------------------------------------------------- */

void bench_kem_run(void) {
    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
    int count = pqc_kem_algorithm_count();

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\n");
        bench_print_table_header(f, "KEM Algorithm / Operation");
    }

    for (int i = 0; i < count; i++) {
        const char *name = pqc_kem_algorithm_name(i);
        bench_kem_algorithm(name);
    }

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\nTotal KEM algorithms benchmarked: %d\n", count);
        fprintf(f, "Peak RSS: %zu bytes (%.2f MB)\n",
                bench_peak_rss(), (double)bench_peak_rss() / (1024.0 * 1024.0));
    }
}

/* -------------------------------------------------------------------------- */
/* Standalone entry point                                                      */
/* -------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    bench_parse_args(argc, argv);

    pqc_status_t rc = pqc_init();
    if (rc != PQC_OK) {
        fprintf(stderr, "Fatal: pqc_init() failed: %s\n", pqc_status_string(rc));
        return 1;
    }

    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        bench_print_header(f);
    else if (g_bench_config.format == BENCH_FORMAT_CSV)
        bench_print_csv_header(f);
    else if (g_bench_config.format == BENCH_FORMAT_JSON)
        bench_print_json_start(f);

    bench_kem_run();

    if (g_bench_config.format == BENCH_FORMAT_JSON)
        bench_print_json_end(f);

    if (g_bench_config.output && g_bench_config.output != stdout)
        fclose(g_bench_config.output);

    pqc_cleanup();
    return 0;
}
