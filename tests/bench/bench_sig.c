/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Comprehensive digital signature performance benchmarks.
 *
 * Measures keygen, sign, and verify for every enabled signature algorithm
 * with full statistical reporting. Tests multiple message sizes (32B, 256B,
 * 1KB, 64KB). Handles stateful signatures (LMS, XMSS) with limited
 * iterations. Outputs human-readable tables, CSV, or JSON.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"
#include "bench_common.h"

/* -------------------------------------------------------------------------- */
/* Message size configurations                                                 */
/* -------------------------------------------------------------------------- */

typedef struct {
    const char *label;
    size_t      size;
} msg_size_t;

static const msg_size_t g_msg_sizes[] = {
    { "32B",   32      },
    { "256B",  256     },
    { "1KB",   1024    },
    { "64KB",  65536   },
};

#define NUM_MSG_SIZES (sizeof(g_msg_sizes) / sizeof(g_msg_sizes[0]))

/* -------------------------------------------------------------------------- */
/* Fill a buffer with deterministic pseudo-random data                         */
/* -------------------------------------------------------------------------- */

static void fill_test_message(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(i * 137 + 42);
}

/* -------------------------------------------------------------------------- */
/* Benchmark keygen for a single signature algorithm                           */
/* -------------------------------------------------------------------------- */

static void bench_sig_keygen(const char *name, const PQC_SIG *sig,
                              int iters,
                              size_t pk_size, size_t sk_size,
                              size_t max_sig_size) {
    uint8_t *pk = (uint8_t *)calloc(1, pk_size);
    uint8_t *sk = (uint8_t *)calloc(1, sk_size);
    double   *samples = (double *)malloc((size_t)iters * sizeof(double));
    uint64_t *cycles  = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));

    if (!pk || !sk || !samples || !cycles) goto done;

    /* Warmup */
    for (int w = 0; w < BENCH_WARMUP_ITERATIONS && w < iters; w++)
        pqc_sig_keygen(sig, pk, sk);

    for (int i = 0; i < iters; i++) {
        uint64_t c0 = bench_rdtsc();
        double t0 = bench_timer_ms();

        pqc_sig_keygen(sig, pk, sk);

        double t1 = bench_timer_ms();
        uint64_t c1 = bench_rdtsc();

        samples[i] = t1 - t0;
        cycles[i]  = c1 - c0;
    }

    bench_result_t r;
    bench_compute_stats(samples, iters, &r);
    bench_compute_cycles_median(cycles, iters, &r);
    bench_emit_result(name, "keygen", &r,
                      pk_size, sk_size, "max_sig", max_sig_size, NULL, 0);

done:
    free(pk);
    free(sk);
    free(samples);
    free(cycles);
}

/* -------------------------------------------------------------------------- */
/* Benchmark sign + verify at a specific message size                          */
/* -------------------------------------------------------------------------- */

static void bench_sig_sign_verify(const char *name, const PQC_SIG *sig,
                                   int iters, int is_stateful,
                                   size_t pk_size, size_t sk_size,
                                   size_t max_sig_size,
                                   const uint8_t *message, size_t msg_len,
                                   const char *msg_label) {
    uint8_t *pk        = (uint8_t *)calloc(1, pk_size);
    uint8_t *sk        = (uint8_t *)calloc(1, sk_size);
    uint8_t *sk_copy   = (uint8_t *)calloc(1, sk_size);
    uint8_t *signature = (uint8_t *)calloc(1, max_sig_size);
    size_t   sig_len   = 0;

    double   *sign_samples   = (double *)malloc((size_t)iters * sizeof(double));
    double   *verify_samples = (double *)malloc((size_t)iters * sizeof(double));
    uint64_t *sign_cycles    = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
    uint64_t *verify_cycles  = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));

    if (!pk || !sk || !sk_copy || !signature ||
        !sign_samples || !verify_samples ||
        !sign_cycles || !verify_cycles) {
        goto done;
    }

    /* Generate a keypair */
    pqc_sig_keygen(sig, pk, sk);

    /* Warmup (skip for stateful to preserve states) */
    if (!is_stateful) {
        for (int w = 0; w < BENCH_WARMUP_ITERATIONS && w < iters; w++) {
            pqc_sig_sign(sig, signature, &sig_len, message, msg_len, sk);
            pqc_sig_verify(sig, message, msg_len, signature, sig_len, pk);
        }
    }

    /* Sign benchmark */
    for (int i = 0; i < iters; i++) {
        if (is_stateful) {
            /*
             * For stateful schemes, we must use sign_stateful which
             * advances the state. Re-generate keys periodically to
             * avoid state exhaustion.
             */
            if (i % 100 == 0) {
                pqc_sig_keygen(sig, pk, sk);
            }
            memcpy(sk_copy, sk, sk_size);

            uint64_t c0 = bench_rdtsc();
            double t0 = bench_timer_ms();

            pqc_sig_sign_stateful(sig, signature, &sig_len,
                                   message, msg_len, sk_copy);

            double t1 = bench_timer_ms();
            uint64_t c1 = bench_rdtsc();

            sign_samples[i] = t1 - t0;
            sign_cycles[i]  = c1 - c0;

            /* Update sk for subsequent iterations */
            memcpy(sk, sk_copy, sk_size);
        } else {
            uint64_t c0 = bench_rdtsc();
            double t0 = bench_timer_ms();

            pqc_sig_sign(sig, signature, &sig_len, message, msg_len, sk);

            double t1 = bench_timer_ms();
            uint64_t c1 = bench_rdtsc();

            sign_samples[i] = t1 - t0;
            sign_cycles[i]  = c1 - c0;
        }
    }

    /* Generate a valid signature for verify benchmark */
    if (is_stateful) {
        pqc_sig_keygen(sig, pk, sk);
        pqc_sig_sign_stateful(sig, signature, &sig_len, message, msg_len, sk);
    } else {
        pqc_sig_sign(sig, signature, &sig_len, message, msg_len, sk);
    }

    /* Verify benchmark */
    for (int i = 0; i < iters; i++) {
        uint64_t c0 = bench_rdtsc();
        double t0 = bench_timer_ms();

        pqc_sig_verify(sig, message, msg_len, signature, sig_len, pk);

        double t1 = bench_timer_ms();
        uint64_t c1 = bench_rdtsc();

        verify_samples[i] = t1 - t0;
        verify_cycles[i]  = c1 - c0;
    }

    /* Compute and emit results */
    bench_result_t r_sign, r_verify;

    bench_compute_stats(sign_samples, iters, &r_sign);
    bench_compute_cycles_median(sign_cycles, iters, &r_sign);

    bench_compute_stats(verify_samples, iters, &r_verify);
    bench_compute_cycles_median(verify_cycles, iters, &r_verify);

    char sign_op[64], verify_op[64];
    snprintf(sign_op, sizeof(sign_op), "sign(%s)", msg_label);
    snprintf(verify_op, sizeof(verify_op), "verify(%s)", msg_label);

    bench_emit_result(name, sign_op, &r_sign,
                      pk_size, sk_size, "max_sig", max_sig_size, NULL, 0);
    bench_emit_result(name, verify_op, &r_verify,
                      pk_size, sk_size, "max_sig", max_sig_size, NULL, 0);

done:
    free(pk);
    free(sk);
    free(sk_copy);
    free(signature);
    free(sign_samples);
    free(verify_samples);
    free(sign_cycles);
    free(verify_cycles);
}

/* -------------------------------------------------------------------------- */
/* Benchmark a single signature algorithm                                      */
/* -------------------------------------------------------------------------- */

static void bench_sig_algorithm(const char *name) {
    if (!bench_matches_filter(name))
        return;

    PQC_SIG *sig = pqc_sig_new(name);
    if (!sig) {
        fprintf(stderr, "Warning: cannot create signature context for '%s'\n", name);
        return;
    }

    size_t pk_size      = pqc_sig_public_key_size(sig);
    size_t sk_size      = pqc_sig_secret_key_size(sig);
    size_t max_sig_size = pqc_sig_max_signature_size(sig);
    int    is_stateful  = pqc_sig_is_stateful(sig);

    int iters = bench_adjusted_iterations(name, g_bench_config.iterations);

    /* Further reduce for stateful to avoid state exhaustion */
    if (is_stateful && iters > BENCH_SLOW_ITERATIONS)
        iters = BENCH_SLOW_ITERATIONS;

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
        fprintf(f, "\n  %s  (iters=%d%s)\n", name, iters,
                is_stateful ? ", stateful" : "");
        bench_print_table_sizes(f, name,
                                pk_size, "pk", sk_size, "sk",
                                max_sig_size, "max_sig", 0, NULL);
    }

    /* Keygen benchmark */
    bench_sig_keygen(name, sig, iters, pk_size, sk_size, max_sig_size);

    /* Sign/verify at multiple message sizes */
    for (size_t m = 0; m < NUM_MSG_SIZES; m++) {
        uint8_t *msg = (uint8_t *)malloc(g_msg_sizes[m].size);
        if (!msg) continue;
        fill_test_message(msg, g_msg_sizes[m].size);

        bench_sig_sign_verify(name, sig, iters, is_stateful,
                              pk_size, sk_size, max_sig_size,
                              msg, g_msg_sizes[m].size,
                              g_msg_sizes[m].label);
        free(msg);
    }

    pqc_sig_free(sig);
}

/* -------------------------------------------------------------------------- */
/* Run all signature benchmarks                                                */
/* -------------------------------------------------------------------------- */

void bench_sig_run(void) {
    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
    int count = pqc_sig_algorithm_count();

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\n");
        bench_print_table_header(f, "Signature Algorithm / Operation");
    }

    for (int i = 0; i < count; i++) {
        const char *name = pqc_sig_algorithm_name(i);
        bench_sig_algorithm(name);
    }

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\nTotal signature algorithms benchmarked: %d\n", count);
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

    bench_sig_run();

    if (g_bench_config.format == BENCH_FORMAT_JSON)
        bench_print_json_end(f);

    if (g_bench_config.output && g_bench_config.output != stdout)
        fclose(g_bench_config.output);

    pqc_cleanup();
    return 0;
}
