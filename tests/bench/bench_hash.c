/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Hash primitive benchmarks.
 *
 * Measures throughput (MB/s) for SHA-256, SHA-512, SHA3-256, SHA3-512,
 * SHAKE-128, and SHAKE-256 at various input sizes. Also benchmarks the
 * incremental (init/update/final) API with multiple update calls.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"
#include "bench_common.h"

/* Internal hash headers */
#include "../../src/core/common/hash/sha2.h"
#include "../../src/core/common/hash/sha3.h"

/* -------------------------------------------------------------------------- */
/* Input sizes to benchmark                                                    */
/* -------------------------------------------------------------------------- */

typedef struct {
    const char *label;
    size_t      size;
} input_size_t;

static const input_size_t g_input_sizes[] = {
    { "64B",    64        },
    { "256B",   256       },
    { "1KB",    1024      },
    { "4KB",    4096      },
    { "16KB",   16384     },
    { "1MB",    1048576   },
};

#define NUM_INPUT_SIZES (sizeof(g_input_sizes) / sizeof(g_input_sizes[0]))

/* -------------------------------------------------------------------------- */
/* Iteration count based on input size                                         */
/* -------------------------------------------------------------------------- */

static int hash_iters_for_size(size_t size, int base) {
    if (size >= 1048576) return base < 100 ? base : 100;
    if (size >= 16384)   return base < 500 ? base : 500;
    return base;
}

/* -------------------------------------------------------------------------- */
/* Fill buffer with deterministic data                                         */
/* -------------------------------------------------------------------------- */

static void fill_buffer(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(i ^ (i >> 8));
}

/* -------------------------------------------------------------------------- */
/* SHA-256 one-shot benchmark                                                  */
/* -------------------------------------------------------------------------- */

static void bench_sha256_oneshot(void) {
    uint8_t out[PQC_SHA256_BYTES];

    for (size_t s = 0; s < NUM_INPUT_SIZES; s++) {
        size_t size = g_input_sizes[s].size;
        int iters = hash_iters_for_size(size, g_bench_config.iterations);

        uint8_t *buf = (uint8_t *)malloc(size);
        if (!buf) continue;
        fill_buffer(buf, size);

        double *samples = (double *)malloc((size_t)iters * sizeof(double));
        uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
        if (!samples || !cycles) { free(buf); free(samples); free(cycles); continue; }

        /* Warmup */
        for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++)
            pqc_sha256(out, buf, size);

        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc();
            double t0 = bench_timer_ms();
            pqc_sha256(out, buf, size);
            double t1 = bench_timer_ms();
            uint64_t c1 = bench_rdtsc();
            samples[i] = t1 - t0;
            cycles[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(samples, iters, &r);
        bench_compute_cycles_median(cycles, iters, &r);

        char op[64];
        snprintf(op, sizeof(op), "oneshot(%s)", g_input_sizes[s].label);
        bench_emit_result("SHA-256", op, &r, 0, 0,
                          "input", size, "throughput_mbps",
                          (size_t)(r.mean_ms > 0 ? (double)size / r.mean_ms / 1000.0 * 1000.0 : 0));

        /* Print throughput in table mode */
        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
            double mbps = r.mean_ms > 0.0 ? ((double)size / (1024.0 * 1024.0)) / (r.mean_ms / 1000.0) : 0.0;
            fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
        }

        free(buf);
        free(samples);
        free(cycles);
    }
}

/* -------------------------------------------------------------------------- */
/* SHA-512 one-shot benchmark                                                  */
/* -------------------------------------------------------------------------- */

static void bench_sha512_oneshot(void) {
    uint8_t out[PQC_SHA512_BYTES];

    for (size_t s = 0; s < NUM_INPUT_SIZES; s++) {
        size_t size = g_input_sizes[s].size;
        int iters = hash_iters_for_size(size, g_bench_config.iterations);

        uint8_t *buf = (uint8_t *)malloc(size);
        if (!buf) continue;
        fill_buffer(buf, size);

        double *samples = (double *)malloc((size_t)iters * sizeof(double));
        uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
        if (!samples || !cycles) { free(buf); free(samples); free(cycles); continue; }

        for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++)
            pqc_sha512(out, buf, size);

        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc();
            double t0 = bench_timer_ms();
            pqc_sha512(out, buf, size);
            double t1 = bench_timer_ms();
            uint64_t c1 = bench_rdtsc();
            samples[i] = t1 - t0;
            cycles[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(samples, iters, &r);
        bench_compute_cycles_median(cycles, iters, &r);

        char op[64];
        snprintf(op, sizeof(op), "oneshot(%s)", g_input_sizes[s].label);
        bench_emit_result("SHA-512", op, &r, 0, 0,
                          "input", size, NULL, 0);

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
            double mbps = r.mean_ms > 0.0 ? ((double)size / (1024.0 * 1024.0)) / (r.mean_ms / 1000.0) : 0.0;
            fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
        }

        free(buf);
        free(samples);
        free(cycles);
    }
}

/* -------------------------------------------------------------------------- */
/* SHA3-256 one-shot benchmark                                                 */
/* -------------------------------------------------------------------------- */

static void bench_sha3_256_oneshot(void) {
    uint8_t out[PQC_SHA3_256_BYTES];

    for (size_t s = 0; s < NUM_INPUT_SIZES; s++) {
        size_t size = g_input_sizes[s].size;
        int iters = hash_iters_for_size(size, g_bench_config.iterations);

        uint8_t *buf = (uint8_t *)malloc(size);
        if (!buf) continue;
        fill_buffer(buf, size);

        double *samples = (double *)malloc((size_t)iters * sizeof(double));
        uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
        if (!samples || !cycles) { free(buf); free(samples); free(cycles); continue; }

        for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++)
            pqc_sha3_256(out, buf, size);

        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc();
            double t0 = bench_timer_ms();
            pqc_sha3_256(out, buf, size);
            double t1 = bench_timer_ms();
            uint64_t c1 = bench_rdtsc();
            samples[i] = t1 - t0;
            cycles[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(samples, iters, &r);
        bench_compute_cycles_median(cycles, iters, &r);

        char op[64];
        snprintf(op, sizeof(op), "oneshot(%s)", g_input_sizes[s].label);
        bench_emit_result("SHA3-256", op, &r, 0, 0, "input", size, NULL, 0);

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
            double mbps = r.mean_ms > 0.0 ? ((double)size / (1024.0 * 1024.0)) / (r.mean_ms / 1000.0) : 0.0;
            fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
        }

        free(buf);
        free(samples);
        free(cycles);
    }
}

/* -------------------------------------------------------------------------- */
/* SHA3-512 one-shot benchmark                                                 */
/* -------------------------------------------------------------------------- */

static void bench_sha3_512_oneshot(void) {
    uint8_t out[PQC_SHA3_512_BYTES];

    for (size_t s = 0; s < NUM_INPUT_SIZES; s++) {
        size_t size = g_input_sizes[s].size;
        int iters = hash_iters_for_size(size, g_bench_config.iterations);

        uint8_t *buf = (uint8_t *)malloc(size);
        if (!buf) continue;
        fill_buffer(buf, size);

        double *samples = (double *)malloc((size_t)iters * sizeof(double));
        uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
        if (!samples || !cycles) { free(buf); free(samples); free(cycles); continue; }

        for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++)
            pqc_sha3_512(out, buf, size);

        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc();
            double t0 = bench_timer_ms();
            pqc_sha3_512(out, buf, size);
            double t1 = bench_timer_ms();
            uint64_t c1 = bench_rdtsc();
            samples[i] = t1 - t0;
            cycles[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(samples, iters, &r);
        bench_compute_cycles_median(cycles, iters, &r);

        char op[64];
        snprintf(op, sizeof(op), "oneshot(%s)", g_input_sizes[s].label);
        bench_emit_result("SHA3-512", op, &r, 0, 0, "input", size, NULL, 0);

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
            double mbps = r.mean_ms > 0.0 ? ((double)size / (1024.0 * 1024.0)) / (r.mean_ms / 1000.0) : 0.0;
            fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
        }

        free(buf);
        free(samples);
        free(cycles);
    }
}

/* -------------------------------------------------------------------------- */
/* SHAKE-128 one-shot benchmark                                                */
/* -------------------------------------------------------------------------- */

static void bench_shake128_oneshot(void) {
    uint8_t out[32]; /* 32 bytes of output for benchmarking */

    for (size_t s = 0; s < NUM_INPUT_SIZES; s++) {
        size_t size = g_input_sizes[s].size;
        int iters = hash_iters_for_size(size, g_bench_config.iterations);

        uint8_t *buf = (uint8_t *)malloc(size);
        if (!buf) continue;
        fill_buffer(buf, size);

        double *samples = (double *)malloc((size_t)iters * sizeof(double));
        uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
        if (!samples || !cycles) { free(buf); free(samples); free(cycles); continue; }

        for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++)
            pqc_shake128(out, sizeof(out), buf, size);

        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc();
            double t0 = bench_timer_ms();
            pqc_shake128(out, sizeof(out), buf, size);
            double t1 = bench_timer_ms();
            uint64_t c1 = bench_rdtsc();
            samples[i] = t1 - t0;
            cycles[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(samples, iters, &r);
        bench_compute_cycles_median(cycles, iters, &r);

        char op[64];
        snprintf(op, sizeof(op), "oneshot(%s)", g_input_sizes[s].label);
        bench_emit_result("SHAKE-128", op, &r, 0, 0, "input", size, NULL, 0);

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
            double mbps = r.mean_ms > 0.0 ? ((double)size / (1024.0 * 1024.0)) / (r.mean_ms / 1000.0) : 0.0;
            fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
        }

        free(buf);
        free(samples);
        free(cycles);
    }
}

/* -------------------------------------------------------------------------- */
/* SHAKE-256 one-shot benchmark                                                */
/* -------------------------------------------------------------------------- */

static void bench_shake256_oneshot(void) {
    uint8_t out[32];

    for (size_t s = 0; s < NUM_INPUT_SIZES; s++) {
        size_t size = g_input_sizes[s].size;
        int iters = hash_iters_for_size(size, g_bench_config.iterations);

        uint8_t *buf = (uint8_t *)malloc(size);
        if (!buf) continue;
        fill_buffer(buf, size);

        double *samples = (double *)malloc((size_t)iters * sizeof(double));
        uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
        if (!samples || !cycles) { free(buf); free(samples); free(cycles); continue; }

        for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++)
            pqc_shake256(out, sizeof(out), buf, size);

        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc();
            double t0 = bench_timer_ms();
            pqc_shake256(out, sizeof(out), buf, size);
            double t1 = bench_timer_ms();
            uint64_t c1 = bench_rdtsc();
            samples[i] = t1 - t0;
            cycles[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(samples, iters, &r);
        bench_compute_cycles_median(cycles, iters, &r);

        char op[64];
        snprintf(op, sizeof(op), "oneshot(%s)", g_input_sizes[s].label);
        bench_emit_result("SHAKE-256", op, &r, 0, 0, "input", size, NULL, 0);

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
            double mbps = r.mean_ms > 0.0 ? ((double)size / (1024.0 * 1024.0)) / (r.mean_ms / 1000.0) : 0.0;
            fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
        }

        free(buf);
        free(samples);
        free(cycles);
    }
}

/* -------------------------------------------------------------------------- */
/* SHA-256 incremental API benchmark                                           */
/* -------------------------------------------------------------------------- */

static void bench_sha256_incremental(void) {
    /* Benchmark: 4KB total, fed in 64-byte chunks via update */
    const size_t total = 4096;
    const size_t chunk = 64;
    int iters = g_bench_config.iterations;

    uint8_t *buf = (uint8_t *)malloc(total);
    uint8_t out[PQC_SHA256_BYTES];
    if (!buf) return;
    fill_buffer(buf, total);

    double *samples = (double *)malloc((size_t)iters * sizeof(double));
    uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
    if (!samples || !cycles) { free(buf); free(samples); free(cycles); return; }

    for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++) {
        pqc_sha256_ctx ctx;
        pqc_sha256_init(&ctx);
        for (size_t off = 0; off < total; off += chunk)
            pqc_sha256_update(&ctx, buf + off, chunk);
        pqc_sha256_final(&ctx, out);
    }

    for (int i = 0; i < iters; i++) {
        uint64_t c0 = bench_rdtsc();
        double t0 = bench_timer_ms();

        pqc_sha256_ctx ctx;
        pqc_sha256_init(&ctx);
        for (size_t off = 0; off < total; off += chunk)
            pqc_sha256_update(&ctx, buf + off, chunk);
        pqc_sha256_final(&ctx, out);

        double t1 = bench_timer_ms();
        uint64_t c1 = bench_rdtsc();
        samples[i] = t1 - t0;
        cycles[i] = c1 - c0;
    }

    bench_result_t r;
    bench_compute_stats(samples, iters, &r);
    bench_compute_cycles_median(cycles, iters, &r);
    bench_emit_result("SHA-256", "incremental(4KB/64B chunks)", &r,
                      0, 0, "input", total, NULL, 0);

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
        double mbps = r.mean_ms > 0.0 ? ((double)total / (1024.0 * 1024.0)) / (r.mean_ms / 1000.0) : 0.0;
        fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
    }

    free(buf);
    free(samples);
    free(cycles);
}

/* -------------------------------------------------------------------------- */
/* SHA-512 incremental API benchmark                                           */
/* -------------------------------------------------------------------------- */

static void bench_sha512_incremental(void) {
    const size_t total = 4096;
    const size_t chunk = 128;
    int iters = g_bench_config.iterations;

    uint8_t *buf = (uint8_t *)malloc(total);
    uint8_t out[PQC_SHA512_BYTES];
    if (!buf) return;
    fill_buffer(buf, total);

    double *samples = (double *)malloc((size_t)iters * sizeof(double));
    uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
    if (!samples || !cycles) { free(buf); free(samples); free(cycles); return; }

    for (int i = 0; i < iters; i++) {
        uint64_t c0 = bench_rdtsc();
        double t0 = bench_timer_ms();

        pqc_sha512_ctx ctx;
        pqc_sha512_init(&ctx);
        for (size_t off = 0; off < total; off += chunk)
            pqc_sha512_update(&ctx, buf + off, chunk);
        pqc_sha512_final(&ctx, out);

        double t1 = bench_timer_ms();
        uint64_t c1 = bench_rdtsc();
        samples[i] = t1 - t0;
        cycles[i] = c1 - c0;
    }

    bench_result_t r;
    bench_compute_stats(samples, iters, &r);
    bench_compute_cycles_median(cycles, iters, &r);
    bench_emit_result("SHA-512", "incremental(4KB/128B chunks)", &r,
                      0, 0, "input", total, NULL, 0);

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
        double mbps = r.mean_ms > 0.0 ? ((double)total / (1024.0 * 1024.0)) / (r.mean_ms / 1000.0) : 0.0;
        fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
    }

    free(buf);
    free(samples);
    free(cycles);
}

/* -------------------------------------------------------------------------- */
/* SHAKE-256 incremental API benchmark (absorb/squeeze)                        */
/* -------------------------------------------------------------------------- */

static void bench_shake256_incremental(void) {
    const size_t total = 4096;
    const size_t chunk = 136;  /* SHAKE-256 rate */
    const size_t squeeze_len = 256;
    int iters = g_bench_config.iterations;

    uint8_t *buf = (uint8_t *)malloc(total);
    uint8_t *out = (uint8_t *)malloc(squeeze_len);
    if (!buf || !out) { free(buf); free(out); return; }
    fill_buffer(buf, total);

    double *samples = (double *)malloc((size_t)iters * sizeof(double));
    uint64_t *cycles = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
    if (!samples || !cycles) { free(buf); free(out); free(samples); free(cycles); return; }

    for (int i = 0; i < iters; i++) {
        uint64_t c0 = bench_rdtsc();
        double t0 = bench_timer_ms();

        pqc_shake256_ctx ctx;
        pqc_shake256_init(&ctx);
        for (size_t off = 0; off < total; off += chunk) {
            size_t n = (off + chunk <= total) ? chunk : (total - off);
            pqc_shake256_absorb(&ctx, buf + off, n);
        }
        pqc_shake256_finalize(&ctx);
        pqc_shake256_squeeze(&ctx, out, squeeze_len);

        double t1 = bench_timer_ms();
        uint64_t c1 = bench_rdtsc();
        samples[i] = t1 - t0;
        cycles[i] = c1 - c0;
    }

    bench_result_t r;
    bench_compute_stats(samples, iters, &r);
    bench_compute_cycles_median(cycles, iters, &r);
    bench_emit_result("SHAKE-256", "incremental(4KB absorb + 256B squeeze)", &r,
                      0, 0, "input", total, NULL, 0);

    free(buf);
    free(out);
    free(samples);
    free(cycles);
}

/* -------------------------------------------------------------------------- */
/* Run all hash benchmarks                                                     */
/* -------------------------------------------------------------------------- */

void bench_hash_run(void) {
    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\n");
        bench_print_table_header(f, "Hash Algorithm / Operation");

        fprintf(f, "\n  SHA-256\n");
    }
    bench_sha256_oneshot();
    bench_sha256_incremental();

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHA-512\n");
    bench_sha512_oneshot();
    bench_sha512_incremental();

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHA3-256\n");
    bench_sha3_256_oneshot();

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHA3-512\n");
    bench_sha3_512_oneshot();

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHAKE-128\n");
    bench_shake128_oneshot();

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHAKE-256\n");
    bench_shake256_oneshot();
    bench_shake256_incremental();

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\nHash benchmarks complete.\n");
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

    bench_hash_run();

    if (g_bench_config.format == BENCH_FORMAT_JSON)
        bench_print_json_end(f);

    if (g_bench_config.output && g_bench_config.output != stdout)
        fclose(g_bench_config.output);

    pqc_cleanup();
    return 0;
}
