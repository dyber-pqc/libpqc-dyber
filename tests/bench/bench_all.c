/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Master benchmark runner.
 *
 * Runs all benchmarks (KEM, signature, hash) in sequence and produces
 * a combined report. Supports --csv, --json, --kem, --sig, --hash,
 * --algorithm, --iterations, and --output flags.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pqc/pqc.h"
#include "bench_common.h"

/* Forward declarations from individual benchmark files.
 * When building bench_all, we compile it as a standalone translation unit
 * that calls into the run functions. For simplicity, we re-declare
 * them here; the actual implementations are linked from the object files
 * of bench_kem.c, bench_sig.c, bench_hash.c (with main() excluded via
 * the BENCH_NO_MAIN guard, or we duplicate the logic inline).
 *
 * For the monolithic approach, we include the benchmark logic directly.
 */

/* -------------------------------------------------------------------------- */
/* Inline KEM benchmarks (re-implemented to avoid duplicate main symbols)      */
/* -------------------------------------------------------------------------- */

static void run_kem_benchmarks(void) {
    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
    int count = pqc_kem_algorithm_count();

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\n");
        bench_print_table_header(f, "KEM Algorithm / Operation");
    }

    for (int idx = 0; idx < count; idx++) {
        const char *name = pqc_kem_algorithm_name(idx);
        if (!bench_matches_filter(name)) continue;

        PQC_KEM *kem = pqc_kem_new(name);
        if (!kem) continue;

        size_t pk_size = pqc_kem_public_key_size(kem);
        size_t sk_size = pqc_kem_secret_key_size(kem);
        size_t ct_size = pqc_kem_ciphertext_size(kem);
        size_t ss_size = pqc_kem_shared_secret_size(kem);
        int iters = bench_adjusted_iterations(name, g_bench_config.iterations);

        uint8_t *pk = (uint8_t *)calloc(1, pk_size);
        uint8_t *sk = (uint8_t *)calloc(1, sk_size);
        uint8_t *ct = (uint8_t *)calloc(1, ct_size);
        uint8_t *ss = (uint8_t *)calloc(1, ss_size);
        uint8_t *ss2 = (uint8_t *)calloc(1, ss_size);
        double *samples = (double *)malloc(3 * (size_t)iters * sizeof(double));
        uint64_t *cycles = (uint64_t *)malloc(3 * (size_t)iters * sizeof(uint64_t));

        if (!pk || !sk || !ct || !ss || !ss2 || !samples || !cycles) {
            free(pk); free(sk); free(ct); free(ss); free(ss2);
            free(samples); free(cycles);
            pqc_kem_free(kem);
            continue;
        }

        double *kg_s = samples;
        double *en_s = samples + iters;
        double *de_s = samples + 2 * iters;
        uint64_t *kg_c = cycles;
        uint64_t *en_c = cycles + iters;
        uint64_t *de_c = cycles + 2 * iters;

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            fprintf(f, "\n  %s  (iters=%d)\n", name, iters);
            bench_print_table_sizes(f, name, pk_size, "pk", sk_size, "sk",
                                    ct_size, "ct", ss_size, "ss");
        }

        /* Warmup */
        for (int w = 0; w < BENCH_WARMUP_ITERATIONS && w < iters; w++) {
            pqc_kem_keygen(kem, pk, sk);
            pqc_kem_encaps(kem, ct, ss, pk);
            pqc_kem_decaps(kem, ss2, ct, sk);
        }

        /* Keygen */
        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc(); double t0 = bench_timer_ms();
            pqc_kem_keygen(kem, pk, sk);
            double t1 = bench_timer_ms(); uint64_t c1 = bench_rdtsc();
            kg_s[i] = t1 - t0; kg_c[i] = c1 - c0;
        }
        pqc_kem_keygen(kem, pk, sk);

        /* Encaps */
        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc(); double t0 = bench_timer_ms();
            pqc_kem_encaps(kem, ct, ss, pk);
            double t1 = bench_timer_ms(); uint64_t c1 = bench_rdtsc();
            en_s[i] = t1 - t0; en_c[i] = c1 - c0;
        }
        pqc_kem_encaps(kem, ct, ss, pk);

        /* Decaps */
        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc(); double t0 = bench_timer_ms();
            pqc_kem_decaps(kem, ss2, ct, sk);
            double t1 = bench_timer_ms(); uint64_t c1 = bench_rdtsc();
            de_s[i] = t1 - t0; de_c[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(kg_s, iters, &r); bench_compute_cycles_median(kg_c, iters, &r);
        bench_emit_result(name, "keygen", &r, pk_size, sk_size, "ct", ct_size, "ss", ss_size);
        bench_compute_stats(en_s, iters, &r); bench_compute_cycles_median(en_c, iters, &r);
        bench_emit_result(name, "encaps", &r, pk_size, sk_size, "ct", ct_size, "ss", ss_size);
        bench_compute_stats(de_s, iters, &r); bench_compute_cycles_median(de_c, iters, &r);
        bench_emit_result(name, "decaps", &r, pk_size, sk_size, "ct", ct_size, "ss", ss_size);

        free(pk); free(sk); free(ct); free(ss); free(ss2);
        free(samples); free(cycles);
        pqc_kem_free(kem);
    }

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\nKEM benchmarks: %d algorithms\n", count);
}

/* -------------------------------------------------------------------------- */
/* Inline signature benchmarks                                                 */
/* -------------------------------------------------------------------------- */

static void fill_test_msg(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(i * 137 + 42);
}

static void run_sig_benchmarks(void) {
    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
    int count = pqc_sig_algorithm_count();

    static const struct { const char *label; size_t size; } msizes[] = {
        {"32B", 32}, {"256B", 256}, {"1KB", 1024}, {"64KB", 65536}
    };

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\n");
        bench_print_table_header(f, "Signature Algorithm / Operation");
    }

    for (int idx = 0; idx < count; idx++) {
        const char *name = pqc_sig_algorithm_name(idx);
        if (!bench_matches_filter(name)) continue;

        PQC_SIG *sig = pqc_sig_new(name);
        if (!sig) continue;

        size_t pk_size = pqc_sig_public_key_size(sig);
        size_t sk_size = pqc_sig_secret_key_size(sig);
        size_t max_sig_size = pqc_sig_max_signature_size(sig);
        int is_stateful = pqc_sig_is_stateful(sig);
        int iters = bench_adjusted_iterations(name, g_bench_config.iterations);
        if (is_stateful && iters > BENCH_SLOW_ITERATIONS)
            iters = BENCH_SLOW_ITERATIONS;

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            fprintf(f, "\n  %s  (iters=%d%s)\n", name, iters,
                    is_stateful ? ", stateful" : "");
            bench_print_table_sizes(f, name, pk_size, "pk", sk_size, "sk",
                                    max_sig_size, "max_sig", 0, NULL);
        }

        /* Keygen */
        {
            uint8_t *pk = (uint8_t *)calloc(1, pk_size);
            uint8_t *sk = (uint8_t *)calloc(1, sk_size);
            double *s = (double *)malloc((size_t)iters * sizeof(double));
            uint64_t *c = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
            if (pk && sk && s && c) {
                for (int w = 0; w < BENCH_WARMUP_ITERATIONS && w < iters; w++)
                    pqc_sig_keygen(sig, pk, sk);
                for (int i = 0; i < iters; i++) {
                    uint64_t c0 = bench_rdtsc(); double t0 = bench_timer_ms();
                    pqc_sig_keygen(sig, pk, sk);
                    double t1 = bench_timer_ms(); uint64_t c1 = bench_rdtsc();
                    s[i] = t1 - t0; c[i] = c1 - c0;
                }
                bench_result_t r;
                bench_compute_stats(s, iters, &r);
                bench_compute_cycles_median(c, iters, &r);
                bench_emit_result(name, "keygen", &r, pk_size, sk_size,
                                  "max_sig", max_sig_size, NULL, 0);
            }
            free(pk); free(sk); free(s); free(c);
        }

        /* Sign/Verify at each message size */
        for (int m = 0; m < 4; m++) {
            uint8_t *pk = (uint8_t *)calloc(1, pk_size);
            uint8_t *sk = (uint8_t *)calloc(1, sk_size);
            uint8_t *signature = (uint8_t *)calloc(1, max_sig_size);
            uint8_t *msg = (uint8_t *)malloc(msizes[m].size);
            size_t sig_len = 0;

            double *ss = (double *)malloc((size_t)iters * sizeof(double));
            double *vs = (double *)malloc((size_t)iters * sizeof(double));
            uint64_t *sc = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
            uint64_t *vc = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));

            if (!pk || !sk || !signature || !msg || !ss || !vs || !sc || !vc) {
                free(pk); free(sk); free(signature); free(msg);
                free(ss); free(vs); free(sc); free(vc);
                continue;
            }

            fill_test_msg(msg, msizes[m].size);
            pqc_sig_keygen(sig, pk, sk);

            /* Sign */
            for (int i = 0; i < iters; i++) {
                if (is_stateful && i % 100 == 0)
                    pqc_sig_keygen(sig, pk, sk);

                uint64_t c0 = bench_rdtsc(); double t0 = bench_timer_ms();
                if (is_stateful)
                    pqc_sig_sign_stateful(sig, signature, &sig_len, msg, msizes[m].size, sk);
                else
                    pqc_sig_sign(sig, signature, &sig_len, msg, msizes[m].size, sk);
                double t1 = bench_timer_ms(); uint64_t c1 = bench_rdtsc();
                ss[i] = t1 - t0; sc[i] = c1 - c0;
            }

            /* Prepare valid signature for verify */
            if (is_stateful) {
                pqc_sig_keygen(sig, pk, sk);
                pqc_sig_sign_stateful(sig, signature, &sig_len, msg, msizes[m].size, sk);
            } else {
                pqc_sig_sign(sig, signature, &sig_len, msg, msizes[m].size, sk);
            }

            /* Verify */
            for (int i = 0; i < iters; i++) {
                uint64_t c0 = bench_rdtsc(); double t0 = bench_timer_ms();
                pqc_sig_verify(sig, msg, msizes[m].size, signature, sig_len, pk);
                double t1 = bench_timer_ms(); uint64_t c1 = bench_rdtsc();
                vs[i] = t1 - t0; vc[i] = c1 - c0;
            }

            bench_result_t r;
            char op[64];
            snprintf(op, sizeof(op), "sign(%s)", msizes[m].label);
            bench_compute_stats(ss, iters, &r); bench_compute_cycles_median(sc, iters, &r);
            bench_emit_result(name, op, &r, pk_size, sk_size, "max_sig", max_sig_size, NULL, 0);

            snprintf(op, sizeof(op), "verify(%s)", msizes[m].label);
            bench_compute_stats(vs, iters, &r); bench_compute_cycles_median(vc, iters, &r);
            bench_emit_result(name, op, &r, pk_size, sk_size, "max_sig", max_sig_size, NULL, 0);

            free(pk); free(sk); free(signature); free(msg);
            free(ss); free(vs); free(sc); free(vc);
        }

        pqc_sig_free(sig);
    }

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\nSignature benchmarks: %d algorithms\n", count);
}

/* -------------------------------------------------------------------------- */
/* Inline hash benchmarks (simplified)                                         */
/* -------------------------------------------------------------------------- */

/* We include the internal hash headers directly */
#include "../../src/core/common/hash/sha2.h"
#include "../../src/core/common/hash/sha3.h"

typedef void (*hash_oneshot_fn)(uint8_t *, const uint8_t *, size_t);
typedef void (*xof_oneshot_fn)(uint8_t *, size_t, const uint8_t *, size_t);

static void bench_hash_generic(const char *name, hash_oneshot_fn fn,
                                size_t out_len) {
    static const struct { const char *l; size_t s; } sizes[] = {
        {"64B",64},{"256B",256},{"1KB",1024},{"4KB",4096},{"16KB",16384},{"1MB",1048576}
    };

    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) return;

    for (int si = 0; si < 6; si++) {
        size_t sz = sizes[si].s;
        int iters = g_bench_config.iterations;
        if (sz >= 1048576) iters = iters < 100 ? iters : 100;
        else if (sz >= 16384) iters = iters < 500 ? iters : 500;

        uint8_t *buf = (uint8_t *)malloc(sz);
        double *samp = (double *)malloc((size_t)iters * sizeof(double));
        uint64_t *cyc = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
        if (!buf || !samp || !cyc) { free(buf); free(samp); free(cyc); continue; }

        for (size_t i = 0; i < sz; i++) buf[i] = (uint8_t)(i ^ (i >> 8));

        for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++)
            fn(out, buf, sz);

        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc(); double t0 = bench_timer_ms();
            fn(out, buf, sz);
            double t1 = bench_timer_ms(); uint64_t c1 = bench_rdtsc();
            samp[i] = t1 - t0; cyc[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(samp, iters, &r);
        bench_compute_cycles_median(cyc, iters, &r);

        char op[64];
        snprintf(op, sizeof(op), "oneshot(%s)", sizes[si].l);
        bench_emit_result(name, op, &r, 0, 0, "input", sz, NULL, 0);

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
            double mbps = r.mean_ms > 0.0 ? ((double)sz / (1024.0*1024.0)) / (r.mean_ms/1000.0) : 0.0;
            fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
        }

        free(buf); free(samp); free(cyc);
    }
    free(out);
}

static void bench_xof_generic(const char *name, xof_oneshot_fn fn) {
    uint8_t out[32];
    static const struct { const char *l; size_t s; } sizes[] = {
        {"64B",64},{"256B",256},{"1KB",1024},{"4KB",4096},{"16KB",16384},{"1MB",1048576}
    };

    for (int si = 0; si < 6; si++) {
        size_t sz = sizes[si].s;
        int iters = g_bench_config.iterations;
        if (sz >= 1048576) iters = iters < 100 ? iters : 100;
        else if (sz >= 16384) iters = iters < 500 ? iters : 500;

        uint8_t *buf = (uint8_t *)malloc(sz);
        double *samp = (double *)malloc((size_t)iters * sizeof(double));
        uint64_t *cyc = (uint64_t *)malloc((size_t)iters * sizeof(uint64_t));
        if (!buf || !samp || !cyc) { free(buf); free(samp); free(cyc); continue; }

        for (size_t i = 0; i < sz; i++) buf[i] = (uint8_t)(i ^ (i >> 8));

        for (int w = 0; w < BENCH_WARMUP_ITERATIONS; w++)
            fn(out, sizeof(out), buf, sz);

        for (int i = 0; i < iters; i++) {
            uint64_t c0 = bench_rdtsc(); double t0 = bench_timer_ms();
            fn(out, sizeof(out), buf, sz);
            double t1 = bench_timer_ms(); uint64_t c1 = bench_rdtsc();
            samp[i] = t1 - t0; cyc[i] = c1 - c0;
        }

        bench_result_t r;
        bench_compute_stats(samp, iters, &r);
        bench_compute_cycles_median(cyc, iters, &r);

        char op[64];
        snprintf(op, sizeof(op), "oneshot(%s)", sizes[si].l);
        bench_emit_result(name, op, &r, 0, 0, "input", sz, NULL, 0);

        if (g_bench_config.format == BENCH_FORMAT_TABLE) {
            FILE *f = g_bench_config.output ? g_bench_config.output : stdout;
            double mbps = r.mean_ms > 0.0 ? ((double)sz / (1024.0*1024.0)) / (r.mean_ms/1000.0) : 0.0;
            fprintf(f, "    -> Throughput: %.2f MB/s\n", mbps);
        }

        free(buf); free(samp); free(cyc);
    }
}

static void run_hash_benchmarks(void) {
    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\n");
        bench_print_table_header(f, "Hash Algorithm / Operation");
    }

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHA-256\n");
    bench_hash_generic("SHA-256", (hash_oneshot_fn)pqc_sha256, PQC_SHA256_BYTES);

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHA-512\n");
    bench_hash_generic("SHA-512", (hash_oneshot_fn)pqc_sha512, PQC_SHA512_BYTES);

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHA3-256\n");
    bench_hash_generic("SHA3-256", (hash_oneshot_fn)pqc_sha3_256, PQC_SHA3_256_BYTES);

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHA3-512\n");
    bench_hash_generic("SHA3-512", (hash_oneshot_fn)pqc_sha3_512, PQC_SHA3_512_BYTES);

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHAKE-128\n");
    bench_xof_generic("SHAKE-128", (xof_oneshot_fn)pqc_shake128);

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\n  SHAKE-256\n");
    bench_xof_generic("SHAKE-256", (xof_oneshot_fn)pqc_shake256);

    if (g_bench_config.format == BENCH_FORMAT_TABLE)
        fprintf(f, "\nHash benchmarks complete.\n");
}

/* -------------------------------------------------------------------------- */
/* Main entry point                                                            */
/* -------------------------------------------------------------------------- */

int main(int argc, char **argv) {
    bench_parse_args(argc, argv);

    pqc_status_t rc = pqc_init();
    if (rc != PQC_OK) {
        fprintf(stderr, "Fatal: pqc_init() failed: %s\n", pqc_status_string(rc));
        return 1;
    }

    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;

    if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        bench_print_header(f);
    } else if (g_bench_config.format == BENCH_FORMAT_CSV) {
        bench_print_csv_header(f);
    } else if (g_bench_config.format == BENCH_FORMAT_JSON) {
        bench_print_json_start(f);
    }

    if (g_bench_config.run_kem)
        run_kem_benchmarks();

    if (g_bench_config.run_sig)
        run_sig_benchmarks();

    if (g_bench_config.run_hash)
        run_hash_benchmarks();

    if (g_bench_config.format == BENCH_FORMAT_JSON) {
        bench_print_json_end(f);
    } else if (g_bench_config.format == BENCH_FORMAT_TABLE) {
        fprintf(f, "\n================================================================\n");
        fprintf(f, " All benchmarks complete.\n");
        fprintf(f, " Peak RSS: %zu bytes (%.2f MB)\n",
                bench_peak_rss(), (double)bench_peak_rss() / (1024.0 * 1024.0));
        fprintf(f, "================================================================\n");
    }

    if (g_bench_config.output && g_bench_config.output != stdout)
        fclose(g_bench_config.output);

    pqc_cleanup();
    return 0;
}
