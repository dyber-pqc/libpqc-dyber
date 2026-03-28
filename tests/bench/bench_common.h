/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Shared benchmark utilities: portable timing, statistics, and output
 * formatting for all libpqc-dyber performance benchmarks.
 */

#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <float.h>
#include <math.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Platform-specific includes                                                  */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <psapi.h>
    #pragma comment(lib, "psapi.lib")
#elif defined(__APPLE__)
    #include <mach/mach.h>
    #include <mach/mach_time.h>
    #include <sys/resource.h>
    #include <time.h>
#else /* Linux / POSIX */
    #include <sys/resource.h>
    #include <time.h>
#endif

/* -------------------------------------------------------------------------- */
/* CPU cycle counter (optional, x86/x64 only)                                  */
/* -------------------------------------------------------------------------- */

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #define BENCH_HAVE_RDTSC 1
    #if defined(_MSC_VER)
        #include <intrin.h>
        static inline uint64_t bench_rdtsc(void) { return __rdtsc(); }
    #else
        static inline uint64_t bench_rdtsc(void) {
            uint32_t lo, hi;
            __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
            return ((uint64_t)hi << 32) | lo;
        }
    #endif
#else
    #define BENCH_HAVE_RDTSC 0
    static inline uint64_t bench_rdtsc(void) { return 0; }
#endif

/* -------------------------------------------------------------------------- */
/* Configuration defaults                                                      */
/* -------------------------------------------------------------------------- */

#define BENCH_DEFAULT_ITERATIONS    1000
#define BENCH_SLOW_ITERATIONS       10
#define BENCH_VERY_SLOW_ITERATIONS  3
#define BENCH_MAX_SAMPLES           100000
#define BENCH_WARMUP_ITERATIONS     5

/* -------------------------------------------------------------------------- */
/* Output format flags                                                         */
/* -------------------------------------------------------------------------- */

typedef enum {
    BENCH_FORMAT_TABLE = 0,
    BENCH_FORMAT_CSV   = 1,
    BENCH_FORMAT_JSON  = 2,
} bench_format_t;

/* -------------------------------------------------------------------------- */
/* Result structure                                                            */
/* -------------------------------------------------------------------------- */

typedef struct {
    double  min_ms;
    double  max_ms;
    double  mean_ms;
    double  median_ms;
    double  stddev_ms;
    double  ops_per_sec;
    uint64_t cycles_median;
    int     iterations;
} bench_result_t;

/* -------------------------------------------------------------------------- */
/* Global configuration                                                        */
/* -------------------------------------------------------------------------- */

typedef struct {
    int           iterations;
    bench_format_t format;
    const char   *filter_algorithm;
    int           run_kem;
    int           run_sig;
    int           run_hash;
    FILE         *output;
    int           json_first_entry;
} bench_config_t;

static bench_config_t g_bench_config = {
    .iterations       = BENCH_DEFAULT_ITERATIONS,
    .format           = BENCH_FORMAT_TABLE,
    .filter_algorithm = NULL,
    .run_kem          = 1,
    .run_sig          = 1,
    .run_hash         = 1,
    .output           = NULL,
    .json_first_entry = 1,
};

/* -------------------------------------------------------------------------- */
/* Portable high-resolution timer (milliseconds)                               */
/* -------------------------------------------------------------------------- */

static inline double bench_timer_ms(void) {
#if defined(_WIN32)
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER count;
    if (freq.QuadPart == 0)
        QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart * 1000.0;
#elif defined(__APPLE__)
    static mach_timebase_info_data_t info = {0};
    if (info.denom == 0)
        mach_timebase_info(&info);
    uint64_t now = mach_absolute_time();
    return (double)(now * info.numer) / (double)(info.denom * 1000000ULL);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1.0e6;
#endif
}

/* -------------------------------------------------------------------------- */
/* Peak resident set size (bytes), 0 if unavailable                            */
/* -------------------------------------------------------------------------- */

static inline size_t bench_peak_rss(void) {
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        return (size_t)pmc.PeakWorkingSetSize;
    return 0;
#elif defined(__APPLE__)
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0)
        return (size_t)ru.ru_maxrss; /* bytes on macOS */
    return 0;
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0)
        return (size_t)ru.ru_maxrss * 1024; /* kilobytes on Linux */
    return 0;
#endif
}

/* -------------------------------------------------------------------------- */
/* Comparison function for qsort (double)                                      */
/* -------------------------------------------------------------------------- */

static int bench_compare_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return  1;
    return 0;
}

static int bench_compare_uint64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return  1;
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Compute statistics from sample array                                        */
/* -------------------------------------------------------------------------- */

static void bench_compute_stats(double *samples, int n, bench_result_t *result) {
    if (n <= 0) {
        memset(result, 0, sizeof(*result));
        return;
    }

    result->iterations = n;

    /* Sort for min/max/median */
    qsort(samples, (size_t)n, sizeof(double), bench_compare_double);

    result->min_ms = samples[0];
    result->max_ms = samples[n - 1];

    /* Median */
    if (n % 2 == 0)
        result->median_ms = (samples[n / 2 - 1] + samples[n / 2]) / 2.0;
    else
        result->median_ms = samples[n / 2];

    /* Mean */
    double sum = 0.0;
    for (int i = 0; i < n; i++)
        sum += samples[i];
    result->mean_ms = sum / (double)n;

    /* Standard deviation */
    double var = 0.0;
    for (int i = 0; i < n; i++) {
        double d = samples[i] - result->mean_ms;
        var += d * d;
    }
    result->stddev_ms = (n > 1) ? sqrt(var / (double)(n - 1)) : 0.0;

    /* Operations per second */
    if (result->mean_ms > 0.0)
        result->ops_per_sec = 1000.0 / result->mean_ms;
    else
        result->ops_per_sec = 0.0;
}

static void bench_compute_cycles_median(uint64_t *cycle_samples, int n,
                                         bench_result_t *result) {
    if (n <= 0 || !BENCH_HAVE_RDTSC) {
        result->cycles_median = 0;
        return;
    }
    qsort(cycle_samples, (size_t)n, sizeof(uint64_t), bench_compare_uint64);
    if (n % 2 == 0)
        result->cycles_median = (cycle_samples[n / 2 - 1] + cycle_samples[n / 2]) / 2;
    else
        result->cycles_median = cycle_samples[n / 2];
}

/* -------------------------------------------------------------------------- */
/* Slow algorithm detection                                                    */
/* -------------------------------------------------------------------------- */

static int bench_is_slow_algorithm(const char *name) {
    if (!name) return 0;
    if (strstr(name, "McEliece"))    return 2; /* very slow */
    if (strstr(name, "Frodo"))       return 1; /* slow */
    if (strstr(name, "XMSS"))        return 2; /* stateful, very slow keygen */
    if (strstr(name, "LMS"))         return 2; /* stateful */
    if (strstr(name, "SLH-DSA") && strstr(name, "256"))  return 1;
    if (strstr(name, "SPHINCS+") && strstr(name, "256")) return 1;
    return 0;
}

static int bench_adjusted_iterations(const char *name, int base) {
    int slow = bench_is_slow_algorithm(name);
    if (slow == 2) return (base < BENCH_VERY_SLOW_ITERATIONS) ? base : BENCH_VERY_SLOW_ITERATIONS;
    if (slow == 1) return (base < BENCH_SLOW_ITERATIONS) ? base : BENCH_SLOW_ITERATIONS;
    return base;
}

/* -------------------------------------------------------------------------- */
/* Algorithm name matches filter                                               */
/* -------------------------------------------------------------------------- */

static int bench_matches_filter(const char *name) {
    if (!g_bench_config.filter_algorithm) return 1;
    /* Case-insensitive substring match */
    const char *f = g_bench_config.filter_algorithm;
    const char *n = name;
    size_t flen = strlen(f);
    size_t nlen = strlen(n);
    if (flen > nlen) return 0;
    for (size_t i = 0; i <= nlen - flen; i++) {
        size_t j;
        for (j = 0; j < flen; j++) {
            char a = n[i + j];
            char b = f[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) break;
        }
        if (j == flen) return 1;
    }
    return 0;
}

/* -------------------------------------------------------------------------- */
/* Output: Human-readable table                                                */
/* -------------------------------------------------------------------------- */

static void bench_print_table_header(FILE *f, const char *title) {
    fprintf(f, "\n%-36s %10s %10s %10s %10s %10s %12s",
            title, "Min(ms)", "Max(ms)", "Mean(ms)", "Median(ms)",
            "StdDev(ms)", "Ops/sec");
#if BENCH_HAVE_RDTSC
    fprintf(f, " %14s", "Cycles(med)");
#endif
    fprintf(f, "\n");
    for (int i = 0; i < 120; i++) fputc('-', f);
    fprintf(f, "\n");
}

static void bench_print_table_row(FILE *f, const char *label,
                                   const bench_result_t *r) {
    fprintf(f, "%-36s %10.3f %10.3f %10.3f %10.3f %10.3f %12.1f",
            label, r->min_ms, r->max_ms, r->mean_ms, r->median_ms,
            r->stddev_ms, r->ops_per_sec);
#if BENCH_HAVE_RDTSC
    if (r->cycles_median > 0)
        fprintf(f, " %14llu", (unsigned long long)r->cycles_median);
    else
        fprintf(f, " %14s", "N/A");
#endif
    fprintf(f, "\n");
}

static void bench_print_table_sizes(FILE *f, const char *label,
                                     size_t s1, const char *n1,
                                     size_t s2, const char *n2,
                                     size_t s3, const char *n3,
                                     size_t s4, const char *n4) {
    (void)label;
    fprintf(f, "  Sizes: %s=%zu", n1, s1);
    if (n2) fprintf(f, ", %s=%zu", n2, s2);
    if (n3) fprintf(f, ", %s=%zu", n3, s3);
    if (n4) fprintf(f, ", %s=%zu", n4, s4);
    fprintf(f, " bytes\n");
}

/* -------------------------------------------------------------------------- */
/* Output: CSV                                                                 */
/* -------------------------------------------------------------------------- */

static void bench_print_csv_header(FILE *f) {
    fprintf(f, "algorithm,operation,iterations,min_ms,max_ms,mean_ms,median_ms,"
               "stddev_ms,ops_per_sec,cycles_median,"
               "pk_bytes,sk_bytes,extra1_name,extra1_bytes,extra2_name,extra2_bytes\n");
}

static void bench_print_csv_row(FILE *f, const char *algorithm,
                                 const char *operation,
                                 const bench_result_t *r,
                                 size_t pk_bytes, size_t sk_bytes,
                                 const char *extra1_name, size_t extra1_bytes,
                                 const char *extra2_name, size_t extra2_bytes) {
    fprintf(f, "%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%llu,"
               "%zu,%zu,%s,%zu,%s,%zu\n",
            algorithm, operation, r->iterations,
            r->min_ms, r->max_ms, r->mean_ms, r->median_ms,
            r->stddev_ms, r->ops_per_sec,
            (unsigned long long)r->cycles_median,
            pk_bytes, sk_bytes,
            extra1_name ? extra1_name : "", extra1_bytes,
            extra2_name ? extra2_name : "", extra2_bytes);
}

/* -------------------------------------------------------------------------- */
/* Output: JSON                                                                */
/* -------------------------------------------------------------------------- */

static void bench_print_json_start(FILE *f) {
    fprintf(f, "{\n  \"benchmarks\": [\n");
    g_bench_config.json_first_entry = 1;
}

static void bench_print_json_entry(FILE *f, const char *algorithm,
                                    const char *operation,
                                    const bench_result_t *r,
                                    size_t pk_bytes, size_t sk_bytes,
                                    const char *extra1_name, size_t extra1_bytes,
                                    const char *extra2_name, size_t extra2_bytes) {
    if (!g_bench_config.json_first_entry)
        fprintf(f, ",\n");
    g_bench_config.json_first_entry = 0;

    fprintf(f, "    {\n");
    fprintf(f, "      \"algorithm\": \"%s\",\n", algorithm);
    fprintf(f, "      \"operation\": \"%s\",\n", operation);
    fprintf(f, "      \"iterations\": %d,\n", r->iterations);
    fprintf(f, "      \"min_ms\": %.6f,\n", r->min_ms);
    fprintf(f, "      \"max_ms\": %.6f,\n", r->max_ms);
    fprintf(f, "      \"mean_ms\": %.6f,\n", r->mean_ms);
    fprintf(f, "      \"median_ms\": %.6f,\n", r->median_ms);
    fprintf(f, "      \"stddev_ms\": %.6f,\n", r->stddev_ms);
    fprintf(f, "      \"ops_per_sec\": %.1f,\n", r->ops_per_sec);
    fprintf(f, "      \"cycles_median\": %llu,\n", (unsigned long long)r->cycles_median);
    fprintf(f, "      \"pk_bytes\": %zu,\n", pk_bytes);
    fprintf(f, "      \"sk_bytes\": %zu", sk_bytes);
    if (extra1_name) {
        fprintf(f, ",\n      \"%s_bytes\": %zu", extra1_name, extra1_bytes);
    }
    if (extra2_name) {
        fprintf(f, ",\n      \"%s_bytes\": %zu", extra2_name, extra2_bytes);
    }
    fprintf(f, "\n    }");
}

static void bench_print_json_end(FILE *f) {
    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"peak_rss_bytes\": %zu\n", bench_peak_rss());
    fprintf(f, "}\n");
}

/* -------------------------------------------------------------------------- */
/* Unified output dispatch                                                     */
/* -------------------------------------------------------------------------- */

static void bench_emit_result(const char *algorithm, const char *operation,
                               const bench_result_t *r,
                               size_t pk_bytes, size_t sk_bytes,
                               const char *extra1_name, size_t extra1_bytes,
                               const char *extra2_name, size_t extra2_bytes) {
    FILE *f = g_bench_config.output ? g_bench_config.output : stdout;

    switch (g_bench_config.format) {
    case BENCH_FORMAT_CSV:
        bench_print_csv_row(f, algorithm, operation, r,
                            pk_bytes, sk_bytes,
                            extra1_name, extra1_bytes,
                            extra2_name, extra2_bytes);
        break;
    case BENCH_FORMAT_JSON:
        bench_print_json_entry(f, algorithm, operation, r,
                               pk_bytes, sk_bytes,
                               extra1_name, extra1_bytes,
                               extra2_name, extra2_bytes);
        break;
    case BENCH_FORMAT_TABLE:
    default: {
        char label[128];
        snprintf(label, sizeof(label), "%s / %s", algorithm, operation);
        bench_print_table_row(f, label, r);
        break;
    }
    }
}

/* -------------------------------------------------------------------------- */
/* Command-line argument parsing helper                                        */
/* -------------------------------------------------------------------------- */

static void bench_parse_args(int argc, char **argv) {
    g_bench_config.output = stdout;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--csv") == 0) {
            g_bench_config.format = BENCH_FORMAT_CSV;
        } else if (strcmp(argv[i], "--json") == 0) {
            g_bench_config.format = BENCH_FORMAT_JSON;
        } else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
            g_bench_config.iterations = atoi(argv[++i]);
            if (g_bench_config.iterations < 1)
                g_bench_config.iterations = 1;
        } else if (strcmp(argv[i], "--algorithm") == 0 && i + 1 < argc) {
            g_bench_config.filter_algorithm = argv[++i];
        } else if (strcmp(argv[i], "--kem") == 0) {
            g_bench_config.run_kem  = 1;
            g_bench_config.run_sig  = 0;
            g_bench_config.run_hash = 0;
        } else if (strcmp(argv[i], "--sig") == 0) {
            g_bench_config.run_kem  = 0;
            g_bench_config.run_sig  = 1;
            g_bench_config.run_hash = 0;
        } else if (strcmp(argv[i], "--hash") == 0) {
            g_bench_config.run_kem  = 0;
            g_bench_config.run_sig  = 0;
            g_bench_config.run_hash = 1;
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            g_bench_config.output = fopen(argv[++i], "w");
            if (!g_bench_config.output) {
                fprintf(stderr, "Error: cannot open output file '%s'\n", argv[i]);
                g_bench_config.output = stdout;
            }
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [OPTIONS]\n\n", argv[0]);
            printf("Options:\n");
            printf("  --csv                Output in CSV format\n");
            printf("  --json               Output in JSON format\n");
            printf("  --iterations N       Set base iteration count (default: %d)\n",
                   BENCH_DEFAULT_ITERATIONS);
            printf("  --algorithm NAME     Filter by algorithm name (substring match)\n");
            printf("  --kem                Run only KEM benchmarks\n");
            printf("  --sig                Run only signature benchmarks\n");
            printf("  --hash               Run only hash benchmarks\n");
            printf("  --output FILE        Write output to file\n");
            printf("  --help, -h           Show this help message\n");
            exit(0);
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Print library and platform info                                             */
/* -------------------------------------------------------------------------- */

static void bench_print_header(FILE *f) {
    if (g_bench_config.format != BENCH_FORMAT_TABLE)
        return;

    fprintf(f, "================================================================\n");
    fprintf(f, " libpqc-dyber Benchmark Suite\n");
    fprintf(f, " Copyright (c) 2024-2026 Dyber, Inc.\n");
    fprintf(f, "================================================================\n");
    fprintf(f, " Platform:   ");
#if defined(_WIN32)
    fprintf(f, "Windows");
#elif defined(__APPLE__)
    fprintf(f, "macOS");
#elif defined(__linux__)
    fprintf(f, "Linux");
#else
    fprintf(f, "Unknown");
#endif

#if defined(__x86_64__) || defined(_M_X64)
    fprintf(f, " x86_64");
#elif defined(__aarch64__) || defined(_M_ARM64)
    fprintf(f, " arm64");
#elif defined(__i386__) || defined(_M_IX86)
    fprintf(f, " x86");
#elif defined(__arm__) || defined(_M_ARM)
    fprintf(f, " arm");
#endif

    fprintf(f, "\n");
    fprintf(f, " Compiler:   ");
#if defined(_MSC_VER)
    fprintf(f, "MSVC %d", _MSC_VER);
#elif defined(__clang__)
    fprintf(f, "Clang %d.%d.%d", __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    fprintf(f, "GCC %d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
    fprintf(f, "Unknown");
#endif
    fprintf(f, "\n");
    fprintf(f, " RDTSC:      %s\n", BENCH_HAVE_RDTSC ? "available" : "not available");
    fprintf(f, " Iterations: %d (auto-adjusted for slow algorithms)\n",
            g_bench_config.iterations);
    fprintf(f, "================================================================\n");
}

#endif /* BENCH_COMMON_H */
