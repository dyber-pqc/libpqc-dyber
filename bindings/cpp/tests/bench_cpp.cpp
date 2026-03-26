/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * C++ binding benchmarks for all PQC algorithms.
 * Uses std::chrono for high-resolution timing across keygen,
 * encaps/sign, decaps/verify for every enabled algorithm.
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <numeric>
#include <string>
#include <vector>

#include "pqc/pqc.h"

static const int DEFAULT_ITERATIONS = 100;
static const int SLOW_ITERATIONS = 5;
static const int WARMUP_ITERATIONS = 5;

static bool is_slow(const std::string &name) {
    return name.find("McEliece") != std::string::npos ||
           name.find("Frodo") != std::string::npos ||
           name.find("XMSS") != std::string::npos ||
           name.find("LMS") != std::string::npos;
}

static int adjusted_iters(const std::string &name, int base) {
    return is_slow(name) ? std::min(base, SLOW_ITERATIONS) : base;
}

struct Stats {
    double min_ms, max_ms, mean_ms, median_ms, stddev_ms, ops_per_sec;
};

static Stats compute_stats(std::vector<double> &samples) {
    int n = static_cast<int>(samples.size());
    std::sort(samples.begin(), samples.end());

    Stats s{};
    s.min_ms = samples.front();
    s.max_ms = samples.back();
    s.median_ms = (n % 2 == 0)
        ? (samples[n / 2 - 1] + samples[n / 2]) / 2.0
        : samples[n / 2];

    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    s.mean_ms = sum / n;

    double var = 0.0;
    for (auto v : samples) {
        double d = v - s.mean_ms;
        var += d * d;
    }
    s.stddev_ms = (n > 1) ? std::sqrt(var / (n - 1)) : 0.0;
    s.ops_per_sec = s.mean_ms > 0 ? 1000.0 / s.mean_ms : 0.0;
    return s;
}

static void print_csv(const char *algo, const char *op, int iters,
                       const Stats &s, size_t pk, size_t sk) {
    std::printf("cpp,%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%zu,%zu\n",
                algo, op, iters, s.min_ms, s.max_ms, s.mean_ms,
                s.median_ms, s.stddev_ms, s.ops_per_sec, pk, sk);
}

using Clock = std::chrono::high_resolution_clock;

static double elapsed_ms(Clock::time_point t0, Clock::time_point t1) {
    return std::chrono::duration<double, std::milli>(t1 - t0).count();
}

int main(int argc, char **argv) {
    int base_iters = DEFAULT_ITERATIONS;
    if (argc > 1) {
        int v = std::atoi(argv[1]);
        if (v > 0) base_iters = v;
    }

    pqc_init();

    std::printf("language,algorithm,operation,iterations,"
                "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec,"
                "pk_bytes,sk_bytes\n");

    // KEM benchmarks
    int kem_count = pqc_kem_algorithm_count();
    for (int idx = 0; idx < kem_count; idx++) {
        const char *name = pqc_kem_algorithm_name(idx);
        PQC_KEM *kem = pqc_kem_new(name);
        if (!kem) continue;

        int iters = adjusted_iters(name, base_iters);
        size_t pk_size = pqc_kem_public_key_size(kem);
        size_t sk_size = pqc_kem_secret_key_size(kem);
        size_t ct_size = pqc_kem_ciphertext_size(kem);
        size_t ss_size = pqc_kem_shared_secret_size(kem);

        std::vector<uint8_t> pk(pk_size), sk(sk_size), ct(ct_size), ss(ss_size), ss2(ss_size);

        // Warmup
        for (int w = 0; w < WARMUP_ITERATIONS; w++) {
            pqc_kem_keygen(kem, pk.data(), sk.data());
            pqc_kem_encaps(kem, ct.data(), ss.data(), pk.data());
            pqc_kem_decaps(kem, ss2.data(), ct.data(), sk.data());
        }

        // Keygen
        std::vector<double> samples(iters);
        for (int i = 0; i < iters; i++) {
            auto t0 = Clock::now();
            pqc_kem_keygen(kem, pk.data(), sk.data());
            auto t1 = Clock::now();
            samples[i] = elapsed_ms(t0, t1);
        }
        print_csv(name, "keygen", iters, compute_stats(samples), pk_size, sk_size);

        // Encaps
        pqc_kem_keygen(kem, pk.data(), sk.data());
        for (int i = 0; i < iters; i++) {
            auto t0 = Clock::now();
            pqc_kem_encaps(kem, ct.data(), ss.data(), pk.data());
            auto t1 = Clock::now();
            samples[i] = elapsed_ms(t0, t1);
        }
        print_csv(name, "encaps", iters, compute_stats(samples), pk_size, sk_size);

        // Decaps
        pqc_kem_encaps(kem, ct.data(), ss.data(), pk.data());
        for (int i = 0; i < iters; i++) {
            auto t0 = Clock::now();
            pqc_kem_decaps(kem, ss2.data(), ct.data(), sk.data());
            auto t1 = Clock::now();
            samples[i] = elapsed_ms(t0, t1);
        }
        print_csv(name, "decaps", iters, compute_stats(samples), pk_size, sk_size);

        pqc_kem_free(kem);
    }

    // Signature benchmarks
    std::vector<uint8_t> msg(1024);
    for (size_t i = 0; i < msg.size(); i++) msg[i] = static_cast<uint8_t>(i * 137 + 42);

    int sig_count = pqc_sig_algorithm_count();
    for (int idx = 0; idx < sig_count; idx++) {
        const char *name = pqc_sig_algorithm_name(idx);
        PQC_SIG *sig = pqc_sig_new(name);
        if (!sig) continue;

        int iters = adjusted_iters(name, base_iters);
        if (pqc_sig_is_stateful(sig)) iters = std::min(iters, SLOW_ITERATIONS);

        size_t pk_size = pqc_sig_public_key_size(sig);
        size_t sk_size = pqc_sig_secret_key_size(sig);
        size_t max_sig_size = pqc_sig_max_signature_size(sig);

        std::vector<uint8_t> pk(pk_size), sk(sk_size), signature(max_sig_size);
        size_t sig_len = 0;

        // Keygen
        std::vector<double> samples(iters);
        for (int i = 0; i < iters; i++) {
            auto t0 = Clock::now();
            pqc_sig_keygen(sig, pk.data(), sk.data());
            auto t1 = Clock::now();
            samples[i] = elapsed_ms(t0, t1);
        }
        print_csv(name, "keygen", iters, compute_stats(samples), pk_size, sk_size);

        // Sign
        pqc_sig_keygen(sig, pk.data(), sk.data());
        for (int i = 0; i < iters; i++) {
            auto t0 = Clock::now();
            pqc_sig_sign(sig, signature.data(), &sig_len,
                         msg.data(), msg.size(), sk.data());
            auto t1 = Clock::now();
            samples[i] = elapsed_ms(t0, t1);
        }
        print_csv(name, "sign(1KB)", iters, compute_stats(samples), pk_size, sk_size);

        // Verify
        pqc_sig_sign(sig, signature.data(), &sig_len, msg.data(), msg.size(), sk.data());
        for (int i = 0; i < iters; i++) {
            auto t0 = Clock::now();
            pqc_sig_verify(sig, msg.data(), msg.size(),
                           signature.data(), sig_len, pk.data());
            auto t1 = Clock::now();
            samples[i] = elapsed_ms(t0, t1);
        }
        print_csv(name, "verify(1KB)", iters, compute_stats(samples), pk_size, sk_size);

        pqc_sig_free(sig);
    }

    pqc_cleanup();
    return 0;
}
