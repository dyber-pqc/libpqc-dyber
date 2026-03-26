/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Java binding benchmarks for all PQC algorithms.
 * Uses System.nanoTime() for precise measurements across keygen,
 * encaps/sign, decaps/verify for every enabled algorithm.
 */

package com.dyber.pqc;

import java.util.Arrays;
import java.util.List;

public class BenchmarkTest {

    private static final int DEFAULT_ITERATIONS = 100;
    private static final int SLOW_ITERATIONS = 5;
    private static final int WARMUP_ITERATIONS = 5;

    private static boolean isSlow(String name) {
        return name.contains("McEliece") || name.contains("Frodo")
            || name.contains("XMSS") || name.contains("LMS");
    }

    private static int adjustedIterations(String name, int base) {
        return isSlow(name) ? Math.min(base, SLOW_ITERATIONS) : base;
    }

    private static double[] computeStats(double[] samples) {
        int n = samples.length;
        double[] sorted = Arrays.copyOf(samples, n);
        Arrays.sort(sorted);

        double min = sorted[0];
        double max = sorted[n - 1];
        double median = (n % 2 == 0)
            ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
            : sorted[n / 2];

        double sum = 0;
        for (double s : sorted) sum += s;
        double mean = sum / n;

        double var = 0;
        for (double s : sorted) {
            double d = s - mean;
            var += d * d;
        }
        double stddev = (n > 1) ? Math.sqrt(var / (n - 1)) : 0.0;
        double opsPerSec = mean > 0 ? 1000.0 / mean : 0;

        return new double[]{min, max, mean, median, stddev, opsPerSec};
    }

    private static void printCsvRow(String algorithm, String operation,
                                     int iterations, double[] stats,
                                     long pkSize, long skSize) {
        System.out.printf("java,%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%d,%d%n",
            algorithm, operation, iterations,
            stats[0], stats[1], stats[2], stats[3], stats[4], stats[5],
            pkSize, skSize);
    }

    public static void main(String[] args) throws Exception {
        int baseIters = DEFAULT_ITERATIONS;
        if (args.length > 0) {
            try { baseIters = Integer.parseInt(args[0]); } catch (NumberFormatException ignored) {}
        }

        PqcLibrary.init();

        System.out.println("language,algorithm,operation,iterations,"
            + "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec,"
            + "pk_bytes,sk_bytes");

        // KEM benchmarks
        for (String name : PqcLibrary.kemAlgorithmNames()) {
            int iters = adjustedIterations(name, baseIters);
            Kem kem = new Kem(name);
            long pkSize = kem.publicKeySize();
            long skSize = kem.secretKeySize();

            // Warmup
            for (int w = 0; w < WARMUP_ITERATIONS; w++) kem.keygen();

            // Keygen
            double[] samples = new double[iters];
            for (int i = 0; i < iters; i++) {
                long t0 = System.nanoTime();
                kem.keygen();
                long t1 = System.nanoTime();
                samples[i] = (t1 - t0) / 1_000_000.0;
            }
            printCsvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize);

            // Encaps
            Kem.KeyPair kp = kem.keygen();
            for (int i = 0; i < iters; i++) {
                long t0 = System.nanoTime();
                kem.encaps(kp.publicKey());
                long t1 = System.nanoTime();
                samples[i] = (t1 - t0) / 1_000_000.0;
            }
            printCsvRow(name, "encaps", iters, computeStats(samples), pkSize, skSize);

            // Decaps
            Kem.EncapsResult er = kem.encaps(kp.publicKey());
            for (int i = 0; i < iters; i++) {
                long t0 = System.nanoTime();
                kem.decaps(er.ciphertext(), kp.secretKey());
                long t1 = System.nanoTime();
                samples[i] = (t1 - t0) / 1_000_000.0;
            }
            printCsvRow(name, "decaps", iters, computeStats(samples), pkSize, skSize);

            kem.close();
        }

        // Signature benchmarks
        byte[] msg = new byte[1024];
        for (int i = 0; i < msg.length; i++) msg[i] = (byte) (i * 137 + 42);

        for (String name : PqcLibrary.sigAlgorithmNames()) {
            int iters = adjustedIterations(name, baseIters);
            Signature sig = new Signature(name);
            long pkSize = sig.publicKeySize();
            long skSize = sig.secretKeySize();

            if (sig.isStateful()) {
                iters = Math.min(iters, SLOW_ITERATIONS);
            }

            for (int w = 0; w < WARMUP_ITERATIONS && w < iters; w++) sig.keygen();

            // Keygen
            double[] samples = new double[iters];
            for (int i = 0; i < iters; i++) {
                long t0 = System.nanoTime();
                sig.keygen();
                long t1 = System.nanoTime();
                samples[i] = (t1 - t0) / 1_000_000.0;
            }
            printCsvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize);

            // Sign
            Signature.KeyPair kp = sig.keygen();
            for (int i = 0; i < iters; i++) {
                long t0 = System.nanoTime();
                sig.sign(msg, kp.secretKey());
                long t1 = System.nanoTime();
                samples[i] = (t1 - t0) / 1_000_000.0;
            }
            printCsvRow(name, "sign(1KB)", iters, computeStats(samples), pkSize, skSize);

            // Verify
            byte[] signature = sig.sign(msg, kp.secretKey());
            for (int i = 0; i < iters; i++) {
                long t0 = System.nanoTime();
                sig.verify(msg, signature, kp.publicKey());
                long t1 = System.nanoTime();
                samples[i] = (t1 - t0) / 1_000_000.0;
            }
            printCsvRow(name, "verify(1KB)", iters, computeStats(samples), pkSize, skSize);

            sig.close();
        }

        PqcLibrary.cleanup();
    }
}
