/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * C# binding benchmarks for all PQC algorithms.
 * Uses System.Diagnostics.Stopwatch for high-resolution timing.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Dyber.Pqc;

namespace Dyber.Pqc.Benchmarks
{
    class Program
    {
        const int DefaultIterations = 100;
        const int SlowIterations = 5;
        const int WarmupIterations = 5;

        static bool IsSlow(string name) =>
            name.Contains("McEliece") || name.Contains("Frodo") ||
            name.Contains("XMSS") || name.Contains("LMS");

        static int AdjustedIters(string name, int baseIters) =>
            IsSlow(name) ? Math.Min(baseIters, SlowIterations) : baseIters;

        static (double min, double max, double mean, double median,
                double stddev, double opsPerSec)
            ComputeStats(double[] samples)
        {
            Array.Sort(samples);
            int n = samples.Length;
            double min = samples[0];
            double max = samples[n - 1];
            double median = (n % 2 == 0)
                ? (samples[n / 2 - 1] + samples[n / 2]) / 2.0
                : samples[n / 2];
            double mean = samples.Average();
            double variance = samples.Sum(s => (s - mean) * (s - mean)) / (n - 1);
            double stddev = n > 1 ? Math.Sqrt(variance) : 0.0;
            double opsPerSec = mean > 0 ? 1000.0 / mean : 0.0;
            return (min, max, mean, median, stddev, opsPerSec);
        }

        static void PrintRow(string algo, string op, int iters,
            (double min, double max, double mean, double median,
             double stddev, double opsPerSec) stats,
            long pkSize, long skSize)
        {
            Console.WriteLine($"csharp,{algo},{op},{iters}," +
                $"{stats.min:F6},{stats.max:F6},{stats.mean:F6}," +
                $"{stats.median:F6},{stats.stddev:F6},{stats.opsPerSec:F1}," +
                $"{pkSize},{skSize}");
        }

        static void Main(string[] args)
        {
            int baseIters = DefaultIterations;
            if (args.Length > 0 && int.TryParse(args[0], out int parsed))
                baseIters = parsed;

            PqcLibrary.Init();

            Console.WriteLine("language,algorithm,operation,iterations," +
                "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec," +
                "pk_bytes,sk_bytes");

            var sw = new Stopwatch();
            double ticksToMs = 1000.0 / Stopwatch.Frequency;

            // KEM benchmarks
            foreach (string name in PqcLibrary.KemAlgorithmNames())
            {
                int iters = AdjustedIters(name, baseIters);
                using var kem = new Kem(name);
                long pkSize = kem.PublicKeySize;
                long skSize = kem.SecretKeySize;

                // Warmup
                for (int w = 0; w < WarmupIterations; w++) kem.Keygen();

                // Keygen
                var samples = new double[iters];
                for (int i = 0; i < iters; i++)
                {
                    sw.Restart();
                    kem.Keygen();
                    sw.Stop();
                    samples[i] = sw.ElapsedTicks * ticksToMs;
                }
                PrintRow(name, "keygen", iters, ComputeStats(samples), pkSize, skSize);

                // Encaps
                var (pk, sk) = kem.Keygen();
                for (int i = 0; i < iters; i++)
                {
                    sw.Restart();
                    kem.Encaps(pk);
                    sw.Stop();
                    samples[i] = sw.ElapsedTicks * ticksToMs;
                }
                PrintRow(name, "encaps", iters, ComputeStats(samples), pkSize, skSize);

                // Decaps
                var (ct, ss) = kem.Encaps(pk);
                for (int i = 0; i < iters; i++)
                {
                    sw.Restart();
                    kem.Decaps(ct, sk);
                    sw.Stop();
                    samples[i] = sw.ElapsedTicks * ticksToMs;
                }
                PrintRow(name, "decaps", iters, ComputeStats(samples), pkSize, skSize);
            }

            // Signature benchmarks
            byte[] msg = new byte[1024];
            for (int i = 0; i < msg.Length; i++) msg[i] = (byte)(i * 137 + 42);

            foreach (string name in PqcLibrary.SigAlgorithmNames())
            {
                int iters = AdjustedIters(name, baseIters);
                using var sig = new Signature(name);
                long pkSize = sig.PublicKeySize;
                long skSize = sig.SecretKeySize;

                if (sig.IsStateful) iters = Math.Min(iters, SlowIterations);

                var samples = new double[iters];

                // Keygen
                for (int i = 0; i < iters; i++)
                {
                    sw.Restart();
                    sig.Keygen();
                    sw.Stop();
                    samples[i] = sw.ElapsedTicks * ticksToMs;
                }
                PrintRow(name, "keygen", iters, ComputeStats(samples), pkSize, skSize);

                // Sign
                var (pk, sk) = sig.Keygen();
                for (int i = 0; i < iters; i++)
                {
                    sw.Restart();
                    sig.Sign(msg, sk);
                    sw.Stop();
                    samples[i] = sw.ElapsedTicks * ticksToMs;
                }
                PrintRow(name, "sign(1KB)", iters, ComputeStats(samples), pkSize, skSize);

                // Verify
                byte[] signature = sig.Sign(msg, sk);
                for (int i = 0; i < iters; i++)
                {
                    sw.Restart();
                    sig.Verify(msg, signature, pk);
                    sw.Stop();
                    samples[i] = sw.ElapsedTicks * ticksToMs;
                }
                PrintRow(name, "verify(1KB)", iters, ComputeStats(samples), pkSize, skSize);
            }

            PqcLibrary.Cleanup();
        }
    }
}
