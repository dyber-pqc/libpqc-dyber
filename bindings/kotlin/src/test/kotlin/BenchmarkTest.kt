/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Kotlin binding benchmarks for all PQC algorithms.
 * Uses System.nanoTime() and measureTimeMillis for timing.
 */

package com.dyber.pqc

import kotlin.math.min
import kotlin.math.sqrt
import kotlin.system.measureNanoTime

const val DEFAULT_ITERATIONS = 100
const val SLOW_ITERATIONS = 5
const val WARMUP_ITERATIONS = 5

fun isSlow(name: String): Boolean =
    "McEliece" in name || "Frodo" in name || "XMSS" in name || "LMS" in name

fun adjustedIters(name: String, base: Int): Int =
    if (isSlow(name)) minOf(base, SLOW_ITERATIONS) else base

data class Stats(
    val min: Double, val max: Double, val mean: Double,
    val median: Double, val stddev: Double, val opsPerSec: Double
)

fun computeStats(samples: DoubleArray): Stats {
    val sorted = samples.sorted()
    val n = sorted.size
    val min = sorted.first()
    val max = sorted.last()
    val median = if (n % 2 == 0) (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0 else sorted[n / 2]
    val mean = sorted.average()
    val variance = sorted.sumOf { (it - mean) * (it - mean) } / (n - 1).toDouble()
    val stddev = if (n > 1) sqrt(variance) else 0.0
    val opsPerSec = if (mean > 0) 1000.0 / mean else 0.0
    return Stats(min, max, mean, median, stddev, opsPerSec)
}

fun csvRow(algo: String, op: String, iters: Int, s: Stats, pkSize: Long, skSize: Long) {
    println("kotlin,$algo,$op,$iters," +
        "%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%d,%d".format(
            s.min, s.max, s.mean, s.median, s.stddev, s.opsPerSec, pkSize, skSize))
}

inline fun timerMs(block: () -> Unit): Double {
    val ns = measureNanoTime { block() }
    return ns / 1_000_000.0
}

fun main(args: Array<String>) {
    val baseIters = args.firstOrNull()?.toIntOrNull()?.takeIf { it > 0 } ?: DEFAULT_ITERATIONS

    PqcLibrary.init()

    println("language,algorithm,operation,iterations," +
        "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec," +
        "pk_bytes,sk_bytes")

    // KEM benchmarks
    for (name in PqcLibrary.kemAlgorithmNames()) {
        val iters = adjustedIters(name, baseIters)
        val kem = Kem(name)
        val pkSize = kem.publicKeySize
        val skSize = kem.secretKeySize

        repeat(WARMUP_ITERATIONS) { kem.keygen() }

        var samples = DoubleArray(iters) { timerMs { kem.keygen() } }
        csvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize)

        val (pk, sk) = kem.keygen()
        samples = DoubleArray(iters) { timerMs { kem.encaps(pk) } }
        csvRow(name, "encaps", iters, computeStats(samples), pkSize, skSize)

        val (ct, _) = kem.encaps(pk)
        samples = DoubleArray(iters) { timerMs { kem.decaps(ct, sk) } }
        csvRow(name, "decaps", iters, computeStats(samples), pkSize, skSize)

        kem.free()
    }

    // Signature benchmarks
    val msg = ByteArray(1024) { ((it * 137 + 42) and 0xFF).toByte() }

    for (name in PqcLibrary.sigAlgorithmNames()) {
        var iters = adjustedIters(name, baseIters)
        val sig = Signature(name)
        val pkSize = sig.publicKeySize
        val skSize = sig.secretKeySize
        if (sig.isStateful) iters = minOf(iters, SLOW_ITERATIONS)

        var samples = DoubleArray(iters) { timerMs { sig.keygen() } }
        csvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize)

        val (pk, sk) = sig.keygen()
        samples = DoubleArray(iters) { timerMs { sig.sign(msg, sk) } }
        csvRow(name, "sign(1KB)", iters, computeStats(samples), pkSize, skSize)

        val signature = sig.sign(msg, sk)
        samples = DoubleArray(iters) { timerMs { sig.verify(msg, signature, pk) } }
        csvRow(name, "verify(1KB)", iters, computeStats(samples), pkSize, skSize)

        sig.free()
    }

    PqcLibrary.cleanup()
}
