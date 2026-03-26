/*
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * Scala binding benchmarks for all PQC algorithms.
 * Uses System.nanoTime for high-resolution timing.
 */

package com.dyber.pqc

import scala.math.{min, sqrt}

object BenchmarkTest {

  val DefaultIterations = 100
  val SlowIterations = 5
  val WarmupIterations = 5

  def isSlow(name: String): Boolean =
    name.contains("McEliece") || name.contains("Frodo") ||
    name.contains("XMSS") || name.contains("LMS")

  def adjustedIters(name: String, base: Int): Int =
    if (isSlow(name)) min(base, SlowIterations) else base

  case class Stats(
    minMs: Double, maxMs: Double, meanMs: Double,
    medianMs: Double, stddevMs: Double, opsPerSec: Double
  )

  def computeStats(samples: Array[Double]): Stats = {
    val sorted = samples.sorted
    val n = sorted.length
    val minV = sorted.head
    val maxV = sorted.last
    val median = if (n % 2 == 0) (sorted(n / 2 - 1) + sorted(n / 2)) / 2.0
                 else sorted(n / 2)
    val mean = sorted.sum / n
    val variance = sorted.map(s => (s - mean) * (s - mean)).sum / (n - 1).toDouble
    val stddev = if (n > 1) sqrt(variance) else 0.0
    val opsPerSec = if (mean > 0) 1000.0 / mean else 0.0
    Stats(minV, maxV, mean, median, stddev, opsPerSec)
  }

  def csvRow(algo: String, op: String, iters: Int, s: Stats,
             pkSize: Long, skSize: Long): Unit = {
    println(f"scala,$algo,$op,$iters,${s.minMs}%.6f,${s.maxMs}%.6f," +
      f"${s.meanMs}%.6f,${s.medianMs}%.6f,${s.stddevMs}%.6f," +
      f"${s.opsPerSec}%.1f,$pkSize,$skSize")
  }

  def timerMs(block: => Unit): Double = {
    val t0 = System.nanoTime()
    block
    val t1 = System.nanoTime()
    (t1 - t0) / 1000000.0
  }

  def main(args: Array[String]): Unit = {
    val baseIters = args.headOption.flatMap(s => scala.util.Try(s.toInt).toOption)
      .filter(_ > 0).getOrElse(DefaultIterations)

    PqcLibrary.init()

    println("language,algorithm,operation,iterations," +
      "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec," +
      "pk_bytes,sk_bytes")

    // KEM benchmarks
    for (name <- PqcLibrary.kemAlgorithmNames()) {
      val iters = adjustedIters(name, baseIters)
      val kem = new Kem(name)
      val pkSize = kem.publicKeySize
      val skSize = kem.secretKeySize

      (0 until WarmupIterations).foreach(_ => kem.keygen())

      var samples = Array.tabulate(iters)(_ => timerMs(kem.keygen()))
      csvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize)

      val (pk, sk) = kem.keygen()
      samples = Array.tabulate(iters)(_ => timerMs(kem.encaps(pk)))
      csvRow(name, "encaps", iters, computeStats(samples), pkSize, skSize)

      val (ct, _) = kem.encaps(pk)
      samples = Array.tabulate(iters)(_ => timerMs(kem.decaps(ct, sk)))
      csvRow(name, "decaps", iters, computeStats(samples), pkSize, skSize)

      kem.free()
    }

    // Signature benchmarks
    val msg = Array.tabulate[Byte](1024)(i => ((i * 137 + 42) & 0xFF).toByte)

    for (name <- PqcLibrary.sigAlgorithmNames()) {
      var iters = adjustedIters(name, baseIters)
      val sig = new Signature(name)
      val pkSize = sig.publicKeySize
      val skSize = sig.secretKeySize
      if (sig.isStateful) iters = min(iters, SlowIterations)

      var samples = Array.tabulate(iters)(_ => timerMs(sig.keygen()))
      csvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize)

      val (pk, sk) = sig.keygen()
      samples = Array.tabulate(iters)(_ => timerMs(sig.sign(msg, sk)))
      csvRow(name, "sign(1KB)", iters, computeStats(samples), pkSize, skSize)

      val signature = sig.sign(msg, sk)
      samples = Array.tabulate(iters)(_ => timerMs(sig.verify(msg, signature, pk)))
      csvRow(name, "verify(1KB)", iters, computeStats(samples), pkSize, skSize)

      sig.free()
    }

    PqcLibrary.cleanup()
  }
}
