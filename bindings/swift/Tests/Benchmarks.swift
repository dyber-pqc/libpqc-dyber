// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Swift binding benchmarks for all PQC algorithms.
// Uses ContinuousClock / DispatchTime for high-resolution timing.

import Foundation
import PqcDyber

let defaultIterations = 100
let slowIterations = 5
let warmupIterations = 5

func isSlow(_ name: String) -> Bool {
    name.contains("McEliece") || name.contains("Frodo") ||
    name.contains("XMSS") || name.contains("LMS")
}

func adjustedIters(_ name: String, _ base: Int) -> Int {
    isSlow(name) ? min(base, slowIterations) : base
}

func computeStats(_ samples: [Double]) -> (min: Double, max: Double,
    mean: Double, median: Double, stddev: Double, opsPerSec: Double) {
    let sorted = samples.sorted()
    let n = sorted.count
    let minV = sorted.first!
    let maxV = sorted.last!
    let median: Double = n % 2 == 0
        ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        : sorted[n / 2]
    let mean = sorted.reduce(0.0, +) / Double(n)
    let variance = sorted.reduce(0.0) { $0 + ($1 - mean) * ($1 - mean) } / Double(n - 1)
    let stddev = n > 1 ? sqrt(variance) : 0.0
    let opsPerSec = mean > 0 ? 1000.0 / mean : 0.0
    return (minV, maxV, mean, median, stddev, opsPerSec)
}

func csvRow(_ algo: String, _ op: String, _ iters: Int,
            _ s: (min: Double, max: Double, mean: Double, median: Double,
                  stddev: Double, opsPerSec: Double),
            _ pkSize: Int, _ skSize: Int) {
    print(String(format: "swift,%@,%@,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%d,%d",
                 algo, op, iters, s.min, s.max, s.mean, s.median,
                 s.stddev, s.opsPerSec, pkSize, skSize))
}

func timerMs(_ block: () -> Void) -> Double {
    let start = DispatchTime.now()
    block()
    let end = DispatchTime.now()
    return Double(end.uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000.0
}

func main() {
    let baseIters: Int
    if CommandLine.arguments.count > 1, let v = Int(CommandLine.arguments[1]), v > 0 {
        baseIters = v
    } else {
        baseIters = defaultIterations
    }

    PqcLibrary.initialize()

    print("language,algorithm,operation,iterations," +
          "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec," +
          "pk_bytes,sk_bytes")

    // KEM benchmarks
    for name in PqcLibrary.kemAlgorithmNames() {
        let iters = adjustedIters(name, baseIters)
        guard let kem = Kem(algorithm: name) else { continue }
        let pkSize = kem.publicKeySize
        let skSize = kem.secretKeySize

        for _ in 0..<warmupIterations { _ = try? kem.keygen() }

        var samples = (0..<iters).map { _ in timerMs { _ = try? kem.keygen() } }
        csvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize)

        guard let (pk, sk) = try? kem.keygen() else { continue }
        samples = (0..<iters).map { _ in timerMs { _ = try? kem.encaps(publicKey: pk) } }
        csvRow(name, "encaps", iters, computeStats(samples), pkSize, skSize)

        guard let (ct, _) = try? kem.encaps(publicKey: pk) else { continue }
        samples = (0..<iters).map { _ in timerMs { _ = try? kem.decaps(ciphertext: ct, secretKey: sk) } }
        csvRow(name, "decaps", iters, computeStats(samples), pkSize, skSize)

        kem.free()
    }

    // Signature benchmarks
    var msg = Data(count: 1024)
    for i in 0..<1024 { msg[i] = UInt8((i * 137 + 42) & 0xFF) }

    for name in PqcLibrary.sigAlgorithmNames() {
        var iters = adjustedIters(name, baseIters)
        guard let sig = Signature(algorithm: name) else { continue }
        let pkSize = sig.publicKeySize
        let skSize = sig.secretKeySize
        if sig.isStateful { iters = min(iters, slowIterations) }

        var samples = (0..<iters).map { _ in timerMs { _ = try? sig.keygen() } }
        csvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize)

        guard let (pk, sk) = try? sig.keygen() else { continue }
        samples = (0..<iters).map { _ in timerMs { _ = try? sig.sign(message: msg, secretKey: sk) } }
        csvRow(name, "sign(1KB)", iters, computeStats(samples), pkSize, skSize)

        guard let signature = try? sig.sign(message: msg, secretKey: sk) else { continue }
        samples = (0..<iters).map { _ in timerMs { _ = try? sig.verify(message: msg, signature: signature, publicKey: pk) } }
        csvRow(name, "verify(1KB)", iters, computeStats(samples), pkSize, skSize)

        sig.free()
    }

    PqcLibrary.cleanup()
}

main()
