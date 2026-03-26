/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * JavaScript/Node.js binding benchmarks for all PQC algorithms.
 * Uses performance.now() for high-resolution timing.
 */

"use strict";

const { performance } = require("perf_hooks");

let pqc;
try {
    pqc = require("pqc-dyber");
} catch (e) {
    console.error("Error: pqc-dyber module not found. Install it first.");
    process.exit(1);
}

const DEFAULT_ITERATIONS = 100;
const SLOW_ITERATIONS = 5;
const WARMUP_ITERATIONS = 5;

function isSlow(name) {
    return /McEliece|Frodo|XMSS|LMS/.test(name);
}

function adjustedIters(name, base) {
    return isSlow(name) ? Math.min(base, SLOW_ITERATIONS) : base;
}

function computeStats(samples) {
    const sorted = [...samples].sort((a, b) => a - b);
    const n = sorted.length;
    const min = sorted[0];
    const max = sorted[n - 1];
    const median =
        n % 2 === 0
            ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2
            : sorted[Math.floor(n / 2)];
    const mean = sorted.reduce((a, b) => a + b, 0) / n;
    const variance =
        n > 1
            ? sorted.reduce((acc, v) => acc + (v - mean) ** 2, 0) / (n - 1)
            : 0;
    const stddev = Math.sqrt(variance);
    const opsPerSec = mean > 0 ? 1000 / mean : 0;

    return { min, max, mean, median, stddev, opsPerSec };
}

function csvRow(algo, op, iters, stats, pkSize, skSize) {
    console.log(
        `javascript,${algo},${op},${iters},` +
            `${stats.min.toFixed(6)},${stats.max.toFixed(6)},` +
            `${stats.mean.toFixed(6)},${stats.median.toFixed(6)},` +
            `${stats.stddev.toFixed(6)},${stats.opsPerSec.toFixed(1)},` +
            `${pkSize},${skSize}`
    );
}

function main() {
    const baseIters =
        process.argv.length > 2 ? parseInt(process.argv[2], 10) || DEFAULT_ITERATIONS : DEFAULT_ITERATIONS;

    pqc.init();

    console.log(
        "language,algorithm,operation,iterations," +
            "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec," +
            "pk_bytes,sk_bytes"
    );

    // KEM benchmarks
    for (const name of pqc.kemAlgorithmNames()) {
        const iters = adjustedIters(name, baseIters);
        const kem = new pqc.Kem(name);
        const pkSize = kem.publicKeySize;
        const skSize = kem.secretKeySize;

        // Warmup
        for (let w = 0; w < WARMUP_ITERATIONS; w++) kem.keygen();

        // Keygen
        let samples = new Array(iters);
        for (let i = 0; i < iters; i++) {
            const t0 = performance.now();
            kem.keygen();
            samples[i] = performance.now() - t0;
        }
        csvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize);

        // Encaps
        const { publicKey, secretKey } = kem.keygen();
        for (let i = 0; i < iters; i++) {
            const t0 = performance.now();
            kem.encaps(publicKey);
            samples[i] = performance.now() - t0;
        }
        csvRow(name, "encaps", iters, computeStats(samples), pkSize, skSize);

        // Decaps
        const { ciphertext, sharedSecret } = kem.encaps(publicKey);
        for (let i = 0; i < iters; i++) {
            const t0 = performance.now();
            kem.decaps(ciphertext, secretKey);
            samples[i] = performance.now() - t0;
        }
        csvRow(name, "decaps", iters, computeStats(samples), pkSize, skSize);

        kem.free();
    }

    // Signature benchmarks
    const msg = Buffer.alloc(1024);
    for (let i = 0; i < msg.length; i++) msg[i] = (i * 137 + 42) & 0xff;

    for (const name of pqc.sigAlgorithmNames()) {
        let iters = adjustedIters(name, baseIters);
        const sig = new pqc.Signature(name);
        const pkSize = sig.publicKeySize;
        const skSize = sig.secretKeySize;

        if (sig.isStateful) iters = Math.min(iters, SLOW_ITERATIONS);

        // Keygen
        let samples = new Array(iters);
        for (let i = 0; i < iters; i++) {
            const t0 = performance.now();
            sig.keygen();
            samples[i] = performance.now() - t0;
        }
        csvRow(name, "keygen", iters, computeStats(samples), pkSize, skSize);

        // Sign
        const { publicKey, secretKey } = sig.keygen();
        for (let i = 0; i < iters; i++) {
            const t0 = performance.now();
            sig.sign(msg, secretKey);
            samples[i] = performance.now() - t0;
        }
        csvRow(name, "sign(1KB)", iters, computeStats(samples), pkSize, skSize);

        // Verify
        const signature = sig.sign(msg, secretKey);
        for (let i = 0; i < iters; i++) {
            const t0 = performance.now();
            sig.verify(msg, signature, publicKey);
            samples[i] = performance.now() - t0;
        }
        csvRow(name, "verify(1KB)", iters, computeStats(samples), pkSize, skSize);

        sig.free();
    }

    pqc.cleanup();
}

main();
