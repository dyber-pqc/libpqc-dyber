#!/usr/bin/env python3
"""
libpqc-dyber - Post-Quantum Cryptography Library
Copyright (c) 2024-2026 Dyber, Inc.
SPDX-License-Identifier: Apache-2.0 OR MIT

Python binding benchmarks for all PQC algorithms.
Measures keygen, encaps/sign, decaps/verify with statistical reporting.
"""

import csv
import io
import math
import statistics
import sys
import time

try:
    import pqc_dyber as pqc
except ImportError:
    sys.stderr.write("Error: pqc_dyber module not found. Install it first.\n")
    sys.exit(1)

DEFAULT_ITERATIONS = 100
SLOW_ITERATIONS = 5
MSG_SIZES = [
    ("32B", 32),
    ("256B", 256),
    ("1KB", 1024),
    ("64KB", 65536),
]


def is_slow(name: str) -> bool:
    return any(s in name for s in ("McEliece", "Frodo", "XMSS", "LMS"))


def adjusted_iters(name: str, base: int) -> int:
    if is_slow(name):
        return min(base, SLOW_ITERATIONS)
    return base


def compute_stats(samples: list[float]) -> dict:
    n = len(samples)
    if n == 0:
        return {}
    sorted_s = sorted(samples)
    mean = statistics.mean(sorted_s)
    med = statistics.median(sorted_s)
    sd = statistics.stdev(sorted_s) if n > 1 else 0.0
    ops = 1000.0 / mean if mean > 0 else 0.0
    return {
        "iterations": n,
        "min_ms": sorted_s[0],
        "max_ms": sorted_s[-1],
        "mean_ms": mean,
        "median_ms": med,
        "stddev_ms": sd,
        "ops_per_sec": ops,
    }


def bench_time(func, *args) -> float:
    """Time a single call in milliseconds."""
    t0 = time.perf_counter()
    func(*args)
    t1 = time.perf_counter()
    return (t1 - t0) * 1000.0


def main():
    writer = csv.writer(sys.stdout)
    writer.writerow([
        "language", "algorithm", "operation", "iterations",
        "min_ms", "max_ms", "mean_ms", "median_ms", "stddev_ms",
        "ops_per_sec", "pk_bytes", "sk_bytes",
    ])

    base_iters = DEFAULT_ITERATIONS
    if len(sys.argv) > 1:
        try:
            base_iters = int(sys.argv[1])
        except ValueError:
            pass

    # --- KEM benchmarks ---
    for alg_name in pqc.kem_algorithms():
        iters = adjusted_iters(alg_name, base_iters)
        kem = pqc.KEM(alg_name)
        pk_size = kem.public_key_size
        sk_size = kem.secret_key_size

        # Keygen
        samples = []
        for _ in range(iters):
            samples.append(bench_time(kem.keygen))
        stats = compute_stats(samples)
        writer.writerow([
            "python", alg_name, "keygen", stats["iterations"],
            f"{stats['min_ms']:.6f}", f"{stats['max_ms']:.6f}",
            f"{stats['mean_ms']:.6f}", f"{stats['median_ms']:.6f}",
            f"{stats['stddev_ms']:.6f}", f"{stats['ops_per_sec']:.1f}",
            pk_size, sk_size,
        ])

        # Encaps
        pk, sk = kem.keygen()
        samples = []
        for _ in range(iters):
            samples.append(bench_time(kem.encaps, pk))
        stats = compute_stats(samples)
        writer.writerow([
            "python", alg_name, "encaps", stats["iterations"],
            f"{stats['min_ms']:.6f}", f"{stats['max_ms']:.6f}",
            f"{stats['mean_ms']:.6f}", f"{stats['median_ms']:.6f}",
            f"{stats['stddev_ms']:.6f}", f"{stats['ops_per_sec']:.1f}",
            pk_size, sk_size,
        ])

        # Decaps
        ct, ss = kem.encaps(pk)
        samples = []
        for _ in range(iters):
            samples.append(bench_time(kem.decaps, ct, sk))
        stats = compute_stats(samples)
        writer.writerow([
            "python", alg_name, "decaps", stats["iterations"],
            f"{stats['min_ms']:.6f}", f"{stats['max_ms']:.6f}",
            f"{stats['mean_ms']:.6f}", f"{stats['median_ms']:.6f}",
            f"{stats['stddev_ms']:.6f}", f"{stats['ops_per_sec']:.1f}",
            pk_size, sk_size,
        ])

    # --- Signature benchmarks ---
    for alg_name in pqc.sig_algorithms():
        iters = adjusted_iters(alg_name, base_iters)
        sig = pqc.Signature(alg_name)
        pk_size = sig.public_key_size
        sk_size = sig.secret_key_size
        msg = bytes(range(256)) * 4  # 1KB message

        # Keygen
        samples = []
        for _ in range(iters):
            samples.append(bench_time(sig.keygen))
        stats = compute_stats(samples)
        writer.writerow([
            "python", alg_name, "keygen", stats["iterations"],
            f"{stats['min_ms']:.6f}", f"{stats['max_ms']:.6f}",
            f"{stats['mean_ms']:.6f}", f"{stats['median_ms']:.6f}",
            f"{stats['stddev_ms']:.6f}", f"{stats['ops_per_sec']:.1f}",
            pk_size, sk_size,
        ])

        # Sign
        pk, sk = sig.keygen()
        samples = []
        for _ in range(iters):
            samples.append(bench_time(sig.sign, msg, sk))
        stats = compute_stats(samples)
        writer.writerow([
            "python", alg_name, "sign(1KB)", stats["iterations"],
            f"{stats['min_ms']:.6f}", f"{stats['max_ms']:.6f}",
            f"{stats['mean_ms']:.6f}", f"{stats['median_ms']:.6f}",
            f"{stats['stddev_ms']:.6f}", f"{stats['ops_per_sec']:.1f}",
            pk_size, sk_size,
        ])

        # Verify
        signature = sig.sign(msg, sk)
        samples = []
        for _ in range(iters):
            samples.append(bench_time(sig.verify, msg, signature, pk))
        stats = compute_stats(samples)
        writer.writerow([
            "python", alg_name, "verify(1KB)", stats["iterations"],
            f"{stats['min_ms']:.6f}", f"{stats['max_ms']:.6f}",
            f"{stats['mean_ms']:.6f}", f"{stats['median_ms']:.6f}",
            f"{stats['stddev_ms']:.6f}", f"{stats['ops_per_sec']:.1f}",
            pk_size, sk_size,
        ])


if __name__ == "__main__":
    main()
