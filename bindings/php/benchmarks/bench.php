<?php
/**
 * libpqc-dyber - Post-Quantum Cryptography Library
 * Copyright (c) 2024-2026 Dyber, Inc.
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * PHP binding benchmarks for all PQC algorithms.
 * Uses hrtime(true) for nanosecond-precision timing.
 */

declare(strict_types=1);

const DEFAULT_ITERATIONS = 100;
const SLOW_ITERATIONS = 5;
const WARMUP_ITERATIONS = 5;

function is_slow(string $name): bool {
    return str_contains($name, 'McEliece') || str_contains($name, 'Frodo')
        || str_contains($name, 'XMSS') || str_contains($name, 'LMS');
}

function adjusted_iters(string $name, int $base): int {
    return is_slow($name) ? min($base, SLOW_ITERATIONS) : $base;
}

function compute_stats(array $samples): array {
    sort($samples);
    $n = count($samples);
    $min = $samples[0];
    $max = $samples[$n - 1];
    $median = ($n % 2 === 0)
        ? ($samples[$n / 2 - 1] + $samples[$n / 2]) / 2.0
        : $samples[intdiv($n, 2)];
    $mean = array_sum($samples) / $n;
    $variance = 0.0;
    foreach ($samples as $s) {
        $variance += ($s - $mean) ** 2;
    }
    $stddev = $n > 1 ? sqrt($variance / ($n - 1)) : 0.0;
    $ops = $mean > 0 ? 1000.0 / $mean : 0.0;

    return compact('min', 'max', 'mean', 'median', 'stddev', 'ops');
}

function csv_row(string $algo, string $op, int $iters, array $stats,
                  int $pkSize, int $skSize): void {
    printf("php,%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%d,%d\n",
        $algo, $op, $iters,
        $stats['min'], $stats['max'], $stats['mean'], $stats['median'],
        $stats['stddev'], $stats['ops'], $pkSize, $skSize);
}

function timer_ms(callable $fn): float {
    $t0 = hrtime(true);
    $fn();
    $t1 = hrtime(true);
    return ($t1 - $t0) / 1_000_000.0;
}

// Main
$baseIters = isset($argv[1]) ? (int)$argv[1] : DEFAULT_ITERATIONS;
if ($baseIters <= 0) $baseIters = DEFAULT_ITERATIONS;

pqc_init();

echo "language,algorithm,operation,iterations,"
    . "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec,"
    . "pk_bytes,sk_bytes\n";

// KEM benchmarks
foreach (pqc_kem_algorithm_names() as $name) {
    $iters = adjusted_iters($name, $baseIters);
    $kem = new PqcKem($name);
    $pkSize = $kem->publicKeySize();
    $skSize = $kem->secretKeySize();

    for ($w = 0; $w < WARMUP_ITERATIONS; $w++) $kem->keygen();

    // Keygen
    $samples = [];
    for ($i = 0; $i < $iters; $i++) {
        $samples[] = timer_ms(fn() => $kem->keygen());
    }
    csv_row($name, 'keygen', $iters, compute_stats($samples), $pkSize, $skSize);

    // Encaps
    [$pk, $sk] = $kem->keygen();
    $samples = [];
    for ($i = 0; $i < $iters; $i++) {
        $samples[] = timer_ms(fn() => $kem->encaps($pk));
    }
    csv_row($name, 'encaps', $iters, compute_stats($samples), $pkSize, $skSize);

    // Decaps
    [$ct, $ss] = $kem->encaps($pk);
    $samples = [];
    for ($i = 0; $i < $iters; $i++) {
        $samples[] = timer_ms(fn() => $kem->decaps($ct, $sk));
    }
    csv_row($name, 'decaps', $iters, compute_stats($samples), $pkSize, $skSize);

    $kem->free();
}

// Signature benchmarks
$msg = str_repeat("\x00", 1024);
for ($i = 0; $i < 1024; $i++) $msg[$i] = chr(($i * 137 + 42) & 0xFF);

foreach (pqc_sig_algorithm_names() as $name) {
    $iters = adjusted_iters($name, $baseIters);
    $sig = new PqcSignature($name);
    $pkSize = $sig->publicKeySize();
    $skSize = $sig->secretKeySize();
    if ($sig->isStateful()) $iters = min($iters, SLOW_ITERATIONS);

    // Keygen
    $samples = [];
    for ($i = 0; $i < $iters; $i++) {
        $samples[] = timer_ms(fn() => $sig->keygen());
    }
    csv_row($name, 'keygen', $iters, compute_stats($samples), $pkSize, $skSize);

    // Sign
    [$pk, $sk] = $sig->keygen();
    $samples = [];
    for ($i = 0; $i < $iters; $i++) {
        $samples[] = timer_ms(fn() => $sig->sign($msg, $sk));
    }
    csv_row($name, 'sign(1KB)', $iters, compute_stats($samples), $pkSize, $skSize);

    // Verify
    $signature = $sig->sign($msg, $sk);
    $samples = [];
    for ($i = 0; $i < $iters; $i++) {
        $samples[] = timer_ms(fn() => $sig->verify($msg, $signature, $pk));
    }
    csv_row($name, 'verify(1KB)', $iters, compute_stats($samples), $pkSize, $skSize);

    $sig->free();
}

pqc_cleanup();
