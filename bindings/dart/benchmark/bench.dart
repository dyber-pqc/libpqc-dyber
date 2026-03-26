// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Dart binding benchmarks for all PQC algorithms.
// Uses Stopwatch for high-resolution timing.

import 'dart:typed_data';
import 'package:pqc_dyber/pqc_dyber.dart';

const int defaultIterations = 100;
const int slowIterations = 5;
const int warmupIterations = 5;

bool isSlow(String name) {
  return name.contains('McEliece') ||
      name.contains('Frodo') ||
      name.contains('XMSS') ||
      name.contains('LMS');
}

int adjustedIters(String name, int base) {
  return isSlow(name) ? (base < slowIterations ? base : slowIterations) : base;
}

Map<String, double> computeStats(List<double> samples) {
  final sorted = List<double>.from(samples)..sort();
  final n = sorted.length;
  final min = sorted.first;
  final max = sorted.last;
  final median = n.isEven
      ? (sorted[n ~/ 2 - 1] + sorted[n ~/ 2]) / 2.0
      : sorted[n ~/ 2];
  final mean = sorted.reduce((a, b) => a + b) / n;
  var variance = 0.0;
  for (final s in sorted) {
    final d = s - mean;
    variance += d * d;
  }
  final stddev = n > 1 ? (variance / (n - 1)).sqrt() : 0.0;
  final opsPerSec = mean > 0 ? 1000.0 / mean : 0.0;

  return {
    'min': min,
    'max': max,
    'mean': mean,
    'median': median,
    'stddev': stddev,
    'ops_per_sec': opsPerSec,
  };
}

void csvRow(String algo, String op, int iters, Map<String, double> stats,
    int pkSize, int skSize) {
  print('dart,$algo,$op,$iters,'
      '${stats["min"]!.toStringAsFixed(6)},'
      '${stats["max"]!.toStringAsFixed(6)},'
      '${stats["mean"]!.toStringAsFixed(6)},'
      '${stats["median"]!.toStringAsFixed(6)},'
      '${stats["stddev"]!.toStringAsFixed(6)},'
      '${stats["ops_per_sec"]!.toStringAsFixed(1)},'
      '$pkSize,$skSize');
}

double timerMs(void Function() fn) {
  final sw = Stopwatch()..start();
  fn();
  sw.stop();
  return sw.elapsedMicroseconds / 1000.0;
}

void main(List<String> args) {
  var baseIters = defaultIterations;
  if (args.isNotEmpty) {
    baseIters = int.tryParse(args.first) ?? defaultIterations;
  }

  PqcLibrary.init();

  print('language,algorithm,operation,iterations,'
      'min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec,'
      'pk_bytes,sk_bytes');

  // KEM benchmarks
  for (final name in PqcLibrary.kemAlgorithmNames()) {
    final iters = adjustedIters(name, baseIters);
    final kem = Kem(name);
    final pkSize = kem.publicKeySize;
    final skSize = kem.secretKeySize;

    for (var w = 0; w < warmupIterations; w++) kem.keygen();

    var samples = List.generate(iters, (_) => timerMs(() => kem.keygen()));
    csvRow(name, 'keygen', iters, computeStats(samples), pkSize, skSize);

    final kp = kem.keygen();
    samples =
        List.generate(iters, (_) => timerMs(() => kem.encaps(kp.publicKey)));
    csvRow(name, 'encaps', iters, computeStats(samples), pkSize, skSize);

    final er = kem.encaps(kp.publicKey);
    samples = List.generate(
        iters, (_) => timerMs(() => kem.decaps(er.ciphertext, kp.secretKey)));
    csvRow(name, 'decaps', iters, computeStats(samples), pkSize, skSize);

    kem.free();
  }

  // Signature benchmarks
  final msg = Uint8List(1024);
  for (var i = 0; i < 1024; i++) msg[i] = (i * 137 + 42) & 0xFF;

  for (final name in PqcLibrary.sigAlgorithmNames()) {
    var iters = adjustedIters(name, baseIters);
    final sig = Signature(name);
    final pkSize = sig.publicKeySize;
    final skSize = sig.secretKeySize;
    if (sig.isStateful) iters = iters < slowIterations ? iters : slowIterations;

    var samples = List.generate(iters, (_) => timerMs(() => sig.keygen()));
    csvRow(name, 'keygen', iters, computeStats(samples), pkSize, skSize);

    final kp = sig.keygen();
    samples = List.generate(
        iters, (_) => timerMs(() => sig.sign(msg, kp.secretKey)));
    csvRow(name, 'sign(1KB)', iters, computeStats(samples), pkSize, skSize);

    final signature = sig.sign(msg, kp.secretKey);
    samples = List.generate(iters,
        (_) => timerMs(() => sig.verify(msg, signature, kp.publicKey)));
    csvRow(
        name, 'verify(1KB)', iters, computeStats(samples), pkSize, skSize);

    sig.free();
  }

  PqcLibrary.cleanup();
}

extension on double {
  double sqrt() => this >= 0 ? _sqrt(this) : 0.0;
}

double _sqrt(double x) {
  if (x <= 0) return 0.0;
  var guess = x / 2;
  for (var i = 0; i < 50; i++) {
    guess = (guess + x / guess) / 2;
  }
  return guess;
}
