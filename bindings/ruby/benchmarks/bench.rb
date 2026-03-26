#!/usr/bin/env ruby
# frozen_string_literal: true

# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Ruby binding benchmarks for all PQC algorithms.
# Uses Process.clock_gettime for high-resolution timing.

require "pqc_dyber"

DEFAULT_ITERATIONS = 100
SLOW_ITERATIONS = 5
WARMUP_ITERATIONS = 5

def slow?(name)
  name.include?("McEliece") || name.include?("Frodo") ||
    name.include?("XMSS") || name.include?("LMS")
end

def adjusted_iters(name, base)
  slow?(name) ? [base, SLOW_ITERATIONS].min : base
end

def compute_stats(samples)
  sorted = samples.sort
  n = sorted.length
  min_v = sorted.first
  max_v = sorted.last
  median = if n.even?
             (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
           else
             sorted[n / 2]
           end
  mean = sorted.sum / n.to_f
  variance = sorted.map { |s| (s - mean)**2 }.sum / (n - 1).to_f
  stddev = n > 1 ? Math.sqrt(variance) : 0.0
  ops = mean > 0 ? 1000.0 / mean : 0.0
  { min: min_v, max: max_v, mean: mean, median: median,
    stddev: stddev, ops_per_sec: ops }
end

def csv_row(algo, op, iters, stats, pk_size, sk_size)
  puts format("ruby,%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%d,%d",
              algo, op, iters,
              stats[:min], stats[:max], stats[:mean], stats[:median],
              stats[:stddev], stats[:ops_per_sec], pk_size, sk_size)
end

def timer_ms
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  yield
  t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  (t1 - t0) * 1000.0
end

base_iters = ARGV[0] ? ARGV[0].to_i : DEFAULT_ITERATIONS
base_iters = DEFAULT_ITERATIONS if base_iters <= 0

PqcDyber.init

puts "language,algorithm,operation,iterations," \
     "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec," \
     "pk_bytes,sk_bytes"

# KEM benchmarks
PqcDyber.kem_algorithm_names.each do |name|
  iters = adjusted_iters(name, base_iters)
  kem = PqcDyber::Kem.new(name)
  pk_size = kem.public_key_size
  sk_size = kem.secret_key_size

  WARMUP_ITERATIONS.times { kem.keygen }

  samples = Array.new(iters) { timer_ms { kem.keygen } }
  csv_row(name, "keygen", iters, compute_stats(samples), pk_size, sk_size)

  pk, sk = kem.keygen
  samples = Array.new(iters) { timer_ms { kem.encaps(pk) } }
  csv_row(name, "encaps", iters, compute_stats(samples), pk_size, sk_size)

  ct, _ss = kem.encaps(pk)
  samples = Array.new(iters) { timer_ms { kem.decaps(ct, sk) } }
  csv_row(name, "decaps", iters, compute_stats(samples), pk_size, sk_size)

  kem.free
end

# Signature benchmarks
msg = (0...1024).map { |i| (i * 137 + 42) & 0xFF }.pack("C*")

PqcDyber.sig_algorithm_names.each do |name|
  iters = adjusted_iters(name, base_iters)
  sig = PqcDyber::Signature.new(name)
  pk_size = sig.public_key_size
  sk_size = sig.secret_key_size
  iters = [iters, SLOW_ITERATIONS].min if sig.stateful?

  samples = Array.new(iters) { timer_ms { sig.keygen } }
  csv_row(name, "keygen", iters, compute_stats(samples), pk_size, sk_size)

  pk, sk = sig.keygen
  samples = Array.new(iters) { timer_ms { sig.sign(msg, sk) } }
  csv_row(name, "sign(1KB)", iters, compute_stats(samples), pk_size, sk_size)

  signature = sig.sign(msg, sk)
  samples = Array.new(iters) { timer_ms { sig.verify(msg, signature, pk) } }
  csv_row(name, "verify(1KB)", iters, compute_stats(samples), pk_size, sk_size)

  sig.free
end

PqcDyber.cleanup
