# libpqc-dyber - Post-Quantum Cryptography Library
# Copyright (c) 2024-2026 Dyber, Inc.
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# R binding benchmarks for all PQC algorithms.
# Uses system.time and proc.time for timing.

library(pqcdyber)

DEFAULT_ITERATIONS <- 100L
SLOW_ITERATIONS <- 5L
WARMUP_ITERATIONS <- 5L

is_slow <- function(name) {
  grepl("McEliece|Frodo|XMSS|LMS", name)
}

adjusted_iters <- function(name, base) {
  if (is_slow(name)) min(base, SLOW_ITERATIONS) else base
}

compute_stats <- function(samples) {
  sorted <- sort(samples)
  n <- length(sorted)
  min_v <- sorted[1]
  max_v <- sorted[n]
  med <- median(sorted)
  mn <- mean(sorted)
  sd_v <- if (n > 1) sd(sorted) else 0.0
  ops <- if (mn > 0) 1000.0 / mn else 0.0
  list(min = min_v, max = max_v, mean = mn, median = med,
       stddev = sd_v, ops_per_sec = ops)
}

csv_row <- function(algo, op, iters, stats, pk_size, sk_size) {
  cat(sprintf("r,%s,%s,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.1f,%d,%d\n",
              algo, op, iters,
              stats$min, stats$max, stats$mean, stats$median,
              stats$stddev, stats$ops_per_sec, pk_size, sk_size))
}

timer_ms <- function(expr) {
  t0 <- proc.time()["elapsed"]
  force(expr)
  t1 <- proc.time()["elapsed"]
  (t1 - t0) * 1000.0
}

# Parse command-line args
args <- commandArgs(trailingOnly = TRUE)
base_iters <- if (length(args) > 0) as.integer(args[1]) else DEFAULT_ITERATIONS
if (is.na(base_iters) || base_iters <= 0) base_iters <- DEFAULT_ITERATIONS

pqc_init()

cat("language,algorithm,operation,iterations,",
    "min_ms,max_ms,mean_ms,median_ms,stddev_ms,ops_per_sec,",
    "pk_bytes,sk_bytes\n", sep = "")

# KEM benchmarks
kem_names <- pqc_kem_algorithm_names()
for (name in kem_names) {
  iters <- adjusted_iters(name, base_iters)
  kem <- pqc_kem_new(name)
  pk_size <- pqc_kem_public_key_size(kem)
  sk_size <- pqc_kem_secret_key_size(kem)

  # Warmup
  for (w in seq_len(WARMUP_ITERATIONS)) pqc_kem_keygen(kem)

  # Keygen
  samples <- vapply(seq_len(iters), function(i) {
    timer_ms(pqc_kem_keygen(kem))
  }, numeric(1))
  csv_row(name, "keygen", iters, compute_stats(samples), pk_size, sk_size)

  # Encaps
  kp <- pqc_kem_keygen(kem)
  samples <- vapply(seq_len(iters), function(i) {
    timer_ms(pqc_kem_encaps(kem, kp$public_key))
  }, numeric(1))
  csv_row(name, "encaps", iters, compute_stats(samples), pk_size, sk_size)

  # Decaps
  er <- pqc_kem_encaps(kem, kp$public_key)
  samples <- vapply(seq_len(iters), function(i) {
    timer_ms(pqc_kem_decaps(kem, er$ciphertext, kp$secret_key))
  }, numeric(1))
  csv_row(name, "decaps", iters, compute_stats(samples), pk_size, sk_size)

  pqc_kem_free(kem)
}

# Signature benchmarks
msg <- as.raw((0:1023 * 137L + 42L) %% 256L)

sig_names <- pqc_sig_algorithm_names()
for (name in sig_names) {
  iters <- adjusted_iters(name, base_iters)
  sig <- pqc_sig_new(name)
  pk_size <- pqc_sig_public_key_size(sig)
  sk_size <- pqc_sig_secret_key_size(sig)
  if (pqc_sig_is_stateful(sig)) iters <- min(iters, SLOW_ITERATIONS)

  # Keygen
  samples <- vapply(seq_len(iters), function(i) {
    timer_ms(pqc_sig_keygen(sig))
  }, numeric(1))
  csv_row(name, "keygen", iters, compute_stats(samples), pk_size, sk_size)

  # Sign
  kp <- pqc_sig_keygen(sig)
  samples <- vapply(seq_len(iters), function(i) {
    timer_ms(pqc_sig_sign(sig, msg, kp$secret_key))
  }, numeric(1))
  csv_row(name, "sign(1KB)", iters, compute_stats(samples), pk_size, sk_size)

  # Verify
  signature <- pqc_sig_sign(sig, msg, kp$secret_key)
  samples <- vapply(seq_len(iters), function(i) {
    timer_ms(pqc_sig_verify(sig, msg, signature, kp$public_key))
  }, numeric(1))
  csv_row(name, "verify(1KB)", iters, compute_stats(samples), pk_size, sk_size)

  pqc_sig_free(sig)
}

pqc_cleanup()
