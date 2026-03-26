// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Rust binding benchmarks for all PQC algorithms.
// Uses criterion for statistical benchmarking of keygen, encaps/sign,
// decaps/verify across every enabled algorithm.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use pqc_dyber::{kem, sig};

fn bench_kem_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("KEM");

    for alg_name in kem::algorithm_names() {
        let kem_ctx = match kem::Kem::new(alg_name) {
            Ok(k) => k,
            Err(_) => continue,
        };

        group.bench_with_input(
            BenchmarkId::new("keygen", alg_name),
            alg_name,
            |b, _| {
                b.iter(|| kem_ctx.keygen().unwrap());
            },
        );

        let (pk, sk) = kem_ctx.keygen().unwrap();

        group.bench_with_input(
            BenchmarkId::new("encaps", alg_name),
            alg_name,
            |b, _| {
                b.iter(|| kem_ctx.encaps(&pk).unwrap());
            },
        );

        let (ct, _ss) = kem_ctx.encaps(&pk).unwrap();

        group.bench_with_input(
            BenchmarkId::new("decaps", alg_name),
            alg_name,
            |b, _| {
                b.iter(|| kem_ctx.decaps(&ct, &sk).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_sig_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("Signature");
    let msg = vec![0x42u8; 1024]; // 1KB test message

    for alg_name in sig::algorithm_names() {
        let sig_ctx = match sig::Signature::new(alg_name) {
            Ok(s) => s,
            Err(_) => continue,
        };

        // Skip stateful algorithms in criterion (they need special handling)
        if sig_ctx.is_stateful() {
            continue;
        }

        group.bench_with_input(
            BenchmarkId::new("keygen", alg_name),
            alg_name,
            |b, _| {
                b.iter(|| sig_ctx.keygen().unwrap());
            },
        );

        let (pk, sk) = sig_ctx.keygen().unwrap();

        group.bench_with_input(
            BenchmarkId::new("sign/1KB", alg_name),
            alg_name,
            |b, _| {
                b.iter(|| sig_ctx.sign(&msg, &sk).unwrap());
            },
        );

        let signature = sig_ctx.sign(&msg, &sk).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify/1KB", alg_name),
            alg_name,
            |b, _| {
                b.iter(|| sig_ctx.verify(&msg, &signature, &pk).unwrap());
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_kem_algorithms, bench_sig_algorithms);
criterion_main!(benches);
