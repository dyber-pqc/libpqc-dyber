// libpqc-dyber - Post-Quantum Cryptography Library
// Copyright (c) 2024-2026 Dyber, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Build script: locates or builds libpqc and generates Rust FFI bindings.

use std::env;
use std::path::PathBuf;

fn main() {
    // Try pkg-config first
    if try_pkg_config() {
        return;
    }

    // Fall back to cmake build
    build_with_cmake();
}

fn try_pkg_config() -> bool {
    match pkg_config::Config::new()
        .atleast_version("0.1.0")
        .probe("libpqc")
    {
        Ok(lib) => {
            for path in &lib.include_paths {
                println!("cargo:include={}", path.display());
            }
            true
        }
        Err(_) => false,
    }
}

fn build_with_cmake() {
    let source_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("..");

    let dst = cmake::Config::new(&source_dir)
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("PQC_BUILD_TESTS", "OFF")
        .define("PQC_BUILD_BINDINGS", "OFF")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-search=native={}/lib64", dst.display());
    println!("cargo:rustc-link-lib=static=pqc");

    // Platform-specific dependencies
    let target = env::var("TARGET").unwrap();
    if target.contains("linux") {
        println!("cargo:rustc-link-lib=dylib=pthread");
    } else if target.contains("windows") {
        println!("cargo:rustc-link-lib=dylib=bcrypt");
    } else if target.contains("apple") {
        println!("cargo:rustc-link-lib=framework=Security");
    }

    println!("cargo:include={}/include", dst.display());
}
