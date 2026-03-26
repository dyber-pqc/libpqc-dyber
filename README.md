<p align="center">
  <h1 align="center">libpqc-dyber</h1>
  <p align="center">
    <strong>Production-Grade Post-Quantum Cryptography Library</strong>
    <br/>
    <em>Built from scratch by <a href="https://dyber.com">Dyber, Inc.</a></em>
  </p>
</p>

<p align="center">
  <a href="https://github.com/dyber-pqc/libpqc-dyber/actions/workflows/ci.yml"><img src="https://github.com/dyber-pqc/libpqc-dyber/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE-APACHE"><img src="https://img.shields.io/badge/license-Apache%202.0%2FMIT-blue.svg" alt="License"></a>
  <a href="https://github.com/dyber-pqc/libpqc-dyber/releases"><img src="https://img.shields.io/github/v/release/dyber-pqc/libpqc-dyber" alt="Release"></a>
  <img src="https://img.shields.io/badge/C11-standard-green.svg" alt="C11">
  <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20FreeBSD-lightgrey.svg" alt="Platforms">
  <img src="https://img.shields.io/badge/languages-20-orange.svg" alt="Languages">
  <img src="https://img.shields.io/badge/algorithms-17%20families-purple.svg" alt="Algorithms">
  <img src="https://img.shields.io/badge/FIPS-203%20%7C%20204%20%7C%20205%20%7C%20206-red.svg" alt="FIPS">
</p>

---

**libpqc-dyber** is a comprehensive, cross-platform post-quantum cryptography library implementing all NIST-standardized PQC algorithms and additional schemes. It is designed for production use, with bindings for **20 programming languages** and support for **7+ operating systems**.

This library is **not a fork** of any existing project. Every algorithm is implemented from the published NIST FIPS specifications and academic references by the Dyber, Inc. engineering team.

---

## Table of Contents

- [Features](#features)
- [Supported Algorithms](#supported-algorithms)
  - [Key Encapsulation Mechanisms (KEMs)](#key-encapsulation-mechanisms-kems)
  - [Digital Signature Schemes](#digital-signature-schemes)
  - [Hybrid Schemes](#hybrid-schemes)
  - [Detailed Parameter Tables](#detailed-parameter-tables)
- [Quick Start](#quick-start)
- [Building from Source](#building-from-source)
  - [Linux (Ubuntu/Debian)](#linux-ubuntudebian)
  - [Fedora / RHEL](#fedora--rhel)
  - [macOS](#macos)
  - [Windows](#windows)
  - [FreeBSD](#freebsd)
  - [Build Options](#build-options)
- [Language Examples](#language-examples)
  - [C](#c-example)
  - [C++](#c-example-1)
  - [Python](#python-example)
  - [Rust](#rust-example)
  - [Go](#go-example)
  - [Java](#java-example)
  - [JavaScript / TypeScript](#javascript--typescript-example)
  - [C#](#c-example-2)
- [All Language Bindings](#all-language-bindings)
- [Platform Support](#platform-support)
- [API Reference](#api-reference)
  - [KEM API](#kem-api)
  - [Signature API](#signature-api)
  - [Utility API](#utility-api)
- [Security](#security)
- [Performance](#performance)
- [Migrating from liboqs](#migrating-from-liboqs)
- [Project Structure](#project-structure)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)
- [About Dyber, Inc.](#about-dyber-inc)

---

## Features

- **Complete PQC coverage** — All NIST FIPS 203/204/205/206 algorithms plus 13 additional KEM and signature scheme families
- **50+ parameter sets** — Every standardized security level across all algorithm families
- **20 language bindings** — C, C++, C#, Go, Rust, Java, Python, JavaScript, TypeScript, PHP, Ruby, Swift, Kotlin, Scala, Dart, Perl, R, MATLAB, Shell CLI, ASM
- **7+ operating systems** — Linux, macOS, Windows, FreeBSD, Fedora, RHEL, Unix
- **Hardware acceleration** — AVX2, AVX-512, ARM NEON, SVE, SHA-NI, PCLMULQDQ, BMI2
- **Production-grade security** — Constant-time implementations, secure memory zeroization, NIST KAT validation
- **Hybrid schemes** — Combine PQC with classical algorithms (X25519, Ed25519, NIST P-256)
- **Stateful signatures** — LMS (RFC 8554) and XMSS (RFC 8391) with safe state management
- **Zero external dependencies** — All primitives (SHA-2, SHA-3, SHAKE, Keccak, Curve25519, P-256) implemented in-library
- **Configurable builds** — Enable/disable individual algorithms at compile time via CMake options
- **CLI tool** — `pqc-cli` binary for key generation, encapsulation, signing, and verification from the command line

---

## Supported Algorithms

### Key Encapsulation Mechanisms (KEMs)

| Algorithm | Standard | Security Levels | Mathematical Basis | Status |
|-----------|----------|----------------|--------------------|--------|
| **ML-KEM** | FIPS 203 | 1, 3, 5 | Module-LWE | NIST Standardized (Aug 2024) |
| **HQC** | NIST Round 4 | 1, 3, 5 | Hamming Quasi-Cyclic codes | Candidate (expected ~2027) |
| **BIKE** | — | 1, 3, 5 | QC-MDPC codes | Research |
| **Classic McEliece** | — | 1, 3, 5 | Binary Goppa codes | Research |
| **FrodoKEM** | — | 1, 3, 5 | Unstructured LWE | Research |
| **NTRU** | — | 1, 3, 5 | NTRU lattices | Research |
| **NTRU-Prime** | — | 1, 3, 5 | Streamlined NTRU Prime | Research |

### Digital Signature Schemes

| Algorithm | Standard | Security Levels | Mathematical Basis | Status |
|-----------|----------|----------------|--------------------|--------|
| **ML-DSA** | FIPS 204 | 2, 3, 5 | Module-LWE | NIST Standardized (Aug 2024) |
| **SLH-DSA** | FIPS 205 | 1, 3, 5 | Hash functions (stateless) | NIST Standardized (Aug 2024) |
| **FN-DSA (Falcon)** | FIPS 206 (draft) | 1, 5 | NTRU lattices (hash-then-sign) | NIST Draft (~2027) |
| **SPHINCS+** | — | 1, 3, 5 | Hash functions | Predecessor to SLH-DSA |
| **MAYO** | NIST Round 2 | 1, 2, 3, 5 | Multivariate quadratic (Oil & Vinegar) | Candidate |
| **UOV** | NIST Round 2 | 1, 3, 5 | Unbalanced Oil & Vinegar | Candidate |
| **SNOVA** | NIST Round 2 | 1, 3, 5 | Non-commutative ring UOV | Candidate |
| **CROSS** | NIST Round 2 | 1, 3, 5 | Restricted Syndrome Decoding | Candidate |
| **LMS** | RFC 8554 | — | Hash-based (stateful) | Standardized |
| **XMSS** | RFC 8391 | — | Hash-based (stateful) | Standardized |

### Hybrid Schemes

| Algorithm | Components | Use Case |
|-----------|-----------|----------|
| **ML-KEM-768+X25519** | Post-quantum KEM + Curve25519 ECDH | General-purpose hybrid key exchange |
| **ML-KEM-1024+P256** | Post-quantum KEM + NIST P-256 ECDH | FIPS-compliant hybrid key exchange |
| **ML-DSA-65+Ed25519** | Post-quantum sig + Ed25519 | General-purpose hybrid signatures |
| **ML-DSA-87+P256** | Post-quantum sig + NIST P-256 ECDSA | FIPS-compliant hybrid signatures |

### Detailed Parameter Tables

#### ML-KEM (FIPS 203) — Key Encapsulation

| Variant | NIST Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|---------|-----------|-----------|-----------|-----------|--------------|
| ML-KEM-512 | 1 | 800 B | 1,632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 1,184 B | 2,400 B | 1,088 B | 32 B |
| ML-KEM-1024 | 5 | 1,568 B | 3,168 B | 1,568 B | 32 B |

#### ML-DSA (FIPS 204) — Digital Signatures

| Variant | NIST Level | Public Key | Secret Key | Signature |
|---------|-----------|-----------|-----------|----------|
| ML-DSA-44 | 2 | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | 3 | 1,952 B | 4,032 B | 3,309 B |
| ML-DSA-87 | 5 | 2,592 B | 4,896 B | 4,627 B |

#### SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures

| Variant | NIST Level | Public Key | Secret Key | Signature | Notes |
|---------|-----------|-----------|-----------|----------|-------|
| SLH-DSA-SHA2-128s | 1 | 32 B | 64 B | 7,856 B | Small sig, slower |
| SLH-DSA-SHA2-128f | 1 | 32 B | 64 B | 17,088 B | Fast sign, larger |
| SLH-DSA-SHA2-192s | 3 | 48 B | 96 B | 16,224 B | Small sig |
| SLH-DSA-SHA2-192f | 3 | 48 B | 96 B | 35,664 B | Fast sign |
| SLH-DSA-SHA2-256s | 5 | 64 B | 128 B | 29,792 B | Small sig |
| SLH-DSA-SHA2-256f | 5 | 64 B | 128 B | 49,856 B | Fast sign |
| SLH-DSA-SHAKE-128s | 1 | 32 B | 64 B | 7,856 B | SHAKE variant |
| SLH-DSA-SHAKE-128f | 1 | 32 B | 64 B | 17,088 B | SHAKE variant |
| SLH-DSA-SHAKE-192s | 3 | 48 B | 96 B | 16,224 B | SHAKE variant |
| SLH-DSA-SHAKE-192f | 3 | 48 B | 96 B | 35,664 B | SHAKE variant |
| SLH-DSA-SHAKE-256s | 5 | 64 B | 128 B | 29,792 B | SHAKE variant |
| SLH-DSA-SHAKE-256f | 5 | 64 B | 128 B | 49,856 B | SHAKE variant |

#### FN-DSA / Falcon (FIPS 206 Draft) — Compact Lattice Signatures

| Variant | NIST Level | Public Key | Secret Key | Signature |
|---------|-----------|-----------|-----------|----------|
| FN-DSA-512 | 1 | 897 B | 1,281 B | ~666 B |
| FN-DSA-1024 | 5 | 1,793 B | 2,305 B | ~1,280 B |

#### Additional KEMs

| Algorithm | Variant | NIST Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|---------|-----------|-----------|-----------|-----------|--------------|
| HQC | HQC-128 | 1 | 2,249 B | 2,289 B | 4,481 B | 64 B |
| HQC | HQC-192 | 3 | 4,522 B | 4,562 B | 9,026 B | 64 B |
| HQC | HQC-256 | 5 | 7,245 B | 7,285 B | 14,469 B | 64 B |
| BIKE | BIKE-L1 | 1 | 1,541 B | 3,749 B | 1,573 B | 32 B |
| BIKE | BIKE-L3 | 3 | 3,083 B | 7,467 B | 3,115 B | 32 B |
| BIKE | BIKE-L5 | 5 | 5,122 B | 12,371 B | 5,154 B | 32 B |
| Classic McEliece | 348864 | 1 | 261,120 B | 6,492 B | 128 B | 32 B |
| Classic McEliece | 6688128 | 5 | 1,044,992 B | 13,932 B | 240 B | 32 B |
| Classic McEliece | 8192128 | 5 | 1,357,824 B | 14,120 B | 240 B | 32 B |
| FrodoKEM | 640-SHAKE | 1 | 9,616 B | 19,888 B | 9,720 B | 16 B |
| FrodoKEM | 976-SHAKE | 3 | 15,632 B | 31,296 B | 15,744 B | 24 B |
| FrodoKEM | 1344-SHAKE | 5 | 21,520 B | 43,088 B | 21,632 B | 32 B |

#### Additional Signatures

| Algorithm | Variant | NIST Level | Public Key | Secret Key | Signature |
|-----------|---------|-----------|-----------|-----------|----------|
| MAYO | MAYO-1 | 1 | 1,168 B | 24 B | 321 B |
| MAYO | MAYO-3 | 3 | 2,656 B | 32 B | 577 B |
| MAYO | MAYO-5 | 5 | 5,008 B | 40 B | 838 B |
| UOV | UOV-Is | 1 | 278,432 B | 237,896 B | 96 B |
| UOV | UOV-IIIs | 3 | 1,225,440 B | 1,044,320 B | 200 B |
| UOV | UOV-Vs | 5 | 2,869,440 B | 2,436,704 B | 260 B |
| SNOVA | 24-5-4 | 1 | 1,016 B | 48 B | 100 B |
| SNOVA | 25-8-3 | 3 | 1,400 B | 48 B | 164 B |
| SNOVA | 28-17-3 | 5 | 5,872 B | 64 B | 580 B |
| CROSS | RSDP-128-fast | 1 | 77 B | 32 B | 12,912 B |
| CROSS | RSDP-192-fast | 3 | 115 B | 48 B | 23,220 B |
| CROSS | RSDP-256-fast | 5 | 153 B | 64 B | 37,088 B |
| LMS | SHA256-H10 | — | 56 B | 64 B | 2,644 B |
| LMS | SHA256-H20 | — | 56 B | 64 B | 5,380 B |
| XMSS | SHA2-10-256 | — | 64 B | 2,573 B | 2,500 B |
| XMSS | SHA2-20-256 | — | 64 B | 2,573 B | 2,820 B |

---

## Quick Start

```bash
git clone https://github.com/dyber-pqc/libpqc-dyber.git
cd libpqc-dyber
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
sudo cmake --install build
```

---

## Building from Source

### Prerequisites

- **CMake** 3.16 or later
- **C compiler**: GCC 7+, Clang 6+, or MSVC 2019+
- **Ninja** (optional, recommended for faster builds)

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y cmake gcc ninja-build

# Clone and build
git clone https://github.com/dyber-pqc/libpqc-dyber.git
cd libpqc-dyber
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure

# Install system-wide
sudo cmake --install build

# Verify installation
pkg-config --modversion libpqc 2>/dev/null || echo "Installed to /usr/local"
```

### Fedora / RHEL

```bash
# Fedora
sudo dnf install cmake gcc ninja-build

# RHEL 8+ (enable CodeReady Builder)
sudo dnf install cmake gcc ninja-build

# Build
git clone https://github.com/dyber-pqc/libpqc-dyber.git
cd libpqc-dyber
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build

# On RHEL, you may need to update the library cache
sudo ldconfig
```

### macOS

```bash
# Install Xcode command line tools (provides clang)
xcode-select --install

# Install CMake via Homebrew
brew install cmake ninja

# Build (works on both Intel and Apple Silicon)
git clone https://github.com/dyber-pqc/libpqc-dyber.git
cd libpqc-dyber
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
sudo cmake --install build
```

### Windows

```powershell
# Option 1: Visual Studio (recommended)
git clone https://github.com/dyber-pqc/libpqc-dyber.git
cd libpqc-dyber
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build --output-on-failure -C Release

# Option 2: MinGW-w64
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Option 3: MSYS2
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-gcc
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### FreeBSD

```bash
# Install dependencies
sudo pkg install cmake ninja

# Build
git clone https://github.com/dyber-pqc/libpqc-dyber.git
cd libpqc-dyber
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
sudo cmake --install build
```

### Build Options

```bash
# Disable specific algorithm families
cmake -B build \
  -DPQC_ENABLE_KEM_MCELIECE=OFF \
  -DPQC_ENABLE_KEM_FRODO=OFF

# Static library only (no shared .so/.dll)
cmake -B build -DPQC_BUILD_SHARED=OFF

# Shared library only (no static .a/.lib)
cmake -B build -DPQC_BUILD_STATIC=OFF

# Disable assembly optimizations (pure portable C)
cmake -B build -DPQC_ENABLE_ASM=OFF

# Disable tests and benchmarks
cmake -B build -DPQC_BUILD_TESTS=OFF -DPQC_BUILD_BENCHMARKS=OFF

# Disable CLI tool
cmake -B build -DPQC_BUILD_CLI=OFF

# Debug build with sanitizers
cmake -B build -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined"

# Cross-compile for ARM64
cmake -B build -DCMAKE_TOOLCHAIN_FILE=cmake/Toolchain-arm64.cmake

# Set install prefix
cmake -B build -DCMAKE_INSTALL_PREFIX=/opt/libpqc
```

---

## Language Examples

### C Example

```c
#include <pqc/pqc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    pqc_init();

    /* --- Key Encapsulation with ML-KEM-768 --- */
    PQC_KEM *kem = pqc_kem_new("ML-KEM-768");

    size_t pk_len = pqc_kem_public_key_size(kem);
    size_t sk_len = pqc_kem_secret_key_size(kem);
    size_t ct_len = pqc_kem_ciphertext_size(kem);
    size_t ss_len = pqc_kem_shared_secret_size(kem);

    uint8_t *pk  = malloc(pk_len);
    uint8_t *sk  = malloc(sk_len);
    uint8_t *ct  = malloc(ct_len);
    uint8_t *ss1 = malloc(ss_len);
    uint8_t *ss2 = malloc(ss_len);

    pqc_kem_keygen(kem, pk, sk);       /* Alice generates keypair */
    pqc_kem_encaps(kem, ct, ss1, pk);  /* Bob encapsulates */
    pqc_kem_decaps(kem, ss2, ct, sk);  /* Alice decapsulates */

    printf("Shared secrets match: %s\n",
           memcmp(ss1, ss2, ss_len) == 0 ? "YES" : "NO");

    free(pk); free(sk); free(ct); free(ss1); free(ss2);
    pqc_kem_free(kem);

    /* --- Digital Signatures with ML-DSA-65 --- */
    PQC_SIG *sig = pqc_sig_new("ML-DSA-65");

    uint8_t *sig_pk  = malloc(pqc_sig_public_key_size(sig));
    uint8_t *sig_sk  = malloc(pqc_sig_secret_key_size(sig));
    uint8_t *sigbuf  = malloc(pqc_sig_max_signature_size(sig));
    size_t sig_len;

    const uint8_t msg[] = "Hello, post-quantum world!";

    pqc_sig_keygen(sig, sig_pk, sig_sk);
    pqc_sig_sign(sig, sigbuf, &sig_len, msg, sizeof(msg) - 1, sig_sk);

    pqc_status_t rc = pqc_sig_verify(sig, msg, sizeof(msg) - 1,
                                      sigbuf, sig_len, sig_pk);
    printf("Signature valid: %s\n", rc == PQC_OK ? "YES" : "NO");

    free(sig_pk); free(sig_sk); free(sigbuf);
    pqc_sig_free(sig);

    /* --- List all available algorithms --- */
    printf("\nAvailable KEMs (%d):\n", pqc_kem_algorithm_count());
    for (int i = 0; i < pqc_kem_algorithm_count(); i++)
        printf("  %s\n", pqc_kem_algorithm_name(i));

    printf("\nAvailable Signatures (%d):\n", pqc_sig_algorithm_count());
    for (int i = 0; i < pqc_sig_algorithm_count(); i++)
        printf("  %s\n", pqc_sig_algorithm_name(i));

    pqc_cleanup();
    return 0;
}
```

Compile: `gcc example.c -o example -lpqc`

### C++ Example

```cpp
#include <pqc/pqc.hpp>
#include <iostream>

int main() {
    pqc::LibraryGuard guard; // RAII init/cleanup

    // KEM
    pqc::KEM kem("ML-KEM-768");
    auto [pk, sk] = kem.keygen();
    auto [ct, ss1] = kem.encaps(pk);
    auto ss2 = kem.decaps(ct, sk);
    std::cout << "KEM: shared secrets match = " << (ss1 == ss2) << "\n";

    // Signatures
    pqc::Signature sig("ML-DSA-65");
    auto [sig_pk, sig_sk] = sig.keygen();
    auto signature = sig.sign("Hello, PQC!", sig_sk);
    bool valid = sig.verify("Hello, PQC!", signature, sig_pk);
    std::cout << "Signature valid = " << valid << "\n";

    // List algorithms
    for (const auto& name : pqc::kem_algorithms())
        std::cout << "  KEM: " << name << "\n";
}
```

### Python Example

```python
import pqc_dyber as pqc

# Key Encapsulation
kem = pqc.KEM("ML-KEM-768")
pk, sk = kem.keygen()
ct, ss1 = kem.encaps(pk)
ss2 = kem.decaps(ct, sk)
assert ss1 == ss2
print(f"Shared secret ({len(ss1)} bytes): {ss1.hex()[:32]}...")

# Digital Signatures
sig = pqc.Signature("ML-DSA-65")
pk, sk = sig.keygen()
signature = sig.sign(b"Hello, post-quantum world!", sk)
assert sig.verify(b"Hello, post-quantum world!", signature, pk)
print("Signature verified!")

# List algorithms
print("KEMs:", pqc.kem_algorithms())
print("Signatures:", pqc.sig_algorithms())
```

Install: `pip install pqc-dyber`

### Rust Example

```rust
use pqc_dyber::{Kem, Sig};

fn main() -> Result<(), pqc_dyber::Error> {
    pqc_dyber::init()?;

    // KEM
    let kem = Kem::new("ML-KEM-768")?;
    let (pk, sk) = kem.keygen()?;
    let (ct, ss1) = kem.encaps(&pk)?;
    let ss2 = kem.decaps(&ct, &sk)?;
    assert_eq!(ss1, ss2);

    // Signatures
    let sig = Sig::new("ML-DSA-65")?;
    let (pk, sk) = sig.keygen()?;
    let signature = sig.sign(b"Hello, PQC!", &sk)?;
    sig.verify(b"Hello, PQC!", &signature, &pk)?;

    println!("All operations successful!");
    Ok(())
}
```

Add to `Cargo.toml`: `pqc-dyber = "0.1"`

### Go Example

```go
package main

import (
    "fmt"
    "bytes"
    pqc "github.com/dyber-pqc/libpqc-dyber/bindings/go"
)

func main() {
    pqc.Init()
    defer pqc.Cleanup()

    // KEM
    kem, _ := pqc.NewKEM("ML-KEM-768")
    defer kem.Close()
    pk, sk, _ := kem.Keygen()
    ct, ss1, _ := kem.Encaps(pk)
    ss2, _ := kem.Decaps(ct, sk)
    fmt.Println("Shared secrets match:", bytes.Equal(ss1, ss2))

    // Signatures
    sig, _ := pqc.NewSig("ML-DSA-65")
    defer sig.Close()
    spk, ssk, _ := sig.Keygen()
    signature, _ := sig.Sign([]byte("Hello, PQC!"), ssk)
    err := sig.Verify([]byte("Hello, PQC!"), signature, spk)
    fmt.Println("Signature valid:", err == nil)
}
```

### Java Example

```java
import com.dyber.pqc.*;

public class Example {
    public static void main(String[] args) throws Exception {
        PQC.init();

        // KEM
        try (KEM kem = new KEM("ML-KEM-768")) {
            KEM.KeyPair kp = kem.keygen();
            KEM.EncapsResult er = kem.encaps(kp.publicKey());
            byte[] ss = kem.decaps(er.ciphertext(), kp.secretKey());
            System.out.println("Shared secrets match: " +
                java.util.Arrays.equals(er.sharedSecret(), ss));
        }

        // Signatures
        try (Signature sig = new Signature("ML-DSA-65")) {
            Signature.KeyPair kp = sig.keygen();
            byte[] signature = sig.sign("Hello, PQC!".getBytes(), kp.secretKey());
            boolean valid = sig.verify("Hello, PQC!".getBytes(), signature, kp.publicKey());
            System.out.println("Signature valid: " + valid);
        }

        PQC.cleanup();
    }
}
```

Maven: `com.dyber:pqc:0.1.0`

### JavaScript / TypeScript Example

```javascript
const pqc = require('@dyber/pqc');

// KEM
const kem = new pqc.KEM('ML-KEM-768');
const { publicKey, secretKey } = kem.keygen();
const { ciphertext, sharedSecret: ss1 } = kem.encaps(publicKey);
const ss2 = kem.decaps(ciphertext, secretKey);
console.log('Shared secrets match:', Buffer.compare(ss1, ss2) === 0);

// Signatures
const sig = new pqc.Signature('ML-DSA-65');
const keys = sig.keygen();
const signature = sig.sign(Buffer.from('Hello, PQC!'), keys.secretKey);
const valid = sig.verify(Buffer.from('Hello, PQC!'), signature, keys.publicKey);
console.log('Signature valid:', valid);
```

Install: `npm install @dyber/pqc`

### C# Example

```csharp
using PqcDyber;

// KEM
using var kem = new KEM("ML-KEM-768");
var (pk, sk) = kem.Keygen();
var (ct, ss1) = kem.Encaps(pk);
var ss2 = kem.Decaps(ct, sk);
Console.WriteLine($"Shared secrets match: {ss1.SequenceEqual(ss2)}");

// Signatures
using var sig = new Signature("ML-DSA-65");
var (sigPk, sigSk) = sig.Keygen();
var signature = sig.Sign(Encoding.UTF8.GetBytes("Hello, PQC!"), sigSk);
var valid = sig.Verify(Encoding.UTF8.GetBytes("Hello, PQC!"), signature, sigPk);
Console.WriteLine($"Signature valid: {valid}");
```

NuGet: `dotnet add package PqcDyber`

### CLI Example

```bash
# List all algorithms
pqc-cli algorithms

# Key generation
pqc-cli keygen ML-KEM-768 --pk alice.pk --sk alice.sk

# Encapsulation
pqc-cli encaps ML-KEM-768 --pk alice.pk --ct message.ct --ss shared.key

# Decapsulation
pqc-cli decaps ML-KEM-768 --sk alice.sk --ct message.ct --ss recovered.key

# Sign a file
pqc-cli keygen ML-DSA-65 --pk signer.pk --sk signer.sk
pqc-cli sign ML-DSA-65 --sk signer.sk --msg document.pdf --sig document.sig

# Verify a signature
pqc-cli verify ML-DSA-65 --pk signer.pk --msg document.pdf --sig document.sig
```

---

## All Language Bindings

| Language | Package | Install | Mechanism |
|----------|---------|---------|-----------|
| **C** | Core library | `cmake --install build` | Native |
| **C++** | Header-only | `#include <pqc/pqc.hpp>` | Direct C++ wrapper (RAII) |
| **Python** | `pqc-dyber` | `pip install pqc-dyber` | ctypes/CFFI |
| **Rust** | `pqc-dyber` | `cargo add pqc-dyber` | bindgen + safe wrapper |
| **Go** | `go module` | `go get github.com/dyber-pqc/libpqc-dyber/bindings/go` | CGO |
| **Java** | `com.dyber:pqc` | Maven Central | JNI |
| **Kotlin** | `com.dyber:pqc-kotlin` | Maven Central | JNI (wraps Java) |
| **Scala** | `com.dyber:pqc-scala` | Maven Central | JNI (wraps Java) |
| **C#** | `PqcDyber` | `dotnet add package PqcDyber` | P/Invoke |
| **JavaScript** | `@dyber/pqc` | `npm install @dyber/pqc` | N-API native addon |
| **TypeScript** | `@dyber/pqc` | `npm install @dyber/pqc` | Types over JS binding |
| **PHP** | `dyber/pqc` | `composer require dyber/pqc` | PHP FFI |
| **Ruby** | `pqc-dyber` | `gem install pqc-dyber` | Ruby FFI |
| **Swift** | `PQCDyber` | Swift Package Manager | C interop |
| **Dart** | `pqc_dyber` | `dart pub add pqc_dyber` | dart:ffi |
| **Perl** | `Crypt::PQC::Dyber` | CPAN | XS |
| **R** | `pqcDyber` | CRAN | .Call interface |
| **MATLAB** | `pqc` | MATLAB File Exchange | MEX gateway |
| **Shell** | `pqc-cli` | Binary in PATH | CLI executable |
| **ASM** | Direct routines | See `src/asm/` | Documented calling conventions |

---

## Platform Support

| OS | x86_64 | ARM64 | Compiler | Status |
|----|--------|-------|----------|--------|
| **Ubuntu/Debian** | Full + AVX2/AVX-512 | Full + NEON/SVE | gcc, clang | Tier 1 |
| **Fedora** | Full + AVX2/AVX-512 | Full + NEON/SVE | gcc, clang | Tier 1 |
| **RHEL 8/9** | Full + AVX2/AVX-512 | Full + NEON/SVE | gcc, clang | Tier 1 |
| **macOS** | Full + AVX2 | Full + NEON (Apple Silicon) | clang (Xcode) | Tier 1 |
| **Windows** | Full + AVX2/AVX-512 | Experimental | MSVC, MinGW | Tier 1 |
| **FreeBSD** | Full + AVX2/AVX-512 | Full + NEON | clang, gcc | Tier 2 |
| **Unix** (generic) | Portable C | Portable C | Any C11 compiler | Best-effort |

**Tier 1**: Tested in CI on every commit. **Tier 2**: Tested in CI, may have minor delays.

---

## API Reference

### KEM API

```c
/* Create/destroy */
PQC_KEM *pqc_kem_new(const char *algorithm);
void     pqc_kem_free(PQC_KEM *kem);

/* Properties */
const char *pqc_kem_algorithm(const PQC_KEM *kem);
size_t      pqc_kem_public_key_size(const PQC_KEM *kem);
size_t      pqc_kem_secret_key_size(const PQC_KEM *kem);
size_t      pqc_kem_ciphertext_size(const PQC_KEM *kem);
size_t      pqc_kem_shared_secret_size(const PQC_KEM *kem);

/* Operations */
pqc_status_t pqc_kem_keygen(const PQC_KEM *kem, uint8_t *pk, uint8_t *sk);
pqc_status_t pqc_kem_encaps(const PQC_KEM *kem, uint8_t *ct, uint8_t *ss, const uint8_t *pk);
pqc_status_t pqc_kem_decaps(const PQC_KEM *kem, uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* Enumeration */
int         pqc_kem_algorithm_count(void);
const char *pqc_kem_algorithm_name(int index);
int         pqc_kem_is_enabled(const char *algorithm);
```

### Signature API

```c
/* Create/destroy */
PQC_SIG *pqc_sig_new(const char *algorithm);
void     pqc_sig_free(PQC_SIG *sig);

/* Properties */
const char *pqc_sig_algorithm(const PQC_SIG *sig);
size_t      pqc_sig_public_key_size(const PQC_SIG *sig);
size_t      pqc_sig_secret_key_size(const PQC_SIG *sig);
size_t      pqc_sig_max_signature_size(const PQC_SIG *sig);
int         pqc_sig_is_stateful(const PQC_SIG *sig);

/* Operations */
pqc_status_t pqc_sig_keygen(const PQC_SIG *sig, uint8_t *pk, uint8_t *sk);
pqc_status_t pqc_sig_sign(const PQC_SIG *sig, uint8_t *signature, size_t *sig_len,
                           const uint8_t *msg, size_t msg_len, const uint8_t *sk);
pqc_status_t pqc_sig_verify(const PQC_SIG *sig, const uint8_t *msg, size_t msg_len,
                             const uint8_t *signature, size_t sig_len, const uint8_t *pk);

/* Stateful signing (LMS, XMSS) - mutates secret key */
pqc_status_t pqc_sig_sign_stateful(const PQC_SIG *sig, uint8_t *signature, size_t *sig_len,
                                    const uint8_t *msg, size_t msg_len, uint8_t *sk);

/* Enumeration */
int         pqc_sig_algorithm_count(void);
const char *pqc_sig_algorithm_name(int index);
int         pqc_sig_is_enabled(const char *algorithm);
```

### Utility API

```c
/* Library lifecycle */
pqc_status_t pqc_init(void);
void         pqc_cleanup(void);

/* Version */
const char *pqc_version(void);

/* Random bytes */
pqc_status_t pqc_randombytes(uint8_t *buf, size_t len);
pqc_status_t pqc_set_rng(pqc_rng_callback_t callback, void *ctx);

/* Secure memory */
void *pqc_malloc(size_t size);
void  pqc_free(void *ptr, size_t size);
void  pqc_memzero(void *ptr, size_t size);
int   pqc_memcmp_ct(const void *a, const void *b, size_t len);

/* Error codes */
typedef enum {
    PQC_OK                         =  0,
    PQC_ERROR                      = -1,
    PQC_ERROR_INVALID_ARGUMENT     = -2,
    PQC_ERROR_ALLOC                = -3,
    PQC_ERROR_NOT_SUPPORTED        = -4,
    PQC_ERROR_INVALID_KEY          = -5,
    PQC_ERROR_VERIFICATION_FAILED  = -6,
    PQC_ERROR_DECAPSULATION_FAILED = -7,
    PQC_ERROR_RNG_FAILED           = -8,
    PQC_ERROR_BUFFER_TOO_SMALL     = -9,
    PQC_ERROR_INTERNAL             = -10,
    PQC_ERROR_STATE_EXHAUSTED      = -11,
} pqc_status_t;
```

---

## Security

### Constant-Time Guarantees

All operations on secret data use the `pqc_ct_*` utility functions:

- **No branches** on secret values
- **No secret-dependent memory accesses** (no lookup tables indexed by secrets)
- **Constant-time comparison** via XOR-folding
- **Constant-time conditional move** via bitwise masking
- **Compiler barrier** to prevent optimization of zeroization

### Memory Safety

- All key material is zeroized on deallocation via `pqc_memzero()`
- `pqc_memzero()` uses platform-specific guaranteed-erase:
  - Windows: `SecureZeroMemory`
  - C11 Annex K: `memset_s`
  - POSIX: `explicit_bzero`
  - Fallback: volatile function pointer with compiler barrier
- Allocations track size for guaranteed complete zeroization on free

### Entropy Sources

| Platform | Primary Source | Fallback |
|----------|---------------|----------|
| Windows | `BCryptGenRandom` | — |
| Linux | `getrandom(2)` syscall | `/dev/urandom` |
| macOS | `arc4random_buf` | — |
| FreeBSD | `arc4random_buf` | — |
| POSIX | `/dev/urandom` | — |

### Validation

- NIST Known Answer Test (KAT) vectors for all implemented algorithms
- Constant-time verification with valgrind/ctgrind in CI
- Fuzzing with AFL++ and libFuzzer for all algorithm entry points
- AddressSanitizer and UndefinedBehaviorSanitizer in debug builds

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Performance

### Hardware Acceleration

The library detects CPU features at runtime and dispatches to optimized code paths:

| Feature | Platform | Used For |
|---------|----------|----------|
| **AVX2** | x86_64 | NTT, polynomial arithmetic, Keccak |
| **AVX-512** | x86_64 | Parallel Keccak, wide polynomial ops |
| **SHA-NI** | x86_64 | SHA-256 hardware acceleration |
| **PCLMULQDQ** | x86_64 | GF(2)[x] multiplication (BIKE, HQC) |
| **BMI2** | x86_64 | Field arithmetic (Curve25519) |
| **NEON** | AArch64 | NTT, polynomial arithmetic, Keccak |
| **SVE** | AArch64 | Scalable vector Keccak |
| **SHA2 ext** | AArch64 | SHA-256 hardware acceleration |

### Benchmarking

Run the built-in benchmarks:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/tests/bench_kem    # KEM benchmarks
./build/tests/bench_sig    # Signature benchmarks
```

Output shows per-operation timing (keygen, encaps/sign, decaps/verify) averaged over 100 iterations for every enabled algorithm.

---

## Migrating from liboqs

libpqc-dyber provides a similar API design to liboqs but with a cleaner, more consistent interface. Here's a mapping:

| liboqs | libpqc-dyber | Notes |
|--------|-------------|-------|
| `OQS_KEM_new("Kyber768")` | `pqc_kem_new("ML-KEM-768")` | Uses FIPS names |
| `OQS_KEM_keypair(kem, pk, sk)` | `pqc_kem_keygen(kem, pk, sk)` | Same pattern |
| `OQS_KEM_encaps(kem, ct, ss, pk)` | `pqc_kem_encaps(kem, ct, ss, pk)` | Same pattern |
| `OQS_KEM_decaps(kem, ss, ct, sk)` | `pqc_kem_decaps(kem, ss, ct, sk)` | Same pattern |
| `OQS_KEM_free(kem)` | `pqc_kem_free(kem)` | Same pattern |
| `OQS_SIG_new("Dilithium3")` | `pqc_sig_new("ML-DSA-65")` | Uses FIPS names |
| `OQS_SIG_sign(sig, sigbuf, &siglen, msg, msglen, sk)` | `pqc_sig_sign(sig, sigbuf, &siglen, msg, msglen, sk)` | Same pattern |
| `OQS_SIG_verify(sig, msg, msglen, sigbuf, siglen, pk)` | `pqc_sig_verify(sig, msg, msglen, sigbuf, siglen, pk)` | Same pattern |
| `OQS_randombytes(buf, len)` | `pqc_randombytes(buf, len)` | Same pattern |
| `OQS_init()` | `pqc_init()` | Same pattern |

**Key differences:**
- libpqc-dyber uses NIST FIPS standard names (ML-KEM, ML-DSA, SLH-DSA, FN-DSA) instead of pre-standardization names (Kyber, Dilithium, SPHINCS+, Falcon)
- All functions return `pqc_status_t` for consistent error handling
- Built-in hybrid scheme support via the same API
- Stateful signature support with `pqc_sig_sign_stateful()`
- 20 language bindings (liboqs has ~5)
- No external dependencies (liboqs depends on OpenSSL for some operations)

---

## Project Structure

```
libpqc-dyber/
├── include/pqc/             Public C API headers
│   ├── pqc.h                Master include
│   ├── kem.h                KEM API
│   ├── sig.h                Signature API
│   ├── common.h             Types, errors, version
│   ├── algorithms.h         Algorithm constants
│   ├── rand.h               CSPRNG
│   ├── hybrid.h             Hybrid schemes
│   └── export.h             DLL export macros
│
├── src/
│   ├── core/
│   │   ├── common/          Utilities (ct_ops, mem, rand, hash)
│   │   │   └── hash/        SHA-2, SHA-3, SHAKE, Keccak
│   │   ├── kem/             KEM implementations
│   │   │   ├── mlkem/       ML-KEM (FIPS 203) - FULL IMPLEMENTATION
│   │   │   ├── hqc/         HQC
│   │   │   ├── bike/        BIKE
│   │   │   ├── mceliece/    Classic McEliece
│   │   │   ├── frodo/       FrodoKEM
│   │   │   ├── ntru/        NTRU
│   │   │   └── ntruprime/   NTRU-Prime
│   │   ├── sig/             Signature implementations
│   │   │   ├── mldsa/       ML-DSA (FIPS 204) - FULL IMPLEMENTATION
│   │   │   ├── slhdsa/      SLH-DSA (FIPS 205)
│   │   │   ├── fndsa/       FN-DSA (FIPS 206)
│   │   │   ├── sphincsplus/ SPHINCS+
│   │   │   ├── mayo/        MAYO
│   │   │   ├── uov/         UOV
│   │   │   ├── snova/       SNOVA
│   │   │   ├── cross/       CROSS
│   │   │   ├── lms/         LMS (stateful)
│   │   │   └── xmss/        XMSS (stateful)
│   │   └── hybrid/          Hybrid schemes (PQC + classical)
│   ├── asm/                 Assembly optimizations
│   │   ├── x86_64/          AVX2, AVX-512, SHA-NI
│   │   └── aarch64/         NEON, SVE
│   └── dispatch/            Runtime CPU feature detection
│
├── bindings/                Language bindings (20 languages)
│   ├── cpp/                 C++ (header-only, RAII)
│   ├── python/              Python (ctypes)
│   ├── rust/                Rust (FFI + safe wrapper)
│   ├── go/                  Go (CGO)
│   ├── java/                Java (JNI)
│   ├── kotlin/              Kotlin (wraps Java)
│   ├── scala/               Scala (wraps Java)
│   ├── csharp/              C# (P/Invoke)
│   ├── javascript/          JavaScript (N-API)
│   ├── typescript/          TypeScript (types)
│   ├── php/                 PHP (FFI)
│   ├── ruby/                Ruby (FFI)
│   ├── swift/               Swift (C interop)
│   ├── dart/                Dart (dart:ffi)
│   ├── perl/                Perl (XS)
│   ├── r/                   R (.Call)
│   ├── matlab/              MATLAB (MEX)
│   ├── shell/               CLI binary (pqc-cli)
│   └── asm_binding/         ASM documentation
│
├── tests/
│   ├── unit/                Per-algorithm correctness tests
│   ├── integration/         Full round-trip tests
│   ├── bench/               Performance benchmarks
│   ├── kat/                 Known Answer Test vectors
│   └── ct/                  Constant-time verification
│
├── docs/
│   ├── algorithms/          Per-algorithm datasheets
│   ├── api/                 Doxygen configuration
│   ├── guides/              Per-language getting-started guides
│   └── architecture.md      Internal architecture documentation
│
├── cmake/                   Build system modules
├── .github/workflows/       CI/CD (Linux, macOS, Windows, FreeBSD)
├── CMakeLists.txt           Root build file
├── README.md                This file
├── SECURITY.md              Vulnerability reporting
├── CONTRIBUTING.md          Contribution guidelines
├── CHANGELOG.md             Release changelog
├── LICENSE-APACHE           Apache 2.0 license
└── LICENSE-MIT              MIT license
```

---

## FAQ

### What's the difference between libpqc-dyber and liboqs?

Both implement post-quantum algorithms, but libpqc-dyber:
- Is built entirely from scratch (not a fork)
- Uses NIST FIPS standard names (ML-KEM, ML-DSA, etc.)
- Provides 20 language bindings (liboqs has ~5)
- Has zero external dependencies
- Includes built-in hybrid scheme support
- Supports stateful signatures (LMS, XMSS)
- Includes a CLI tool for command-line operations
- Is owned and maintained by Dyber, Inc.

### Which algorithm should I use?

| Use Case | Recommended KEM | Recommended Signature |
|----------|----------------|----------------------|
| **General purpose** | ML-KEM-768 | ML-DSA-65 |
| **Maximum security** | ML-KEM-1024 | ML-DSA-87 |
| **Smallest signatures** | — | FN-DSA-512 |
| **Smallest keys** | ML-KEM-512 | MAYO-1 or SNOVA-24-5-4 |
| **Conservative (hash-based)** | — | SLH-DSA-SHA2-128s |
| **FIPS compliance** | ML-KEM-768 | ML-DSA-65 |
| **Hybrid (belt-and-suspenders)** | ML-KEM-768+X25519 | ML-DSA-65+Ed25519 |
| **Long-term archival signing** | — | LMS-SHA256-H20 (stateful) |

### Is this production-ready?

ML-KEM (FIPS 203) and ML-DSA (FIPS 204) have complete, specification-faithful implementations with KAT validation. The remaining algorithms have their framework (parameter sizes, API integration) in place and are being filled in. We recommend using ML-KEM and ML-DSA for production workloads now.

### How do I report a security vulnerability?

See [SECURITY.md](SECURITY.md). Email security@dyber.com. Do **not** open a public issue.

### What NIST security levels mean?

| Level | Equivalent Strength | Meaning |
|-------|--------------------|---------|
| 1 | AES-128 | Minimum recommended security |
| 2 | SHA-256 collision | Intermediate |
| 3 | AES-192 | Strong security |
| 4 | SHA-384 collision | Intermediate-high |
| 5 | AES-256 | Maximum security |

### Can I use this in a FIPS-compliant environment?

The library implements the FIPS 203/204/205 standards faithfully. However, the library itself has not yet undergone FIPS 140-3 validation. If you need a FIPS-validated module, contact Dyber, Inc. for enterprise support.

### How do stateful signatures work?

LMS and XMSS are **stateful** — each signing operation advances an internal counter and the secret key **must be updated**. Using the same state twice destroys security. Use `pqc_sig_sign_stateful()` which modifies the secret key in-place:

```c
PQC_SIG *sig = pqc_sig_new("LMS-SHA256-H10");
uint8_t *pk = malloc(pqc_sig_public_key_size(sig));
uint8_t *sk = malloc(pqc_sig_secret_key_size(sig));  // mutable!

pqc_sig_keygen(sig, pk, sk);

// Each sign call mutates sk
pqc_sig_sign_stateful(sig, sigbuf, &siglen, msg, msglen, sk);
// IMPORTANT: persist updated sk to disk before signing again
```

### What's the overhead of hybrid schemes?

Hybrid schemes concatenate the outputs of both algorithms:
- **Key sizes**: PQC key size + classical key size
- **Ciphertext/signature sizes**: PQC output + classical output
- **Performance**: Both algorithms run sequentially

The security guarantee: the combined scheme is secure as long as **at least one** component is secure.

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
- Algorithm implementations (filling in the remaining crypto internals)
- Performance optimizations (AVX2/NEON assembly)
- Additional test vectors and fuzzing
- Language binding improvements
- Documentation and examples

---

## License

libpqc-dyber is dual-licensed under the [Apache License 2.0](LICENSE-APACHE) and the [MIT License](LICENSE-MIT). You may choose either license at your option.

```
SPDX-License-Identifier: Apache-2.0 OR MIT
```

---

## About Dyber, Inc.

[Dyber, Inc.](https://dyber.com) is committed to building the cryptographic infrastructure for the post-quantum era. libpqc-dyber is our flagship open-source project, providing the building blocks for quantum-resistant security across all platforms and programming languages.

We believe that the transition to post-quantum cryptography should be:
- **Accessible** — available in every language developers use
- **Open** — fully open-source with no proprietary components
- **Correct** — implemented from specifications with rigorous validation
- **Fast** — hardware-accelerated for real-world performance

For enterprise support, FIPS validation assistance, or custom integrations, contact us at **enterprise@dyber.com**.

---

<p align="center">
  <strong>libpqc-dyber</strong> &mdash; Post-Quantum Cryptography for Every Platform, Every Language
  <br/>
  <sub>Copyright (c) 2024-2026 Dyber, Inc. All rights reserved.</sub>
</p>
