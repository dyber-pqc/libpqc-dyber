# ASM-Optimized Routines - Direct Usage Guide

Copyright (c) 2024-2026 Dyber, Inc.
SPDX-License-Identifier: Apache-2.0 OR MIT

## Overview

libpqc-dyber includes hand-optimized assembly routines for performance-critical
inner loops of post-quantum cryptographic algorithms. These routines target
x86-64 (with AVX2/AVX-512 extensions) and AArch64 (with NEON/SVE) platforms.

The recommended way to use libpqc-dyber is through the high-level C API
(`pqc/kem.h`, `pqc/sig.h`). The library automatically dispatches to the
best available assembly implementation at runtime. This document describes
how to link against or call the low-level ASM routines directly, which may
be useful for embedded systems, custom integrations, or benchmarking.

## Architecture Support

| Platform  | ISA Extensions    | Algorithms with ASM                |
|-----------|-------------------|------------------------------------|
| x86-64    | AVX2              | ML-KEM (NTT), ML-DSA (NTT)        |
| x86-64    | AVX-512           | ML-KEM (NTT), ML-DSA (NTT), SHA-3 |
| AArch64   | NEON              | ML-KEM (NTT), ML-DSA (NTT)        |
| AArch64   | SVE / SVE2        | ML-KEM (NTT), SHA-3               |

## File Layout

Assembly source files are located under `src/asm/`:

```
src/asm/
  x86_64/
    avx2/
      mlkem_ntt_avx2.S        # ML-KEM NTT butterfly (AVX2)
      mldsa_ntt_avx2.S        # ML-DSA NTT (AVX2)
      keccak_avx2.S           # Keccak-f[1600] (AVX2)
    avx512/
      mlkem_ntt_avx512.S      # ML-KEM NTT butterfly (AVX-512)
      keccak_avx512.S         # Keccak-f[1600] (AVX-512)
  aarch64/
    neon/
      mlkem_ntt_neon.S         # ML-KEM NTT butterfly (NEON)
      mldsa_ntt_neon.S         # ML-DSA NTT (NEON)
    sve/
      mlkem_ntt_sve.S          # ML-KEM NTT (SVE)
      keccak_sve.S             # Keccak-f[1600] (SVE)
```

## Runtime Dispatch

The library uses runtime CPU feature detection (via CPUID on x86-64 or
auxiliary vector / HWCAP on AArch64) to select the optimal implementation.
The dispatch layer is in `src/dispatch/dispatch.h` and is transparent to
callers of the public API.

If you need to force a specific implementation (e.g., for benchmarking),
set the environment variable before calling `pqc_init()`:

```
PQC_FORCE_IMPL=avx2      # Force AVX2 on x86-64
PQC_FORCE_IMPL=avx512    # Force AVX-512
PQC_FORCE_IMPL=neon      # Force NEON on AArch64
PQC_FORCE_IMPL=generic   # Force portable C (no ASM)
```

## Calling ASM Routines Directly

The ASM routines use the platform's standard C calling convention and are
exported with C linkage. Each routine is declared in the corresponding
internal header. For example:

```c
#include "src/core/kem/mlkem/ntt.h"

/* Direct call to the NTT forward transform.
 * The dispatch layer normally handles this, but you can call it directly
 * after checking CPU capabilities yourself. */
extern void pqc_mlkem_ntt_avx2(int16_t coeffs[256]);
```

**Important:** These internal symbols are NOT part of the stable public API.
They may change between releases without notice. Always prefer the public
`pqc_kem_*` / `pqc_sig_*` API unless you have a specific need.

## Linking

### Static Linking (Recommended for ASM Access)

```bash
# Build the static library
cmake -B build -DPQC_BUILD_SHARED=OFF
cmake --build build

# Link your application
gcc -o myapp myapp.c -Iinclude -Lbuild -lpqc_static
```

### Extracting Individual Object Files

If you only need specific ASM routines (e.g., for a constrained environment):

```bash
# Build and then extract
cmake --build build
ar x build/libpqc_static.a mlkem_ntt_avx2.S.o
```

## Integrating into Custom Build Systems

If you are not using CMake, you can assemble the `.S` files directly:

### x86-64 (GCC/Clang)

```bash
gcc -c -mavx2 src/asm/x86_64/avx2/mlkem_ntt_avx2.S -o mlkem_ntt_avx2.o
gcc -c -mavx512f src/asm/x86_64/avx512/mlkem_ntt_avx512.S -o mlkem_ntt_avx512.o
```

### AArch64 (GCC/Clang)

```bash
gcc -c -march=armv8-a+simd src/asm/aarch64/neon/mlkem_ntt_neon.S -o mlkem_ntt_neon.o
gcc -c -march=armv8-a+sve src/asm/aarch64/sve/mlkem_ntt_sve.S -o mlkem_ntt_sve.o
```

### Windows (MSVC with MASM)

The x86-64 ASM files use GAS syntax. For MSVC, use the `.asm` variants
(automatically generated during the CMake build) or assemble with `nasm`:

```bash
nasm -f win64 src/asm/x86_64/avx2/mlkem_ntt_avx2.asm -o mlkem_ntt_avx2.obj
```

## Benchmarking

Use the built-in benchmark tool to compare generic vs. ASM performance:

```bash
cmake -B build -DPQC_BUILD_BENCHMARKS=ON
cmake --build build
./build/bench/pqc_bench --filter="ntt"
```

To benchmark a specific implementation:

```bash
PQC_FORCE_IMPL=generic ./build/bench/pqc_bench --filter="ML-KEM-768"
PQC_FORCE_IMPL=avx2    ./build/bench/pqc_bench --filter="ML-KEM-768"
```

## Security Considerations

- ASM routines are written to be constant-time where required by the
  algorithm specification. Do not modify the control flow.
- The routines assume properly aligned input buffers (16-byte alignment
  for NEON, 32-byte for AVX2, 64-byte for AVX-512). Use `pqc_malloc()`
  or aligned allocation to ensure correct alignment.
- Stack-allocated sensitive data is zeroized before function return.
