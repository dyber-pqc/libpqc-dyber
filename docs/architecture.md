# libpqc-dyber Architecture

## Overview

libpqc-dyber is a layered cryptography library:

```
┌─────────────────────────────────────────────────────┐
│  Language Bindings (20 languages)                    │
│  Python, Rust, Go, Java, C++, C#, JS, ...           │
├─────────────────────────────────────────────────────┤
│  Public C API                                        │
│  pqc_kem_*(), pqc_sig_*(), pqc_randombytes()        │
├─────────────────────────────────────────────────────┤
│  Algorithm Dispatch Layer                            │
│  vtable-based runtime algorithm selection            │
├─────────┬──────────┬──────────┬────────────────────┤
│  KEMs   │  Sigs    │  Hybrid  │  Stateful Sigs     │
│ ML-KEM  │ ML-DSA   │ KEM+ECDH │ LMS, XMSS         │
│ HQC     │ SLH-DSA  │ Sig+EdDSA│                    │
│ BIKE    │ FN-DSA   │          │                    │
│ McEliece│ SPHINCS+ │          │                    │
│ Frodo   │ MAYO/UOV │          │                    │
│ NTRU    │ SNOVA    │          │                    │
│         │ CROSS    │          │                    │
├─────────┴──────────┴──────────┴────────────────────┤
│  Common Utilities                                    │
│  Hash (SHA-2, SHA-3, SHAKE, Keccak)                 │
│  Constant-time ops, Secure memory, CSPRNG           │
├─────────────────────────────────────────────────────┤
│  Platform Abstraction                                │
│  OS entropy, CPU detection, SIMD dispatch            │
└─────────────────────────────────────────────────────┘
```

## Key Design Decisions

### Vtable Dispatch
Each algorithm family registers a vtable (function pointer struct) containing:
- keygen, encaps/sign, decaps/verify function pointers
- Size constants (pk, sk, ct/sig, ss)
- Algorithm name, security level, standard reference

This allows runtime algorithm selection by name string while maintaining zero overhead for compiled-in algorithms.

### Constant-Time Guarantees
All operations on secret data use the `ct_ops` module:
- No branches on secret values
- No secret-dependent memory accesses
- Comparison, selection, and conditional move via bitwise operations
- Verified with valgrind/ctgrind in CI

### Memory Safety
- `pqc_malloc/pqc_free` track allocation sizes for guaranteed zeroization
- `pqc_memzero` uses volatile writes to prevent compiler optimization
- `mlock` used for key material where available

### CSPRNG
Platform-specific OS entropy:
- Windows: `BCryptGenRandom`
- Linux: `getrandom(2)` syscall
- macOS/FreeBSD: `arc4random_buf`
- Fallback: `/dev/urandom`

Custom RNG override available for deterministic testing.

## Build System

CMake with modular algorithm toggles:
```bash
cmake -B build -DPQC_ENABLE_KEM_MCELIECE=OFF  # Disable specific algorithms
```

Each algorithm can be independently enabled/disabled at compile time.

## Language Binding Strategy

| Mechanism | Languages |
|-----------|-----------|
| Direct C | C (core library) |
| Header-only C++ | C++ |
| ctypes/cffi | Python |
| CGO | Go |
| bindgen + safe wrapper | Rust |
| JNI | Java, Kotlin, Scala |
| P/Invoke | C# |
| N-API | JavaScript, TypeScript |
| FFI | PHP, Ruby, Dart, Perl |
| .Call | R |
| MEX | MATLAB |
| C interop | Swift |
| CLI binary | Shell |
