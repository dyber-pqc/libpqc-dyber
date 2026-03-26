# BoringSSL Integration for libpqc-dyber

Copyright (c) 2024-2026 Dyber, Inc.
SPDX-License-Identifier: Apache-2.0 OR MIT

## Overview

This integration provides a shim layer that adds post-quantum cryptography
support to BoringSSL. Unlike OpenSSL 3.x, BoringSSL does not expose a
provider model, so this library registers custom EVP_PKEY methods, NamedGroup
entries, and SignatureScheme entries directly.

### Supported Algorithms

| Algorithm | Type | TLS Usage |
|-----------|------|-----------|
| ML-KEM-512 | KEM | Key exchange (NamedGroup 0x0200) |
| ML-KEM-768 | KEM | Key exchange (NamedGroup 0x0201) |
| ML-KEM-1024 | KEM | Key exchange (NamedGroup 0x0202) |
| X25519 + ML-KEM-768 | Hybrid KEM | Key exchange (NamedGroup 0x6399) |
| P-256 + ML-KEM-768 | Hybrid KEM | Key exchange (NamedGroup 0x639A) |
| ML-DSA-44 | Signature | Authentication (SignatureScheme 0x0901) |
| ML-DSA-65 | Signature | Authentication (SignatureScheme 0x0902) |
| ML-DSA-87 | Signature | Authentication (SignatureScheme 0x0903) |
| SLH-DSA-SHA2-128s | Signature | Authentication (SignatureScheme 0x0904) |

## Building

### Prerequisites

- CMake 3.16+
- C11 compiler
- BoringSSL (built from source)
- libpqc-dyber (parent project)

### As Part of the Parent Build

```bash
cd libpqc-dyber
mkdir build && cd build
cmake .. -DBORINGSSL_ROOT=/path/to/boringssl
make pqc_boringssl
```

### Standalone

```bash
cd integrations/boringssl
mkdir build && cd build
cmake .. \
  -DBORINGSSL_ROOT=/path/to/boringssl \
  -DLIBPQC_DIR=/path/to/libpqc-dyber/install
make
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `PQC_BORINGSSL_SHARED` | OFF | Build as shared library |
| `PQC_BORINGSSL_BUILD_TESTS` | ON | Build test suite |
| `BORINGSSL_ROOT` | (none) | Path to BoringSSL build tree |

## Usage

### Initialization

```c
#include "pqc_boringssl.h"

/* One-time initialization (registers NIDs and EVP_PKEY methods) */
if (!PQC_BoringSSL_init()) {
    fprintf(stderr, "PQC initialization failed\n");
    exit(1);
}
```

### TLS 1.3 with ML-KEM-768

```c
SSL_CTX *ctx = SSL_CTX_new(TLS_method());

/* Register ML-KEM-768 as a key exchange group */
PQC_BoringSSL_register_kem(ctx, "ML-KEM-768");

/* Or register all hybrid groups at once */
PQC_BoringSSL_register_hybrid_groups(ctx);
```

### TLS Authentication with ML-DSA

```c
/* Register ML-DSA-65 for certificate verification */
PQC_BoringSSL_register_sig(ctx, "ML-DSA-65");
```

### Hybrid Key Exchange (X25519 + ML-KEM-768)

The hybrid groups combine a classical key exchange with a PQC KEM. The shared
secret is derived by hashing the concatenation of both component secrets:

```
combined_secret = SHA-256(classical_secret || pqc_secret)
```

Wire format for the key share:

```
ClientHello key_share:
  [32 bytes X25519 public key] || [1184 bytes ML-KEM-768 public key]

ServerHello key_share:
  [32 bytes X25519 public key] || [1088 bytes ML-KEM-768 ciphertext]
```

## Architecture

```
src/
  pqc_boringssl.h          - Public API
  pqc_boringssl_internal.h - Internal declarations
  pqc_boringssl.c          - Main registration and EVP_PKEY wiring
  pqc_boringssl_kem.c      - KEM key-share generation/processing
  pqc_boringssl_sig.c      - Signature CertificateVerify handling
tests/
  test_boringssl.c          - Integration test suite
```

## Limitations

BoringSSL does not currently expose a stable public C API for registering
custom NamedGroup or SignatureScheme values. This integration provides the
complete cryptographic logic (key generation, encapsulation, decapsulation,
signing, verification) and the registration stubs. When BoringSSL stabilizes
its custom-group API, the stubs will be updated to wire in automatically.

For production use today, consider:

1. Patching BoringSSL's internal group table to include the PQC groups, then
   calling the key-share callbacks from this library.
2. Using the standalone TLS integration layer (`integrations/tls/`), which
   works with any TLS library including BoringSSL.

## Testing

```bash
cd build
ctest --output-on-failure
```

## Related

- `integrations/openssl/` - OpenSSL 3.x provider
- `integrations/tls/` - Standalone TLS integration layer
