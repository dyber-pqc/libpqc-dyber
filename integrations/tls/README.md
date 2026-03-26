# TLS Integration Layer for libpqc-dyber

Copyright (c) 2024-2026 Dyber, Inc.
SPDX-License-Identifier: Apache-2.0 OR MIT

## Overview

A standalone TLS integration layer that provides post-quantum key exchange
and signature support for any TLS library (OpenSSL, BoringSSL, or custom
implementations).

Implements:

- **draft-ietf-tls-hybrid-design** — hybrid key exchange framework
- **draft-connolly-tls-mlkem-key-agreement** — ML-KEM in TLS 1.3
- **FIPS 203** ML-KEM, **FIPS 204** ML-DSA, **FIPS 205** SLH-DSA

## Supported Groups and Algorithms

### Key Exchange Groups (NamedGroup)

| Group | Code | Type | Client Share | Server Share | Secret |
|-------|------|------|-------------|-------------|--------|
| ML-KEM-512 | 0x0200 | Pure PQC | 800 B | 768 B | 32 B |
| ML-KEM-768 | 0x0201 | Pure PQC | 1184 B | 1088 B | 32 B |
| ML-KEM-1024 | 0x0202 | Pure PQC | 1568 B | 1568 B | 32 B |
| X25519+ML-KEM-768 | 0x6399 | Hybrid | 1216 B | 1120 B | 32 B |
| P-256+ML-KEM-768 | 0x639A | Hybrid | 1249 B | 1153 B | 32 B |

### Signature Algorithms (SignatureScheme)

| Algorithm | Code | Public Key | Secret Key | Max Signature |
|-----------|------|-----------|-----------|--------------|
| ML-DSA-44 | 0x0901 | 1312 B | 2560 B | 2420 B |
| ML-DSA-65 | 0x0902 | 1952 B | 4032 B | 3309 B |
| ML-DSA-87 | 0x0903 | 2592 B | 4896 B | 4627 B |
| SLH-DSA-SHA2-128s | 0x0904 | 32 B | 64 B | 7856 B |
| SLH-DSA-SHA2-128f | 0x0905 | 32 B | 64 B | 17088 B |
| SLH-DSA-SHA2-192s | 0x0906 | 48 B | 96 B | 16224 B |
| SLH-DSA-SHA2-192f | 0x0907 | 48 B | 96 B | 35664 B |
| SLH-DSA-SHA2-256s | 0x0908 | 64 B | 128 B | 29792 B |
| SLH-DSA-SHA2-256f | 0x0909 | 64 B | 128 B | 49856 B |

## Building

### Prerequisites

- CMake 3.16+
- C11 compiler
- libpqc-dyber (parent project)
- OpenSSL or BoringSSL (optional; required for hybrid groups)

### As Part of the Parent Build

```bash
cd libpqc-dyber
mkdir build && cd build
cmake ..
make pqc_tls
```

### Standalone

```bash
cd integrations/tls
mkdir build && cd build
cmake .. -DLIBPQC_DIR=/path/to/libpqc-dyber/install
make
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `PQC_TLS_SHARED` | OFF | Build as shared library |
| `PQC_TLS_BUILD_TESTS` | ON | Build test suite |

## Usage

### How to Use with OpenSSL

```c
#include "pqc_tls.h"
#include <openssl/ssl.h>

/* 1. Create key share for ClientHello */
PQC_TLS_KeyShare *ks = pqc_tls_keyshare_new(PQC_TLS_GROUP_X25519_MLKEM768);
uint8_t client_share[2048];
size_t  client_share_len = sizeof(client_share);
pqc_tls_keyshare_generate(ks, client_share, &client_share_len);

/* 2. Insert client_share into the ClientHello key_share extension
 *    using SSL_set1_client_key_share() or a custom callback. */

/* 3. On the server, process the client share:
 *    (server creates its own PQC_TLS_KeyShare) */
PQC_TLS_KeyShare *srv = pqc_tls_keyshare_new(PQC_TLS_GROUP_X25519_MLKEM768);
uint8_t server_share[2048], secret[64];
size_t  server_share_len = sizeof(server_share);
size_t  secret_len = sizeof(secret);
pqc_tls_keyshare_encapsulate(srv,
    client_share, client_share_len,
    server_share, &server_share_len,
    secret, &secret_len);

/* 4. Client processes server share to recover the same secret */
size_t client_secret_len = sizeof(secret);
pqc_tls_keyshare_decapsulate(ks,
    server_share, server_share_len,
    secret, &client_secret_len);

/* 5. Feed 'secret' into the TLS key schedule (HKDF) */

pqc_tls_keyshare_free(ks);
pqc_tls_keyshare_free(srv);
```

### How to Use with BoringSSL

The API is identical. BoringSSL uses the same OpenSSL-compatible headers.
See also `integrations/boringssl/` for a shim that registers groups
directly into BoringSSL's SSL_CTX.

### Wire Format for Hybrid Key Shares

Hybrid key shares use simple concatenation:

```
ClientHello key_share entry (group 0x6399 = X25519+ML-KEM-768):
  +------+------+---------------------------+
  | X25519 pub  |   ML-KEM-768 public key   |
  | (32 bytes)  |       (1184 bytes)        |
  +------+------+---------------------------+

ServerHello key_share entry:
  +------+------+---------------------------+
  | X25519 pub  |  ML-KEM-768 ciphertext    |
  | (32 bytes)  |       (1088 bytes)        |
  +------+------+---------------------------+
```

The hybrid shared secret is:

```
shared_secret = SHA-256(X25519_secret || ML-KEM_secret)
```

This 32-byte combined secret is then fed into the TLS 1.3 key schedule.

### IANA Codepoint Reference

Group IDs follow the emerging IANA assignments and experimental allocations
used by Chrome and Cloudflare:

| Codepoint | Description |
|-----------|-------------|
| 0x0200 | ML-KEM-512 |
| 0x0201 | ML-KEM-768 |
| 0x0202 | ML-KEM-1024 |
| 0x6399 | X25519MLKEM768 (experimental, Chrome/Cloudflare) |
| 0x639A | SecP256r1MLKEM768 (experimental) |

Signature algorithm codes:

| Codepoint | Description |
|-----------|-------------|
| 0x0901 | ML-DSA-44 |
| 0x0902 | ML-DSA-65 |
| 0x0903 | ML-DSA-87 |
| 0x0904-0x0909 | SLH-DSA variants |

### Example: TLS 1.3 Handshake with ML-KEM-768

```
Client                                          Server

ClientHello
  supported_groups: [ML-KEM-768 (0x0201)]
  key_share: ML-KEM-768 public key (1184 B)
                                    ---------->
                                                ServerHello
                                                  key_share: ML-KEM-768
                                                    ciphertext (1088 B)
                                                {EncryptedExtensions}
                                                {Certificate}
                                                  (ML-DSA-65 public key)
                                                {CertificateVerify}
                                                  (ML-DSA-65 signature)
                                                {Finished}
                                    <----------
{Finished}
                                    ---------->

Shared secret (32 bytes) derived from ML-KEM decapsulation
is used in HKDF-Expand-Label to derive traffic keys.
```

### Example: Hybrid X25519+ML-KEM-768

```
Client                                          Server

ClientHello
  supported_groups: [X25519MLKEM768 (0x6399)]
  key_share:
    X25519 public (32 B) || ML-KEM-768 pk (1184 B)
    = 1216 bytes total
                                    ---------->
                                                ServerHello
                                                  key_share:
                                                    X25519 pub (32 B) ||
                                                    ML-KEM ct (1088 B)
                                                    = 1120 bytes total
                                    <----------

Both sides compute:
  x25519_ss  = X25519(priv, peer_pub)         -- 32 bytes
  mlkem_ss   = ML-KEM-768-Decaps(ct, sk)      -- 32 bytes
  combined   = SHA-256(x25519_ss || mlkem_ss)  -- 32 bytes

Combined secret enters the TLS 1.3 key schedule.
```

## TLS 1.2 Support

TLS 1.2 has limited PQC support because its key exchange model does not
natively support KEM-style algorithms. This library provides a custom
extension mechanism (extension type 0xFF01, private-use range) for hybrid
key exchange only:

```c
/* Client side */
PQC_TLS_KeyShare *ks;
uint8_t ext[4096];
size_t ext_len = sizeof(ext);
pqc_tls12_build_client_extension(
    PQC_TLS_GROUP_X25519_MLKEM768, ext, &ext_len, &ks);
/* Insert ext into ClientHello via SSL_CTX_add_custom_ext */

/* Server side */
uint8_t response[4096], secret[64];
size_t resp_len = sizeof(response), secret_len = sizeof(secret);
pqc_tls12_process_client_extension(
    ext, ext_len, response, &resp_len, secret, &secret_len);

/* Client processes response */
pqc_tls12_process_server_extension(
    ks, response, resp_len, secret, &secret_len);
```

Pure PQC key exchange requires TLS 1.3.

## Architecture

```
src/
  pqc_tls.h          - Public API header
  pqc_tls_internal.h - Internal types and table definitions
  pqc_tls.c          - Key-share lifecycle, hybrid combiner, sign/verify
  pqc_tls_groups.c   - NamedGroup table (pure PQC and hybrid)
  pqc_tls_sigalgs.c  - SignatureScheme table
  pqc_tls12.c        - TLS 1.2 custom extension helpers
tests/
  test_tls_keyshare.c - Round-trip test suite
```

## Testing

```bash
cd build
ctest --output-on-failure
```

The test suite verifies:

- Key share round-trips for all pure PQC groups
- Key share round-trips for hybrid groups (when OpenSSL is available)
- Sign/verify round-trips for all signature algorithms
- Error handling (NULL arguments, unsupported groups, out-of-order calls)

## Related

- `integrations/openssl/` - OpenSSL 3.x provider
- `integrations/boringssl/` - BoringSSL shim layer
