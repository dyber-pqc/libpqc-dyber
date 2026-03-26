# libpqc-dyber OpenSSL 3.x Provider

An OpenSSL 3.0+ provider that exposes all libpqc-dyber post-quantum cryptographic
algorithms through OpenSSL's EVP framework. This enables transparent PQC support
in any application that uses OpenSSL, including TLS 1.3 hybrid key exchange.

## Supported Algorithms

### KEM (Key Encapsulation Mechanisms)

| Algorithm | NIST Level | Standard |
|-----------|-----------|----------|
| ML-KEM-512 / 768 / 1024 | 1 / 3 / 5 | FIPS 203 |
| HQC-128 / 192 / 256 | 1 / 3 / 5 | NIST Round 4 |
| BIKE-L1 / L3 / L5 | 1 / 3 / 5 | NIST Round 4 |
| Classic McEliece (5 variants) | 1-5 | NIST Round 4 |
| FrodoKEM (6 variants) | 1 / 3 / 5 | Conservative |
| NTRU (4 variants) | 1 / 3 / 5 | Legacy |
| NTRUPrime (5 variants) | 1-5 | Legacy |
| ML-KEM-768+X25519 | 3 | Hybrid |
| ML-KEM-1024+P256 | 5 | Hybrid |

### Signatures

| Algorithm | NIST Level | Standard |
|-----------|-----------|----------|
| ML-DSA-44 / 65 / 87 | 2 / 3 / 5 | FIPS 204 |
| SLH-DSA (12 variants) | 1 / 3 / 5 | FIPS 205 |
| FN-DSA-512 / 1024 | 1 / 5 | NIST Draft |
| SPHINCS+ (12 variants) | 1 / 3 / 5 | Legacy names |
| MAYO-1 / 2 / 3 / 5 | 1 / 1 / 3 / 5 | NIST Additional |
| UOV-Is / IIIs / Vs | 1 / 3 / 5 | NIST Additional |
| SNOVA (3 variants) | 1 / 3 / 5 | NIST Additional |
| CROSS (6 variants) | 1 / 3 / 5 | NIST Additional |
| LMS (4 variants) | 1 | Stateful HBS |
| XMSS (3 variants) | 1 | Stateful HBS |
| ML-DSA-65+Ed25519 | 3 | Hybrid |
| ML-DSA-87+P256 | 5 | Hybrid |

### TLS 1.3 Named Groups

| Group Name | Group ID | Description |
|-----------|----------|-------------|
| MLKEM512 | 0x0200 | ML-KEM-512 standalone |
| MLKEM768 | 0x0201 | ML-KEM-768 standalone |
| MLKEM1024 | 0x0202 | ML-KEM-1024 standalone |
| X25519MLKEM768 | 0x6399 | X25519 + ML-KEM-768 hybrid |
| SecP256r1MLKEM768 | 0x639A | P-256 + ML-KEM-768 hybrid |
| SecP256r1MLKEM1024 | 0x6401 | P-256 + ML-KEM-1024 hybrid |

## Prerequisites

- **OpenSSL 3.0+** (development headers and libraries)
- **libpqc-dyber** (built as a static or shared library)
- **CMake 3.16+**
- A C11-compatible compiler (GCC, Clang, or MSVC)

## Building

### As part of the libpqc-dyber tree

```bash
cd libpqc-dyber
mkdir build && cd build
cmake .. -DPQC_BUILD_OPENSSL_PROVIDER=ON
cmake --build .
```

### Standalone build

```bash
cd integrations/openssl
mkdir build && cd build
cmake .. \
    -DCMAKE_PREFIX_PATH=/path/to/openssl \
    -DLIBPQC_DIR=/path/to/libpqc-dyber/install
cmake --build .
```

### Windows (MSVC)

```powershell
cd integrations\openssl
mkdir build; cd build
cmake .. -G "Visual Studio 17 2022" `
    -DOPENSSL_ROOT_DIR=C:\OpenSSL `
    -DLIBPQC_DIR=C:\libpqc-dyber
cmake --build . --config Release
```

## Installation

```bash
# Install to the OpenSSL modules directory
sudo cmake --install build

# Or manually copy the provider:
sudo cp build/pqc_provider.so /usr/lib/ossl-modules/
```

## Configuration

### Option 1: OpenSSL config file

Copy `openssl.cnf.example` to your OpenSSL configuration directory and set:

```bash
export OPENSSL_CONF=/path/to/openssl.cnf
```

### Option 2: Environment variable

Point OpenSSL to the directory containing the provider:

```bash
export OPENSSL_MODULES=/path/to/provider/directory
```

Then load programmatically:

```c
OSSL_PROVIDER_load(NULL, "pqc_provider");
```

### Option 3: Programmatic loading

```c
#include <openssl/provider.h>

OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "pqc_provider");
if (prov == NULL) {
    /* handle error */
}
```

## Usage Examples

### KEM: Key encapsulation with ML-KEM-768

```c
#include <openssl/evp.h>

EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
EVP_PKEY *pkey = NULL;

EVP_PKEY_keygen_init(kctx);
EVP_PKEY_keygen(kctx, &pkey);

/* Encapsulate */
EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
EVP_PKEY_encapsulate_init(ectx, NULL);

size_t ct_len, ss_len;
EVP_PKEY_encapsulate(ectx, NULL, &ct_len, NULL, &ss_len);

unsigned char *ct = malloc(ct_len);
unsigned char *ss = malloc(ss_len);
EVP_PKEY_encapsulate(ectx, ct, &ct_len, ss, &ss_len);

/* Decapsulate */
EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
EVP_PKEY_decapsulate_init(dctx, NULL);

size_t ss2_len = ss_len;
unsigned char *ss2 = malloc(ss2_len);
EVP_PKEY_decapsulate(dctx, ss2, &ss2_len, ct, ct_len);
/* ss and ss2 are identical */
```

### Signature: Sign/verify with ML-DSA-65

```c
#include <openssl/evp.h>

/* Generate key */
EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
EVP_PKEY *pkey = NULL;
EVP_PKEY_keygen_init(kctx);
EVP_PKEY_keygen(kctx, &pkey);

/* Sign */
EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, NULL, pkey, NULL);
EVP_DigestSignUpdate(mdctx, msg, msg_len);
size_t siglen;
EVP_DigestSignFinal(mdctx, NULL, &siglen);
unsigned char *sig = malloc(siglen);
EVP_DigestSignFinal(mdctx, sig, &siglen);

/* Verify */
EVP_MD_CTX *vctx = EVP_MD_CTX_new();
EVP_DigestVerifyInit_ex(vctx, NULL, NULL, NULL, NULL, pkey, NULL);
EVP_DigestVerifyUpdate(vctx, msg, msg_len);
int valid = EVP_DigestVerifyFinal(vctx, sig, siglen);
/* valid == 1 if signature is correct */
```

### TLS 1.3 with hybrid key exchange

```bash
# Server
openssl s_server -cert server.pem -key server.key \
    -groups X25519MLKEM768:X25519 \
    -provider pqc_provider -provider default

# Client
openssl s_client -connect localhost:4433 \
    -groups X25519MLKEM768:X25519 \
    -provider pqc_provider -provider default
```

### Listing algorithms

```bash
# List all KEM algorithms
openssl list -kem-algorithms -provider pqc_provider

# List all signature algorithms
openssl list -signature-algorithms -provider pqc_provider
```

## Testing

```bash
cd build
ctest --output-on-failure
```

Or run the test binary directly:

```bash
OPENSSL_MODULES=./build ./build/test_openssl_provider
```

## Architecture

The provider follows the standard OpenSSL 3.x provider architecture:

```
OSSL_provider_init()
  |
  +-- OSSL_OP_KEYMGMT    -> pqc_keymgmt_prov.c  (key generation, import/export)
  +-- OSSL_OP_KEM         -> pqc_kem_prov.c      (encapsulate/decapsulate)
  +-- OSSL_OP_SIGNATURE   -> pqc_sig_prov.c      (sign/verify, DigestSign/Verify)
  +-- TLS-GROUP capability -> pqc_tls_groups.c   (TLS 1.3 named groups)
```

Each algorithm shares the same dispatch functions; the algorithm name is captured
during `keymgmt_gen_init` and stored in the key object. The KEM and signature
dispatch functions use this name to instantiate the correct libpqc context.

## License

Copyright (c) 2024-2026 Dyber, Inc.

Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

SPDX-License-Identifier: Apache-2.0 OR MIT
