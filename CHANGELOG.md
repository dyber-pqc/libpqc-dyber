# Changelog

All notable changes to libpqc-dyber will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-26

### Added
- Initial project structure and build system
- Core cryptographic utilities (constant-time ops, secure memory, CSPRNG)
- Hash primitives: SHA-256, SHA-512, SHA-3, SHAKE-128/256, Keccak-f[1600]
- ML-KEM (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ML-DSA (FIPS 204): ML-DSA-44, ML-DSA-65, ML-DSA-87
- SLH-DSA (FIPS 205): All 12 parameter sets
- FN-DSA (FIPS 206 draft): FN-DSA-512, FN-DSA-1024
- Additional KEMs: HQC, BIKE, Classic McEliece, FrodoKEM, NTRU, NTRU-Prime
- Additional signatures: SPHINCS+, MAYO, UOV, SNOVA, CROSS
- Stateful signatures: LMS (RFC 8554), XMSS (RFC 8391)
- Hybrid schemes: PQC + X25519/Ed25519/P-256
- Language bindings for 20 languages
- Comprehensive test suite with KAT validation
- CI/CD for Linux, macOS, Windows, FreeBSD
