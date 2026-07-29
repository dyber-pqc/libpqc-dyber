# Changelog

All notable changes to libpqc-dyber will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

Fixes from an external security audit (reported 2026-07-28 by Conner /
Spartan8806), plus three further defects found while verifying them.

- **SNOVA, CROSS: heap buffer overflow in `sign()`** (critical). The declared
  `max_signature_size` was smaller than what the serialiser emits, so signing
  into a correctly sized buffer wrote past its end on every call. SNOVA sizes
  are now derived from `(n, l)`; CROSS sizes are worst-case bounds for the
  encoding it actually produces. Both packers now refuse rather than exceed
  the buffer.
- **NTRU, NTRU Prime: heap buffer overflow in keygen and encaps** (critical,
  found during verification). Public size constants were copied from the
  respective specifications while the code uses a different, larger encoding.
  Sizes are now derived from the real layout in one place. This also fixes
  decapsulation deriving the wrong shared secret, which was a consequence of
  the truncated key material.
- **NTRU: stack buffer overrun in `ntru_poly_inv_mod_q`** (found during
  verification). Abandoned extended-GCD scratch arrays were sized
  `NTRU_MAX_N` but indexed at `[n]`, overrunning on NTRU-HPS-4096-821. The
  dead arrays were removed.
- **XMSS: every leaf derived the same WOTS+ one-time key** (critical).
  `xmss_wots_keygen`/`sign`/`pk_from_sig` re-set the address type, which
  zeroes the type-specific fields and wiped the leaf index the caller had
  just set. Signatures still round-tripped, so this was invisible to
  round-trip tests.
- **LMS: signatures never verified.** The authentication path was derived
  from the secret seed rather than taken from the Merkle tree, and the
  verifier's left/right child order was inverted. The path now comes from
  the real tree, shared with root computation.
- **XMSS: WOTS+ checksum dropped its most significant nibble**, leaving the
  final chain constant at zero.
- **HQC, BIKE, FrodoKEM: decapsulation returned the validity bit**, exposing
  a plaintext-checking oracle through the public API. These now always return
  `PQC_OK`; the ciphertext comparisons are branchless. The same branch was
  removed from NTRU Prime.
- **Signature length was ignored by six `verify()` implementations**, causing
  out-of-bounds reads on truncated input. `pqc_sig_verify()` now rejects
  over-long lengths before dispatch, and CROSS, LMS, MAYO, SNOVA, UOV and
  XMSS validate their own.
- **XMSS: per-node hash keys and bitmasks collapsed to one per tree level.**
  The key/bitmask selector aliased the tree index; it now uses the RFC 8391
  `keyAndMask` field at offset 28. The L-tree address is likewise preserved.
- **`pqc_randombytes()` return value ignored at 14 call sites.** A failing
  caller-supplied RNG left buffers untouched, so keys, seeds and nonces were
  derived from uninitialised memory. All sites now propagate the failure;
  the affected KEM internals return a status instead of `void`.
- **FN-DSA: signed integer overflow in `ntru_solve.c`** (undefined behaviour).
  Field-norm accumulation now uses unsigned arithmetic.

### Changed

- LMS-SHA256-H20 and H25 keygen now return `PQC_ERROR_NOT_SUPPORTED` rather
  than substituting a hash of the secret seed for the Merkle root. Trees
  above height 15 are not computable without cached traversal state, which
  the 64-byte secret key has no room for.
- CROSS signature sizes increased substantially; they now bound the encoding
  this implementation emits, which is not the specification's compact one.
- NTRU and NTRU Prime key and ciphertext sizes changed to match the encoding
  actually used. Keys from earlier builds are not compatible.

### Added

- `tests/unit/test_security_audit.c`: regression tests asserting the
  violated invariant for each defect above, rather than round-trip success.

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
