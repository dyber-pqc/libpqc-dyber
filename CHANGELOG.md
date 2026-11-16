# Changelog

All notable changes to libpqc-dyber will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 0.3.0

ML-DSA and SLH-DSA now implement FIPS 204 and FIPS 205. Before this
release neither interoperated with any other implementation. Their
signatures verified under libpqc-dyber, because signing and verification
shared the same deviations, and verified nowhere else. Both are now
checked against OpenSSL 3.5 in both directions, for every parameter set,
with and without a context string.

**This release changes signature bytes and, for SLH-DSA, public keys.**

- ML-DSA keys are unchanged. Signatures made by 0.2.x do not verify under
  0.3.0, and the reverse.
- SLH-DSA keys must be regenerated: `PK.root` is a function of the
  address layout, which changed. Signatures do not carry over either.
- `ML-DSA-65+Ed25519` and `ML-DSA-87+P256` signatures change with their
  ML-DSA half.
- The `SPHINCS+-*` names share the SLH-DSA core, so their keys and
  signatures change too. They sign without the FIPS 205 message prefix
  and take no context string. Their conformance to SPHINCS+ round 3 is
  not tested; use the `SLH-DSA-*` names.

Reported by Conner (Spartan8806). Testing his findings against OpenSSL
turned up the SLH-DSA address-layout and SHA-2 defects below, which a
round-trip test could not see.

### Security

- **ML-DSA signed the message without the FIPS 204 section 5.2 prefix.**
  `mu` was computed as `H(tr || M)`, which is ML-DSA.Sign_internal on the
  raw message. ML-DSA.Sign hashes `M' = 0x00 || len(ctx) || ctx || M`.
  The leading `0x00` separates pure ML-DSA from HashML-DSA, and the
  context string is how an application stops a signature made for one
  purpose being accepted for another. Without the prefix there was
  neither, and no conformant verifier accepted the signatures. The
  lattice arithmetic was correct.
- **SLH-DSA signed the message without the FIPS 205 section 10.2
  prefix**: the same omission, in `slh_sign` / `slh_verify`.
- **SLH-DSA cleared the FORS and WOTS+ key-pair address.**
  `slhdsa_set_type()` is a correct setTypeAndClear, but FIPS 205
  Algorithms 6, 7, 8, 14, 15 and 17 restore the key-pair address right
  after it, and this code did not. Every FORS instance depended on
  `idx_tree` alone and was the same across all 2^h' leaves of a layer-0
  tree, so distinct FORS few-time key pairs fell from 2^h to 2^(h-h'):
  512 times more reuse for 128s and 192s, and 8 times for 128f and 192f.
  The same defect class as the XMSS leaf index fixed in 0.2.0.
- **SLH-DSA `H_msg` produced one byte too few** in 8 of the 12 parameter
  sets. It emitted `ceil((k*a + h) / 8)` bytes, while the digest split
  reads `m = ceil(k*a/8) + ceil((h-h/d)/8) + ceil((h/d)/8)`. The missing
  byte, zeroed by the caller, was the top of `idx_leaf`: 128f and 256f
  signed with layer-0 leaf 0 only, and 128s and 192s reached 2 of 512
  leaves.
- **SLH-DSA used its own ADRS layout.** FIPS 205 section 4.2 gives the
  tree address 12 bytes. This code gave it 8, which put type, key pair,
  chain and hash four bytes early and left the last word always zero.
  Every tweakable hash input in all twelve parameter sets differed from
  the standard.
- **SLH-DSA-SHA2 did not compress the address.** FIPS 205 section 11.2
  hashes the 22-byte ADRSc; this code hashed the full 32-byte ADRS. A
  comment described this as a simplification.
- **SLH-DSA-SHA2 at security categories 3 and 5 computed F with
  SHA-512.** Section 11.2.2 moves only H and T_l to SHA-512; F and PRF
  stay on SHA-256.
- **SLH-DSA-SHA2 `H_msg` seeded MGF1 with the inner hash alone.** The
  standard seeds it with `R || PK.seed || SHA-x(R || PK.seed || PK.root
  || M)`.

### Added

- `pqc_sig_sign_ctx()` and `pqc_sig_verify_ctx()`: sign and verify with a
  context string of up to 255 bytes. `pqc_sig_sign()` and
  `pqc_sig_verify()` are these with an empty context. For an algorithm
  with no context input, a non-empty context returns
  `PQC_ERROR_NOT_SUPPORTED` rather than being dropped.
- `tests/interop/`: a small command-line front end to the signature API,
  and `openssl_interop.py`, which signs with libpqc-dyber and verifies
  with OpenSSL and the reverse, for all 3 ML-DSA and 12 SLH-DSA parameter
  sets, with and without a context. It also checks that a signature is
  rejected under a different context by both implementations. 90 checks.
  As negative controls: with the old ML-DSA message hashing put back, 15
  of the 18 ML-DSA checks fail; with the old SLH-DSA address layout and
  SHA-2 hashing, all 48 cross-implementation SLH-DSA checks fail.
  Registered with ctest under the `interop`
  label (skipped where OpenSSL lacks the algorithms), and run in a new CI
  job against Homebrew's OpenSSL, where a skip counts as a failure.
- `test_security_audit`: an SLH-DSA invariant group. Distinct key-pair
  indices must give distinct FORS and WOTS+ public keys, the caller's
  key-pair address must survive a call, and `H_msg` must write exactly m
  bytes. Also a context-string group for the new API.

### Changed

- SLH-DSA PRF_msg with SHA-256 now streams the message instead of copying
  messages under 64 KiB into a stack buffer first.

## [0.2.1] - 2026-11-10

This is a security release. The classical half of every hybrid scheme —
X25519, Ed25519, ECDH P-256 and ECDSA P-256 — did not implement its
specification. None of them matched a single published test vector, and
in 0.2.0 none of the four hybrid schemes completed a round trip: across
50 fresh key pairs each, `ML-KEM-768+X25519` never agreed on a shared
secret, `ML-KEM-1024+P256` failed in encapsulation every time, and
neither `ML-DSA-65+Ed25519` nor `ML-DSA-87+P256` produced a signature
that verified.

**Hybrid keys, ciphertexts, shared secrets and signatures from earlier
versions are not compatible with this release.** Anyone holding
`ML-KEM-768+X25519`, `ML-KEM-1024+P256`, `ML-DSA-65+Ed25519` or
`ML-DSA-87+P256` key material must regenerate it. The post-quantum
algorithms on their own (ML-KEM, ML-DSA and the rest) are untouched; their
keys and outputs do not change.

Found while validating the library against @noble/post-quantum and
OpenSSL 3.5 for a WebAssembly build: ML-KEM and ML-DSA matched byte for
byte, X25519 did not. The first two entries below are that report; the
rest came from auditing the remaining code in `src/core/hybrid/` the same
way. None of it had known-answer tests, and the hybrid schemes were not on
the round-trip allow list either.

### Security

- **X25519: the Montgomery ladder ran on a different curve.** The ladder
  step computed `z2 = E * (AA + 121666 * E)`. RFC 7748 specifies
  `E * (AA + 121665 * E)`, which equals `E * (BB + 121666 * E)`; the code
  added `AA` where it needed `BB`. The result is a ladder for the curve
  with A = 486666 rather than 486662: not X25519, not interoperable with
  anything, and on a curve nobody has analysed.
- **Curve25519: `fe25519_frombytes` dropped twelve bits of every field
  element.** It loaded 48 bits into each 51-bit limb, losing bits 48-50,
  99-101, 150-152 and 201-203, and folded bit 255 into the value instead
  of ignoring it as RFC 7748 requires. Any coordinate with one of those
  bits set decoded to the wrong value. This affected X25519 public keys
  and every Ed25519 constant and point.
- **Curve25519: `fe25519_tobytes` never performed the final reduction.**
  The low limb of p was written as 2^56 - 19 instead of 2^51 - 19, so the
  conditional subtraction of p could not trigger. Values in [p, 2^255)
  were emitted unreduced, and `fe25519_iszero` reported a nonzero value
  for anything that reduced to p — which is what `x - x` produces.
- **Curve25519: `fe25519_mul121666` overflowed without a 128-bit integer
  type.** The path used by compilers that lack `__int128` (MSVC among
  them) multiplied a 51-bit limb by 121666 in 64 bits; the product needs
  68. It now goes through the general multiplication.
- **Curve25519: `fe25519_sub` could underflow.** It added 2p and did not
  carry, so subtracting the result of an earlier subtraction could take a
  limb below zero. It now adds 8p and carries.
- **Ed25519: the curve constants d and 2d were wrong.** 21 of the 32
  bytes of d and 22 of 2d differed from the real values, so no point
  operation was on the Ed25519 curve.
- **Ed25519: point addition mixed two formulas.** It took `C = 2d*T1*T2`
  and `D = 2*Z1*Z2` from one variant of the extended-coordinate addition
  and the undoubled `E` and `H` from another, halving both coordinates of
  every sum.
- **Ed25519: verification accepted S >= l.** The range check required by
  RFC 8032 section 5.1.7 was a comment with no code, so `(R, S + l)`
  verified whenever `(R, S)` did. Point decoding likewise accepted
  y >= p and x = 0 with the sign bit set, both of which RFC 8032 section
  5.1.3 says must fail.
- **Ed25519: `sc25519_reduce` dropped carries on its correction step.**
  Not reachable in practice (probability around 2^-124); fixed so the
  function is correct for every input.
- **P-256: point doubling corrupted its own input.**
  `p256_point_double(r, r)` — how scalar multiplication calls it — wrote
  the new Y before reading the old Y to compute Z. Every scalar
  multiplication, and so every key, shared secret and signature, was
  wrong.
- **P-256: `p256_scalar_mul` did not reduce mod n.** It kept the low 256
  bits of the 512-bit product and subtracted n from that a few times. No
  ECDSA value computed with it was correct. It now folds the high half
  down using 2^256 mod n, in constant time.
- **P-256: `p256_fe_mul` discarded a carry.** The Solinas reduction
  stopped one pass early, giving a result off by a multiple of 2^256 for
  some operands: 12 of 4.8 x 10^10 uniformly random pairs (about one in
  2^32) and 1,473 of 300,000 pairs built from runs of zero and one bits.
  Rare enough to pass any casual test; a scalar multiplication performs
  several thousand of these.
- **ECDSA P-256: the message hash was used unreduced.** Both the RFC 6979
  nonce derivation (`bits2octets`) and the signing equation took the hash
  as a raw 256-bit integer; it must be reduced mod n. Affects one hash in
  2^32.
- **P-256: point decoding accepted coordinates >= p**, which name the
  same point as their reduced form but are not valid encodings.
- **ECDH and ECDSA P-256 accepted a private scalar of 0 or >= n.** Both
  now refuse.

### Fixed

- `p256_fe_sub` no longer branches on the borrow of its (possibly secret)
  operands.
- The second 64x64 multiplication helper in `field_p256.c`, used only by
  `p256_scalar_mul` on compilers without `__int128`, missed a carry. Both
  callers now share one helper.

### Added

- `tests/unit/test_hybrid_classical.c`: known-answer tests for the four
  classical primitives. RFC 7748 section 5.2 (both single-shot vectors
  and the iterated test at 1 and 1,000 iterations; set `PQC_TEST_SLOW=1`
  for 1,000,000) and the section 6.1 Diffie-Hellman exchange; RFC 8032
  section 7.1 TEST 1, 2, 3 and SHA(abc); the NIST CAVP ECC CDH primitive
  vector for P-256; RFC 6979 appendix A.2.5 for ECDSA. Also the rejection
  cases above, a regression vector for each arithmetic defect, and
  round trips of all four hybrid schemes through the public API. 138
  checks; 61 of them fail against 0.2.0.
- The four hybrid schemes are now on the round-trip allow lists in
  `test_kem_all.c` and `test_sig_all.c`.

### Known issues

Not addressed by this release:

- **The hybrid KEM combiner does not bind the classical ciphertext or
  public key.** `hybrid_kem.c` derives the shared secret as
  `SHA-256(ss_pq || ss_classical) || SHA-256(ss_classical || ss_pq)`.
  Neither the X25519/P-256 ephemeral share nor the recipient's classical
  public key is hashed in. If ML-KEM were broken, what is left is unhashed
  Diffie-Hellman, which is malleable, so the combined KEM would not be
  IND-CCA secure. For ML-KEM-768 + X25519 the construction to adopt is
  X-Wing (draft-connolly-cfrg-xwing-kem). Changing the combiner changes
  every shared secret again, so it is left for a release of its own.
- **P-256 scalar multiplication is not constant time.** It is a plain
  double-and-add that skips the addition on zero bits, over point
  formulas that branch on special cases. The scalar is secret in ECDH
  and in ECDSA signing. The field and scalar multiplication, addition
  and subtraction underneath are branch-free.
- Hybrid signatures are the two component signatures concatenated over
  the same message with no domain separation, so each half is also a
  valid signature on its own under its component key.
- Ed25519 verification accepts small-order and mixed-order public keys.
  RFC 8032 permits this; some protocols need the stricter policy.
- `ecdh_p256_shared_secret` returns SHA-256 of the shared x-coordinate
  rather than the coordinate itself, so the P-256 half of
  `ML-KEM-1024+P256` is not the raw ECDH output other libraries produce.

## [0.2.0] - 2026-07-29

This is a security release. It fixes five critical memory-safety defects,
two signature schemes that were cryptographically broken, and a
decapsulation oracle in three KEMs. **It changes key and signature sizes
for CROSS, NTRU and NTRU Prime — keys generated by 0.1.0 are not
compatible.** Anyone using those algorithms must regenerate keys.

Reported by Conner (Spartan8806, https://github.com/spartan8806), with
three further defects found while verifying the report and two more found
by the sanitizer jobs once they were running again.

### Security

- **XMSS: signatures intermittently failed to verify.** `xmss_hash_f`
  leaves the `keyAndMask` address field set, and a WOTS+ chain whose
  base-w digit is zero performs no hash steps at all — so the address fed
  to the next chain's secret-key PRF depended on how many steps the
  previous chain took, which differs between key generation (always w-1
  steps) and signing (digit-many steps). Affected chains derived
  different secrets in the two paths. This was latent until the
  `keyAndMask` fix below made that field significant; before then every
  node shared one key and the leftover state could not matter. Reproduced
  at roughly 1 run in 12, and on every platform.
- **FN-DSA: undefined behaviour converting out-of-range doubles to
  `int32_t`** in `ntru_solve.c` and `sign.c`. The NTRU solver can diverge
  and produce magnitudes around 1e15; an out-of-range or NaN
  float-to-integer conversion is undefined, not wrapping. Conversions are
  now clamped, leaving the caller's own correctness checks to reject the
  result. Caught by the UndefinedBehaviorSanitizer job.

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

### Fixed

- **`pqc_hybrid_kem_count()`, `pqc_hybrid_kem_name()`,
  `pqc_hybrid_sig_count()` and `pqc_hybrid_sig_name()` are now
  implemented.** All four are declared in the installed header
  `include/pqc/hybrid.h` but were never defined anywhere in `src/`, so any
  consumer that referenced them failed to link — which is how the Go
  binding was failing. They are driven off the same vtable lists used for
  registration, so the enumeration cannot drift from what is actually
  registered.
- **`pqc_sig_sign()` no longer dereferences a NULL function pointer for
  stateful schemes.** LMS and XMSS leave `.sign` NULL and are signed
  through `pqc_sig_sign_stateful()`; the stateless entry point did not
  check, so calling it on one of them crashed rather than reporting the
  misuse. It now returns `PQC_ERROR_NOT_SUPPORTED`.

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
  Several of these defects were invisible to round-trip testing because
  signing and verification shared the broken code. 125 checks.
- The signature-buffer bounds group sweeps every registered algorithm
  (`pqc_sig_algorithm_count()`) rather than a fixed list: 54 considered, 47
  signed. Staying inside `max_signature_size()` is a property every
  algorithm owes its caller whether or not it is otherwise correct, so it
  is deliberately not gated on brokenness — excluding schemes by name for
  being broken is how the SNOVA and CROSS overflow survived. Remaining
  skips are for key-generation cost only.
- The WOTS+ round-trip invariant (`pk_from_sig(sign(m), m) == keygen()`)
  over many base-w digit patterns, which is what isolated the XMSS
  chain-secret defect above.

### Changed (CI)

- The Security Audit workflow gains a non-advisory regression job that runs
  the new suite under ASan and UBSan. Every other job in that workflow is
  advisory (`continue-on-error`), so nothing there could previously fail a
  run on a real finding.
- All jobs across every workflow now declare `timeout-minutes`; a previous
  CI run reached 14 hours before being cancelled.
- The NuGet publish step passes its token through the environment rather
  than the command line, where it was visible in the process list.

  Note: the scheduled Security Audit runs that failed between May and June
  did so because the repository's GitHub account was locked for billing
  ("The job was not started because your account is locked due to a billing
  issue"), not because of workflow configuration. Those jobs never started.
  The changes above do not address that, and the audit only resumes
  examining the code once Actions billing is in good standing.

### Known issues

The following are pre-existing and not addressed by this release. All are
already excluded from the benchmark suite.

- Classic McEliece, NTRU and NTRU Prime: decapsulation derives a shared
  secret that does not match encapsulation.
- MAYO, UOV, SNOVA and CROSS: signatures do not verify against their own
  public keys.
- FN-DSA: key generation fails; `ffSampling` uses a single global sigma
  rather than per-coefficient Gram-Schmidt sigmas, and the `ccs`
  acceptance factor is consequently still omitted.
- LMS-SHA256-H20 and H25 cannot generate keys (see above).

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
